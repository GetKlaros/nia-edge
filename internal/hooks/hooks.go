// Package hooks answers the tool hooks of the coding agents that run their
// own tools (Claude Code, Codex, Gemini CLI, and Pi and Oh My Pi through
// nia-edge's extension): before a tool runs, Nia decides it; after, the
// session is told it holds a result of that tool.
//
// It decides as the model path does (local.Decide): when the signed policy in
// force can decide the call, Nia receives its hash and the decision for each
// state of the session, never its arguments; the tool's output never leaves
// the machine. A secret in an output is withheld from the model here.
//
// It fails closed: a payload it cannot read, a decision it cannot obtain, an
// answer that is not "allow" refuse the call. "allow" answers nothing, so
// the agent's own permission rules still apply: Nia never widens them, and a
// call held for a reviewer is refused, never put to the person at the
// terminal.
package hooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/GetKlaros/nia-edge/internal/inspect"
	"github.com/GetKlaros/nia-edge/internal/local"
)

// Agent is a hook dialect.
type Agent string

const (
	ClaudeCode Agent = "claude-code"
	Codex      Agent = "codex"
	GeminiCLI  Agent = "gemini-cli"
	// Pi and Omp speak nia-edge's own dialect, from its extension
	// (tool_call, tool_result).
	Pi  Agent = "pi"
	Omp Agent = "omp"
)

// Route returns the agent whose hooks a path receives, or "".
func Route(path string) Agent {
	switch path {
	case "/v1/hooks/claude-code":
		return ClaudeCode
	case "/v1/hooks/codex":
		return Codex
	case "/v1/hooks/gemini-cli":
		return GeminiCLI
	case "/v1/hooks/pi":
		return Pi
	case "/v1/hooks/omp":
		return Omp
	}
	return ""
}

// Handler answers both dialects.
type Handler struct {
	Nia   local.Authority
	Rules func() *local.Rules
	// Releases keeps the allowed calls of the MCP servers nia-edge serves
	// (mcp__<server>__<tool>): such a call runs only against one, once.
	Releases *local.Releases
	Logger   *slog.Logger
}

// MaxPayload bounds what a hook may send.
const MaxPayload = 1 << 20

type payload struct {
	Event    string          `json:"hook_event_name"`
	Session  string          `json:"session_id"`
	Tool     string          `json:"tool_name"`
	Input    json.RawMessage `json:"tool_input"`
	Response json.RawMessage `json:"tool_response"`
}

var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,120}$`)

// session names the agent's conversation for Nia, apart from the model
// path's: cc- or cx- and the agent's own id, or its hash when Nia would not
// take it as it is.
func session(agent Agent, id string) string {
	prefix := map[Agent]string{ClaudeCode: "cc-", Codex: "cx-", GeminiCLI: "gm-", Pi: "pi-", Omp: "om-"}[agent]
	if sessionPattern.MatchString(id) {
		return prefix + id
	}
	sum := sha256.Sum256([]byte(id))
	return prefix + hex.EncodeToString(sum[:16])
}

func (h *Handler) log(message string, args ...any) {
	if h.Logger != nil {
		h.Logger.Warn(message, args...)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	agent := Route(r.URL.Path)
	if agent == "" || r.Method != http.MethodPost {
		http.Error(w, "not a hook route", http.StatusNotFound)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxPayload+1))
	var hook payload
	if err != nil || len(raw) > MaxPayload || json.Unmarshal(raw, &hook) != nil || hook.Tool == "" {
		// Unreadable: whatever event it was, nothing is let through.
		writeJSON(w, Refusal(agent, hook.Event, "Nia could not read this hook"))
		return
	}
	ctx := r.Context()
	conversation := session(agent, hook.Session)
	switch hook.Event {
	case "PreToolUse", "BeforeTool", "tool_call":
		writeJSON(w, h.before(ctx, agent, conversation, hook))
	case "PostToolUse", "AfterTool", "tool_result":
		writeJSON(w, h.after(ctx, agent, conversation, hook))
	default:
		// Not an event of a tool: nothing to decide.
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) before(ctx context.Context, agent Agent, conversation string, hook payload) any {
	arguments := string(hook.Input)
	if strings.TrimSpace(arguments) == "" || arguments == "null" {
		arguments = "{}"
	}
	verdict, err := local.Decide(ctx, h.Nia, h.Rules, conversation, hook.Tool, arguments, nil)
	if err != nil {
		h.log("a hook call was refused: Nia could not decide", "tool", hook.Tool, "error", err.Error())
		return Refusal(agent, "before", "Nia could not decide this call, so it was not run")
	}
	if verdict.Allowed {
		if h.Releases != nil && strings.HasPrefix(hook.Tool, h.Releases.Prefix) && h.Releases.Prefix != "" {
			h.Releases.Release(hook.Tool, arguments, time.Now())
		}
		return nil
	}
	message := verdict.Message
	if message == "" {
		message = "Nia refused this call"
	}
	return Refusal(agent, "before", message)
}

// Refusal is the answer that refuses, in the agent's dialect: before a tool,
// the call is not run; after it, its output does not reach the model.
func Refusal(agent Agent, event, reason string) any {
	after := event == "after" || event == "PostToolUse" || event == "AfterTool" || event == "tool_result"
	reason = "[Nia agent firewall] " + reason
	switch agent {
	case GeminiCLI:
		// BeforeTool: the call is not run. AfterTool: the reason replaces
		// the output the model gets.
		return map[string]any{"decision": "deny", "reason": reason}
	case Pi, Omp:
		if after {
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": reason}}, "isError": true}
		}
		return map[string]any{"block": true, "reason": reason}
	}
	if after {
		return map[string]any{"continue": false, "stopReason": reason + "; the turn was stopped."}
	}
	return deny(strings.TrimPrefix(reason, "[Nia agent firewall] "))
}

func (h *Handler) after(ctx context.Context, agent Agent, conversation string, hook payload) any {
	if err := h.Nia.Ingested(ctx, conversation, hook.Tool); err != nil {
		// The session could not be told what it now holds: the output does
		// not reach the model.
		h.log("a tool output was withheld: Nia could not record it", "tool", hook.Tool, "error", err.Error())
		return withhold(agent, hook, "Nia could not record this tool's output, so the model does not see it", false)
	}
	if len(hook.Response) == 0 || len(inspect.Secrets(string(hook.Response))) == 0 {
		return nil
	}
	return withhold(agent, hook, "Nia redacted secrets from this tool output", true)
}

func deny(reason string) map[string]any {
	return map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": "[Nia agent firewall] " + reason,
	}}
}

// withhold keeps an output from the model: redacted when redact, else every
// string replaced. Codex can replace only an MCP tool's output: for another
// tool, the turn stops.
func withhold(agent Agent, hook payload, reason string, redact bool) any {
	var value any
	if json.Unmarshal(hook.Response, &value) != nil {
		value = nil
	}
	replaced := mapStrings(value, func(text string) string {
		if redact {
			return inspect.RedactSecrets(text)
		}
		return "[withheld by Nia]"
	})
	switch agent {
	case GeminiCLI:
		// The reason replaces the output: the redacted output, as text.
		if !redact {
			return Refusal(agent, "after", reason)
		}
		shown := replaced
		if object, ok := replaced.(map[string]any); ok && object["llmContent"] != nil {
			shown = object["llmContent"]
		}
		text, ok := shown.(string)
		if !ok {
			encoded, _ := json.Marshal(shown)
			text = string(encoded)
		}
		return map[string]any{"decision": "deny", "reason": text + "\n[" + reason + ".]"}
	case Pi, Omp:
		if !redact {
			return Refusal(agent, "after", reason)
		}
		content, ok := replaced.([]any)
		if !ok {
			return Refusal(agent, "after", reason)
		}
		return map[string]any{"content": append(content, map[string]any{"type": "text", "text": "[" + reason + ".]"})}
	}
	if agent == Codex {
		if strings.HasPrefix(hook.Tool, "mcp__") {
			return map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName":        "PostToolUse",
				"updatedMCPToolOutput": replaced,
				"additionalContext":    reason + ".",
			}}
		}
		return map[string]any{"continue": false, "stopReason": "[Nia agent firewall] " + reason + "; the turn was stopped."}
	}
	out := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":     "PostToolUse",
		"updatedToolOutput": replaced,
		"additionalContext": reason + ".",
	}}
	if !redact {
		out["decision"] = "block"
		out["reason"] = reason + "."
	}
	return out
}

func mapStrings(value any, change func(string) string) any {
	switch v := value.(type) {
	case string:
		return change(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = mapStrings(item, change)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = mapStrings(item, change)
		}
		return out
	}
	return value
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Cache-Control", "no-store")
	if body == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
