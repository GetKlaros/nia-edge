// Package hooks answers the tool hooks of the coding agents that run their
// own tools (Claude Code, Codex): before a tool runs, Nia decides it; after,
// the session is told it holds a result of that tool.
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

	"github.com/GetKlaros/nia-edge/internal/inspect"
	"github.com/GetKlaros/nia-edge/internal/local"
)

// Agent is a hook dialect.
type Agent string

const (
	ClaudeCode Agent = "claude-code"
	Codex      Agent = "codex"
)

// Route returns the agent whose hooks a path receives, or "".
func Route(path string) Agent {
	switch path {
	case "/v1/hooks/claude-code":
		return ClaudeCode
	case "/v1/hooks/codex":
		return Codex
	}
	return ""
}

// Handler answers both dialects.
type Handler struct {
	Nia    local.Authority
	Rules  func() *local.Rules
	Logger *slog.Logger
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
	prefix := "cc-"
	if agent == Codex {
		prefix = "cx-"
	}
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
		writeJSON(w, deny("Nia could not read this hook"))
		return
	}
	ctx := r.Context()
	conversation := session(agent, hook.Session)
	switch hook.Event {
	case "PreToolUse":
		writeJSON(w, h.before(ctx, conversation, hook))
	case "PostToolUse":
		writeJSON(w, h.after(ctx, agent, conversation, hook))
	default:
		// Not an event of a tool: nothing to decide.
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) before(ctx context.Context, conversation string, hook payload) any {
	arguments := string(hook.Input)
	if strings.TrimSpace(arguments) == "" || arguments == "null" {
		arguments = "{}"
	}
	verdict, err := local.Decide(ctx, h.Nia, h.Rules, conversation, hook.Tool, arguments, nil)
	if err != nil {
		h.log("a hook call was refused: Nia could not decide", "tool", hook.Tool, "error", err.Error())
		return deny("Nia could not decide this call, so it was not run")
	}
	if verdict.Allowed {
		return nil
	}
	message := verdict.Message
	if message == "" {
		message = "Nia refused this call"
	}
	return deny(message)
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
