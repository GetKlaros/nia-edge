package hooks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/engine"
	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/simulate"
)

// SimulateCommand is what an allowed shell command becomes when the role
// simulates: nia-edge runs it in a sandbox, has its effect judged, and
// applies it.
const SimulateCommand = "/usr/local/bin/nia-edge simulate "

// shells names each agent's shell tool, as its hooks report it; its
// command is the "command" argument.
var shells = map[Agent]string{
	ClaudeCode: "Bash",
	Codex:      "Bash",
	GeminiCLI:  "run_shell_command",
	Pi:         "bash",
	Omp:        "bash",
	OpenCode:   "bash",
}

// Tickets hold the commands handed to `nia-edge simulate`, each used once.
type Tickets struct {
	mu      sync.Mutex
	pending map[string]*ticket
}

type ticket struct {
	command, session string
	timeout          time.Duration
	expires          time.Time
	claimed          bool
}

const (
	ticketLife  = 10 * time.Minute
	ticketLimit = 256
)

var ticketPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (t *Tickets) issue(command, session string, timeout time.Duration) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for id, p := range t.pending {
		if now.After(p.expires) {
			delete(t.pending, id)
		}
	}
	if t.pending == nil {
		t.pending = map[string]*ticket{}
	}
	if len(t.pending) >= ticketLimit {
		return "", false
	}
	raw := make([]byte, 16)
	rand.Read(raw)
	id := hex.EncodeToString(raw)
	t.pending[id] = &ticket{command: command, session: session, timeout: timeout, expires: now.Add(ticketLife)}
	return id, true
}

// simulated rewrites an allowed shell command when the role simulates: the
// agent runs `nia-edge simulate <ticket>` instead. An agent whose command
// cannot be rewritten is refused, never run unsimulated.
func (h *Handler) simulated(agent Agent, conversation string, hook payload) any {
	if h.Rules == nil {
		return nil
	}
	rules := h.Rules()
	if rules == nil || rules.Role == nil || rules.Role.Simulate == nil || shells[agent] != hook.Tool {
		return nil
	}
	var input map[string]any
	decoder := json.NewDecoder(bytes.NewReader(hook.Input))
	decoder.UseNumber()
	if decoder.Decode(&input) != nil {
		return Refusal(agent, "before", "Nia simulates this role's commands, and this one could not be read")
	}
	command, ok := input["command"].(string)
	if !ok || strings.TrimSpace(command) == "" {
		return Refusal(agent, "before", "Nia simulates this role's commands, and this one could not be read")
	}
	if agent == ClaudeCode || h.Simulations == nil {
		return Refusal(agent, "before", "Nia simulates this role's commands, and cannot yet for this agent, so this call was not run")
	}
	id, ok := h.Simulations.issue(command, conversation, time.Duration(rules.Role.Simulate.Timeout)*time.Second)
	if !ok {
		return Refusal(agent, "before", "too many commands wait for their simulation")
	}
	input["command"] = SimulateCommand + id
	switch agent {
	case Codex:
		// Codex applies a rewritten input only with "allow", which grants
		// nothing more: its own approvals and sandbox still apply.
		return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": input}}
	case GeminiCLI:
		return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "BeforeTool", "tool_input": input}}
	}
	// nia-edge's own extensions and plugin.
	return map[string]any{"input": input}
}

// SimulationRoute reports whether a path is one of the simulation's.
func SimulationRoute(path string) bool { return strings.HasPrefix(path, "/v1/simulate/") }

// ServeSimulation hands a ticket's command to `nia-edge simulate`, once,
// then has the effect it reports judged by Nia (the nia:effect call).
func (h *Handler) ServeSimulation(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/simulate/")
	id, effectRoute := strings.CutSuffix(rest, "/effect")
	if !ticketPattern.MatchString(id) || h.Simulations == nil {
		http.Error(w, "no such ticket", http.StatusNotFound)
		return
	}
	t := h.Simulations
	t.mu.Lock()
	p := t.pending[id]
	if p == nil || time.Now().After(p.expires) || (r.Method == http.MethodGet && (effectRoute || p.claimed)) || (r.Method == http.MethodPost && (!effectRoute || !p.claimed)) || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
		t.mu.Unlock()
		http.Error(w, "no such ticket", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet {
		p.claimed = true
		t.mu.Unlock()
		writeJSON(w, map[string]any{"command": p.command, "timeout_seconds": int(p.timeout / time.Second)})
		return
	}
	delete(t.pending, id)
	t.mu.Unlock()
	writeJSON(w, h.judge(r.Context(), p.session, r.Body))
}

func (h *Handler) judge(ctx context.Context, session string, body io.Reader) map[string]any {
	refused := func(message string) map[string]any { return map[string]any{"allowed": false, "message": message} }
	raw, err := io.ReadAll(io.LimitReader(body, MaxPayload+1))
	var effect simulate.Effect
	if err != nil || len(raw) > MaxPayload || json.Unmarshal(raw, &effect) != nil || effect.Paths == nil || effect.Deleted < 0 {
		return refused("Nia could not read this command's effect")
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(effect) != nil {
		return refused("Nia could not read this command's effect")
	}
	verdict, err := local.Decide(ctx, h.Nia, h.Rules, session, engine.EffectTool, strings.TrimSpace(encoded.String()), nil)
	if err != nil {
		h.log("a simulated command was not applied: Nia could not decide its effect", "error", err.Error())
		return refused("Nia could not decide this command's effect, so it was not applied")
	}
	if !verdict.Allowed {
		message := verdict.Message
		if message == "" {
			message = "Nia refused this command's effect"
		}
		return refused(message)
	}
	return map[string]any{"allowed": true}
}
