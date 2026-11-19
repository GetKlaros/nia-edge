package agents

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Governing an agent that runs its own tools (Claude Code, Codex): its tool
// hooks are nia-edge's, in the machine's managed configuration, which every
// user of the machine gets and none can turn off from their own settings.
// Before a tool runs, Nia decides it; after, the session learns it holds a
// result of that tool. This governs the agent, it does not confine it: a
// user who is root on the machine, or who runs another program, goes around
// it. Hermes and OpenClaw are confined by their installers.
//
// Every file changed is saved first, beside it (<file>.nia-edge.json, with
// its former content or the fact that it did not exist), and Restore puts it
// back exactly.

// Onboarding names what is changed for one agent.
type Onboarding struct {
	Kind string
	// File is the managed configuration nia-edge's hooks go into.
	File string
	// Model, when set, also sends the agent's model calls to nia-edge.
	Model bool
}

// Edge is nia-edge's address on the machine, as the hooks reach it.
const Edge = "http://127.0.0.1:8787"

// HookCommand is how Codex runs nia-edge's hook.
const HookCommand = "/usr/local/bin/nia-edge hook codex"

// Managed files, by agent.
var managed = map[string]string{
	"claude-code": "/etc/claude-code/managed-settings.json",
	"codex":       "/etc/codex/requirements.toml",
}

// Governable lists the agents nia-edge governs by their hooks.
func Governable() []string { return []string{"claude-code", "codex"} }

// For returns what onboarding the agent changes, under root (tests).
func For(kind, root string, model bool) (Onboarding, error) {
	file, ok := managed[kind]
	if !ok {
		return Onboarding{}, fmt.Errorf("%s is not governed by its hooks: %s", kind, strings.Join(Governable(), ", ")+" are; Hermes and OpenClaw are confined by their installers")
	}
	if model && kind != "claude-code" {
		return Onboarding{}, fmt.Errorf("-model is for claude-code only for now: %s's model calls go to its provider", kind)
	}
	return Onboarding{Kind: kind, File: filepath.Join(root, file), Model: model}, nil
}

type saved struct {
	Version  int    `json:"version"`
	Existed  bool   `json:"existed"`
	Original string `json:"original"`
	// SHA256 of what nia-edge wrote: a file changed since is not overwritten.
	Wrote string `json:"wrote"`
}

func (o Onboarding) backup() string { return o.File + ".nia-edge.json" }

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Plan returns the file as onboarding leaves it, and whether it changes.
func (o Onboarding) Plan() (before, after []byte, err error) {
	before, err = os.ReadFile(o.File)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	// Onboarding again starts from the original, so it is the same.
	if prior, ok := o.saved(); ok {
		before = []byte(prior.Original)
	}
	switch o.Kind {
	case "claude-code":
		after, err = claudeSettings(before, o.Model)
	case "codex":
		after, err = codexRequirements(before)
	}
	return before, after, err
}

func (o Onboarding) saved() (saved, bool) {
	raw, err := os.ReadFile(o.backup())
	if err != nil {
		return saved{}, false
	}
	var s saved
	if json.Unmarshal(raw, &s) != nil || s.Version != 1 {
		return saved{}, false
	}
	return s, true
}

// Apply writes the managed configuration, saving the former one first.
func (o Onboarding) Apply() error {
	current, err := os.ReadFile(o.File)
	existed := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, after, err := o.Plan()
	if err != nil {
		return err
	}
	prior, already := o.saved()
	if already && digest(current) != prior.Wrote {
		return fmt.Errorf("%s changed since nia-edge wrote it: restore or merge it by hand first (%s holds the original)", o.File, o.backup())
	}
	record := prior
	if !already {
		record = saved{Version: 1, Existed: existed, Original: string(current)}
	}
	record.Wrote = digest(after)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(o.File), 0o755); err != nil {
		return err
	}
	// The original first: whatever fails next, it can be put back.
	if err := writeAtomic(o.backup(), encoded, 0o600); err != nil {
		return err
	}
	return writeAtomic(o.File, after, 0o644)
}

// Restore puts the managed configuration back as it was before onboarding.
func (o Onboarding) Restore() error {
	prior, ok := o.saved()
	if !ok {
		return fmt.Errorf("%s was not onboarded by nia-edge (no %s)", o.Kind, o.backup())
	}
	current, err := os.ReadFile(o.File)
	if err == nil && digest(current) != prior.Wrote {
		return fmt.Errorf("%s changed since nia-edge wrote it: put back %s's original by hand", o.File, o.backup())
	}
	if prior.Existed {
		if err := writeAtomic(o.File, []byte(prior.Original), 0o644); err != nil {
			return err
		}
	} else if err := os.Remove(o.File); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Remove(o.backup())
}

// Status says whether the agent's managed configuration holds nia-edge's
// hooks: "machine" when it does, "" when it does not, "changed" when
// nia-edge's are there but the file changed since nia-edge wrote it.
func (o Onboarding) Status() string {
	current, err := os.ReadFile(o.File)
	if err != nil || !governedBy(o.Kind, current) {
		return ""
	}
	if prior, ok := o.saved(); ok && digest(current) != prior.Wrote {
		return "changed"
	}
	return "machine"
}

func governedBy(kind string, data []byte) bool {
	switch kind {
	case "claude-code":
		return bytes.Contains(data, []byte(Edge+"/v1/hooks/claude-code"))
	case "codex":
		return bytes.Contains(data, []byte(codexBegin)) && bytes.Contains(data, []byte(HookCommand))
	}
	return false
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// claudeSettings adds nia-edge's HTTP hooks to Claude Code's managed
// settings: they block when nia-edge cannot be reached ("onFailure":
// "block", Claude Code 2.1.295 and later), and a user's disableAllHooks
// does not turn managed hooks off.
func claudeSettings(before []byte, model bool) ([]byte, error) {
	settings := map[string]any{}
	if len(bytes.TrimSpace(before)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(before))
		decoder.UseNumber()
		if err := decoder.Decode(&settings); err != nil {
			return nil, fmt.Errorf("Claude Code's managed settings are not JSON: %w", err)
		}
	}
	if disabled, _ := settings["disableAllHooks"].(bool); disabled {
		return nil, errors.New("Claude Code's managed settings turn every hook off (disableAllHooks): remove it first")
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		if settings["hooks"] != nil {
			return nil, errors.New("Claude Code's managed settings have hooks that are not an object")
		}
		hooks = map[string]any{}
	}
	url := Edge + "/v1/hooks/claude-code"
	for event, timeout := range map[string]int{"PreToolUse": 330, "PostToolUse": 30} {
		entries, _ := hooks[event].([]any)
		if hooks[event] != nil && entries == nil {
			return nil, fmt.Errorf("Claude Code's managed hooks for %s are not a list", event)
		}
		kept := []any{}
		for _, entry := range entries {
			if !strings.Contains(fmt.Sprint(entry), url) {
				kept = append(kept, entry)
			}
		}
		kept = append(kept, map[string]any{
			"matcher": "*",
			"hooks": []any{map[string]any{
				"type": "http", "url": url, "timeout": timeout, "onFailure": "block",
			}},
		})
		hooks[event] = kept
	}
	settings["hooks"] = hooks
	if model {
		env, _ := settings["env"].(map[string]any)
		if env == nil {
			env = map[string]any{}
		}
		// nia-edge calls the provider with its own key; Claude Code's is
		// not forwarded.
		env["ANTHROPIC_BASE_URL"] = Edge
		settings["env"] = env
	}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

const (
	codexBegin = "# >>> nia-edge: Nia decides every tool call (nia-edge agents restore codex)"
	codexEnd   = "# <<< nia-edge"
)

// codexRequirements appends nia-edge's command hooks to Codex's
// requirements: managed hooks, which Codex trusts and a user cannot turn
// off. Codex lets a call through when its hook fails; nia-edge's hook
// answers "deny" whatever fails, within the hook's timeout.
func codexRequirements(before []byte) ([]byte, error) {
	text := string(before)
	if i := strings.Index(text, codexBegin); i >= 0 {
		j := strings.Index(text[i:], codexEnd)
		if j < 0 {
			return nil, errors.New("Codex's requirements hold nia-edge's block without its end: fix it by hand")
		}
		text = text[:i] + strings.TrimPrefix(text[i+j+len(codexEnd):], "\n")
	}
	lines := strings.Split(text, "\n")
	features := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "hooks") && strings.Contains(trimmed, "=") && strings.Contains(trimmed, "{") {
			return nil, errors.New("Codex's requirements set hooks inline (hooks = {…}): write them as tables first")
		}
		if strings.HasPrefix(trimmed, "features") && !strings.HasPrefix(trimmed, "[") {
			return nil, errors.New("Codex's requirements set features as dotted keys or inline: write them as a [features] table first")
		}
		if trimmed == "[features]" {
			features = i
		}
	}
	// A user's own configuration can turn hooks off ([features] hooks =
	// false), managed ones included: the requirements pin them on.
	pinned := false
	if features >= 0 {
		for i := features + 1; i < len(lines); i++ {
			trimmed := strings.TrimSpace(lines[i])
			if strings.HasPrefix(trimmed, "[") {
				break
			}
			key, _, found := strings.Cut(trimmed, "=")
			if found && strings.TrimSpace(key) == "hooks" {
				lines[i] = "hooks = true"
				pinned = true
			}
		}
		if !pinned {
			lines = append(lines[:features+1], append([]string{"hooks = true"}, lines[features+1:]...)...)
			pinned = true
		}
		text = strings.Join(lines, "\n")
	}
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	var block strings.Builder
	block.WriteString(codexBegin + "\n")
	if !pinned {
		block.WriteString("[features]\nhooks = true\n")
	}
	for _, event := range []struct {
		name    string
		timeout int
	}{{"PreToolUse", 330}, {"PostToolUse", 60}} {
		fmt.Fprintf(&block, "[[hooks.%s]]\nmatcher = \".*\"\n[[hooks.%s.hooks]]\ntype = \"command\"\ncommand = %q\ntimeout = %d\n", event.name, event.name, HookCommand, event.timeout)
	}
	block.WriteString(codexEnd + "\n")
	if text != "" {
		text += "\n"
	}
	return []byte(text + block.String()), nil
}
