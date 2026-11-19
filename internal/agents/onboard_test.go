package agents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeCodeOnboardAndRestore(t *testing.T) {
	root := t.TempDir()
	o, err := For("claude-code", root, true)
	if err != nil {
		t.Fatal(err)
	}
	original := `{"permissions":{"deny":["Read(./.env)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/audit"}]}]}}`
	write(t, root, "/etc/claude-code/managed-settings.json", original)

	if o.Status() != "" {
		t.Fatal("not onboarded yet")
	}
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	// Twice is the same as once.
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(o.File)
	var settings struct {
		Permissions map[string]any `json:"permissions"`
		Env         map[string]string
		Hooks       map[string][]struct {
			Matcher string
			Hooks   []map[string]any
		}
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Permissions == nil || settings.Env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:8787" {
		t.Fatalf("%s", raw)
	}
	pre := settings.Hooks["PreToolUse"]
	if len(pre) != 2 || pre[0].Hooks[0]["command"] != "/opt/audit" {
		t.Fatalf("the organisation's own hook must stay, nia-edge's once: %s", raw)
	}
	nia := pre[1].Hooks[0]
	if nia["url"] != "http://127.0.0.1:8787/v1/hooks/claude-code" || nia["onFailure"] != "block" || nia["type"] != "http" || pre[1].Matcher != "*" {
		t.Fatalf("%v", nia)
	}
	if len(settings.Hooks["PostToolUse"]) != 1 {
		t.Fatalf("%s", raw)
	}
	if o.Status() != "machine" {
		t.Fatal(o.Status())
	}
	if err := o.Restore(); err != nil {
		t.Fatal(err)
	}
	back, _ := os.ReadFile(o.File)
	if string(back) != original {
		t.Fatalf("restore must give the original back byte for byte: %s", back)
	}
	if _, err := os.Stat(o.File + ".nia-edge.json"); !os.IsNotExist(err) {
		t.Fatal("the backup must go with the restore")
	}
}

func TestOnboardWithoutAFileRestoresToNone(t *testing.T) {
	root := t.TempDir()
	o, _ := For("claude-code", root, false)
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(o.File)
	if strings.Contains(string(raw), "ANTHROPIC_BASE_URL") {
		t.Fatal("the model goes to nia-edge only with -model")
	}
	if err := o.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(o.File); !os.IsNotExist(err) {
		t.Fatal("a file that did not exist does not exist again")
	}
}

func TestAChangedFileIsNotOverwritten(t *testing.T) {
	root := t.TempDir()
	o, _ := For("claude-code", root, false)
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/etc/claude-code/managed-settings.json", `{"hooks":{"PreToolUse":[{"hooks":[{"url":"http://127.0.0.1:8787/v1/hooks/claude-code"}]}]},"other":1}`)
	if o.Status() != "changed" {
		t.Fatal(o.Status())
	}
	if err := o.Restore(); err == nil {
		t.Fatal("a file someone changed since is not put back over")
	}
	if err := o.Apply(); err == nil {
		t.Fatal("nor written over")
	}
}

func TestClaudeCodeRefusals(t *testing.T) {
	for _, original := range []string{
		`{"disableAllHooks": true}`,
		`not json`,
		`{"hooks": []}`,
		`{"hooks": {"PreToolUse": {}}}`,
	} {
		root := t.TempDir()
		write(t, root, "/etc/claude-code/managed-settings.json", original)
		o, _ := For("claude-code", root, false)
		if err := o.Apply(); err == nil {
			t.Errorf("%s: onboarding must refuse", original)
		}
		if raw, _ := os.ReadFile(o.File); string(raw) != original {
			t.Errorf("%s: a refusal changes nothing", original)
		}
	}
}

func TestCodexRequirements(t *testing.T) {
	root := t.TempDir()
	o, err := For("codex", root, false)
	if err != nil {
		t.Fatal(err)
	}
	original := "allowed_approval_policies = [\"on-request\"]\n\n[hooks]\nmanaged_dir = \"/etc/codex/hooks\"\n"
	write(t, root, "/etc/codex/requirements.toml", original)
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(o.File)
	text := string(raw)
	if !strings.Contains(text, "[features]\nhooks = true\n") {
		t.Fatalf("hooks pinned on: %s", text)
	}
	if !strings.HasPrefix(text, original) || strings.Count(text, codexBegin) != 1 || strings.Count(text, "[[hooks.PreToolUse]]") != 1 || strings.Count(text, "[[hooks.PostToolUse]]") != 1 {
		t.Fatalf("%s", text)
	}
	if !strings.Contains(text, `command = "/usr/local/bin/nia-edge hook codex"`) || !strings.Contains(text, "timeout = 330") {
		t.Fatalf("%s", text)
	}
	if o.Status() != "machine" {
		t.Fatal(o.Status())
	}
	if err := o.Restore(); err != nil {
		t.Fatal(err)
	}
	if back, _ := os.ReadFile(o.File); string(back) != original {
		t.Fatalf("%s", back)
	}
	if _, err := For("codex", root, true); err == nil {
		t.Fatal("-model is for claude-code only")
	}
	if _, err := For("hermes", root, false); err == nil {
		t.Fatal("hermes is confined, not governed by hooks")
	}
	// A [features] table of the organisation's own: pinned in it.
	write(t, root, "/etc/codex/requirements.toml", "[features]\nhooks = false\nweb_search = true\n\n[x]\ny = 1\n")
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(o.File)
	if text := string(raw); !strings.HasPrefix(text, "[features]\nhooks = true\nweb_search = true\n") || strings.Count(text, "[features]") != 1 {
		t.Fatalf("%s", text)
	}
	if err := o.Restore(); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/etc/codex/requirements.toml", "[features]\n\n[x]\n")
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(o.File)
	if !strings.HasPrefix(string(raw), "[features]\nhooks = true\n") {
		t.Fatalf("%s", raw)
	}
	if err := o.Restore(); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/etc/codex/requirements.toml", "features.hooks = false\n")
	if err := o.Apply(); err == nil {
		t.Fatal("dotted features cannot be pinned safely")
	}
	write(t, root, "/etc/codex/requirements.toml", "hooks = { PreToolUse = [] }\n")
	if err := o.Apply(); err == nil {
		t.Fatal("inline hooks cannot take nia-edge's tables")
	}
}

func TestGovernedShowsInFind(t *testing.T) {
	root := machine(t)
	write(t, root, "/home/alice/.claude.json", `{"mcpServers":{}}`)
	o, _ := For("claude-code", root, false)
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	found, err := Find(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range found {
		if a.Kind == "claude-code" {
			if a.Governed != "machine" || !strings.HasPrefix(a.Next, "governed") {
				t.Fatalf("%+v", a)
			}
			return
		}
	}
	t.Fatal("no claude-code found")
}

func TestBackupIsPrivate(t *testing.T) {
	root := t.TempDir()
	o, _ := For("codex", root, false)
	if err := o.Apply(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "/etc/codex/requirements.toml.nia-edge.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
}
