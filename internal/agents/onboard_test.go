package agents

import (
	"encoding/json"
	"errors"
	"io/fs"
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
	// -model: nia-edge is Codex's provider, a top-level key before any table.
	withModel, err := For("codex", root, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := withModel.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(o.File)
	text = string(raw)
	if !strings.HasPrefix(text, codexModelBegin+"\nmodel_provider = \"nia-edge\"\n"+codexModelEnd+"\n") ||
		!strings.Contains(text, "[model_providers.nia-edge]\nname = \"nia-edge\"\nbase_url = \"http://127.0.0.1:8787/v1\"\nwire_api = \"responses\"\n") {
		t.Fatalf("%s", text)
	}
	// Again, with or without -model: the blocks are replaced, not added.
	if err := withModel.Apply(); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(o.File); string(again) != text {
		t.Fatalf("%s", again)
	}
	if err := withModel.Restore(); err != nil {
		t.Fatal(err)
	}
	if back, _ := os.ReadFile(o.File); string(back) != original {
		t.Fatalf("%s", back)
	}
	if _, err := codexRequirements([]byte("model_provider = \"azure\"\n"), true); err == nil {
		t.Fatal("a provider the administrator chose is not replaced")
	}
	if _, err := For("gemini-cli", root, true); err == nil {
		t.Fatal("-model is for claude-code and codex")
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

func TestGeminiCLIOnboarding(t *testing.T) {
	root := t.TempDir()
	onboarding, err := For("gemini-cli", root, false)
	if err != nil {
		t.Fatal(err)
	}
	if onboarding.File != filepath.Join(root, "/etc/gemini-cli/settings.json") {
		t.Fatal(onboarding.File)
	}
	// The administrator's own settings are kept, hooks pinned on.
	if err := os.MkdirAll(filepath.Dir(onboarding.File), 0o755); err != nil {
		t.Fatal(err)
	}
	original := `{"security":{"auth":{"enforcedType":"gemini-api-key"}},"hooksConfig":{"enabled":false},"hooks":{"BeforeTool":[{"matcher":"write_file","hooks":[{"type":"command","command":"/opt/audit"}]}]}}`
	if err := os.WriteFile(onboarding.File, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := onboarding.Apply(); err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	data, _ := os.ReadFile(onboarding.File)
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	before := settings["hooks"].(map[string]any)["BeforeTool"].([]any)
	if len(before) != 2 || !strings.Contains(string(data), "/opt/audit") || !strings.Contains(string(data), GeminiHookCommand) ||
		settings["hooksConfig"].(map[string]any)["enabled"] != true || !strings.Contains(string(data), "enforcedType") {
		t.Fatalf("%s", data)
	}
	if onboarding.Status() != "machine" {
		t.Fatal(onboarding.Status())
	}
	// Again: the same, not twice.
	if err := onboarding.Apply(); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(onboarding.File); string(again) != string(data) {
		t.Fatalf("%s", again)
	}
	if err := onboarding.Restore(); err != nil {
		t.Fatal(err)
	}
	if back, _ := os.ReadFile(onboarding.File); string(back) != original {
		t.Fatalf("%s", back)
	}
	if _, err := geminiSettings([]byte(`{not json`)); err == nil {
		t.Fatal("not JSON")
	}
}

func TestPiOnboardingPerUser(t *testing.T) {
	root := t.TempDir()
	home := "/home/dana"
	if err := os.MkdirAll(filepath.Join(root, home, ".pi/agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	me := Owner{Name: "dana", UID: os.Getuid(), GID: os.Getgid()}
	onboarding, err := ForUser("pi", root, me, home)
	if err != nil {
		t.Fatal(err)
	}
	if onboarding.Status() != "" {
		t.Fatal("not yet")
	}
	if err := onboarding.Apply(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(root, home, ".pi/agent/extensions/nia-edge.ts"))
	if !strings.Contains(string(data), `"http://127.0.0.1:8787/v1/hooks/pi"`) || !strings.Contains(string(data), `agent.on("tool_call"`) {
		t.Fatalf("%s", data)
	}
	if onboarding.Status() != "machine" {
		t.Fatal(onboarding.Status())
	}
	// Changed by someone: reported, not overwritten.
	if err := os.WriteFile(onboarding.File, []byte("// mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if onboarding.Status() != "" || onboarding.Apply() == nil {
		t.Fatal("a changed extension is not overwritten")
	}
	if err := os.WriteFile(onboarding.File, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := onboarding.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(onboarding.File); !os.IsNotExist(err) {
		t.Fatal("removed")
	}
	// No agent directory: nothing is made up.
	other, _ := ForUser("omp", root, me, "/home/nobody")
	if err := other.Apply(); err == nil || !strings.Contains(err.Error(), "run it once") {
		t.Fatalf("%v", err)
	}
	if _, err := ForUser("codex", root, me, home); err == nil {
		t.Fatal("codex is governed machine-wide")
	}
}

func TestOpenCodeOnboarding(t *testing.T) {
	root := t.TempDir()
	onboarding, err := For("opencode", root, false)
	if err != nil {
		t.Fatal(err)
	}
	if onboarding.File != filepath.Join(root, "/etc/opencode/opencode.json") {
		t.Fatal(onboarding.File)
	}
	plugin := filepath.Join(root, OpenCodePlugin)
	// The administrator's own configuration and plugins are kept.
	if err := os.MkdirAll(filepath.Dir(onboarding.File), 0o755); err != nil {
		t.Fatal(err)
	}
	original := `{"share":"disabled","plugin":["opencode-audit@1.0.0"]}`
	if err := os.WriteFile(onboarding.File, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	// A plugin file that is not nia-edge's is never overwritten.
	if err := os.WriteFile(plugin, []byte("export default {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := onboarding.Apply(); err == nil {
		t.Fatal("overwrote a plugin that is not nia-edge's")
	}
	if err := os.Remove(plugin); err != nil {
		t.Fatal(err)
	}
	if err := onboarding.Apply(); err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	data, _ := os.ReadFile(onboarding.File)
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if plugins := config["plugin"].([]any); len(plugins) != 2 || plugins[0] != "opencode-audit@1.0.0" || plugins[1] != OpenCodePlugin || config["share"] != "disabled" {
		t.Fatalf("%s", data)
	}
	if code, _ := os.ReadFile(plugin); !strings.Contains(string(code), Edge+"/v1/hooks/opencode") || !strings.Contains(string(code), `"tool.execute.before"`) {
		t.Fatalf("%s", code)
	}
	if onboarding.Status() != "machine" {
		t.Fatal(onboarding.Status())
	}
	// Again: the same, not twice.
	if err := onboarding.Apply(); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(onboarding.File); string(again) != string(data) {
		t.Fatalf("%s", again)
	}
	// The plugin changed: not governed as written.
	if err := os.WriteFile(plugin, []byte("export default {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if onboarding.Status() != "changed" {
		t.Fatal(onboarding.Status())
	}
	if err := onboarding.Restore(); err != nil {
		t.Fatal(err)
	}
	if back, _ := os.ReadFile(onboarding.File); string(back) != original {
		t.Fatalf("%s", back)
	}
	if _, err := os.Stat(plugin); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the plugin is still there")
	}
	if _, err := opencodeConfig([]byte(`{"plugin":"x"}`)); err == nil {
		t.Fatal("plugins not a list")
	}
	if _, err := For("opencode", root, true); err == nil {
		t.Fatal("-model for opencode")
	}
}
