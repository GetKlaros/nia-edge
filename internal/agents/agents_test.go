package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func machine(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "/etc/passwd", strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"alice:x:1000:1000::/home/alice:/bin/bash",
		"hermes:x:1001:1001::/home/hermes:/bin/bash",
		"bob:x:1002:999::/home/bob:/bin/bash",
		"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin",
	}, "\n")+"\n")
	write(t, root, "/etc/group", "sudo:x:27:alice\ndocker:x:999:\nalice:x:1000:\n")
	write(t, root, "/etc/systemd/system/nia-agent-firewall.service",
		"[Service]\nExecStart=/bin/sh /usr/local/lib/nia-edge/firewall-linux.sh apply hermes nia-mcp\n")
	// alice: OpenClaw under her own account, gateway running, three servers.
	write(t, root, "/home/alice/.openclaw/openclaw.json", `{
  // JSON5 as people write it
  "mcp": {"servers": {"fs": {"command": "npx"}, "mail": {"url": "https://x"}, "host": {"url": "http://127.0.0.1:8787/host/mcp"},}},
  "agents": {"defaults": {"model": {"primary": "openai/gpt-5"}}},
  "models": {"providers": {"openai": {"baseUrl": "https://api.openai.com/v1", "apiKey": "sk-not-printed"}}},
}`)
	write(t, root, "/proc/42/status", "Name:\tnode\nUid:\t1000\t1000\t1000\t1000\n")
	write(t, root, "/proc/42/cmdline", "node\x00/home/alice/.openclaw/tools/node-v24/lib/node_modules/openclaw/dist/entry.js\x00gateway\x00")
	// hermes: behind nia-edge.
	write(t, root, "/home/hermes/.hermes/config.yaml",
		"model:\n  provider: custom\n  base_url: http://127.0.0.1:8787/v1\nmcp_servers:\n  host:\n    url: http://127.0.0.1:8787/host/mcp\n  mail:\n    url: x\nterminal:\n  backend: docker\n")
	// bob: Codex, primary group docker, and a Claude Code file that is a link.
	write(t, root, "/home/bob/.codex/config.toml",
		"model = \"o4\"\n[mcp_servers.docs]\ncommand = \"npx\"\n[mcp_servers.docs.env]\nA = \"b\"\n[mcp_servers.\"two words\"]\nurl = \"x\"\n")
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "/home/bob/.claude.json")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFind(t *testing.T) {
	root := machine(t)
	found, err := Find(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 {
		t.Fatalf("found %d agents: %+v", len(found), found)
	}
	alice, bob, hermes := found[0], found[1], found[2]

	if alice.Kind != "openclaw" || !alice.Running || alice.Confined || alice.Settings.MCPServers != 3 || alice.Settings.Model != "other" {
		t.Fatalf("alice: %+v", alice)
	}
	if strings.Join(alice.Groups, ",") != "sudo" || alice.Next != "sudo sh openclaw-linux.sh --from alice: a user of its own, behind nia-edge" {
		t.Fatalf("alice: %+v", alice)
	}
	if bob.Kind != "codex" || bob.Running || bob.Settings.MCPServers != 2 || strings.Join(bob.Groups, ",") != "docker" {
		t.Fatalf("bob: %+v", bob)
	}
	if bob.Next != "sudo nia-edge agents onboard codex: Nia decides each tool call" || bob.Governed != "" {
		t.Fatalf("bob: %+v", bob)
	}
	if hermes.Kind != "hermes" || !hermes.Confined || hermes.Settings.MCPServers != 2 || hermes.Settings.Model != "unknown" || len(hermes.Groups) != 0 {
		t.Fatalf("hermes: %+v", hermes)
	}
	if hermes.Next != "behind nia-edge: prove it with sudo -u hermes nia-edge doctor" {
		t.Fatalf("hermes: %+v", hermes)
	}
}

func TestConfinedModelElsewhere(t *testing.T) {
	a := Agent{User: "openclaw", Confined: true, Settings: Config{Model: "other"}}
	if got := next(Kinds[1], a); got != "its model is not nia-edge's: point it at http://127.0.0.1:8787/v1" {
		t.Fatal(got)
	}
}

func TestOpenClawThroughNiaEdge(t *testing.T) {
	c := readOpenClaw([]byte(`{"agents":{"defaults":{"model":{"primary":"nia/m"}}},"models":{"providers":{"nia":{"baseUrl":"http://127.0.0.1:8787/v1"}}}}`))
	if c.Model != "nia-edge" || c.MCPServers != 0 {
		t.Fatalf("%+v", c)
	}
	// A look-alike host is not nia-edge.
	c = readOpenClaw([]byte(`{"agents":{"defaults":{"model":{"primary":"nia/m"}}},"models":{"providers":{"nia":{"baseUrl":"http://127.0.0.1:87870/v1"}}}}`))
	if c.Model != "other" {
		t.Fatalf("%+v", c)
	}
	if c := readOpenClaw([]byte(`{unquoted: 1}`)); c.MCPServers != -1 || c.Model != "unknown" {
		t.Fatalf("%+v", c)
	}
}

func TestJSONC(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{`{"a": "// not a comment", "b": [1,2,],}`, true},
		{`{"a": "/* nor this */"} // trailing`, true},
		{`{"a": "\"quoted\" // still a string"}`, true},
		{`{"a": 1 /* unterminated`, false},
		{`{a: 1}`, false},
	} {
		if _, ok := jsonc([]byte(tc.in)); ok != tc.ok {
			t.Errorf("%s: ok %v", tc.in, ok)
		}
	}
	value, _ := jsonc([]byte(`{"a": "x // y", "b": [1,],}`))
	if value["a"] != "x // y" || len(value["b"].([]any)) != 1 {
		t.Fatalf("%v", value)
	}
}

func TestOpenCodeAndClaude(t *testing.T) {
	c := readOpenCode([]byte(`{"mcp":{"servers":{"a":{"type":"local"},"b":{"type":"remote"}}},"model":"nia/m","provider":{"nia":{"options":{"baseURL":"http://127.0.0.1:8787/v1"}}}}`))
	if c.MCPServers != 2 || c.Model != "nia-edge" {
		t.Fatalf("%+v", c)
	}
	// OpenCode 1: a server may itself be named servers.
	c = readOpenCode([]byte(`{"mcp":{"servers":{"type":"local"},"x":{"type":"local"}}}`))
	if c.MCPServers != 2 {
		t.Fatalf("%+v", c)
	}
	c = readClaude([]byte(`{"mcpServers":{"a":{}},"projects":{"/p":{"mcpServers":{"b":{},"c":{}}}}}`))
	if c.MCPServers != 3 || c.Model != "other" {
		t.Fatalf("%+v", c)
	}
}

func TestNothingFound(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	found, err := Find(Options{Root: root})
	if err != nil || len(found) != 0 {
		t.Fatalf("%v %v", found, err)
	}
	if _, err := Find(Options{Root: t.TempDir()}); err == nil {
		t.Fatal("no /etc/passwd must be an error")
	}
}

func TestGeminiOmpAndPi(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/passwd", "carol:x:1003:1003::/home/carol:/bin/bash\n")
	write(t, root, "/etc/group", "carol:x:1003:\n")
	write(t, root, "/home/carol/.gemini/settings.json", `{"mcpServers":{"github":{"httpUrl":"https://x"},"fs":{"command":"npx"}}}`)
	write(t, root, "/home/carol/.omp/agent/config.yml", "model: x\n")
	write(t, root, "/home/carol/.pi/agent/settings.json", `{}`)
	write(t, root, "/proc/7/status", "Name:\tomp\nUid:\t1003\t1003\t1003\t1003\n")
	write(t, root, "/proc/7/cmdline", "/home/carol/.local/bin/omp\x00")
	write(t, root, "/proc/8/status", "Name:\tnode\nUid:\t1003\t1003\t1003\t1003\n")
	write(t, root, "/proc/8/cmdline", "node\x00/usr/lib/node_modules/@mariozechner/pi-coding-agent/dist/cli.js\x00")
	found, err := Find(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Agent{}
	for _, agent := range found {
		got[agent.Kind] = agent
	}
	if len(found) != 3 || got["gemini-cli"].Settings.MCPServers != 2 || got["gemini-cli"].Running {
		t.Fatalf("%+v", found)
	}
	if !got["omp"].Running || !got["pi"].Running || got["omp"].Settings.MCPServers != -1 {
		t.Fatalf("%+v", found)
	}
	if !strings.Contains(got["omp"].Next, "no installer for omp yet") {
		t.Fatalf("%s", got["omp"].Next)
	}
}
