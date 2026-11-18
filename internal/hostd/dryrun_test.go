//go:build linux

package hostd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const etcRole = `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],` +
	`"host":{"services":["nginx"],"etc":{"protected":["/etc/ssh/sshd_config","/etc/sudoers.d"],"secrets":["/etc/app/token.conf"],"permit":["cron"]}}}`

// layer stands for podman: it runs a Go function against the upper layer as
// overlayfs would write it (copy-up, whiteouts), with the lower /etc beside.
type layer struct {
	script func(lower, upper string) error
	spec   SandboxSpec
}

func (l *layer) Prepare(string) (func(), error) { return func() {}, nil }

func (l *layer) Run(_ context.Context, spec SandboxSpec) (string, error) {
	l.spec = spec
	return "ran\n", l.script(spec.Etc, spec.Upper)
}

func copyUp(t *testing.T, lower, upper, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(lower, rel))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(lower, rel))
	os.MkdirAll(filepath.Dir(filepath.Join(upper, rel)), 0o755)
	if err := os.WriteFile(filepath.Join(upper, rel), data, info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(upper, rel)
}

func etcMachine(t *testing.T, sandbox *layer) (*Server, string) {
	t.Helper()
	s, _, _ := machine(t, etcRole)
	etc := t.TempDir()
	files := map[string]struct {
		body string
		mode os.FileMode
	}{
		"nginx/nginx.conf":     {"worker_processes 1;\n", 0o644},
		"ssh/sshd_config":      {"PermitRootLogin no\n", 0o644},
		"shadow":               {"root:$y$secret:1:0:99999:7:::\n", 0o640},
		"app/token.conf":       {"token=abc\n", 0o644},
		"sudoers.d/admins":     {"%admin ALL=(ALL) ALL\n", 0o440},
		"motd":                 {"hello\n", 0o644},
		"cron.d/old":           {"* * * * * root true\n", 0o644},
		"issue":                {"Debian\n", 0o644},
		"ssh/ssh_host_ed25519": {"PRIVATE KEY\n", 0o600},
	}
	for rel, f := range files {
		os.MkdirAll(filepath.Join(etc, filepath.Dir(rel)), 0o755)
		if err := os.WriteFile(filepath.Join(etc, rel), []byte(f.body), f.mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(etc, rel), f.mode)
	}
	s.EtcRoot, s.ScratchRoot, s.Sandbox = etc, layerDir(t), sandbox
	return s, etc
}

// layerDir is where a test's fake layer lives: on tmpfs when it can, as
// nia-hostd's is. On an overlay /tmp (a Fly machine's), the whiteouts the
// tests make with mknod would be taken by that overlay as deletions.
func layerDir(t *testing.T) string {
	t.Helper()
	if dir, err := os.MkdirTemp("/dev/shm", "nia-layer-"); err == nil {
		t.Cleanup(func() { os.RemoveAll(dir) })
		return dir
	}
	return t.TempDir()
}

func report(t *testing.T, resp Response) Report {
	t.Helper()
	if !resp.OK {
		t.Fatalf("dry run: %+v", resp)
	}
	var r Report
	if err := json.Unmarshal([]byte(resp.Output), &r); err != nil {
		t.Fatalf("%v: %s", err, resp.Output)
	}
	return r
}

func kinds(r Report) map[string]string {
	out := map[string]string{}
	for _, c := range r.Changes {
		out[c.Path] = c.Kind
	}
	return out
}

func TestADryRunReportsItsChangesAndKeepsThePlan(t *testing.T) {
	sandbox := &layer{}
	s, etc := etcMachine(t, sandbox)
	sandbox.script = func(lower, upper string) error {
		os.WriteFile(copyUp(t, lower, upper, "nginx/nginx.conf"), []byte("worker_processes 4;\n"), 0o644)
		os.WriteFile(filepath.Join(upper, "nginx", "site.conf"), []byte("server {}\n"), 0o640)
		copyUp(t, lower, upper, "issue")
		os.Chmod(filepath.Join(upper, "issue"), 0o600)
		copyUp(t, lower, upper, "motd") // copied up, unchanged: nothing to apply
		os.MkdirAll(filepath.Join(upper, "cron.d"), 0o755)
		if err := syscall.Mknod(filepath.Join(upper, "cron.d", "old"), syscall.S_IFCHR, 0); err != nil {
			return err
		}
		return nil
	}
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "edit nginx"}))
	want := map[string]string{"/etc/nginx/nginx.conf": "modified", "/etc/nginx/site.conf": "created", "/etc/issue": "metadata", "/etc/cron.d/old": "deleted"}
	if got := kinds(r); len(got) != len(want) {
		t.Fatalf("changes %v, want %v", got, want)
	} else {
		for path, kind := range want {
			if got[path] != kind {
				t.Errorf("%s: %q, want %q", path, got[path], kind)
			}
		}
	}
	if ok, why := r.Applicable(); !ok || r.Plan == "" || len(s.Plans()) != 1 || s.Plans()[0] != r.Plan {
		t.Errorf("applicable %v %s, plan %q kept %v", ok, why, r.Plan, s.Plans())
	}
	for _, c := range r.Changes {
		if c.Path == "/etc/nginx/nginx.conf" && (!strings.HasPrefix(c.Base, "sha256:") || c.SHA256 == "") {
			t.Errorf("no base or hash: %+v", c)
		}
		if c.Path == "/etc/nginx/site.conf" && (c.Base != "absent" || c.Mode != 0o640) {
			t.Errorf("created: %+v", c)
		}
	}
	// The machine's /etc is untouched; the script only ever saw the layer.
	if data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf")); string(data) != "worker_processes 1;\n" {
		t.Errorf("lower changed: %q", data)
	}
	if sandbox.spec.Script != "edit nginx" || sandbox.spec.Etc != etc || !strings.Contains(strings.Join(sandbox.spec.Masked, " "), "/root") {
		t.Errorf("spec %+v", sandbox.spec)
	}
	entries, _ := s.Journal()
	if len(entries) != 1 || entries[0].Action != DryRunAction || entries[0].Name != r.Plan {
		t.Errorf("journal %+v", entries)
	}
}

func TestSecretsAreDecoysAndAPlanThatTouchesThemCannotApply(t *testing.T) {
	sandbox := &layer{}
	s, etc := etcMachine(t, sandbox)
	var shadowDecoy, tokenDecoy []byte
	sandbox.script = func(lower, upper string) error {
		// The script reads what it sees of the shadow file: the decoy.
		shadowDecoy, _ = os.ReadFile(filepath.Join(upper, "shadow"))
		tokenDecoy, _ = os.ReadFile(filepath.Join(upper, "app/token.conf"))
		os.WriteFile(filepath.Join(upper, "leak"), shadowDecoy, 0o644)
		return nil
	}
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "cat /etc/shadow > /etc/leak"}))
	if !strings.HasPrefix(string(shadowDecoy), "nia-decoy-") || !strings.HasPrefix(string(tokenDecoy), "nia-decoy-") {
		t.Fatalf("the script saw %q and %q", shadowDecoy, tokenDecoy)
	}
	if !contains(r.SecretsRead, "/etc/shadow") || !contains(r.SecretsRead, "/etc/app/token.conf") || !contains(r.SecretsCopied, "/etc/shadow") {
		t.Errorf("read %v copied %v", r.SecretsRead, r.SecretsCopied)
	}
	// Decoys are not changes, and an unread one is not reported.
	if contains(r.SecretsRead, "/etc/ssh/ssh_host_ed25519") || len(r.Changes) != 1 || r.Changes[0].Path != "/etc/leak" {
		t.Errorf("changes %+v read %v", r.Changes, r.SecretsRead)
	}
	if ok, _ := r.Applicable(); ok || len(s.Plans()) != 0 {
		t.Errorf("a plan carrying a secret's decoy is kept: %v", s.Plans())
	}
	if data, _ := os.ReadFile(filepath.Join(etc, "shadow")); !strings.Contains(string(data), "$y$secret") {
		t.Error("the secret changed")
	}

	// Changing a secret: reported, not applicable.
	sandbox.script = func(lower, upper string) error {
		return os.WriteFile(filepath.Join(upper, "sudoers.d/admins"), []byte("ALL ALL=(ALL) NOPASSWD: ALL\n"), 0o440)
	}
	r = report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	if !contains(r.SecretsChanged, "/etc/sudoers.d/admins") {
		t.Errorf("changed %v", r.SecretsChanged)
	}
	if ok, _ := r.Applicable(); ok {
		t.Error("a plan changing a secret is applicable")
	}
}

func TestProtectedPathsAndFailedScriptsMakeNoPlan(t *testing.T) {
	sandbox := &layer{}
	s, _ := etcMachine(t, sandbox)
	sandbox.script = func(lower, upper string) error {
		os.WriteFile(copyUp(t, lower, upper, "ssh/sshd_config"), []byte("PermitRootLogin yes\n"), 0o644)
		return nil
	}
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	if !contains(r.Protected, "/etc/ssh/sshd_config") {
		t.Errorf("protected %v", r.Protected)
	}
	// A new file in a protected directory changes it too.
	sandbox.script = func(lower, upper string) error {
		os.MkdirAll(filepath.Join(upper, "sudoers.d"), 0o755)
		return os.WriteFile(filepath.Join(upper, "sudoers.d", "agent"), []byte("agent ALL=(ALL) NOPASSWD: ALL\n"), 0o440)
	}
	r = report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	if !contains(r.Protected, "/etc/sudoers.d") {
		t.Errorf("protected %v", r.Protected)
	}
	sandbox.script = func(lower, upper string) error {
		os.WriteFile(filepath.Join(upper, "suid"), []byte("x"), 0o755)
		return os.Chmod(filepath.Join(upper, "suid"), 0o755|os.ModeSetuid)
	}
	r = report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	if ok, why := r.Applicable(); ok || !strings.Contains(why, "setuid") {
		t.Errorf("a setuid file is applicable: %+v", r.Changes)
	}
	sandbox.script = func(lower, upper string) error {
		os.WriteFile(filepath.Join(upper, "new"), []byte("x"), 0o644)
		return os.ErrInvalid
	}
	r = report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	if ok, _ := r.Applicable(); ok || r.Failed == "" || len(s.Plans()) != 0 {
		t.Errorf("a failed run made a plan: %+v %v", r, s.Plans())
	}
}

func TestADryRunNeedsTheCatalogueAndAScript(t *testing.T) {
	sandbox := &layer{script: func(string, string) error { t.Error("ran"); return nil }}
	s, _ := etcMachine(t, sandbox)
	for _, script := range []string{"", "a\x00b", "\xff", strings.Repeat("a", scriptLimit+1)} {
		if resp := s.Do(context.Background(), Request{Action: DryRunAction, Script: script}); resp.OK {
			t.Errorf("%q ran", script)
		}
	}
	plain, _, _ := machine(t, role)
	plain.Sandbox = sandbox
	if resp := plain.Do(context.Background(), Request{Action: DryRunAction, Script: "true"}); resp.OK || !strings.Contains(resp.Error, "no dry run") {
		t.Errorf("without etc: %+v", resp)
	}
}

func TestPodmanArgs(t *testing.T) {
	args := strings.Join(Podman{Root: "/var/lib/nia-hostd/podman", RunRoot: "/run/nia-hostd/podman"}.Args(SandboxSpec{
		Root: "/s/root", Etc: "/etc", Upper: "/s/upper", Work: "/s/work", Masked: []string{"/root"}, Script: "echo hi", Timeout: 120e9, PathVariable: "PATH=/usr/bin",
	}), " ")
	for _, want := range []string{"--network none", "--cap-drop all", "--security-opt no-new-privileges", "--read-only", "/etc:/etc:O,upperdir=/s/upper,workdir=/s/work", "--tmpfs /root:", "--rootfs /s/root /bin/sh -c echo hi", "--timeout 120"} {
		if !strings.Contains(args, want) {
			t.Errorf("lacks %q: %s", want, args)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestADryRunNeedsBoundsItCanEnforce(t *testing.T) {
	dir := t.TempDir()
	controllers := filepath.Join(dir, "cgroup.controllers")
	p := Podman{Limits: true, Controllers: controllers}
	if why := p.bounded(); !strings.Contains(why, "no cgroup v2") {
		t.Errorf("%q", why)
	}
	os.WriteFile(controllers, []byte("cpuset cpu io pids\n"), 0o644)
	if why := p.bounded(); !strings.Contains(why, "no memory controller") {
		t.Errorf("%q", why)
	}
	os.WriteFile(controllers, []byte("cpuset cpu io memory hugetlb pids rdma misc\n"), 0o644)
	if why := p.bounded(); why != "" {
		t.Errorf("%q", why)
	}
	if _, err := (Podman{Limits: true, Controllers: filepath.Join(dir, "none")}).Run(t.Context(), SandboxSpec{}); err == nil {
		t.Error("ran unbounded")
	}
	if !DefaultSandbox().(Podman).Limits {
		t.Error("nia-hostd's sandbox does not require bounds")
	}
}
