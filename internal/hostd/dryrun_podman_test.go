//go:build linux

package hostd

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestPodmanDryRun runs a real dry run against this machine's /etc. It needs
// root and podman, and changes nothing: run it in a throwaway container with
// NIA_PODMAN_TEST=yes.
func TestPodmanDryRun(t *testing.T) {
	if os.Getenv("NIA_PODMAN_TEST") != "yes" {
		t.Skip("NIA_PODMAN_TEST=yes runs this, as root, where podman is installed")
	}
	s, _, _ := machine(t, etcRole)
	scratch := t.TempDir()
	s.ScratchRoot = scratch
	s.Sandbox = Podman{Root: scratch + "/podman", RunRoot: scratch + "/podman-run"}
	os.WriteFile("/etc/nia-test.conf", []byte("a=1\n"), 0o644)
	os.WriteFile("/etc/nia-secret.conf", []byte("password=hunter2\n"), 0o600)
	os.WriteFile("/root/.nia-root-secret", []byte("root-only\n"), 0o600)
	defer os.Remove("/etc/nia-test.conf")
	defer os.Remove("/etc/nia-secret.conf")
	defer os.Remove("/root/.nia-root-secret")
	before, _ := os.ReadFile("/etc/hostname")

	script := strings.Join([]string{
		"echo a=2 > /etc/nia-test.conf",
		"echo new > /etc/nia-new.conf",
		"rm /etc/issue.net",
		"chmod 600 /etc/issue",
		"cat /etc/nia-secret.conf",
		"echo escape-usr; touch /usr/nia-x 2>&1",
		"echo escape-sysctl; echo 1 > /proc/sys/vm/drop_caches 2>&1; echo 1 > /proc/sysrq-trigger 2>&1",
		"echo escape-root; ls -A /root",
		"echo escape-net; cat /proc/net/dev | wc -l",
		"echo escape-caps; grep CapEff /proc/self/status",
		"echo escape-dev; ls /dev | tr '\\n' ' '",
		"true",
	}, "\n")
	resp := s.Do(context.Background(), Request{Action: DryRunAction, Script: script})
	r := report(t, resp)
	t.Logf("report: %s", resp.Output)
	got := kinds(r)
	for path, kind := range map[string]string{"/etc/nia-test.conf": "modified", "/etc/nia-new.conf": "created", "/etc/issue.net": "deleted", "/etc/issue": "metadata"} {
		if got[path] != kind {
			t.Errorf("%s: %q, want %q (all: %v)", path, got[path], kind, got)
		}
	}
	if strings.Contains(r.Output, "hunter2") || !contains(r.SecretsRead, "/etc/nia-secret.conf") {
		t.Errorf("secret: read %v, output %q", r.SecretsRead, r.Output)
	}
	if !contains(r.SecretsCopied, "/etc/nia-secret.conf") {
		t.Errorf("the decoy printed is not seen: %v", r.SecretsCopied)
	}
	for _, refused := range []string{"nia-x': Read-only file system", "CapEff:\t0000000000000000"} {
		if !strings.Contains(r.Output, refused) {
			t.Errorf("output lacks %q:\n%s", refused, r.Output)
		}
	}
	if strings.Contains(r.Output, ".nia-root-secret") {
		t.Error("/root is visible")
	}
	if data, _ := os.ReadFile("/etc/nia-test.conf"); string(data) != "a=1\n" {
		t.Errorf("the machine changed: %q", data)
	}
	if _, err := os.Stat("/etc/nia-new.conf"); err == nil {
		t.Error("the machine changed: /etc/nia-new.conf")
	}
	if _, err := os.Stat("/etc/issue.net"); err != nil {
		t.Error("the machine changed: /etc/issue.net")
	}
	if after, _ := os.ReadFile("/etc/hostname"); string(after) != string(before) {
		t.Error("the machine changed: /etc/hostname")
	}
	if _, err := os.Stat("/usr/nia-x"); err == nil {
		t.Error("the machine changed: /usr/nia-x")
	}
}
