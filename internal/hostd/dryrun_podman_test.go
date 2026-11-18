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

// TestPodmanDryRunThenApply applies a real plan to this machine's /etc and
// undoes it. Same conditions as TestPodmanDryRun.
func TestPodmanDryRunThenApply(t *testing.T) {
	if os.Getenv("NIA_PODMAN_TEST") != "yes" {
		t.Skip("NIA_PODMAN_TEST=yes runs this, as root, where podman is installed")
	}
	s, _, _ := machine(t, etcRole)
	// podman refuses a runroot longer than 50 characters.
	scratch, _ := os.MkdirTemp("/tmp", "p")
	defer os.RemoveAll(scratch)
	s.ScratchRoot, s.BackupRoot = scratch, t.TempDir()
	s.Sandbox = Podman{Root: scratch + "/podman", RunRoot: scratch + "/podman-run"}
	s.Run = Exec{}
	os.WriteFile("/etc/nia-apply.conf", []byte("a=1\n"), 0o644)
	os.Remove("/etc/nia-made.d/x.conf")
	os.Remove("/etc/nia-made.d")
	defer os.Remove("/etc/nia-apply.conf")
	defer os.RemoveAll("/etc/nia-made.d")
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "set -e\necho a=2 > /etc/nia-apply.conf\nmkdir -m 750 /etc/nia-made.d\necho x > /etc/nia-made.d/x.conf"}))
	if ok, why := r.Applicable(); !ok {
		t.Fatalf("%s: %+v", why, r)
	}
	resp := s.Do(context.Background(), Request{Action: ApplyAction, Name: r.Plan})
	if !resp.OK {
		t.Fatalf("apply: %+v", resp)
	}
	if data, _ := os.ReadFile("/etc/nia-apply.conf"); string(data) != "a=2\n" {
		t.Errorf("not applied: %q", data)
	}
	if info, err := os.Stat("/etc/nia-made.d"); err != nil || info.Mode().Perm() != 0o750 {
		t.Errorf("dir: %v %v", info, err)
	}
	if data, _ := os.ReadFile("/etc/nia-made.d/x.conf"); string(data) != "x\n" {
		t.Errorf("not applied: %q", data)
	}
	if undo := s.Undo(context.Background(), resp.Journal); !undo.OK {
		t.Fatalf("undo: %+v", undo)
	}
	if data, _ := os.ReadFile("/etc/nia-apply.conf"); string(data) != "a=1\n" {
		t.Errorf("not undone: %q", data)
	}
	if _, err := os.Stat("/etc/nia-made.d"); err == nil {
		t.Error("not undone: /etc/nia-made.d")
	}
}

// TestPodmanGuards: the guards read the merged /etc a real overlay leaves.
func TestPodmanGuards(t *testing.T) {
	if os.Getenv("NIA_PODMAN_TEST") != "yes" {
		t.Skip("NIA_PODMAN_TEST=yes runs this, as root, where podman is installed")
	}
	s, _, _ := machine(t, `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],"host":{"etc":{}}}`)
	scratch, _ := os.MkdirTemp("/tmp", "p")
	defer os.RemoveAll(scratch)
	s.ScratchRoot = scratch
	s.Sandbox = Podman{Root: scratch + "/podman", RunRoot: scratch + "/podman-run"}
	os.MkdirAll("/etc/ssh/sshd_config.d", 0o755)
	os.WriteFile("/etc/ssh/sshd_config", []byte("Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n"), 0o644)
	os.WriteFile("/etc/ssh/sshd_config.d/00-strict.conf", []byte("PasswordAuthentication no\n"), 0o644)
	defer os.RemoveAll("/etc/ssh")
	for script, want := range map[string]string{
		"rm /etc/ssh/sshd_config.d/00-strict.conf":                                    "passwordauthentication",
		"rm -r /etc/ssh/sshd_config.d && mkdir /etc/ssh/sshd_config.d":                "passwordauthentication",
		"echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/00-a.conf":               "permitrootlogin",
		"echo 'toor:x:0:0::/root:/bin/sh' >> /etc/passwd":                             "uid or gid 0",
		"mkdir -p /etc/cron.d && echo '* * * * * root id' > /etc/cron.d/x":            "cron",
		"echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config.d/00-strict.conf && true": "permitrootlogin",
	} {
		r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: script}))
		if !strings.Contains(details(r), want) {
			t.Errorf("%s: want %q, got %q", script, want, details(r))
		}
	}
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "echo 'PermitRootLogin no' > /etc/ssh/sshd_config.d/00-root.conf"}))
	if len(r.Guards) != 0 {
		t.Errorf("stricter refused: %q", details(r))
	}
}
