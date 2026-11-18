//go:build linux

package hostd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const guardRole = `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],"host":{"etc":{}}}`

func guardMachine(t *testing.T, files map[string]string) (*Server, *layer) {
	t.Helper()
	s, _, _ := machine(t, guardRole)
	etc := t.TempDir()
	for rel, body := range files {
		os.MkdirAll(filepath.Join(etc, filepath.Dir(rel)), 0o755)
		os.WriteFile(filepath.Join(etc, rel), []byte(body), 0o644)
	}
	sandbox := &layer{}
	s.EtcRoot, s.ScratchRoot, s.Sandbox = etc, layerDir(t), sandbox
	return s, sandbox
}

func put(t *testing.T, upper, rel, body string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(filepath.Join(upper, rel)), 0o755)
	if err := os.WriteFile(filepath.Join(upper, rel), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func guarded(t *testing.T, s *Server) Report {
	t.Helper()
	return report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
}

func details(r Report) string {
	var out []string
	for _, f := range r.Guards {
		out = append(out, f.Guard+": "+f.Detail)
	}
	return strings.Join(out, "\n")
}

var sshFiles = map[string]string{
	"ssh/sshd_config":           "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n",
	"ssh/sshd_config.d/10.conf": "X11Forwarding no\n",
	"passwd":                    "root:x:0:0:root:/root:/bin/bash\nkoplo:x:1000:1000::/home/koplo:/bin/bash\nhermes:x:1001:1001::/home/hermes:/bin/bash\n",
	"group":                     "root:x:0:\nsudo:x:27:koplo\ndocker:x:998:\nhermes:x:1001:\n",
	"nginx/nginx.conf":          "worker_processes 1;\n",
}

func TestTheSSHGuardSeesWhatSshdWouldDoIncludesAndMatchBlocksIncluded(t *testing.T) {
	for name, c := range map[string]struct {
		rel, body string
		refused   string
	}{
		// sshd takes the first value: an Include read before the main file's line wins.
		"an include weakens":     {"ssh/sshd_config.d/00-agent.conf", "PermitRootLogin yes\n", "permitrootlogin"},
		"a match block weakens":  {"ssh/sshd_config.d/20.conf", "Match User hermes\n  PasswordAuthentication yes\n", "passwordauthentication"},
		"the main file weakens":  {"ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords yes\n", "permitemptypasswords"},
		"the default comes back": {"ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\n", "passwordauthentication"},
		"authorized keys moved":  {"ssh/sshd_config.d/30.conf", "AuthorizedKeysFile /tmp/keys\n", "AuthorizedKeysFile"},
		"stricter is fine":       {"ssh/sshd_config.d/00-root.conf", "PermitRootLogin no\n", ""},
		// Included at the top, any file of sshd_config.d is read before the main file's lines.
		"any include is read first":   {"ssh/sshd_config.d/99.conf", "PasswordAuthentication yes\n", "passwordauthentication"},
		"a duplicate after the first": {"ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nPasswordAuthentication yes\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			s, sandbox := guardMachine(t, sshFiles)
			sandbox.script = func(lower, upper string) error { put(t, upper, c.rel, c.body); return nil }
			r := guarded(t, s)
			if c.refused == "" {
				if len(r.Guards) != 0 {
					t.Errorf("refused: %s", details(r))
				}
				return
			}
			if !strings.Contains(details(r), c.refused) {
				t.Errorf("not refused for %s: %q", c.refused, details(r))
			}
			if ok, _ := r.Applicable(); ok {
				t.Error("applicable")
			}
		})
	}
	// Deleting the include that held the strict value weakens too.
	files := map[string]string{"ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n", "ssh/sshd_config.d/00.conf": "PasswordAuthentication no\n"}
	s, sandbox := guardMachine(t, files)
	sandbox.script = func(lower, upper string) error {
		os.MkdirAll(filepath.Join(upper, "ssh/sshd_config.d"), 0o755)
		return syscall.Mknod(filepath.Join(upper, "ssh/sshd_config.d/00.conf"), syscall.S_IFCHR, 0)
	}
	if r := guarded(t, s); !strings.Contains(details(r), "passwordauthentication") {
		t.Errorf("deleting a strict include: %q", details(r))
	}
}

func TestTheAccountsGuardRefusesNewRootsAndPrivilegedMembers(t *testing.T) {
	for name, c := range map[string]struct{ rel, body, refused string }{
		"uid 0":        {"passwd", sshFiles["passwd"] + "toor:x:0:0::/root:/bin/sh\n", "user toor would have uid or gid 0"},
		"gid 0":        {"passwd", sshFiles["passwd"] + "x:x:1002:0::/:/bin/sh\n", "user x would have uid or gid 0"},
		"sudo member":  {"group", "root:x:0:\nsudo:x:27:koplo,hermes\ndocker:x:998:\nhermes:x:1001:\n", "hermes would join the group sudo"},
		"docker":       {"group", "root:x:0:\nsudo:x:27:koplo\ndocker:x:998:hermes\nhermes:x:1001:\n", "hermes would join the group docker"},
		"a plain user": {"passwd", sshFiles["passwd"] + "web:x:1003:1003::/srv:/usr/sbin/nologin\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			s, sandbox := guardMachine(t, sshFiles)
			sandbox.script = func(lower, upper string) error { put(t, upper, c.rel, c.body); return nil }
			r := guarded(t, s)
			if c.refused == "" && len(r.Guards) != 0 || c.refused != "" && !strings.Contains(details(r), c.refused) {
				t.Errorf("want %q, got %q", c.refused, details(r))
			}
		})
	}
}

func TestRootHooksAreRefusedUnlessPermitted(t *testing.T) {
	for rel, guard := range map[string]string{
		"sudoers.d/agent":               "sudoers",
		"cron.d/backdoor":               "cron",
		"systemd/system/x.service":      "systemd",
		"ld.so.preload":                 "preload",
		"profile.d/x.sh":                "shell_startup",
		"apt/apt.conf.d/99hook":         "package_sources",
		"apt/sources.list.d/x.list":     "package_sources",
		"modprobe.d/x.conf":             "kernel_modules",
		"udev/rules.d/99-x.rules":       "udev",
		"logrotate.d/x":                 "logrotate",
		"polkit-1/rules.d/x.rules":      "polkit",
		"NetworkManager/dispatcher.d/x": "network_hooks",
		"pam.d/sshd":                    "pam",
	} {
		s, sandbox := guardMachine(t, sshFiles)
		sandbox.script = func(lower, upper string) error { put(t, upper, rel, "x\n"); return nil }
		r := guarded(t, s)
		named := len(r.Guards) > 0
		for _, f := range r.Guards {
			named = named && f.Guard == guard
		}
		if !named || !strings.Contains(details(r), "/etc/"+rel+":") {
			t.Errorf("/etc/%s: %q", rel, details(r))
		}
	}
	// nginx is no root hook; a role may permit one by name.
	s, sandbox := guardMachine(t, sshFiles)
	sandbox.script = func(lower, upper string) error {
		put(t, upper, "nginx/nginx.conf", "worker_processes 4;\n")
		return nil
	}
	if r := guarded(t, s); len(r.Guards) != 0 {
		t.Errorf("nginx: %q", details(r))
	}
	permitted, _, _ := machine(t, `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],"host":{"etc":{"permit":["cron"]}}}`)
	permitted.EtcRoot, permitted.ScratchRoot = s.EtcRoot, layerDir(t)
	permitted.Sandbox = &layer{script: func(lower, upper string) error { put(t, upper, "cron.d/backup", "x\n"); return nil }}
	if r := guarded(t, permitted); len(r.Guards) != 0 {
		t.Errorf("permitted cron: %q", details(r))
	}
	if _, err := ParseCatalogue([]byte(`{"etc":{"permit":["everything"]}}`)); err == nil {
		t.Error("an unknown guard is accepted")
	}
}

// The server's schema lists the same guards (ETC_GUARDS in its config): a
// name the server accepts and this nia-edge does not would refuse the
// catalogue whole.
func TestTheGuardsAreTheServers(t *testing.T) {
	want := "ssh accounts sudoers pam cron systemd preload shell_startup login_scripts ssh_client package_sources kernel_modules boot udev logrotate polkit mac trust_store name_resolution interpreters network_hooks"
	if got := strings.Join(Guards, " "); got != want {
		t.Errorf("guards %q, the server's %q", got, want)
	}
}
