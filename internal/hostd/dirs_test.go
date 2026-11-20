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

func TestClosedDirs(t *testing.T) {
	for dir, closed := range map[string]bool{
		"/srv": false, "/srv/www": false, "/opt/app": false, "/var/www": false, "/var/lib/myapp": false, "/data/site": false,
		"/": true, "/usr": true, "/usr/local/bin": true, "/usr/local/share/app": true, "/etc": true, "/etc/nginx": true,
		"/boot": true, "/root": true, "/home": true, "/home/koplo/site": true, "/var": true, "/var/lib": true,
		"/var/lib/dpkg": true, "/var/lib/systemd/x": true, "/var/lib/nia-edge": true, "/var/log": true, "/run": true,
		"/tmp/x": true, "/var/tmp": true, "/proc": true, "/srv/../usr": true, "/srv/www/": true, "srv": true,
	} {
		if got := ClosedDir(dir) != ""; got != closed {
			t.Errorf("%s: closed %v, want %v (%s)", dir, got, closed, ClosedDir(dir))
		}
	}
	for name, dirs := range map[string]string{
		"closed":    `["/usr/local/bin"]`,
		"overlap":   `["/srv","/srv/www"]`,
		"duplicate": `["/srv/www","/srv/www"]`,
		"too many":  `["/a1","/a2","/a3","/a4","/a5","/a6","/a7","/a8","/a9","/b1","/b2","/b3","/b4","/b5","/b6","/b7","/b8"]`,
	} {
		if _, err := ParseCatalogue(json.RawMessage(`{"dirs":` + dirs + `}`)); err == nil {
			t.Errorf("%s: a catalogue with dirs %s was taken", name, dirs)
		}
	}
	if c, err := ParseCatalogue(json.RawMessage(`{"dirs":["/srv/www","/opt/app"]}`)); err != nil || len(c.Dirs) != 2 {
		t.Fatalf("%v %+v", err, c)
	}
}

const dirsRole = `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],` +
	`"host":{"dirs":["/srv/www"],"etc":{"protected":[],"secrets":[],"permit":[]}}}`

const dirsOnlyRole = `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],` +
	`"host":{"dirs":["/srv/www"]}}`

// dirLayer stands for podman with the catalogue's directories: etc writes
// /etc's layer, dirs each directory's.
type dirLayer struct {
	etc  func(lower, upper string) error
	dirs func(dir Layer) error
	spec SandboxSpec
}

func (l *dirLayer) Prepare(string) (func(), error) { return func() {}, nil }

func (l *dirLayer) Run(_ context.Context, spec SandboxSpec) (string, error) {
	l.spec = spec
	if l.etc != nil {
		if err := l.etc(spec.Etc, spec.Upper); err != nil {
			return "", err
		}
	}
	for _, dir := range spec.Dirs {
		if l.dirs != nil {
			if err := l.dirs(dir); err != nil {
				return "", err
			}
		}
	}
	return "ran\n", nil
}

func dirsMachine(t *testing.T, role string, sandbox *dirLayer) (*Server, string) {
	t.Helper()
	s, _, _ := machine(t, role)
	s.EtcRoot, s.ScratchRoot, s.Sandbox, s.BackupRoot = t.TempDir(), layerDir(t), sandbox, t.TempDir()
	os.WriteFile(filepath.Join(s.EtcRoot, "app.conf"), []byte("token=abc\n"), 0o600)
	s.DirsRoot = t.TempDir()
	www := filepath.Join(s.DirsRoot, "srv", "www")
	os.MkdirAll(filepath.Join(www, "old"), 0o755)
	os.WriteFile(filepath.Join(www, "index.html"), []byte("<h1>v1</h1>\n"), 0o644)
	os.WriteFile(filepath.Join(www, "old", "page.html"), []byte("old\n"), 0o644)
	os.WriteFile(filepath.Join(www, ".env"), []byte("DB_PASSWORD=hunter2\n"), 0o600)
	s.Installed = func(string) bool { return false }
	return s, www
}

func TestADryRunChangesACatalogueDirectoryAndTheApplyWritesItOnce(t *testing.T) {
	sandbox := &dirLayer{dirs: func(dir Layer) error {
		if dir.Target != "/srv/www" {
			t.Errorf("layered at %s", dir.Target)
		}
		os.WriteFile(filepath.Join(dir.Upper, "index.html"), []byte("<h1>v2</h1>\n"), 0o644)
		os.WriteFile(filepath.Join(dir.Upper, "new.html"), []byte("new\n"), 0o644)
		os.Symlink("index.html", filepath.Join(dir.Upper, "home.html"))
		os.MkdirAll(filepath.Join(dir.Upper, "old"), 0o755)
		return syscall.Mknod(filepath.Join(dir.Upper, "old", "page.html"), syscall.S_IFCHR, 0)
	}}
	s, www := dirsMachine(t, dirsRole, sandbox)
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "deploy"}))
	got := kinds(r)
	for p, kind := range map[string]string{"/srv/www/index.html": "modified", "/srv/www/new.html": "created", "/srv/www/home.html": "created", "/srv/www/old/page.html": "deleted"} {
		if got[p] != kind {
			t.Errorf("%s: %q, want %q (%v)", p, got[p], kind, got)
		}
	}
	if ok, why := r.Applicable(); !ok {
		t.Fatalf("not applicable: %s", why)
	}
	// The machine is untouched until the apply.
	if data, _ := os.ReadFile(filepath.Join(www, "index.html")); string(data) != "<h1>v1</h1>\n" {
		t.Fatalf("written by the dry run: %q", data)
	}
	applied := s.Do(context.Background(), Request{Action: ApplyAction, Name: r.Plan})
	if !applied.OK {
		t.Fatalf("apply: %+v", applied)
	}
	if data, _ := os.ReadFile(filepath.Join(www, "index.html")); string(data) != "<h1>v2</h1>\n" {
		t.Errorf("index.html: %q", data)
	}
	if target, _ := os.Readlink(filepath.Join(www, "home.html")); target != "index.html" {
		t.Errorf("home.html -> %q", target)
	}
	if _, err := os.Stat(filepath.Join(www, "old", "page.html")); err == nil {
		t.Error("old/page.html is still there")
	}
	if again := s.Do(context.Background(), Request{Action: ApplyAction, Name: r.Plan}); again.OK {
		t.Error("a plan was applied twice")
	}
	// Undo puts the directory back as it was.
	if undo := s.Undo(context.Background(), applied.Journal); !undo.OK {
		t.Fatalf("undo: %+v", undo)
	}
	if data, _ := os.ReadFile(filepath.Join(www, "index.html")); string(data) != "<h1>v1</h1>\n" {
		t.Errorf("after undo, index.html: %q", data)
	}
	for _, gone := range []string{"new.html", "home.html"} {
		if _, err := os.Lstat(filepath.Join(www, gone)); err == nil {
			t.Errorf("after undo, %s is still there", gone)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(www, "old", "page.html")); string(data) != "old\n" {
		t.Errorf("after undo, old/page.html: %q", data)
	}
}

func TestADirectoryPlanCannotRunProgramsLeakSecretsOrEscape(t *testing.T) {
	for name, c := range map[string]struct {
		role string
		etc  func(lower, upper string) error
		dir  func(dir Layer) error
		why  string
	}{
		"an executable": {dirsRole, nil, func(dir Layer) error {
			return os.WriteFile(filepath.Join(dir.Upper, "run.sh"), []byte("#!/bin/sh\n"), 0o755)
		}, "executable"},
		"a link out": {dirsRole, nil, func(dir Layer) error {
			return os.Symlink("/usr/bin/sudo", filepath.Join(dir.Upper, "sudo"))
		}, "outside /srv/www"},
		"a link to a sibling": {dirsRole, nil, func(dir Layer) error {
			return os.Symlink("../other/x", filepath.Join(dir.Upper, "x"))
		}, "outside /srv/www"},
		"a setuid file": {dirsRole, nil, func(dir Layer) error {
			p := filepath.Join(dir.Upper, "s")
			os.WriteFile(p, []byte("x"), 0o644)
			return os.Chmod(p, 0o644|os.ModeSetuid)
		}, "setuid"},
		"a secret of the directory read and copied": {dirsRole, nil, func(dir Layer) error {
			data, _ := os.ReadFile(filepath.Join(dir.Upper, ".env"))
			return os.WriteFile(filepath.Join(dir.Upper, "leak.txt"), data, 0o644)
		}, "decoy came out"},
		"a secret of /etc copied into the directory": {dirsRole, nil, nil, "decoy came out"},
		"/etc changed by a role without etc": {dirsOnlyRole, func(lower, upper string) error {
			return os.WriteFile(filepath.Join(upper, "motd"), []byte("hi\n"), 0o644)
		}, nil, "may not change /etc"},
	} {
		t.Run(name, func(t *testing.T) {
			sandbox := &dirLayer{etc: c.etc, dirs: c.dir}
			s, _ := dirsMachine(t, c.role, sandbox)
			if name == "a secret of /etc copied into the directory" {
				sandbox.dirs = func(dir Layer) error {
					data, _ := os.ReadFile(filepath.Join(sandbox.spec.Upper, "app.conf"))
					if !strings.HasPrefix(string(data), "nia-decoy-") {
						t.Errorf("/etc's secret is not a decoy: %q", data)
					}
					return os.WriteFile(filepath.Join(dir.Upper, "copy.txt"), data, 0o644)
				}
			}
			r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
			if ok, why := r.Applicable(); ok || !strings.Contains(why, c.why) {
				t.Errorf("applicable %v: %q, want %q (%s)", ok, why, c.why, func() string { b, _ := json.Marshal(r); return string(b) }())
			}
		})
	}
}

func TestACatalogueDirectoryReachedThroughALinkIsRefused(t *testing.T) {
	s, www := dirsMachine(t, dirsRole, &dirLayer{})
	os.RemoveAll(www)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, www); err != nil {
		t.Fatal(err)
	}
	resp := s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"})
	if resp.OK || !strings.Contains(resp.Error, "symbolic link") {
		t.Errorf("%+v", resp)
	}
	os.Remove(www)
	resp = s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"})
	if resp.OK || !strings.Contains(resp.Error, "does not exist") {
		t.Errorf("%+v", resp)
	}
}

func TestPodmanLayersTheCatalogueDirectories(t *testing.T) {
	args := strings.Join(Podman{Root: "/r", RunRoot: "/rr"}.Args(SandboxSpec{
		Root: "/scratch/root", Etc: "/etc", Upper: "/scratch/upper", Work: "/scratch/work", Masked: []string{"/srv"},
		Dirs: []Layer{{Lower: "/srv/www", Target: "/srv/www", Upper: "/scratch/dir0/upper", Work: "/scratch/dir0/work"}}, Script: "true",
	}), " ")
	if !strings.Contains(args, "--volume /srv/www:/srv/www:O,upperdir=/scratch/dir0/upper,workdir=/scratch/dir0/work") ||
		strings.Index(args, "--tmpfs /srv:") > strings.Index(args, "--volume /srv/www:") {
		t.Errorf("args: %s", args)
	}
}
