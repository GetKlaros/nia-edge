package simulate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ChildCommand {
		os.Exit(Child())
	}
	os.Exit(m.Run())
}

// home makes a user's home: a project of 300 files and a key.
func home(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"projet/src", "projet/.git", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 300 {
		if err := os.WriteFile(filepath.Join(dir, "projet/src", "f"+strconv.Itoa(i)+".ts"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "projet/.git/config"), []byte("cfg"), 0o644)
	os.WriteFile(filepath.Join(dir, ".ssh/id_ed25519"), []byte("key"), 0o600)
	os.WriteFile(filepath.Join(dir, "projet/index.ts"), []byte("export const a=1\n"), 0o644)
	return dir
}

func simulate(t *testing.T, dir, command string) *Result {
	t.Helper()
	result, err := Run(context.Background(), Options{Command: command, Dir: dir, Home: dir, Timeout: 20 * time.Second, Env: []string{"HOME=" + dir, "PATH=/usr/local/bin:/usr/bin:/bin"}})
	if errors.Is(err, ErrUnsupported) {
		t.Skipf("no sandbox here: %v", err)
	}
	if err != nil {
		t.Fatalf("%s: %v", command, err)
	}
	t.Cleanup(func() { result.Close() })
	return result
}

func TestDisguisedDeletionsAreSeen(t *testing.T) {
	dir := home(t)
	for _, command := range []string{
		"rm -rf projet",
		"rm -fr ~/projet",
		"/bin/rm --recursive --force projet",
		"echo cm0gLXJmIHByb2pldA== | base64 -d | sh",
		"X=rm; $X -rf projet",
		`$(printf '\162\155') -rf projet`,
		"printf 'rm -rf projet\\n' > /tmp/s.sh; sh /tmp/s.sh",
		"find projet -delete",
		"mv projet /tmp/gone",
		"python3 -c \"import shutil; shutil.rmtree('projet')\"",
	} {
		result := simulate(t, dir, command)
		if result.Effect.Deleted != 302 || len(result.Effect.Paths) != 1 || result.Effect.Paths[0] != filepath.Join(dir, "projet") {
			if strings.HasPrefix(command, "python3") && strings.Contains(string(result.Stderr), "not found") {
				continue
			}
			t.Errorf("%s: %+v %s", command, result.Effect, result.Stderr)
		}
	}
	// Nothing happened for real.
	if entries, _ := os.ReadDir(filepath.Join(dir, "projet/src")); len(entries) != 300 {
		t.Fatal(len(entries))
	}
}

func TestTheSandbox(t *testing.T) {
	dir := home(t)
	// A read changes nothing; its output comes back.
	result := simulate(t, dir, "ls projet; cat .ssh/id_ed25519")
	if result.Effect.Deleted != 0 || len(result.Effect.Paths) != 0 || !strings.Contains(string(result.Stdout), "key") || result.ExitCode != 0 {
		t.Fatalf("%+v %q", result.Effect, result.Stdout)
	}
	// Outside the user's files, nothing can be written; no network; no
	// process of the machine; the exit status is the command's.
	result = simulate(t, dir, "touch /etc/nia-test || echo ro; ls /run | wc -l; cat /proc/net/dev | grep -c : ; ps -e 2>/dev/null | wc -l; exit 7")
	out := strings.Fields(string(result.Stdout))
	if len(out) < 3 || out[0] != "ro" || out[1] != "0" || out[2] != "1" || result.ExitCode != 7 {
		t.Fatalf("%q %s", result.Stdout, result.Stderr)
	}
	if _, err := os.Stat("/etc/nia-test"); err == nil {
		t.Fatal("wrote /etc")
	}
	// A key changed is a protected path for the role to judge.
	result = simulate(t, dir, "truncate -s0 .ssh/id_ed25519")
	if len(result.Effect.Paths) != 1 || result.Effect.Paths[0] != filepath.Join(dir, ".ssh/id_ed25519") {
		t.Fatalf("%+v", result.Effect)
	}
	// A setuid file is never applied.
	if _, err := Run(context.Background(), Options{Command: "cp /bin/true x && chmod u+s x", Dir: dir, Home: dir, Timeout: 20 * time.Second, Env: []string{"PATH=/usr/bin:/bin"}}); err == nil || !strings.Contains(err.Error(), "setuid") {
		t.Fatal(err)
	}
	// A command that outlives its time: nothing is kept.
	if _, err := Run(context.Background(), Options{Command: "touch late; sleep 30", Dir: dir, Home: dir, Timeout: time.Second, Env: []string{"PATH=/usr/bin:/bin"}}); err == nil || !strings.Contains(err.Error(), "longer") {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "late")); err == nil {
		t.Fatal("kept a command that timed out")
	}
}

func TestApplyWritesWhatWasSimulated(t *testing.T) {
	dir := home(t)
	result := simulate(t, dir, "echo build > projet/dist.txt && sed -i s/a=1/a=2/ projet/index.ts && rm projet/src/f1.ts && mkdir -p out/deep && echo n > out/deep/new.txt && ln -s index.ts projet/link && rm -rf projet/.git && echo done")
	if result.Effect.Deleted != 2 || string(result.Stdout) != "done\n" {
		t.Fatalf("%+v %q", result.Effect, result.Stdout)
	}
	want := map[string]bool{"projet/dist.txt": true, "projet/index.ts": true, "projet/src/f1.ts": true, "out": true, "projet/link": true, "projet/.git": true}
	for _, path := range result.Effect.Paths {
		rel, _ := filepath.Rel(dir, path)
		if !want[rel] {
			t.Errorf("unexpected %s", rel)
		}
		delete(want, rel)
	}
	if len(want) != 0 {
		t.Fatalf("missing %v", want)
	}
	// Before it is applied, nothing changed.
	if _, err := os.Stat(filepath.Join(dir, "projet/dist.txt")); err == nil {
		t.Fatal("applied before")
	}
	if err := result.Apply(); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{"projet/dist.txt": "build\n", "projet/index.ts": "export const a=2\n", "out/deep/new.txt": "n\n"} {
		if got, _ := os.ReadFile(filepath.Join(dir, path)); string(got) != content {
			t.Errorf("%s: %q", path, got)
		}
	}
	if link, _ := os.Readlink(filepath.Join(dir, "projet/link")); link != "index.ts" {
		t.Error(link)
	}
	for _, gone := range []string{"projet/src/f1.ts", "projet/.git"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); err == nil {
			t.Errorf("%s is still there", gone)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "projet/src")); len(entries) != 299 {
		t.Fatal(len(entries))
	}
}

func TestNothingIsAppliedWhereTheFilesChanged(t *testing.T) {
	dir := home(t)
	result := simulate(t, dir, "echo new > projet/index.ts")
	if err := os.WriteFile(filepath.Join(dir, "projet/index.ts"), []byte("theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := result.Apply(); !errors.Is(err, ErrChanged) {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "projet/index.ts")); string(got) != "theirs\n" {
		t.Fatalf("%q", got)
	}
}
