//go:build linux

package hostd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// failing fails the programs it names.
type failing struct {
	DryRun
	fail map[string]bool
}

func (f *failing) Run(ctx context.Context, env []string, argv ...string) (string, error) {
	f.DryRun.Run(ctx, env, argv...)
	if f.fail[argv[0]] {
		return argv[0] + ": syntax error\n", errors.New("exit status 1")
	}
	return argv[0] + ": ok\n", nil
}

func applyMachine(t *testing.T, sandbox *layer) (*Server, string, *failing) {
	t.Helper()
	s, etc := etcMachine(t, sandbox)
	run := &failing{fail: map[string]bool{}}
	s.Run, s.BackupRoot = run, t.TempDir()
	s.Installed = func(program string) bool { return program == "nginx" || program == "visudo" }
	return s, etc, run
}

func snapshot(t *testing.T, etc string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.Walk(etc, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(etc, p)
		st := info.Sys().(*syscall.Stat_t)
		// 0: owned by the user the tests run as (root on a machine), as before.
		owner := "0"
		if st.Uid != uint32(os.Getuid()) {
			owner = fmt.Sprint(st.Uid)
		}
		desc := info.Mode().String() + " " + owner
		if info.Mode().IsRegular() {
			data, _ := os.ReadFile(p)
			desc += " " + string(data)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			desc += " -> " + target
		}
		out[rel] = desc
		return nil
	})
	return out
}

func nginxScript(t *testing.T) func(lower, upper string) error {
	return func(lower, upper string) error {
		os.WriteFile(copyUp(t, lower, upper, "nginx/nginx.conf"), []byte("worker_processes 4;\n"), 0o644)
		os.MkdirAll(filepath.Join(upper, "nginx", "conf.d"), 0o750)
		os.Chmod(filepath.Join(upper, "nginx", "conf.d"), 0o750)
		os.WriteFile(filepath.Join(upper, "nginx", "conf.d", "site.conf"), []byte("server {}\n"), 0o640)
		os.Symlink("../nginx/nginx.conf", filepath.Join(upper, "nginx", "current"))
		copyUp(t, lower, upper, "issue")
		os.Chmod(filepath.Join(upper, "issue"), 0o600)
		os.MkdirAll(filepath.Join(upper, "cron.d"), 0o755)
		return syscall.Mknod(filepath.Join(upper, "cron.d", "old"), syscall.S_IFCHR, 0)
	}
}

func TestAnApplyWritesThePlanExactlyChecksItAndCanBeUndone(t *testing.T) {
	sandbox := &layer{script: nginxScript(t)}
	s, etc, run := applyMachine(t, sandbox)
	before := snapshot(t, etc)
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	resp := s.Do(context.Background(), Request{Action: ApplyAction, Name: r.Plan})
	if !resp.OK || resp.Journal == "" {
		t.Fatalf("apply: %+v", resp)
	}
	after := snapshot(t, etc)
	for rel, want := range map[string]string{
		"nginx/nginx.conf":       "-rw-r--r-- 0 worker_processes 4;\n",
		"nginx/conf.d":           "drwxr-x--- 0",
		"nginx/conf.d/site.conf": "-rw-r----- 0 server {}\n",
		"nginx/current":          "Lrwxrwxrwx 0 -> ../nginx/nginx.conf",
		"issue":                  "-rw------- 0 Debian\n",
	} {
		if after[rel] != want {
			t.Errorf("%s: %q, want %q", rel, after[rel], want)
		}
	}
	if _, ok := after["cron.d/old"]; ok {
		t.Error("cron.d/old not deleted")
	}
	if len(run.Calls) != 1 || strings.Join(run.Calls[0], " ") != "nginx -t" || !strings.Contains(resp.Output, "nginx: ok") {
		t.Errorf("checks %v, output %q", run.Calls, resp.Output)
	}
	// Once: the plan is spent.
	if again := s.Do(context.Background(), Request{Action: ApplyAction, Name: r.Plan}); again.OK {
		t.Error("a plan applied twice")
	}
	// Undo puts back exactly what was there.
	if undo := s.Undo(context.Background(), resp.Journal); !undo.OK {
		t.Fatalf("undo: %+v", undo)
	}
	restored := snapshot(t, etc)
	for rel, want := range before {
		if restored[rel] != want {
			t.Errorf("after undo %s: %q, want %q", rel, restored[rel], want)
		}
	}
	for rel := range restored {
		if _, ok := before[rel]; !ok {
			t.Errorf("after undo %s is left", rel)
		}
	}
	if again := s.Undo(context.Background(), resp.Journal); again.OK {
		t.Error("undone twice")
	}
}

func TestAFailedCheckPutsTheFormerFilesBack(t *testing.T) {
	sandbox := &layer{script: nginxScript(t)}
	s, etc, run := applyMachine(t, sandbox)
	run.fail["nginx"] = true
	before := snapshot(t, etc)
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	resp := s.Do(context.Background(), Request{Action: ApplyAction, Name: r.Plan})
	if resp.OK || !strings.Contains(resp.Error, "nginx -t failed") || !strings.Contains(resp.Error, "former files are back") {
		t.Fatalf("%+v", resp)
	}
	if after := snapshot(t, etc); len(after) != len(before) {
		t.Errorf("not put back: %v", after)
	} else {
		for rel, want := range before {
			if after[rel] != want {
				t.Errorf("%s: %q, want %q", rel, after[rel], want)
			}
		}
	}
}

func TestAnApplyRefusesAMachineThatMovedOrAPathOutOfEtc(t *testing.T) {
	sandbox := &layer{script: nginxScript(t)}
	s, etc, _ := applyMachine(t, sandbox)
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	os.WriteFile(filepath.Join(etc, "nginx/nginx.conf"), []byte("someone else\n"), 0o644)
	if resp := s.Do(context.Background(), Request{Action: ApplyAction, Name: r.Plan}); resp.OK || !strings.Contains(resp.Error, "changed on the machine") {
		t.Fatalf("%+v", resp)
	}
	if data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf")); string(data) != "someone else\n" {
		t.Errorf("written: %q", data)
	}
	if _, err := os.Stat(filepath.Join(etc, "nginx/conf.d")); err == nil {
		t.Error("a refused plan wrote")
	}

	// A symlink of /etc to elsewhere is never followed out.
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(etc, "escape"))
	scratch := t.TempDir()
	os.MkdirAll(filepath.Join(scratch, "upper", "escape"), 0o755)
	os.WriteFile(filepath.Join(scratch, "upper", "escape", "x"), []byte("pwned\n"), 0o644)
	sum := "1060092d1ce0ae5ca5ac11bc1d078c5fa9e263f3fb6c736293a5dbb018e59258"
	s.plans["evil"] = &plan{report: Report{Plan: "evil", Changes: []Change{{Path: "/etc/escape/x", Kind: "created", Type: "file", Mode: 0o644, SHA256: sum, Base: "absent"}}}, scratch: scratch, cleanup: func() {}, made: now}
	resp := s.Do(context.Background(), Request{Action: ApplyAction, Name: "evil"})
	if _, err := os.Stat(filepath.Join(outside, "x")); err == nil {
		t.Fatalf("written outside /etc: %+v", resp)
	}
	if resp.OK {
		t.Errorf("%+v", resp)
	}
	t.Logf("refused: %s", resp.Error)
	// The writer itself, past the checks: os.Root stops it.
	root, _ := os.OpenRoot(etc)
	defer root.Close()
	err := write(root, "/etc", filepath.Join(scratch, "upper"), []Change{{Path: "/etc/escape/x", Kind: "created", Type: "file", Mode: 0o644}})
	if _, statErr := os.Stat(filepath.Join(outside, "x")); statErr == nil || err == nil {
		t.Errorf("written outside /etc: %v", err)
	}
	t.Logf("writer: %v", err)
}

func TestAPlanReviewIsWhatItsIDHashes(t *testing.T) {
	sandbox := &layer{script: nginxScript(t)}
	s, _, _ := applyMachine(t, sandbox)
	r := report(t, s.Do(context.Background(), Request{Action: DryRunAction, Script: "x"}))
	resp := s.Do(context.Background(), Request{Action: PlanReviewAction, Name: r.Plan})
	var review Review
	if !resp.OK || json.Unmarshal([]byte(resp.Output), &review) != nil {
		t.Fatalf("%+v", resp)
	}
	sum := sha256.Sum256([]byte(review.Changes))
	if hex.EncodeToString(sum[:16]) != r.Plan || review.Plan != r.Plan {
		t.Errorf("the changes do not hash to the plan id")
	}
	files := map[string]ReviewFile{}
	for _, f := range review.Files {
		files[f.Path] = f
	}
	conf := files["/etc/nginx/nginx.conf"]
	if conf.Before == nil || *conf.Before != "worker_processes 1;\n" || conf.After == nil || *conf.After != "worker_processes 4;\n" {
		t.Errorf("nginx.conf: %+v", conf)
	}
	if site := files["/etc/nginx/conf.d/site.conf"]; site.Before != nil || site.After == nil {
		t.Errorf("site.conf: %+v", site)
	}
	if _, ok := files["/etc/issue"]; ok {
		t.Error("a mode change carries texts")
	}
	if resp := s.Do(context.Background(), Request{Action: PlanReviewAction, Name: "0123456789abcdef0123456789abcdef"}); resp.OK {
		t.Error("an unknown plan is reviewed")
	}
	if entries, _ := s.Journal(); len(entries) != 1 {
		t.Errorf("a review was journaled: %d entries", len(entries))
	}
}
