package decisions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GetKlaros/nia-edge/internal/egress"
	"github.com/GetKlaros/nia-edge/internal/local"
)

type fakeAuthority struct {
	local.Authority
	verdict local.Verdict
	err     error
}

func (f fakeAuthority) Decide(context.Context, string, string, string, []json.RawMessage) (local.Verdict, error) {
	return f.verdict, f.err
}

func (f fakeAuthority) DecideHashed(context.Context, string, local.Hashed) (local.Verdict, bool, error) {
	return f.verdict, false, f.err
}

type fakeEgress struct{ verdict egress.Verdict }

func (f fakeEgress) Decide(context.Context, egress.Request) (egress.Verdict, error) {
	return f.verdict, nil
}
func (f fakeEgress) Connected(context.Context, egress.Request) error { return nil }
func (f fakeEgress) Refused(egress.Request, string)                  {}

func TestDecisionsAreLoggedWithoutContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	log := Open(path)
	ctx := context.Background()
	allow := Authority{Authority: fakeAuthority{verdict: local.Verdict{Allowed: true}}, Log: log, Path: "model"}
	if _, err := allow.Decide(ctx, "conversation-1", "terminal", `{"command":"cat SECRET-ARGUMENT"}`, nil); err != nil {
		t.Fatal(err)
	}
	deny := Authority{Authority: fakeAuthority{verdict: local.Verdict{Message: "held: token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, Log: log, Path: "hook"}
	_, _, _ = deny.DecideHashed(ctx, "conversation-1", local.Hashed{Tool: "Bash", Hash: "h"})
	down := Authority{Authority: fakeAuthority{err: errors.New("unreachable")}, Log: log, Path: "hook"}
	_, _ = down.Decide(ctx, "s", "Bash", "{}", nil)
	held := Egress{Authority: fakeEgress{verdict: egress.Verdict{Held: true, Message: "approval"}}, Log: log}
	_, _ = held.Decide(ctx, egress.Request{Session: "s", Host: "paste.example", Port: 443})

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "SECRET-ARGUMENT") || strings.Contains(string(raw), "conversation-1") || strings.Contains(string(raw), "ghp_aaaa") {
		t.Fatalf("content in the log: %s", raw)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("%v", info.Mode())
	}
	entries, err := Last(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Path+" "+e.Decision+" "+e.Tool+e.Host)
	}
	want := []string{"model allow terminal", "hook deny Bash", "hook error Bash", "egress hold paste.example"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%v", got)
	}
	if entries[0].Session != Session("conversation-1") || entries[0].Session != entries[1].Session || len(entries[0].Session) != 8 {
		t.Fatalf("%+v", entries[:2])
	}
	var out bytes.Buffer
	Format(&out, entries[3:])
	if !strings.Contains(out.String(), "egress  hold   paste.example") {
		t.Fatalf("%q", out.String())
	}
}

func TestTheLogRotatesAndReadsAcrossTheRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	log := Open(path)
	log.max = 400
	for i := 0; i < 10; i++ {
		log.Record(Entry{Path: "model", Tool: "t", Decision: "allow", Reason: strings.Repeat("x", 500)})
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("rotated")
	}
	entries, err := Last(path, 0)
	if err != nil || len(entries) < 2 || len(entries) > 10 {
		t.Fatalf("%d %v", len(entries), err)
	}
	if len(entries[0].Reason) > 310 {
		t.Fatal("a reason is clipped")
	}
	if _, err := Last(filepath.Join(t.TempDir(), "none"), 5); !os.IsNotExist(err) {
		t.Fatalf("%v", err)
	}
	// A log that cannot be written stops nothing.
	Open("/nonexistent/dir/decisions.jsonl").Record(Entry{Path: "model", Decision: "allow"})
	var nilLog *Log
	nilLog.Record(Entry{})
}
