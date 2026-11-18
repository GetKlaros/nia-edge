package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestTheJournalIsAChainThatBreaksWhereItIsChanged(t *testing.T) {
	s, _, _ := machine(t, role)
	ctx := context.Background()
	// Two lines from before the chain: kept, counted.
	os.WriteFile(s.JournalPath, []byte(`{"id":"old1","action":"service_status","name":"nginx","ok":true}`+"\n"+`{"id":"old2","action":"service_status","name":"nginx","ok":true}`+"\n"), 0o600)
	for i := 0; i < 3; i++ {
		if resp := s.Do(ctx, Request{Action: ServiceStatus, Name: "nginx"}); !resp.OK {
			t.Fatalf("%+v", resp)
		}
	}
	head, err := s.VerifyJournal()
	if err != nil || head.Seq != 5 || len(head.Hash) != 64 {
		t.Fatalf("%+v %v", head, err)
	}
	entries, _ := s.Journal()
	if entries[2].Seq != 3 || entries[2].Prev == "" || entries[4].Seq != 5 {
		t.Errorf("%+v", entries)
	}
	// The head and an anchor, over the socket's request.
	resp := s.Do(ctx, Request{Action: HeadAction, At: 4})
	var a Anchor
	json.Unmarshal([]byte(resp.Output), &a)
	raw, _ := os.ReadFile(s.JournalPath)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if a.Seq != 5 || a.Hash != head.Hash || a.At != 4 || a.AtHash != lineHash(lines[3]) || a.Broken != "" {
		t.Errorf("anchor %+v", a)
	}
	// An entry changed in place: broken from there, and nothing more runs.
	changed := bytes.Replace(raw, []byte(`"seq":4,`), []byte(`"seq":4, `), 1)
	os.WriteFile(s.JournalPath, changed, 0o600)
	if _, err := s.VerifyJournal(); err == nil || !strings.Contains(err.Error(), "entry 5 does not follow entry 4") {
		t.Errorf("a changed entry: %v", err)
	}
	if resp := s.Do(ctx, Request{Action: ServiceStatus, Name: "nginx"}); resp.OK {
		t.Error("ran on a broken journal")
	}
	json.Unmarshal([]byte(s.Do(ctx, Request{Action: HeadAction}).Output), &a)
	if a.Broken == "" {
		t.Errorf("the head of a broken chain: %+v", a)
	}
	// An entry removed.
	removed := append(append(append([]byte{}, bytes.Join(lines[:2], []byte("\n"))...), '\n'), append(bytes.Join(lines[3:], []byte("\n")), '\n')...)
	os.WriteFile(s.JournalPath, removed, 0o600)
	if _, err := s.VerifyJournal(); err == nil {
		t.Error("a removed entry is not seen")
	}
}
