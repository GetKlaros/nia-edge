package hostd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/policy"
)

func undoOrder(private ed25519.PrivateKey, fields map[string]any) *policy.Signed {
	payload := map[string]any{
		"v": 1, "kind": "undo", "key_id": "k1", "machine_id": "m1", "order_id": "0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
		"issued_at": now.Add(-time.Minute), "not_after": now.Add(5 * time.Minute),
	}
	for k, v := range fields {
		if v == nil {
			delete(payload, k)
		} else {
			payload[k] = v
		}
	}
	raw, _ := json.Marshal(payload)
	return &policy.Signed{Payload: string(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(policy.UndoDomain+string(raw)))), KeyID: "k1", Alg: "ed25519"}
}

func TestAnOrderNiaSignedUndoesAChangeOnce(t *testing.T) {
	s, run, private := machine(t, role)
	ctx := context.Background()
	installed := s.Do(ctx, Request{Action: PackageInstall, Name: "fail2ban"})
	if !installed.OK {
		t.Fatal(installed)
	}
	// The change is listed, not yet undone.
	var listed []ChangeReport
	if resp := s.Do(ctx, Request{Action: ChangesAction}); !resp.OK || json.Unmarshal([]byte(resp.Output), &listed) != nil || len(listed) != 1 || listed[0].ID != installed.Journal || listed[0].UndoneBy != "" {
		t.Fatalf("changes %+v", resp)
	}
	order := undoOrder(private, map[string]any{"entry": installed.Journal})
	resp := s.Do(ctx, Request{Action: UndoOrderAction, Order: order})
	if !resp.OK || strings.Join(run.Calls[len(run.Calls)-1], " ") != "apt-get remove -y -q -- fail2ban" {
		t.Fatalf("%+v %q", resp, run.Calls)
	}
	calls := len(run.Calls)
	// The same order again answers what it did, and runs nothing.
	if again := s.Do(ctx, Request{Action: UndoOrderAction, Order: order}); !again.OK || again.Journal != resp.Journal || len(run.Calls) != calls {
		t.Errorf("again %+v", again)
	}
	if after := s.Do(ctx, Request{Action: ChangesAction}); json.Unmarshal([]byte(after.Output), &listed) != nil || listed[0].UndoneBy != resp.Journal || listed[0].Order != "0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b" {
		t.Errorf("changes after %+v", listed)
	}
}

func TestAnUndoOrderIsRefusedUnlessNiaSignedItForThisMachineNow(t *testing.T) {
	s, run, private := machine(t, role)
	ctx := context.Background()
	installed := s.Do(ctx, Request{Action: PackageInstall, Name: "fail2ban"})
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	policyLike := undoOrder(private, map[string]any{"entry": installed.Journal})
	// A signature over the payload without the domain: a policy's, not an order's.
	policyLike.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(policyLike.Payload)))
	for name, order := range map[string]*policy.Signed{
		"none":            nil,
		"another key":     undoOrder(other, map[string]any{"entry": installed.Journal}),
		"no domain":       policyLike,
		"another machine": undoOrder(private, map[string]any{"entry": installed.Journal, "machine_id": "m2"}),
		"expired":         undoOrder(private, map[string]any{"entry": installed.Journal, "issued_at": now.Add(-time.Hour), "not_after": now.Add(-time.Minute)}),
		"too long":        undoOrder(private, map[string]any{"entry": installed.Journal, "not_after": now.Add(time.Hour)}),
		"not an undo":     undoOrder(private, map[string]any{"entry": installed.Journal, "kind": "apply"}),
		"no entry":        undoOrder(private, map[string]any{"entry": "../journal"}),
		"unknown field":   undoOrder(private, map[string]any{"entry": installed.Journal, "script": "rm -rf /"}),
	} {
		calls := len(run.Calls)
		if resp := s.Do(ctx, Request{Action: UndoOrderAction, Order: order}); resp.OK || len(run.Calls) != calls {
			t.Errorf("%s: %+v", name, resp)
		}
	}
	// A change that cannot be undone stays.
	restart := s.Do(ctx, Request{Action: ServiceRestart, Name: "nginx"})
	if resp := s.Do(ctx, Request{Action: UndoOrderAction, Order: undoOrder(private, map[string]any{"entry": restart.Journal})}); resp.OK {
		t.Errorf("a restart undone: %+v", resp)
	}
}
