package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// UndoDomain comes before an undo order's payload in what Nia signs, so that
// no signature over a policy can pass for an order, nor the other way.
const UndoDomain = "nia-undo/1\n"

// longestOrder is the longest an undo order may live: a person asked for it
// now, not tomorrow.
const longestOrder = 15 * time.Minute

var (
	orderID      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	journalEntry = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}-[0-9a-f]{16}$`)
)

// UndoOrder is a person's request, through Nia, to undo one entry of
// nia-hostd's journal on one machine.
type UndoOrder struct {
	ID       string
	Entry    string
	NotAfter time.Time
}

// OpenUndo verifies an undo order Nia signed with the key pinned at
// enrollment, for this machine, at this instant. Every check that fails
// refuses the order.
func OpenUndo(signed Signed, key Key, machineID string, now time.Time) (*UndoOrder, error) {
	if key.Alg != "ed25519" || signed.Alg != "ed25519" {
		return nil, errors.New("undo: only ed25519 signatures are accepted")
	}
	if signed.KeyID != key.ID {
		return nil, fmt.Errorf("undo: signed by key %s, not by the key %s this machine learned when it enrolled", signed.KeyID, key.ID)
	}
	if !VerifySignature(key.PublicKey, UndoDomain+signed.Payload, signed.Signature) {
		return nil, errors.New("undo: the signature does not match")
	}
	var payload struct {
		V         int       `json:"v"`
		Kind      string    `json:"kind"`
		KeyID     string    `json:"key_id"`
		MachineID string    `json:"machine_id"`
		OrderID   string    `json:"order_id"`
		Entry     string    `json:"entry"`
		IssuedAt  time.Time `json:"issued_at"`
		NotAfter  time.Time `json:"not_after"`
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(signed.Payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("undo: the payload cannot be read: %w", err)
	}
	switch {
	case payload.V != 1 || payload.Kind != "undo":
		return nil, errors.New("undo: not an undo order this nia-edge knows")
	case payload.KeyID != key.ID:
		return nil, errors.New("undo: the payload names another key")
	case payload.MachineID == "" || payload.MachineID != machineID:
		return nil, errors.New("undo: issued for another machine")
	case !orderID.MatchString(payload.OrderID) || !journalEntry.MatchString(payload.Entry):
		return nil, errors.New("undo: no order or no journal entry named")
	case payload.IssuedAt.IsZero() || !payload.NotAfter.After(payload.IssuedAt) || payload.NotAfter.Sub(payload.IssuedAt) > longestOrder:
		return nil, errors.New("undo: no validity, or one too long")
	case payload.IssuedAt.After(now.Add(clockSkew)):
		return nil, errors.New("undo: issued in the future: check this machine's clock")
	case !now.Before(payload.NotAfter):
		return nil, errors.New("undo: the order expired")
	}
	return &UndoOrder{ID: payload.OrderID, Entry: payload.Entry, NotAfter: payload.NotAfter}, nil
}
