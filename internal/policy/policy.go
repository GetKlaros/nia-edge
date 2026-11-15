// Package policy holds the policy a machine applies: the role Nia gave it,
// signed by the server and kept on disk, so that nia-edge can trust it
// without asking again.
//
// The signature is Ed25519 over the exact bytes of the payload. The public
// key is the one the machine learned when it enrolled; a policy signed by
// any other key is refused. A policy is for one machine and has an end:
// past it, there is no policy, and what depends on one is refused.
package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Key is the server's signing key, as the machine pinned it at enrollment.
type Key struct {
	ID  string `json:"id"`
	Alg string `json:"alg"`
	// PublicKey is the 32 bytes of the key, base64.
	PublicKey string `json:"public_key"`
}

// Signed is a policy as the server sends it and as it is kept on disk.
type Signed struct {
	// Payload is JSON; the signature is over these bytes.
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
}

// Policy is a verified policy.
type Policy struct {
	TenantID  string
	MachineID string
	// Role and Dispatchers are the server's JSON, to be read by the engine.
	Role        json.RawMessage
	Dispatchers json.RawMessage
	// Version is a number, or "file".
	Version  string
	Digest   string
	IssuedAt time.Time
	NotAfter time.Time
}

// What the clock may be ahead of the server's, and the longest a policy may
// claim to live: the server's own limit is seven days.
const (
	clockSkew   = 5 * time.Minute
	longestLife = 8 * 24 * time.Hour
)

// ErrNone reports that there is no policy on disk.
var ErrNone = errors.New("no policy")

// VerifySignature reports whether signature is the server's over payload.
// publicKey and signature are base64. Anything malformed is not a signature.
func VerifySignature(publicKey, payload, signature string) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(publicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), []byte(payload), sig)
}

// Open verifies a signed policy and returns it, for one machine at one
// instant. Every check that fails refuses the whole policy.
func Open(signed Signed, key Key, machineID string, now time.Time) (*Policy, error) {
	if key.Alg != "ed25519" || signed.Alg != "ed25519" {
		return nil, errors.New("policy: only ed25519 signatures are accepted")
	}
	if signed.KeyID != key.ID {
		return nil, fmt.Errorf("policy: signed by key %s, not by the key %s this machine learned when it enrolled", signed.KeyID, key.ID)
	}
	if !VerifySignature(key.PublicKey, signed.Payload, signed.Signature) {
		return nil, errors.New("policy: the signature does not match")
	}
	// Only now is the payload read: it is the server's.
	var payload struct {
		V           int             `json:"v"`
		KeyID       string          `json:"key_id"`
		TenantID    string          `json:"tenant_id"`
		MachineID   string          `json:"machine_id"`
		Role        json.RawMessage `json:"role"`
		Dispatchers json.RawMessage `json:"dispatchers"`
		Policy      struct {
			Version json.RawMessage `json:"version"`
			Digest  string          `json:"digest"`
		} `json:"policy"`
		IssuedAt time.Time `json:"issued_at"`
		NotAfter time.Time `json:"not_after"`
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(signed.Payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("policy: the payload cannot be read: %w", err)
	}
	switch {
	case payload.V != 1:
		return nil, fmt.Errorf("policy: version %d of the format is not known to this nia-edge", payload.V)
	case payload.KeyID != key.ID:
		return nil, errors.New("policy: the payload names another key")
	case payload.MachineID == "" || payload.MachineID != machineID:
		return nil, errors.New("policy: issued for another machine")
	case len(payload.Role) == 0 || payload.Policy.Digest == "":
		return nil, errors.New("policy: no role in the payload")
	case payload.IssuedAt.IsZero() || payload.NotAfter.IsZero() || !payload.NotAfter.After(payload.IssuedAt):
		return nil, errors.New("policy: no validity in the payload")
	case payload.NotAfter.Sub(payload.IssuedAt) > longestLife:
		return nil, errors.New("policy: valid for longer than a policy can be")
	case payload.IssuedAt.After(now.Add(clockSkew)):
		return nil, errors.New("policy: issued in the future: check this machine's clock")
	case !now.Before(payload.NotAfter):
		return nil, fmt.Errorf("policy: expired at %s", payload.NotAfter.UTC().Format(time.RFC3339))
	}
	version := string(payload.Policy.Version)
	if unquoted := ""; json.Unmarshal(payload.Policy.Version, &unquoted) == nil {
		version = unquoted
	}
	return &Policy{
		TenantID:    payload.TenantID,
		MachineID:   payload.MachineID,
		Role:        payload.Role,
		Dispatchers: payload.Dispatchers,
		Version:     version,
		Digest:      payload.Policy.Digest,
		IssuedAt:    payload.IssuedAt,
		NotAfter:    payload.NotAfter,
	}, nil
}

// Load reads the signed policy kept on disk. It is not verified: Open does that.
func Load(path string) (Signed, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Signed{}, ErrNone
	}
	if err != nil {
		return Signed{}, err
	}
	var signed Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		return Signed{}, fmt.Errorf("%s is not a policy file: %w", path, err)
	}
	return signed, nil
}

// Save keeps a signed policy on disk, mode 0600, replacing the previous one
// atomically. The file is not secret, and not trusted either: it is verified
// again each time it is read.
func Save(path string, signed Signed) error {
	raw, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
