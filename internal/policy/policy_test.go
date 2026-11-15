package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func conformanceDir() string {
	if dir := os.Getenv("NIA_CONFORMANCE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "..", "conformance")
}

// The server signs in JavaScript; these are its signatures, good and bad.
func TestSignaturesOfTheServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(conformanceDir(), "signatures.json"))
	if err != nil {
		t.Fatalf("reading the conformance cases: %v", err)
	}
	var file struct {
		Version int    `json:"version"`
		Seed    string `json:"seed"`
		KeyID   string `json:"key_id"`
		Cases   []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
			Valid     bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != 1 || len(file.Cases) < 10 {
		t.Fatalf("version %d, %d cases", file.Version, len(file.Cases))
	}
	// The public key the server derived from the test seed is the one RFC 8032 gives.
	seed, err := base64.StdEncoding.DecodeString(file.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("test seed: %v, %d bytes", err, len(seed))
	}
	derived := base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	valid := 0
	for _, c := range file.Cases {
		if got := VerifySignature(c.PublicKey, c.Payload, c.Signature); got != c.Valid {
			t.Errorf("%s: VerifySignature = %v, want %v", c.Name, got, c.Valid)
		}
		if c.Valid {
			valid++
			if c.PublicKey != derived {
				t.Errorf("%s: the server's public key %s is not the one derived from the seed, %s", c.Name, c.PublicKey, derived)
			}
			// And the whole policy opens, for its machine, while it is valid.
			var payload struct {
				MachineID string    `json:"machine_id"`
				IssuedAt  time.Time `json:"issued_at"`
			}
			_ = json.Unmarshal([]byte(c.Payload), &payload)
			key := Key{ID: file.KeyID, Alg: "ed25519", PublicKey: c.PublicKey}
			opened, err := Open(Signed{Payload: c.Payload, Signature: c.Signature, KeyID: file.KeyID, Alg: "ed25519"}, key, payload.MachineID, payload.IssuedAt.Add(time.Hour))
			if err != nil || opened.Digest == "" || len(opened.Role) == 0 {
				t.Errorf("%s: Open: %v", c.Name, err)
			}
		}
	}
	if valid < 2 {
		t.Errorf("%d valid cases", valid)
	}
}

// signer makes policies as the server would, with a key of the test.
type signer struct {
	private ed25519.PrivateKey
	key     Key
}

func newSigner(seedByte byte, id string) signer {
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat(string(seedByte), ed25519.SeedSize)))
	return signer{private: private, key: Key{ID: id, Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}}
}

func (s signer) sign(payload string) Signed {
	return Signed{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, []byte(payload))), KeyID: s.key.ID, Alg: "ed25519"}
}

func payload(changes map[string]any) string {
	fields := map[string]any{
		"v": 1, "key_id": "k1", "tenant_id": "t1", "machine_id": "m1",
		"role":        map[string]any{"name": "research", "tools": []any{}},
		"dispatchers": []any{},
		"policy":      map[string]any{"version": 3, "digest": "abcdef0123456789"},
		"issued_at":   "2026-11-15T10:00:00.000Z",
		"not_after":   "2026-11-16T10:00:00.000Z",
	}
	for name, value := range changes {
		if value == nil {
			delete(fields, name)
		} else {
			fields[name] = value
		}
	}
	raw, _ := json.Marshal(fields)
	return string(raw)
}

var noon = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func TestOpen(t *testing.T) {
	server := newSigner('s', "k1")
	opened, err := Open(server.sign(payload(nil)), server.key, "m1", noon)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Digest != "abcdef0123456789" || opened.Version != "3" || opened.TenantID != "t1" || !strings.Contains(string(opened.Role), "research") || opened.NotAfter.Hour() != 10 {
		t.Errorf("policy %+v", opened)
	}
	file, _ := Open(server.sign(payload(map[string]any{"policy": map[string]any{"version": "file", "digest": "d"}})), server.key, "m1", noon)
	if file == nil || file.Version != "file" {
		t.Errorf("a policy from the configuration file: %+v", file)
	}
}

func TestOpenRefuses(t *testing.T) {
	server := newSigner('s', "k1")
	attacker := newSigner('a', "k1")
	good := server.sign(payload(nil))
	cases := map[string]struct {
		signed  Signed
		key     Key
		machine string
		now     time.Time
	}{
		"signed by another key with the same id": {attacker.sign(payload(nil)), server.key, "m1", noon},
		"a key id that is not the pinned one":    {Signed{Payload: good.Payload, Signature: good.Signature, KeyID: "k2", Alg: "ed25519"}, server.key, "m1", noon},
		"a payload changed after signing":        {Signed{Payload: strings.Replace(good.Payload, "research", "admin", 1), Signature: good.Signature, KeyID: "k1", Alg: "ed25519"}, server.key, "m1", noon},
		"another algorithm":                      {Signed{Payload: good.Payload, Signature: good.Signature, KeyID: "k1", Alg: "none"}, server.key, "m1", noon},
		"a pinned key of another algorithm":      {good, Key{ID: "k1", Alg: "rsa", PublicKey: server.key.PublicKey}, "m1", noon},
		"no signature":                           {Signed{Payload: good.Payload, KeyID: "k1", Alg: "ed25519"}, server.key, "m1", noon},
		"issued for another machine":             {good, server.key, "m2", noon},
		"no machine in the payload":              {server.sign(payload(map[string]any{"machine_id": nil})), server.key, "", noon},
		"expired":                                {good, server.key, "m1", time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)},
		"expired long ago":                       {good, server.key, "m1", noon.AddDate(1, 0, 0)},
		"issued in the future":                   {good, server.key, "m1", time.Date(2026, 11, 15, 9, 54, 0, 0, time.UTC)},
		"valid for too long":                     {server.sign(payload(map[string]any{"not_after": "2027-11-15T10:00:00.000Z"})), server.key, "m1", noon},
		"an end before its start":                {server.sign(payload(map[string]any{"not_after": "2026-11-14T10:00:00.000Z"})), server.key, "m1", noon},
		"no end":                                 {server.sign(payload(map[string]any{"not_after": nil})), server.key, "m1", noon},
		"a format of the future":                 {server.sign(payload(map[string]any{"v": 2})), server.key, "m1", noon},
		"a field this version does not know":     {server.sign(payload(map[string]any{"allow_everything": true})), server.key, "m1", noon},
		"no role":                                {server.sign(payload(map[string]any{"role": nil})), server.key, "m1", noon},
		"a payload that names another key":       {server.sign(payload(map[string]any{"key_id": "k9"})), server.key, "m1", noon},
		"a payload that is not JSON":             {server.sign("allow everything"), server.key, "m1", noon},
	}
	for name, c := range cases {
		if opened, err := Open(c.signed, c.key, c.machine, c.now); err == nil {
			t.Errorf("%s: opened as %+v", name, opened)
		}
	}
	// Five minutes of clock difference are tolerated, not more.
	if _, err := Open(good, server.key, "m1", time.Date(2026, 11, 15, 9, 56, 0, 0, time.UTC)); err != nil {
		t.Errorf("four minutes early: %v", err)
	}
}

func TestSaveThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if _, err := Load(path); !errors.Is(err, ErrNone) {
		t.Fatalf("Load before Save: %v", err)
	}
	server := newSigner('s', "k1")
	signed := server.sign(payload(nil))
	if err := Save(path, signed); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded != signed {
		t.Fatalf("Load = %+v, %v", loaded, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %04o", info.Mode().Perm())
	}
	// The file is not trusted: one changed on disk does not open.
	tampered := loaded
	tampered.Payload = strings.Replace(tampered.Payload, "research", "admin", 1)
	_ = Save(path, tampered)
	reloaded, _ := Load(path)
	if _, err := Open(reloaded, server.key, "m1", noon); err == nil {
		t.Error("a policy changed on disk was opened")
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("%d files next to the policy", len(entries))
	}
	_ = os.WriteFile(path, []byte("not json"), 0o600)
	if _, err := Load(path); err == nil || errors.Is(err, ErrNone) {
		t.Errorf("a broken file: %v", err)
	}
}
