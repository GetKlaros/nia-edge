package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/niaclient"
	"github.com/GetKlaros/nia-edge/internal/policy"
)

// signer is a server's signing key, for the tests.
type signer struct {
	private ed25519.PrivateKey
	key     policy.Key
}

func newSigner(t *testing.T, seedByte byte) signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	sum := sha256.Sum256([]byte(public))
	return signer{private: private, key: policy.Key{ID: hex.EncodeToString(sum[:])[:16], Alg: "ed25519", PublicKey: public}}
}

func (s signer) sign(machine, digest string, issued time.Time, life time.Duration) policy.Signed {
	payload := fmt.Sprintf(`{"dispatchers":[],"issued_at":%q,"key_id":%q,"machine_id":%q,"not_after":%q,"policy":{"digest":%q,"version":3},"role":{"name":"research"},"tenant_id":"t1","v":1}`,
		issued.UTC().Format(time.RFC3339), s.key.ID, machine, issued.Add(life).UTC().Format(time.RFC3339), digest)
	return policy.Signed{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, []byte(payload))), KeyID: s.key.ID, Alg: "ed25519"}
}

// policyServer serves /edge/v1/policy with whatever the test sets.
type policyServer struct {
	*httptest.Server
	mu      sync.Mutex
	answer  *policy.Signed
	fetches int
}

func newPolicyServer(t *testing.T) (*policyServer, *niaclient.Client) {
	t.Helper()
	server := &policyServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		if r.URL.Path != "/edge/v1/policy" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer nia_key1" {
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		}
		server.fetches++
		if server.answer == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"code":"signing_not_configured","message":"no key"}}`)
			return
		}
		_ = json.NewEncoder(w).Encode(server.answer)
	}))
	t.Cleanup(server.Close)
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return server, &niaclient.Client{Base: base, HTTP: niaclient.NewHTTPClient(5 * time.Second)}
}

func (s *policyServer) set(answer *policy.Signed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answer = answer
}

func (s *policyServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func beatFor(keyID, digest string) *niaclient.Beat {
	return &niaclient.Beat{MachineID: "m1", RoleInPolicy: true, PolicyKeyID: keyID, Policy: &niaclient.Policy{Version: json.RawMessage("3"), Digest: digest}}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestThePolicyIsFetchedVerifiedKeptAndReadBack(t *testing.T) {
	server, client := newPolicyServer(t)
	nia := newSigner(t, 1)
	path := filepath.Join(t.TempDir(), "policy.json")
	keep := &keeper{path: path, key: &nia.key, machineID: "m1"}
	keep.load(quiet)
	if keep.valid(time.Now()) != nil || !strings.Contains(keep.status(), "not fetched yet") {
		t.Fatalf("a policy before any was fetched: %s", keep.status())
	}

	signed := nia.sign("m1", "d1", time.Now(), 24*time.Hour)
	server.set(&signed)
	if !keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet) {
		t.Fatal("a first policy did not change the one in force")
	}
	if current := keep.valid(time.Now()); current == nil || current.Digest != "d1" || current.Version != "3" {
		t.Fatalf("policy in force: %+v", current)
	}
	// Same digest, young policy: nothing is asked of the server.
	if keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet) || server.count() != 1 {
		t.Fatalf("fetched again without a reason: %d fetches", server.count())
	}
	// The server names another digest: fetched again.
	next := nia.sign("m1", "d2", time.Now(), 24*time.Hour)
	server.set(&next)
	if !keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d2"), quiet) || keep.valid(time.Now()).Digest != "d2" {
		t.Fatal("the new policy is not in force")
	}

	// Another process reads it back from disk, verified.
	again := &keeper{path: path, key: &nia.key, machineID: "m1"}
	again.load(quiet)
	if current := again.valid(time.Now()); current == nil || current.Digest != "d2" {
		t.Fatalf("read back: %s", again.status())
	}
	// Not for another machine, not under another key.
	other := &keeper{path: path, key: &nia.key, machineID: "m2"}
	other.load(quiet)
	stranger := newSigner(t, 2)
	rekeyed := &keeper{path: path, key: &stranger.key, machineID: "m1"}
	rekeyed.load(quiet)
	if other.valid(time.Now()) != nil || rekeyed.valid(time.Now()) != nil {
		t.Fatal("a policy on disk was accepted for another machine or another key")
	}
}

func TestAPolicyPastHalfItsLifeIsRenewed(t *testing.T) {
	server, client := newPolicyServer(t)
	nia := newSigner(t, 1)
	keep := &keeper{path: filepath.Join(t.TempDir(), "policy.json"), key: &nia.key, machineID: "m1"}
	old := nia.sign("m1", "d1", time.Now().Add(-13*time.Hour), 24*time.Hour)
	server.set(&old)
	keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet)
	fresh := nia.sign("m1", "d1", time.Now(), 24*time.Hour)
	server.set(&fresh)
	if keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet) {
		t.Fatal("the same digest was reported as a change")
	}
	if server.count() != 2 || time.Until(keep.valid(time.Now()).NotAfter) < 23*time.Hour {
		t.Fatalf("not renewed: %d fetches, %s", server.count(), keep.status())
	}
}

func TestAPolicyThatIsNotTheServersIsNeverInForce(t *testing.T) {
	server, client := newPolicyServer(t)
	nia := newSigner(t, 1)
	stranger := newSigner(t, 2)
	good := nia.sign("m1", "d1", time.Now(), 24*time.Hour)
	tampered := good
	tampered.Payload = strings.Replace(good.Payload, `"research"`, `"admin"`, 1)
	forged := stranger.sign("m1", "d1", time.Now(), 24*time.Hour)
	relabelled := forged
	relabelled.KeyID = nia.key.ID
	cases := map[string]policy.Signed{
		"changed after signing":   tampered,
		"signed by another key":   forged,
		"another key, relabelled": relabelled,
		"for another machine":     nia.sign("m2", "d1", time.Now(), 24*time.Hour),
		"expired":                 nia.sign("m1", "d1", time.Now().Add(-25*time.Hour), 24*time.Hour),
		"from the future":         nia.sign("m1", "d1", time.Now().Add(time.Hour), 24*time.Hour),
		"valid for too long":      nia.sign("m1", "d1", time.Now(), 30*24*time.Hour),
	}
	for name, signed := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			keep := &keeper{path: path, key: &nia.key, machineID: "m1"}
			server.set(&signed)
			if keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet) || keep.valid(time.Now()) != nil {
				t.Fatalf("in force: %s", keep.status())
			}
			if _, err := policy.Load(path); err != policy.ErrNone {
				t.Fatalf("a refused policy was kept on disk: %v", err)
			}
		})
	}
}

func TestAServerThatChangedItsKeyIsNotFollowed(t *testing.T) {
	server, client := newPolicyServer(t)
	nia := newSigner(t, 1)
	stranger := newSigner(t, 2)
	keep := &keeper{path: filepath.Join(t.TempDir(), "policy.json"), key: &nia.key, machineID: "m1"}
	signed := nia.sign("m1", "d1", time.Now(), 24*time.Hour)
	server.set(&signed)
	keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet)
	forged := stranger.sign("m1", "d2", time.Now(), 24*time.Hour)
	server.set(&forged)
	if keep.refresh(context.Background(), client, "nia_key1", beatFor(stranger.key.ID, "d2"), quiet) {
		t.Fatal("the policy changed")
	}
	if server.count() != 1 || keep.valid(time.Now()).Digest != "d1" || !strings.Contains(keep.status(), "enroll again") {
		t.Fatalf("%d fetches, %s", server.count(), keep.status())
	}
}

func TestAnUnreachableServerLeavesThePolicyUntilItExpires(t *testing.T) {
	server, client := newPolicyServer(t)
	nia := newSigner(t, 1)
	keep := &keeper{path: filepath.Join(t.TempDir(), "policy.json"), key: &nia.key, machineID: "m1"}
	signed := nia.sign("m1", "d1", time.Now().Add(-13*time.Hour), 24*time.Hour)
	server.set(&signed)
	keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet)
	server.set(nil)
	if keep.refresh(context.Background(), client, "nia_key1", beatFor(nia.key.ID, "d1"), quiet) {
		t.Fatal("a failure changed the policy")
	}
	if current := keep.valid(time.Now()); current == nil || current.Digest != "d1" {
		t.Fatal("the policy in force was dropped before its end")
	}
	if !strings.Contains(keep.status(), "not refreshed") {
		t.Fatalf("status hides the failure: %s", keep.status())
	}
	if keep.valid(time.Now().Add(12*time.Hour)) != nil || !strings.Contains(keep.status(), "none (expired)") {
		t.Fatalf("still in force after its end: %s", keep.status())
	}
}

func TestAServerThatSignsNothingMeansNoPolicy(t *testing.T) {
	server, client := newPolicyServer(t)
	keep := &keeper{path: filepath.Join(t.TempDir(), "policy.json"), machineID: "m1"}
	keep.load(quiet)
	if keep.refresh(context.Background(), client, "nia_key1", beatFor("", "d1"), quiet) || server.count() != 0 || keep.valid(time.Now()) != nil {
		t.Fatalf("%d fetches, %s", server.count(), keep.status())
	}
}
