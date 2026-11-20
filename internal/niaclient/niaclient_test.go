package niaclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func client(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	base, err := ParseBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{Base: base, HTTP: NewHTTPClient(5 * time.Second)}
}

var report = Report{Hostname: "vps-1", OS: "linux", Arch: "amd64", Version: "0.3.0"}

func TestEnroll(t *testing.T) {
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/edge/v1/enroll" || r.Header.Get("Authorization") != "Bearer nen_token" {
			t.Errorf("request %s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		if string(body) != `{"hostname":"vps-1","os":"linux","arch":"amd64","version":"0.3.0"}` {
			t.Errorf("body %s", body)
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"machine_id":"m1","key":"nia_key","key_expires_at":"2027-02-13T10:00:00.000Z","role":"research","upstream":"openai","heartbeat_seconds":30}`)
	})
	got, err := c.Enroll(context.Background(), "nen_token", report)
	if err != nil {
		t.Fatal(err)
	}
	if got.MachineID != "m1" || got.Key != "nia_key" || got.Role != "research" || got.HeartbeatSeconds != 30 || got.KeyExpiresAt.Year() != 2027 {
		t.Errorf("enrollment %+v", got)
	}
}

func TestARefusalNamesNiasReasonAndNotTheToken(t *testing.T) {
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":"invalid_enrollment_token","message":"This enrollment token cannot be used"}}`)
	})
	_, err := c.Enroll(context.Background(), "nen_very-secret", report)
	var refused *Refused
	if !errors.As(err, &refused) || refused.Status != 401 || refused.Code != "invalid_enrollment_token" {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(err.Error(), "nen_very-secret") {
		t.Errorf("the error carries the token: %v", err)
	}
}

func TestAnAnswerWithoutAKeyIsAnError(t *testing.T) {
	for _, answer := range []string{`{}`, `{"machine_id":"m1"}`, `not json`, ``} {
		c := client(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, answer)
		})
		if _, err := c.Enroll(context.Background(), "nen_token", report); err == nil {
			t.Errorf("answer %q was accepted", answer)
		}
	}
}

func TestAnUnreachableNiaIsAnErrorWithoutTheSecret(t *testing.T) {
	c := client(t, func(http.ResponseWriter, *http.Request) {})
	c.Base, _ = url.Parse("http://127.0.0.1:1")
	_, err := c.Heartbeat(context.Background(), "nia_very-secret", report, "")
	if err == nil || strings.Contains(err.Error(), "nia_very-secret") {
		t.Errorf("error %v", err)
	}
}

func TestARedirectIsNotFollowedWithTheKey(t *testing.T) {
	elsewhere := 0
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	defer other.Close()
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	if _, err := c.Heartbeat(context.Background(), "nia_key", report, ""); err == nil {
		t.Error("a redirect was taken for an answer")
	}
	if elsewhere != 0 {
		t.Error("the key followed a redirect to another host")
	}
}

func TestHeartbeat(t *testing.T) {
	var sent map[string]any
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/v1/heartbeat" || r.Header.Get("Authorization") != "Bearer nia_key" {
			t.Errorf("request %s %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&sent)
		fmt.Fprint(w, `{"machine_id":"m1","role":"research","role_in_policy":true,"policy":{"version":"file","digest":"abcdef0123456789"},"heartbeat_seconds":45,"server_time":"2026-11-15T10:00:00.000Z"}`)
	})
	beat, err := c.Heartbeat(context.Background(), "nia_key", report, "")
	if err != nil {
		t.Fatal(err)
	}
	if !beat.RoleInPolicy || beat.Policy == nil || beat.Policy.Digest != "abcdef0123456789" || string(beat.Policy.Version) != `"file"` || beat.HeartbeatSeconds != 45 {
		t.Errorf("beat %+v", beat)
	}
	// No host name in a heartbeat, and no digest when no policy is applied here.
	if _, has := sent["hostname"]; has || sent["policy_digest"] != nil || sent["os"] != "linux" {
		t.Errorf("heartbeat body %v", sent)
	}
	if _, err := c.Heartbeat(context.Background(), "nia_key", report, "abcdef0123456789"); err != nil {
		t.Fatal(err)
	}
	if _, has := sent["model_path"]; sent["policy_digest"] != "abcdef0123456789" || has {
		t.Errorf("heartbeat body %v", sent)
	}
	withPath := report
	withPath.ModelPath = "provider"
	if _, err := c.Heartbeat(context.Background(), "nia_key", withPath, ""); err != nil || sent["model_path"] != "provider" {
		t.Errorf("heartbeat body %v %v", sent, err)
	}
}

func TestParseBaseURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://nia.example":         true,
		"https://nia.example/":        true,
		"https://nia.example/base":    true,
		"http://localhost:8787":       true,
		"http://127.0.0.1:8787":       true,
		"http://[::1]:8787":           true,
		"http://nia:8787":             true,
		"http://nia.example":          false,
		"http://10.0.0.5:8787":        false,
		"ftp://nia.example":           false,
		"nia.example":                 false,
		"":                            false,
		"https://user:pw@nia.example": false,
		"https://nia.example?x=1":     false,
		"https://nia.example#x":       false,
	} {
		if _, err := ParseBaseURL(raw); (err == nil) != ok {
			t.Errorf("ParseBaseURL(%q): error %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestInventoryIsSentAsWrittenAndTakesNoAnswer(t *testing.T) {
	raw := []byte(`{"scanned_at":"2026-11-20T10:00:00Z","services":[],"etc":[],"truncated":false}`)
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/edge/v1/inventory" || r.Header.Get("Authorization") != "Bearer nia_key" || string(body) != string(raw) {
			t.Errorf("request %s %s %s", r.Method, r.URL.Path, body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.Inventory(context.Background(), "nia_key", raw); err != nil {
		t.Fatal(err)
	}
	refusing := client(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"code":"invalid_request","message":"no"}}`)
	})
	var refused *Refused
	if err := refusing.Inventory(context.Background(), "nia_key", raw); !errors.As(err, &refused) || refused.Code != "invalid_request" {
		t.Fatalf("got %v", err)
	}
}
