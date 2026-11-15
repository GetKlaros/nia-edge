package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func remote(t *testing.T, handler http.HandlerFunc) *Remote {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL)
	return &Remote{Base: base, Key: "nia_machine", HTTP: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

var sample = Request{Session: "edge-host", Run: "run-1", Host: "example.com", Port: 443, Method: "CONNECT", URL: "https://example.com:443/"}

func TestDecideAsksNiaAboutTheEgressTool(t *testing.T) {
	var body map[string]any
	var header http.Header
	r := remote(t, func(w http.ResponseWriter, request *http.Request) {
		header = request.Header.Clone()
		raw, _ := io.ReadAll(request.Body)
		_ = json.Unmarshal(raw, &body)
		if request.URL.Path != "/v1/tools/decide" {
			t.Errorf("path %s", request.URL.Path)
		}
		fmt.Fprint(w, `{"decision":"allow","reason":"allowed"}`)
	})
	r.Wait = 30
	verdict, err := r.Decide(context.Background(), sample)
	if err != nil || !verdict.Allowed {
		t.Fatalf("verdict %+v, error %v", verdict, err)
	}
	if header.Get("Authorization") != "Bearer nia_machine" || header.Get("X-Nia-Session-Id") != "edge-host" || header.Get("X-Nia-Run-Id") != "run-1" {
		t.Errorf("headers %v", header)
	}
	arguments, _ := body["arguments"].(map[string]any)
	if body["tool"] != "egress" || body["wait"] != float64(30) || arguments["host"] != "example.com" || arguments["port"] != float64(443) || arguments["method"] != "CONNECT" || arguments["url"] != "https://example.com:443/" {
		t.Errorf("body %v", body)
	}
}

func TestOnlyAnExplicitAllowAllows(t *testing.T) {
	for answer, want := range map[string]Verdict{
		`{"decision":"allow"}`:                                                 {Allowed: true},
		`{"decision":"deny","message":"denied"}`:                               {Message: "denied"},
		`{"decision":"require_approval","message":"held","approval_id":"ap1"}`: {Held: true, Message: "held", ApprovalID: "ap1"},
	} {
		r := remote(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, answer) })
		if got, err := r.Decide(context.Background(), sample); err != nil || got != want {
			t.Errorf("%s: %+v, %v", answer, got, err)
		}
	}
	// None of these is a decision: each refuses the connection.
	for _, answer := range []string{`{}`, `{"decision":"ALLOW"}`, `{"decision":"allowed"}`, `{"decision":true}`, `{"decision":""}`, `allow`, ``, `{"decision":"allow"`, `[]`, `null`} {
		r := remote(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, answer) })
		if got, err := r.Decide(context.Background(), sample); err == nil || got.Allowed {
			t.Errorf("answer %q: %+v, %v", answer, got, err)
		}
	}
	for _, status := range []int{201, 204, 302, 400, 401, 403, 429, 500, 502} {
		r := remote(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(status)
			fmt.Fprint(w, `{"decision":"allow"}`)
		})
		if got, err := r.Decide(context.Background(), sample); err == nil || got.Allowed {
			t.Errorf("status %d: %+v, %v", status, got, err)
		}
	}
}

func TestConnectedMustBeRecorded(t *testing.T) {
	var body map[string]any
	r := remote(t, func(w http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		_ = json.Unmarshal(raw, &body)
		if request.URL.Path != "/v1/tools/result" {
			t.Errorf("path %s", request.URL.Path)
		}
		fmt.Fprint(w, `{"action":"allow","output":"connection to example.com:443"}`)
	})
	if err := r.Connected(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if body["tool"] != "egress" || body["output"] != "connection to example.com:443" {
		t.Errorf("body %v", body)
	}
	failing := remote(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	if err := failing.Connected(context.Background(), sample); err == nil {
		t.Error("an unrecorded connection was accepted")
	}
}

func TestAnUnreachableNiaIsAnErrorWithoutTheKey(t *testing.T) {
	r := remote(t, func(http.ResponseWriter, *http.Request) {})
	r.Base, _ = url.Parse("http://127.0.0.1:1")
	_, err := r.Decide(context.Background(), sample)
	if err == nil || strings.Contains(err.Error(), "nia_machine") {
		t.Errorf("error %v", err)
	}
}
