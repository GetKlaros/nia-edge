package hostmcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/hostd"
	"github.com/GetKlaros/nia-edge/internal/local"
)

type fakeHost struct {
	asked []hostd.Request
	down  bool
}

func (f *fakeHost) Do(_ context.Context, req hostd.Request) (hostd.Response, error) {
	if f.down {
		return hostd.Response{}, errors.New("down")
	}
	f.asked = append(f.asked, req)
	return hostd.Response{OK: true, Output: "restarted", Journal: "j1"}, nil
}

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func setup() (*Handler, *fakeHost, *local.Releases) {
	host := &fakeHost{}
	releases := &local.Releases{Prefix: "mcp__host__"}
	return &Handler{
		Catalogue: func() (*hostd.Catalogue, error) {
			return &hostd.Catalogue{Services: []string{"nginx"}, Sync: []hostd.SyncPair{{Name: "site", Source: "/a", Destination: "/b"}}}, nil
		},
		Releases: releases, Host: host, Version: "test", Now: func() time.Time { return now },
	}, host, releases
}

func rpc(t *testing.T, h http.Handler, body string, headers ...string) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/host/mcp", strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	var answer map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &answer)
	return recorder.Code, answer
}

func TestItSpeaksMCPAndListsTheCatalogue(t *testing.T) {
	h, _, _ := setup()
	if code, answer := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`); code != 200 || answer["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("%d %v", code, answer)
	}
	if code, _ := rpc(t, h, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != http.StatusAccepted {
		t.Errorf("notification: %d", code)
	}
	_, answer := rpc(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	listed, _ := json.Marshal(answer["result"])
	for _, want := range []string{`"service_restart"`, `"enum":["nginx"]`, `"sync"`, `"enum":["site"]`} {
		if !strings.Contains(string(listed), want) {
			t.Errorf("tools/list lacks %s: %s", want, listed)
		}
	}
	// No package in the catalogue: no tool to install one.
	if strings.Contains(string(listed), "package_install") {
		t.Errorf("an empty kind is listed: %s", listed)
	}
	if code, _ := rpc(t, h, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, "Origin", "https://evil.example"); code != http.StatusForbidden {
		t.Errorf("a foreign origin: %d", code)
	}
}

func TestACallRunsOnlyAgainstItsReleaseOnce(t *testing.T) {
	h, host, releases := setup()
	call := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"service_restart","arguments":{"service":"nginx"}}}`
	_, answer := rpc(t, h, call)
	if result := answer["result"].(map[string]any); result["isError"] != true || len(host.asked) != 0 {
		t.Fatalf("ran without a release: %v", answer)
	}
	// Released with the same arguments, written another way.
	releases.Release("mcp__host__service_restart", `{ "service" : "nginx" }`, now)
	_, answer = rpc(t, h, call)
	if result := answer["result"].(map[string]any); result["isError"] != false || len(host.asked) != 1 || host.asked[0] != (hostd.Request{Action: hostd.ServiceRestart, Name: "nginx"}) {
		t.Fatalf("%v %v", answer, host.asked)
	}
	// Once.
	_, answer = rpc(t, h, call)
	if answer["result"].(map[string]any)["isError"] != true || len(host.asked) != 1 {
		t.Errorf("a release ran twice: %v", answer)
	}
	// Another argument, another tool, or an expired release: nothing.
	releases.Release("mcp__host__service_restart", `{"service":"sshd"}`, now)
	releases.Release("mcp__host__service_reload", `{"service":"nginx"}`, now)
	releases.Release("mcp__host__service_restart", `{"service":"nginx"}`, now.Add(-time.Hour))
	_, answer = rpc(t, h, call)
	if answer["result"].(map[string]any)["isError"] != true || len(host.asked) != 1 {
		t.Errorf("ran on another release: %v", answer)
	}
	// nia-hostd out of reach: nothing ran, and the agent is told.
	host.down = true
	releases.Release("mcp__host__service_restart", `{"service":"nginx"}`, now)
	_, answer = rpc(t, h, call)
	if text, _ := json.Marshal(answer); answer["result"].(map[string]any)["isError"] != true || !strings.Contains(string(text), "nothing ran") {
		t.Errorf("%s", text)
	}
}
