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

func TestItSpeaksMCPAndListsTheFiveActionsAlways(t *testing.T) {
	h, _, _ := setup()
	if code, answer := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`); code != 200 || answer["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("%d %v", code, answer)
	}
	if code, _ := rpc(t, h, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != http.StatusAccepted {
		t.Errorf("notification: %d", code)
	}
	_, answer := rpc(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	listed, _ := json.Marshal(answer["result"])
	for _, want := range []string{`"service_status"`, `"service_restart"`, `"service_reload"`, `"package_install"`, `"sync"`, `"readOnlyHint":true`} {
		if !strings.Contains(string(listed), want) {
			t.Errorf("tools/list lacks %s: %s", want, listed)
		}
	}
	// The list does not follow the catalogue: an agent keeps what it listed.
	h.Catalogue = func() (*hostd.Catalogue, error) { return nil, errors.New("no catalogue") }
	_, again := rpc(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if relisted, _ := json.Marshal(again["result"]); string(relisted) != string(listed) {
		t.Errorf("the list changed with the catalogue: %s", relisted)
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
	// A name outside the catalogue, even released: refused, with the names allowed.
	releases.Release("mcp__host__service_restart", `{"service":"sshd"}`, now)
	_, answer = rpc(t, h, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"service_restart","arguments":{"service":"sshd"}}}`)
	if text, _ := json.Marshal(answer); answer["result"].(map[string]any)["isError"] != true || len(host.asked) != 1 || !strings.Contains(string(text), "accepts: nginx") {
		t.Errorf("ran outside the catalogue: %s", text)
	}
	_, answer = rpc(t, h, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"package_install","arguments":{"package":"curl"}}}`)
	if text, _ := json.Marshal(answer); answer["result"].(map[string]any)["isError"] != true || !strings.Contains(string(text), "allows no package") {
		t.Errorf("a kind without names: %s", text)
	}
	// nia-hostd out of reach: nothing ran, and the agent is told.
	host.down = true
	releases.Release("mcp__host__service_restart", `{"service":"nginx"}`, now)
	_, answer = rpc(t, h, call)
	if text, _ := json.Marshal(answer); answer["result"].(map[string]any)["isError"] != true || !strings.Contains(string(text), "nothing ran") {
		t.Errorf("%s", text)
	}
}

func TestADryRunTakesAScriptOnlyWithEtcInTheCatalogue(t *testing.T) {
	h, host, releases := setup()
	call := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"dry_run","arguments":{"script":"echo x > /etc/motd"}}}`
	releases.Release("mcp__host__dry_run", `{"script":"echo x > /etc/motd"}`, now)
	_, answer := rpc(t, h, call)
	if text, _ := json.Marshal(answer); answer["result"].(map[string]any)["isError"] != true || len(host.asked) != 0 || !strings.Contains(string(text), "no dry run") {
		t.Errorf("without etc: %s", text)
	}
	h.Catalogue = func() (*hostd.Catalogue, error) { return &hostd.Catalogue{Etc: &hostd.EtcRules{}}, nil }
	_, answer = rpc(t, h, call)
	if answer["result"].(map[string]any)["isError"] != false || len(host.asked) != 1 || host.asked[0] != (hostd.Request{Action: hostd.DryRunAction, Script: "echo x > /etc/motd"}) {
		t.Errorf("%v %+v", answer, host.asked)
	}
	releases.Release("mcp__host__apply", `{"plan":"p1"}`, now)
	_, answer = rpc(t, h, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"apply","arguments":{"plan":"p1"}}}`)
	if answer["result"].(map[string]any)["isError"] != false || len(host.asked) != 2 || host.asked[1] != (hostd.Request{Action: hostd.ApplyAction, Name: "p1"}) {
		t.Errorf("%v %+v", answer, host.asked)
	}
}

func TestDescribeReport(t *testing.T) {
	report, _ := json.Marshal(hostd.Report{
		Plan: "p1",
		Changes: []hostd.Change{
			{Path: "/etc/motd", Kind: "modified", Type: "file", Mode: 0o644, Size: 2},
			{Path: "/etc/old", Kind: "deleted"},
		},
		Guards:      []hostd.Finding{{Guard: "cron", Detail: "created /etc/cron.d/x: this runs commands"}},
		SecretsRead: []string{"/etc/shadow"}, Protected: []string{}, SecretsChanged: []string{}, SecretsCopied: []string{"/etc/shadow"},
		Output: "hi\n",
	})
	text := DescribeReport(string(report))
	for _, want := range []string{"plan p1", "was not changed", "not changed.", "- modified /etc/motd (file, 2 bytes, 0644 0:0)", "- deleted /etc/old", "Refused by the cron guard: created /etc/cron.d/x", "Secrets read (the run saw decoys, not the secrets): /etc/shadow", "cannot be applied", "Output:\nhi"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
}
