package hooks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/GetKlaros/nia-edge/internal/local"
)

type fakeNia struct {
	mu        sync.Mutex
	decided   []string
	ingested  []string
	sessions  []string
	allow     bool
	failing   bool
	ingestErr bool
}

func (f *fakeNia) Ingested(_ context.Context, session, tool string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ingestErr {
		return errors.New("down")
	}
	f.ingested = append(f.ingested, tool)
	f.sessions = append(f.sessions, session)
	return nil
}

func (f *fakeNia) Hosted(context.Context, string, []string) ([]string, error) { return nil, nil }

func (f *fakeNia) Decide(_ context.Context, session, tool, arguments string, _ []json.RawMessage) (local.Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decided = append(f.decided, tool+" "+arguments)
	f.sessions = append(f.sessions, session)
	if f.failing {
		return local.Verdict{}, errors.New("unreachable")
	}
	if f.allow {
		return local.Verdict{Allowed: true}, nil
	}
	return local.Verdict{Message: "held for a reviewer"}, nil
}

func (f *fakeNia) DecideHashed(context.Context, string, local.Hashed) (local.Verdict, bool, error) {
	return local.Verdict{}, true, nil
}

func post(t *testing.T, h *Handler, path, body string) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return recorder.Code, recorder.Body.String()
}

func TestBeforeAToolRuns(t *testing.T) {
	nia := &fakeNia{allow: true}
	h := &Handler{Nia: nia}
	code, body := post(t, h, "/v1/hooks/claude-code", `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	// Allowed: nothing said, the agent's own rules still apply.
	if code != 200 || body != "" {
		t.Fatalf("%d %q", code, body)
	}
	if nia.decided[0] != `Bash {"command":"ls"}` || nia.sessions[0] != "cc-s1" {
		t.Fatalf("%v %v", nia.decided, nia.sessions)
	}

	nia.allow = false
	_, body = post(t, h, "/v1/hooks/codex", `{"hook_event_name":"PreToolUse","session_id":"019a","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`)
	if !strings.Contains(body, `"permissionDecision":"deny"`) || !strings.Contains(body, "held for a reviewer") || nia.sessions[1] != "cx-019a" {
		t.Fatalf("a hold is a deny, never an ask: %s", body)
	}

	nia.failing = true
	_, body = post(t, h, "/v1/hooks/claude-code", `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{}}`)
	if !strings.Contains(body, `"permissionDecision":"deny"`) {
		t.Fatalf("Nia out of reach refuses: %s", body)
	}
	for _, unreadable := range []string{`not json`, `{"hook_event_name":"PreToolUse"}`, strings.Repeat("x", MaxPayload+10)} {
		if _, body := post(t, h, "/v1/hooks/claude-code", unreadable); !strings.Contains(body, `"deny"`) {
			t.Fatalf("unreadable must refuse: %s", body)
		}
	}
	// A session id Nia would not take is hashed, not passed on.
	nia.failing, nia.allow = false, true
	post(t, h, "/v1/hooks/claude-code", `{"hook_event_name":"PreToolUse","session_id":"../../x y","tool_name":"Read","tool_input":{}}`)
	if s := nia.sessions[len(nia.sessions)-1]; !strings.HasPrefix(s, "cc-") || strings.ContainsAny(s, "./ ") || len(s) != 35 {
		t.Fatal(s)
	}
}

func TestAfterAToolRan(t *testing.T) {
	nia := &fakeNia{}
	h := &Handler{Nia: nia}
	code, body := post(t, h, "/v1/hooks/claude-code", `{"hook_event_name":"PostToolUse","session_id":"s1","tool_name":"WebFetch","tool_input":{},"tool_response":{"text":"hello"}}`)
	if code != 200 || body != "" || nia.ingested[0] != "WebFetch" {
		t.Fatalf("%d %q %v", code, body, nia.ingested)
	}
	secret := `{"stdout":"key=AKIAIOSFODNN7EXAMPLE and ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	_, body = post(t, h, "/v1/hooks/claude-code", `{"hook_event_name":"PostToolUse","session_id":"s1","tool_name":"Bash","tool_input":{},"tool_response":`+secret+`}`)
	if !strings.Contains(body, "updatedToolOutput") || strings.Contains(body, "ghp_aaaa") {
		t.Fatalf("a secret is redacted before the model sees it: %s", body)
	}
	// Codex replaces an MCP tool's output only: another tool's turn stops.
	_, body = post(t, h, "/v1/hooks/codex", `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash","tool_input":{},"tool_response":`+secret+`}`)
	if !strings.Contains(body, `"continue":false`) || strings.Contains(body, "ghp_aaaa") {
		t.Fatalf("%s", body)
	}
	_, body = post(t, h, "/v1/hooks/codex", `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"mcp__docs__get","tool_input":{},"tool_response":`+secret+`}`)
	if !strings.Contains(body, "updatedMCPToolOutput") || strings.Contains(body, "ghp_aaaa") {
		t.Fatalf("%s", body)
	}
	// Nia could not record what the session now holds: withheld.
	nia.ingestErr = true
	_, body = post(t, h, "/v1/hooks/claude-code", `{"hook_event_name":"PostToolUse","session_id":"s1","tool_name":"WebFetch","tool_input":{},"tool_response":{"text":"page"}}`)
	if !strings.Contains(body, `"decision":"block"`) || strings.Contains(body, "page") {
		t.Fatalf("%s", body)
	}
}

func TestRoutes(t *testing.T) {
	if Route("/v1/hooks/claude-code") != ClaudeCode || Route("/v1/hooks/codex") != Codex || Route("/v1/hooks/other") != "" {
		t.Fatal("routes")
	}
	recorder := httptest.NewRecorder()
	(&Handler{Nia: &fakeNia{}}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/hooks/codex", nil))
	if recorder.Code != 404 {
		t.Fatal(recorder.Code)
	}
}
