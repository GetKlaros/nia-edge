package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func runHook(t *testing.T, edge, payload string) (int, string) {
	t.Helper()
	var out, errs bytes.Buffer
	env := func(name string) string {
		if name == "NIA_EDGE_URL" {
			return edge
		}
		return ""
	}
	code := run(context.Background(), []string{"hook", "codex"}, env, strings.NewReader(payload), &out, &errs)
	return code, out.String()
}

func TestHookCommandRefusesWhateverFails(t *testing.T) {
	// nia-edge not there: Codex lets a call through when its hook fails, so
	// the hook itself answers deny, and exits 0.
	code, out := runHook(t, "http://127.0.0.1:1", `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Fatalf("%d %s", code, out)
	}
	code, out = runHook(t, "http://127.0.0.1:1", `{"hook_event_name":"PostToolUse","tool_name":"Bash"}`)
	if code != 0 || !strings.Contains(out, `"continue":false`) {
		t.Fatalf("%d %s", code, out)
	}
	for _, answer := range []struct {
		status int
		body   string
	}{{500, ""}, {200, "not json"}, {302, ""}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if answer.status == 302 {
				w.Header().Set("Location", "http://example.com/")
			}
			w.WriteHeader(answer.status)
			io.WriteString(w, answer.body)
		}))
		_, out := runHook(t, server.URL, `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
		server.Close()
		if !strings.Contains(out, `"deny"`) {
			t.Fatalf("%d %q: %s", answer.status, answer.body, out)
		}
	}
}

func TestHookCommandPassesNiaEdgesAnswer(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = r.URL.Path + " " + string(raw)
		if strings.Contains(string(raw), "allowed") {
			return
		}
		io.WriteString(w, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no"}}`)
	}))
	defer server.Close()
	_, out := runHook(t, server.URL, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x"}}`)
	if got != `/v1/hooks/codex {"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x"}}` || !strings.Contains(out, `"reason`) && !strings.Contains(out, "permissionDecisionReason") {
		t.Fatalf("%s | %s", got, out)
	}
	if _, out := runHook(t, server.URL, `{"hook_event_name":"PreToolUse","tool_name":"allowed"}`); out != "" {
		t.Fatalf("allowed answers nothing: %q", out)
	}
}

func TestGeminiHookCommand(t *testing.T) {
	run1 := func(base, payload string) (int, string) {
		var out, errs bytes.Buffer
		env := func(name string) string {
			if name == "NIA_EDGE_URL" {
				return base
			}
			return ""
		}
		code := run(context.Background(), []string{"hook", "gemini-cli"}, env, strings.NewReader(payload), &out, &errs)
		return code, out.String()
	}
	// Gemini CLI lets a call through when its hook fails: the hook answers deny.
	for _, event := range []string{"BeforeTool", "AfterTool"} {
		code, out := run1("http://127.0.0.1:1", `{"hook_event_name":"`+event+`","tool_name":"run_shell_command"}`)
		if code != 0 || !strings.Contains(out, `"decision":"deny"`) {
			t.Fatalf("%s: %d %s", event, code, out)
		}
	}
	// Allowed: nia-edge says nothing, Gemini CLI reads an empty object.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	if code, out := run1(server.URL, `{"hook_event_name":"BeforeTool","tool_name":"read_file"}`); code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("%d %q", code, out)
	}
}
