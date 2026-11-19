package hooks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GetKlaros/nia-edge/internal/engine"
	"github.com/GetKlaros/nia-edge/internal/local"
)

func simulatingRules(t *testing.T) func() *local.Rules {
	t.Helper()
	role, err := engine.ParseRole(json.RawMessage(`{"name":"dev","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[{"name":"*","when_untrusted":"allow","output":"untrusted","sensitive":false,"effect":"none"}],"simulate":{"max_deleted":20,"protected":["(^|/)\\.ssh(/|$)"],"timeout_seconds":60}}`))
	if err != nil {
		t.Fatal(err)
	}
	return func() *local.Rules { return &local.Rules{Role: role, Digest: "0123456789abcdef"} }
}

func call(h *Handler, method, path, body string) (int, string) {
	recorder := httptest.NewRecorder()
	h.ServeSimulation(recorder, httptest.NewRequest(method, path, strings.NewReader(body)))
	return recorder.Code, recorder.Body.String()
}

func TestAnAllowedCommandIsSimulated(t *testing.T) {
	nia := &fakeNia{allow: true}
	h := &Handler{Nia: nia, Rules: simulatingRules(t), Simulations: &Tickets{}}
	for agent, want := range map[string]string{"pi": `"input"`, "opencode": `"input"`, "codex": `"updatedInput"`, "claude-code": `"updatedInput"`, "gemini-cli": `"tool_input"`} {
		tool := map[string]string{"pi": "bash", "opencode": "bash", "codex": "Bash", "claude-code": "Bash", "gemini-cli": "run_shell_command"}[agent]
		event := map[string]string{"pi": "tool_call", "opencode": "tool_call", "codex": "PreToolUse", "claude-code": "PreToolUse", "gemini-cli": "BeforeTool"}[agent]
		_, body := post(t, h, "/v1/hooks/"+agent, `{"hook_event_name":"`+event+`","session_id":"s","tool_name":"`+tool+`","tool_input":{"command":"rm -rf projet","timeout":5}}`)
		if !strings.Contains(body, want) || !strings.Contains(body, SimulateCommand) || !strings.Contains(body, `"timeout":5`) {
			t.Fatalf("%s: %s", agent, body)
		}
		// Claude Code: no permissionDecision, its own permissions decide.
		if agent == "claude-code" && strings.Contains(body, "permissionDecision") {
			t.Fatalf("%s: %s", agent, body)
		}
	}
	// Another tool is not rewritten; a command that cannot be read is refused.
	if _, body := post(t, h, "/v1/hooks/pi", `{"hook_event_name":"tool_call","session_id":"s","tool_name":"read","tool_input":{"path":"a"}}`); body != "" {
		t.Fatal(body)
	}
	if _, body := post(t, h, "/v1/hooks/claude-code", `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":7}}`); !strings.Contains(body, `"deny"`) {
		t.Fatal(body)
	}

	_, body := post(t, h, "/v1/hooks/pi", `{"hook_event_name":"tool_call","session_id":"s","tool_name":"bash","tool_input":{"command":"rm -rf projet"}}`)
	var answer struct {
		Input struct {
			Command string `json:"command"`
		} `json:"input"`
	}
	json.Unmarshal([]byte(body), &answer)
	id := strings.TrimPrefix(answer.Input.Command, SimulateCommand)
	// The effect before the command: refused.
	if code, _ := call(h, http.MethodPost, "/v1/simulate/"+id+"/effect", `{"deleted":0,"paths":[]}`); code != 404 {
		t.Fatal(code)
	}
	code, got := call(h, http.MethodGet, "/v1/simulate/"+id, "")
	if code != 200 || !strings.Contains(got, `"command":"rm -rf projet"`) || !strings.Contains(got, `"timeout_seconds":60`) {
		t.Fatal(code, got)
	}
	// Once only.
	if code, _ := call(h, http.MethodGet, "/v1/simulate/"+id, ""); code != 404 {
		t.Fatal(code)
	}
	// 302 files deleted: held by the role, whatever the command looked like.
	nia.allow = false
	if _, got := call(h, http.MethodPost, "/v1/simulate/"+id+"/effect", `{"deleted":302,"paths":["/home/dev/projet"]}`); !strings.Contains(got, `"allowed":false`) {
		t.Fatal(got)
	}
	if last := nia.decided[len(nia.decided)-1]; last != `nia:effect {"deleted":302,"paths":["/home/dev/projet"]}` {
		t.Fatal(last)
	}
	// The ticket is spent.
	if code, _ := call(h, http.MethodPost, "/v1/simulate/"+id+"/effect", `{"deleted":0,"paths":[]}`); code != 404 {
		t.Fatal(code)
	}
	// Without a role that simulates, nothing is rewritten.
	plain := &Handler{Nia: &fakeNia{allow: true}, Simulations: &Tickets{}}
	if _, body := post(t, plain, "/v1/hooks/pi", `{"hook_event_name":"tool_call","session_id":"s","tool_name":"bash","tool_input":{"command":"ls"}}`); body != "" {
		t.Fatal(body)
	}
}
