package local

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/canon"
	"github.com/GetKlaros/nia-edge/internal/engine"
	"github.com/GetKlaros/nia-edge/internal/turn"
)

// fakeNia records what it is told and answers from a table.
type fakeNia struct {
	mu            sync.Mutex
	ingested      []string
	asked         []string
	verdicts      map[string]Verdict
	hostedAsked   []string
	hostedAllowed []string
	down          bool
	// hashed are the calls decided on the machine; tainted picks the
	// decision as Nia's session state would, and wantArguments asks for them.
	hashed        []Hashed
	tainted       bool
	wantArguments bool
	reviews       []json.RawMessage
}

func (n *fakeNia) DecideHashed(_ context.Context, _ string, call Hashed) (Verdict, bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return Verdict{}, false, errors.New("down")
	}
	n.hashed = append(n.hashed, call)
	if n.wantArguments {
		return Verdict{}, true, nil
	}
	picked := call.Clean
	if n.tainted {
		picked = call.Tainted
	}
	if picked.Decision == engine.Allow {
		return Verdict{Allowed: true}, false, nil
	}
	return Verdict{Message: picked.Decision + " " + picked.Reason}, false, nil
}

func (n *fakeNia) Ingested(_ context.Context, session, tool string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return errors.New("down")
	}
	n.ingested = append(n.ingested, session+" "+tool)
	return nil
}

func (n *fakeNia) Hosted(_ context.Context, session string, tools []string) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return nil, errors.New("down")
	}
	n.hostedAsked = append(n.hostedAsked, strings.Join(tools, ","))
	return n.hostedAllowed, nil
}

func (n *fakeNia) Decide(_ context.Context, session, tool, arguments string, reviews []json.RawMessage) (Verdict, error) {
	n.reviews = append(n.reviews, reviews...)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return Verdict{}, errors.New("down")
	}
	n.asked = append(n.asked, tool+" "+arguments)
	if verdict, ok := n.verdicts[tool]; ok {
		return verdict, nil
	}
	return Verdict{Allowed: true}, nil
}

type provider struct {
	*httptest.Server
	mu          sync.Mutex
	calls       int
	lastBody    string
	lastHeaders http.Header
	lastPath    string
	answer      string
	contentType string
	status      int
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	p := &provider{status: 200, contentType: "application/json"}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.calls++
		p.lastBody, p.lastHeaders, p.lastPath = string(raw), r.Header.Clone(), r.URL.Path
		w.Header().Set("Content-Type", p.contentType)
		w.WriteHeader(p.status)
		_, _ = io.WriteString(w, p.answer)
	}))
	t.Cleanup(p.Close)
	return p
}

func setup(t *testing.T) (*Handler, *provider, *fakeNia) {
	t.Helper()
	p := newProvider(t)
	base, _ := url.Parse(p.URL + "/v1")
	nia := &fakeNia{verdicts: map[string]Verdict{}}
	return &Handler{Provider: base, Key: "provider-secret", HTTP: NewProviderClient(10 * time.Second), Nia: nia}, p, nia
}

func post(h *Handler, path, body string, headers ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer the-agents-own-key")
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	return recorder
}

const chatCall = `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"terminal","arguments":"{\"command\":\"ls\"}"}}]}}]}`

func TestAnAllowedTurnIsReleasedAsTheProviderSentIt(t *testing.T) {
	h, p, nia := setup(t)
	p.answer = chatCall
	got := post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"list files"}]}`, "Openai-Beta", "x")
	if got.Code != 200 || got.Body.String() != chatCall {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if p.lastPath != "/v1/chat/completions" || p.lastHeaders.Get("Authorization") != "Bearer provider-secret" || p.lastHeaders.Get("Openai-Beta") != "x" {
		t.Errorf("the provider got %s with %v", p.lastPath, p.lastHeaders)
	}
	if strings.Contains(p.lastBody+p.lastHeaders.Get("Authorization"), "the-agents-own-key") {
		t.Error("the agent's own key reached the provider")
	}
	if len(nia.asked) != 1 || nia.asked[0] != `terminal {"command":"ls"}` || len(nia.ingested) != 0 {
		t.Errorf("Nia was asked %v, told %v", nia.asked, nia.ingested)
	}
}

func TestARefusedCallIsReplacedByWhatNiaSays(t *testing.T) {
	for _, c := range []struct {
		path, body, answer, contentType string
		format                          turn.Format
		stream                          bool
	}{
		{"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"x"}]}`, chatCall, "application/json", turn.ChatCompletions, false},
		{"/v1/chat/completions", `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"function\":{\"name\":\"terminal\",\"arguments\":\"{}\"}}]}}]}\n\ndata: [DONE]\n\n", "text/event-stream", turn.ChatCompletions, true},
		{"/v1/messages", `{"model":"m","messages":[{"role":"user","content":"x"}]}`, `{"content":[{"type":"tool_use","id":"t","name":"terminal","input":{}}]}`, "application/json", turn.AnthropicMessages, false},
		{"/v1/messages", `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`, "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"terminal\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n", "text/event-stream", turn.AnthropicMessages, true},
		{"/v1/responses", `{"model":"m","input":"x"}`, `{"output":[{"type":"function_call","call_id":"c","name":"terminal","arguments":"{}"}]}`, "application/json", turn.Responses, false},
		{"/v1/responses", `{"model":"m","stream":true,"input":"x"}`, "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"function_call\",\"call_id\":\"c\",\"name\":\"terminal\",\"arguments\":\"{}\"}]}}\n\n", "text/event-stream", turn.Responses, true},
	} {
		h, p, nia := setup(t)
		h.Anthropic = c.format == turn.AnthropicMessages
		nia.verdicts["terminal"] = Verdict{Message: "Nia is holding terminal for a human approval."}
		p.answer, p.contentType = c.answer, c.contentType
		got := post(h, c.path, c.body)
		if got.Code != 200 {
			t.Fatalf("%s: %d %s", c.path, got.Code, got.Body.String())
		}
		// What the agent gets is a complete response in its own API: this code reads it back.
		output, err := turn.ReadOutput(c.format, c.stream, got.Body.String())
		if err != nil {
			t.Fatalf("%s stream=%v: the synthetic response is not readable: %v\n%s", c.path, c.stream, err, got.Body.String())
		}
		if len(output.ToolCalls) != 0 || !strings.Contains(output.Text, "Nia is holding terminal") || !strings.Contains(output.Text, "[Nia agent firewall] This action was not run") {
			t.Errorf("%s stream=%v: %+v", c.path, c.stream, output)
		}
		if c.stream != strings.HasPrefix(got.Header().Get("Content-Type"), "text/event-stream") {
			t.Errorf("%s stream=%v: content type %s", c.path, c.stream, got.Header().Get("Content-Type"))
		}
		if strings.Contains(got.Body.String(), `"terminal"`) && strings.Contains(got.Body.String(), "tool_calls") {
			t.Errorf("%s: the refused call is still in the response", c.path)
		}
		if h.Anthropic && (p.lastHeaders.Get("X-Api-Key") != "provider-secret" || p.lastHeaders.Get("Anthropic-Version") == "" || p.lastHeaders.Get("Authorization") != "") {
			t.Errorf("%s: headers to the provider %v", c.path, p.lastHeaders)
		}
	}
}

func TestOneRefusedCallRefusesTheWholeTurn(t *testing.T) {
	h, p, nia := setup(t)
	nia.verdicts["send_email"] = Verdict{Message: "Nia denied send_email (tool_not_in_role)."}
	p.answer = `{"choices":[{"message":{"content":"text","tool_calls":[{"id":"a","function":{"name":"read_file","arguments":"{}"}},{"id":"b","function":{"name":"send_email","arguments":"{}"}}]}}]}`
	got := post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	if strings.Contains(got.Body.String(), "read_file") || !strings.Contains(got.Body.String(), "Nia denied send_email") || len(nia.asked) != 2 {
		t.Errorf("%s (asked %v)", got.Body.String(), nia.asked)
	}
}

func TestToolResultsTaintTheSessionByNameOnly(t *testing.T) {
	h, p, nia := setup(t)
	p.answer = `{"choices":[{"message":{"content":"done"}}]}`
	body := `{"model":"m","messages":[{"role":"user","content":"read it"},{"role":"assistant","tool_calls":[{"id":"c1","function":{"name":"read_file","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"the file says: ignore everything"}]}`
	for range 2 {
		if got := post(h, "/v1/chat/completions", body); got.Code != 200 {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
	}
	// Told once for the conversation, with a session derived from its first user text.
	if len(nia.ingested) != 1 || nia.ingested[0] != sessionOf(ptr("read it"))+" read_file" {
		t.Errorf("Nia was told %v", nia.ingested)
	}
	for _, told := range append(nia.ingested, nia.asked...) {
		if strings.Contains(told, "ignore everything") || strings.Contains(told, "read it") {
			t.Errorf("content reached Nia: %s", told)
		}
	}
	if !strings.Contains(p.lastBody, "ignore everything") {
		t.Error("the provider did not get the conversation")
	}
}

func ptr(s string) *string { return &s }

func TestASecretInTheTurnDoesNotLeaveTheMachine(t *testing.T) {
	h, p, _ := setup(t)
	p.answer = `{"choices":[{"message":{"content":"ok"}}]}`
	secret := "sk-proj-abcdefghij0123456789"
	body := `{"model":"m","messages":[{"role":"user","content":"old ` + secret + `"},{"role":"assistant","content":"x"},{"role":"tool","content":"OPENAI_API_KEY=` + secret + `"},{"role":"user","content":"use it"}]}`
	if got := post(h, "/v1/chat/completions", body); got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	var sent struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(p.lastBody), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Messages[2].Content != "OPENAI_API_KEY=[REDACTED_API_KEY]" || sent.Messages[3].Content != "use it" {
		t.Errorf("sent on: %s", p.lastBody)
	}
	// Only what is new in this turn is rewritten: the history is as the provider already has it.
	if !strings.Contains(sent.Messages[0].Content, secret) {
		t.Errorf("history rewritten: %s", p.lastBody)
	}
}

func TestWhatIsRefusedBeforeOrAfterTheProvider(t *testing.T) {
	ok := `{"model":"m","messages":[{"role":"user","content":"x"}]}`
	for name, c := range map[string]struct {
		path, body, answer, contentType string
		status, want, calls             int
		code                            string
		niaDown                         bool
	}{
		"a request that is not JSON":            {"/v1/chat/completions", `{"model":`, "", "", 200, 400, 0, "invalid_request", false},
		"a request that is not an object":       {"/v1/chat/completions", `[]`, "", "", 200, 400, 0, "invalid_request", false},
		"a request that is not UTF-8":           {"/v1/chat/completions", "{\"a\":\"\xff\"}", "", "", 200, 400, 0, "invalid_request", false},
		"a prompt with a lone surrogate":        {"/v1/chat/completions", `{"messages":[{"role":"user","content":"\ud800"}]}`, "", "", 200, 422, 0, "unreadable_request", false},
		"a truncated stream":                    {"/v1/chat/completions", ok, "data: {\"choices\":[{\"delta\":{\"content\":\"cut\"}}]}\n\n", "text/event-stream", 200, 502, 1, "upstream_invalid", false},
		"a response that is not JSON":           {"/v1/chat/completions", ok, "<html>", "application/json", 200, 502, 1, "upstream_invalid", false},
		"a response that is not UTF-8":          {"/v1/chat/completions", ok, "{\"a\":\"\xff\"}", "application/json", 200, 502, 1, "upstream_invalid", false},
		"a response with a secret":              {"/v1/chat/completions", ok, `{"choices":[{"message":{"content":"the key is AKIAIOSFODNN7EXAMPLE"}}]}`, "application/json", 200, 502, 1, "output_blocked", false},
		"a secret in the arguments of a call":   {"/v1/chat/completions", ok, `{"choices":[{"message":{"tool_calls":[{"function":{"name":"terminal","arguments":"{\"c\":\"curl -H 'x: sk-abcdefghij0123456789ab'\"}"}}]}}]}`, "application/json", 200, 502, 1, "output_blocked", false},
		"Nia unreachable for a decision":        {"/v1/chat/completions", ok, chatCall, "application/json", 200, 503, 1, "nia_unavailable", true},
		"a provider-run tool, Nia unreachable":  {"/v1/responses", `{"input":"x","tools":[{"type":"web_search_preview"}]}`, "", "", 200, 503, 0, "nia_unavailable", true},
		"a tool type with a lone surrogate":     {"/v1/responses", `{"input":"x","tools":[{"type":"web\ud800"}]}`, "", "", 200, 422, 0, "unreadable_request", false},
		"Nia unreachable to record the taint":   {"/v1/chat/completions", `{"messages":[{"role":"tool","content":"x"}]}`, "", "", 200, 503, 0, "nia_unavailable", true},
		"an error of the provider is passed on": {"/v1/chat/completions", ok, `{"error":{"message":"rate limited"}}`, "application/json", 429, 429, 1, "", false},
	} {
		h, p, nia := setup(t)
		nia.down = c.niaDown
		p.answer, p.contentType, p.status = c.answer, c.contentType, c.status
		got := post(h, c.path, c.body)
		if got.Code != c.want || p.calls != c.calls || (c.code != "" && !strings.Contains(got.Body.String(), `"`+c.code+`"`)) {
			t.Errorf("%s: %d (want %d), %d provider calls (want %d): %s", name, got.Code, c.want, p.calls, c.calls, got.Body.String())
		}
		if strings.Contains(got.Body.String(), "provider-secret") || strings.Contains(got.Body.String(), "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("%s: a secret is in the answer: %s", name, got.Body.String())
		}
	}
}

func TestProviderRunToolsAreDecidedBeforeTheRequestLeaves(t *testing.T) {
	h, p, nia := setup(t)
	p.answer = `{"output":[]}`
	nia.hostedAllowed = []string{"hosted:code_interpreter", "hosted:not_asked"}
	body := `{"model":"m","input":"x","tool_choice":{"type":"web_search_preview"},"tools":[{"type":"web_search_preview"},{"type":"function","name":"a"},{"type":"code_interpreter"},{"type":"mcp","server_label":"crm"}]}`
	if got := post(h, "/v1/responses", body); got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if len(nia.hostedAsked) != 1 || nia.hostedAsked[0] != "hosted:web_search_preview,hosted:code_interpreter,hosted:mcp:crm" {
		t.Errorf("Nia was asked %v", nia.hostedAsked)
	}
	want := `{"model":"m","input":"x","tool_choice":"auto","tools":[{"type":"function","name":"a"},{"type":"code_interpreter"}]}`
	if p.lastBody != want {
		t.Errorf("sent on:\n got %s\nwant %s", p.lastBody, want)
	}

	// All allowed: the request goes as the agent wrote it, byte for byte.
	nia.hostedAllowed = []string{"hosted:web_search"}
	untouched := `{ "model":"m", "messages":[], "web_search_options":{} }`
	p.answer = `{"choices":[{"message":{"content":"ok"}}]}`
	if got := post(h, "/v1/chat/completions", untouched); got.Code != 200 || p.lastBody != untouched {
		t.Errorf("%d, sent on %s", got.Code, p.lastBody)
	}
	// None declared: Nia is not asked.
	asked := len(nia.hostedAsked)
	post(h, "/v1/chat/completions", `{"messages":[],"tools":[{"type":"function","function":{"name":"a"}}]}`)
	if len(nia.hostedAsked) != asked {
		t.Error("Nia was asked about a request with no provider-run tool")
	}
}

func TestClientToolsAreNotMistakenForProviderRunOnes(t *testing.T) {
	h, p, _ := setup(t)
	p.answer = `{"choices":[{"message":{"content":"ok"}}]}`
	for path, body := range map[string]string{
		"/v1/chat/completions": `{"messages":[],"tools":[{"type":"function","function":{"name":"a"}}]}`,
		"/v1/responses":        `{"input":"x","tools":[{"type":"function","name":"a"},{"type":"custom","name":"b"},{"type":"local_shell"}]}`,
		"/v1/messages":         `{"messages":[],"tools":[{"name":"a","input_schema":{}},{"type":"custom","name":"b"},{"type":"bash_20250124","name":"bash"},{"type":"text_editor_20250728","name":"e"}]}`,
	} {
		if path == "/v1/messages" {
			p.answer = `{"content":[{"type":"text","text":"ok"}]}`
		} else if path == "/v1/responses" {
			p.answer = `{"output":[]}`
		}
		if got := post(h, path, body); got.Code != 200 {
			t.Errorf("%s: %d %s", path, got.Code, got.Body.String())
		}
	}
}

func TestTheProviderIsNeverFollowedElsewhere(t *testing.T) {
	h, _, _ := setup(t)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("followed a redirect with %v", r.Header)
	}))
	defer elsewhere.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	h.Provider, _ = url.Parse(redirecting.URL + "/v1")
	if got := post(h, "/v1/chat/completions", `{"messages":[{"role":"user","content":"x"}]}`); got.Code != http.StatusTemporaryRedirect {
		t.Errorf("%d %s", got.Code, got.Body.String())
	}
}

func TestRemoteSpeaksTheDecisionAPI(t *testing.T) {
	var seen []string
	nia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		seen = append(seen, r.URL.Path+" "+r.Header.Get("Authorization")+" "+r.Header.Get("X-Nia-Session-Id")+" "+r.Header.Get("X-Nia-Run-Id")+" "+string(raw))
		switch {
		case r.URL.Path == "/v1/tools/hosted" && strings.Contains(string(raw), "silent"):
			_, _ = io.WriteString(w, `{"removed":[]}`)
		case r.URL.Path == "/v1/tools/hosted":
			_, _ = io.WriteString(w, `{"allowed":["hosted:a"],"removed":["hosted:b"],"tainted_by":[]}`)
		case r.URL.Path == "/v1/tools/result":
			_, _ = io.WriteString(w, `{"action":"allow","output":"","findings":[],"tainted_by":["read_file"]}`)
		case strings.Contains(string(raw), `"hashed_held"`):
			_, _ = io.WriteString(w, `{"decision":"arguments_required","reason":"approval_needs_arguments","message":null}`)
		case strings.Contains(string(raw), `"arguments_required"`):
			_, _ = io.WriteString(w, `{"decision":"arguments_required","message":null}`)
		case strings.Contains(string(raw), `"terminal"`):
			_, _ = io.WriteString(w, `{"decision":"require_approval","reason":"untrusted_session","message":"held","approval_id":"a1"}`)
		case strings.Contains(string(raw), `"odd"`):
			_, _ = io.WriteString(w, `{"decision":"maybe"}`)
		case strings.Contains(string(raw), `"broken"`):
			w.WriteHeader(500)
		default:
			_, _ = io.WriteString(w, `{"decision":"allow","message":null}`)
		}
	}))
	defer nia.Close()
	base, _ := url.Parse(nia.URL)
	remote := &Remote{Base: base, Key: "nia_machine", Run: "run-1", HTTP: NewProviderClient(5 * time.Second)}
	ctx := context.Background()
	if err := remote.Ingested(ctx, "c-1", "read_file"); err != nil {
		t.Fatal(err)
	}
	if v, err := remote.Decide(ctx, "c-1", "read_file", `{"path":"a"}`, nil); err != nil || !v.Allowed {
		t.Errorf("allow: %+v %v", v, err)
	}
	if v, err := remote.Decide(ctx, "c-1", "terminal", `{}`, nil); err != nil || v.Allowed || v.Message != "held" {
		t.Errorf("hold: %+v %v", v, err)
	}
	// Decided here: the hash and the decisions go, the arguments never.
	allow := engine.Decision{Decision: engine.Allow, Reason: "allowed"}
	if v, again, err := remote.DecideHashed(ctx, "c-1", Hashed{Tool: "read_file", Hash: strings.Repeat("a", 64), Digest: "0123456789abcdef", Clean: allow, Tainted: allow, Exposed: allow, Both: allow}); err != nil || again || !v.Allowed {
		t.Errorf("hashed: %+v %v %v", v, again, err)
	}
	last := seen[len(seen)-1]
	if !strings.Contains(last, `"arguments_hash":"aaaa`) || !strings.Contains(last, `"policy_digest":"0123456789abcdef"`) || strings.Contains(last, `"arguments":`) {
		t.Errorf("sent %s", last)
	}
	if v, again, err := remote.DecideHashed(ctx, "c-1", Hashed{Tool: "hashed_held", Hash: strings.Repeat("a", 64), Digest: "0123456789abcdef", Clean: allow, Tainted: allow, Exposed: allow, Both: allow}); err != nil || !again || v.Allowed {
		t.Errorf("arguments required: %+v %v %v", v, again, err)
	}
	// Asking again for arguments it was sent is no decision.
	for _, tool := range []string{"odd", "broken", "arguments_required"} {
		if v, err := remote.Decide(ctx, "c-1", tool, `{}`, nil); err == nil || v.Allowed {
			t.Errorf("%s: %+v %v", tool, v, err)
		}
	}
	if allowed, err := remote.Hosted(ctx, "c-1", []string{"hosted:a", "hosted:b"}); err != nil || len(allowed) != 1 || allowed[0] != "hosted:a" {
		t.Errorf("hosted: %v %v", allowed, err)
	}
	// An answer that does not say what is allowed allows nothing.
	if allowed, err := remote.Hosted(ctx, "c-1", []string{"hosted:silent"}); err == nil {
		t.Errorf("an answer without a decision: %v", allowed)
	}
	if seen[0] != `/v1/tools/result Bearer nia_machine c-1 run-1 {"output":"","tool":"read_file"}` || seen[1] != `/v1/tools/decide Bearer nia_machine c-1 run-1 {"arguments":"{\"path\":\"a\"}","tool":"read_file"}` {
		t.Errorf("sent: %q", seen[:2])
	}
}

// rules is a policy in force: terminal runs ls, and asks a human once the
// session is tainted; shell is a dispatcher.
func rules(t *testing.T) func() *Rules {
	t.Helper()
	role, err := engine.ParseRole(json.RawMessage(`{"name":"ops","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[` +
		`{"name":"terminal","when_untrusted":"require_approval","output":"untrusted","sensitive":false,"effect":"none","arguments":[]},` +
		`{"name":"shell","when_untrusted":"allow","output":"untrusted","sensitive":false,"effect":"none","arguments":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	dispatchers, err := engine.ParseDispatchers(json.RawMessage(`[{"tool":"shell","calls":"calls","name":"name","arguments":"arguments"}]`))
	if err != nil {
		t.Fatal(err)
	}
	ready := &Rules{Role: role, Dispatchers: dispatchers, Digest: "0123456789abcdef"}
	return func() *Rules { return ready }
}

func TestThePolicyInForceDecidesAndTheArgumentsStayHere(t *testing.T) {
	h, p, nia := setup(t)
	h.Rules = rules(t)
	p.answer = chatCall
	got := post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"list files"}]}`)
	if got.Code != 200 || got.Body.String() != chatCall {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if len(nia.asked) != 0 || len(nia.hashed) != 1 {
		t.Fatalf("Nia was asked %v with arguments, %d by hash", nia.asked, len(nia.hashed))
	}
	call := nia.hashed[0]
	hash, _ := canon.ArgumentsHash("terminal", `{"command":"ls"}`)
	if call.Tool != "terminal" || call.Hash != hash || call.Digest != "0123456789abcdef" {
		t.Errorf("sent %+v", call)
	}
	if call.Clean.Decision != engine.Allow || call.Tainted.Decision != engine.RequireApproval || call.Both.Reason != "untrusted_session" {
		t.Errorf("decided %+v", call)
	}
	// What goes to Nia, as Remote sends it, holds no argument.
	encoded, _ := json.Marshal(map[string]engine.Decision{"clean": call.Clean, "tainted": call.Tainted, "exposed": call.Exposed, "both": call.Both})
	if strings.Contains(string(encoded), "ls") {
		t.Errorf("the decisions carry the arguments: %s", encoded)
	}
}

func TestNiaPicksTheDecisionForItsSessionState(t *testing.T) {
	h, p, nia := setup(t)
	h.Rules = rules(t)
	nia.tainted = true
	p.answer = chatCall
	got := post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"list files"}]}`)
	if got.Code != 200 || got.Body.String() == chatCall || !strings.Contains(got.Body.String(), "require_approval untrusted_session") {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
}

func TestTheArgumentsGoToNiaOnlyWhenItAsksOrCannotBeSure(t *testing.T) {
	h, p, nia := setup(t)
	h.Rules = rules(t)
	nia.wantArguments = true
	p.answer = chatCall
	if got := post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"list files"}]}`); got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if len(nia.hashed) != 1 || len(nia.asked) != 1 || nia.asked[0] != `terminal {"command":"ls"}` {
		t.Fatalf("hashed %d, asked %v", len(nia.hashed), nia.asked)
	}

	// A dispatcher is decided by Nia from its arguments.
	h, p, nia = setup(t)
	h.Rules = rules(t)
	p.answer = `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"shell","arguments":"{\"calls\":[]}"}}]}}]}`
	if got := post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"x"}]}`); got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if len(nia.hashed) != 0 || len(nia.asked) != 1 {
		t.Fatalf("hashed %d, asked %v", len(nia.hashed), nia.asked)
	}

	// With no policy in force, Nia decides from the arguments.
	h, p, nia = setup(t)
	h.Rules = func() *Rules { return nil }
	p.answer = chatCall
	post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"list files"}]}`)
	if len(nia.hashed) != 0 || len(nia.asked) != 1 {
		t.Fatalf("hashed %d, asked %v", len(nia.hashed), nia.asked)
	}

	// Nia out of reach refuses the turn.
	h, p, nia = setup(t)
	h.Rules = rules(t)
	nia.down = true
	p.answer = chatCall
	if got := post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"list files"}]}`); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
}

func TestTheProviderGetsAStableIDOfTheConversationWhenItRoutesByIt(t *testing.T) {
	h, p, _ := setup(t)
	p.answer = `{"choices":[{"message":{"content":"hi"}}]}`
	seen := func(first string) string {
		post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"`+first+`"}]}`)
		return p.lastHeaders.Get("X-Opencode-Session")
	}
	if got := seen("a"); got != "" {
		t.Fatalf("sent %q without a session header set", got)
	}
	h.SessionHeader = "x-opencode-session"
	one, again, other := seen("a"), seen("a"), seen("b")
	if !strings.HasPrefix(one, "nia-") || len(one) != 36 || one != again || one == other {
		t.Errorf("ids %q %q %q", one, again, other)
	}
	// Not the id Nia knows the conversation by.
	first := "a"
	if strings.Contains(one, strings.TrimPrefix(sessionOf(&first), "c-")) {
		t.Error("the provider got Nia's session id")
	}
}

func TestAReleasedHostActionCanRunOnceAndARefusedOneCannot(t *testing.T) {
	h, p, nia := setup(t)
	h.Releases = &Releases{Prefix: "mcp__host__"}
	call := func(name, args string) string {
		encoded, _ := json.Marshal(args)
		return `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"` + name + `","arguments":` + string(encoded) + `}}]}}]}`
	}
	p.answer = call("mcp__host__service_restart", `{"service":"nginx"}`)
	post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"restart nginx"}]}`)
	if !h.Releases.Take("mcp__host__service_restart", `{"service":"nginx"}`, time.Now()) || h.Releases.Take("mcp__host__service_restart", `{"service":"nginx"}`, time.Now()) {
		t.Fatal("not released exactly once")
	}
	nia.verdicts["mcp__host__package_install"] = Verdict{Message: "held"}
	p.answer = call("mcp__host__package_install", `{"package":"fail2ban"}`)
	post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"install it"}]}`)
	if h.Releases.Take("mcp__host__package_install", `{"package":"fail2ban"}`, time.Now()) {
		t.Error("a call Nia did not allow was released")
	}
	// Through a dispatcher, the inner call is what runs.
	h.Rules = rules(t)
	p.answer = call("shell", `{"calls":[{"name":"mcp__host__service_reload","arguments":{"service":"nginx"}}]}`)
	post(h, "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"reload"}]}`)
	if !h.Releases.Take("mcp__host__service_reload", `{"service":"nginx"}`, time.Now()) {
		t.Error("the inner call of a dispatcher was not released")
	}
}

func TestAnApplySendsItsPlanForTheReviewer(t *testing.T) {
	h, _, nia := setup(t)
	h.Rules = rules(t)
	// Nia asks for the arguments of a call it holds for a reviewer.
	nia.wantArguments = true
	plan := strings.Repeat("ab", 16)
	asked := []string{}
	h.Review = func(_ context.Context, id string) json.RawMessage {
		asked = append(asked, id)
		return json.RawMessage(`{"plan":"` + id + `"}`)
	}
	ctx := context.Background()
	// Directly, and through a dispatcher.
	h.decide(ctx, "c-1", "mcp__host__apply", `{"plan":"`+plan+`"}`)
	h.decide(ctx, "c-1", "shell", `{"calls":[{"name":"mcp__host__apply","arguments":{"plan":"`+plan+`"}},{"name":"terminal","arguments":{}}]}`)
	// Not an apply, or not a plan id: nothing is asked.
	h.decide(ctx, "c-1", "terminal", `{"plan":"`+plan+`"}`)
	h.decide(ctx, "c-1", "mcp__host__apply", `{"plan":"../x"}`)
	if len(asked) != 2 || asked[0] != plan || len(nia.reviews) != 2 {
		t.Errorf("asked %v, sent %d reviews", asked, len(nia.reviews))
	}
}
