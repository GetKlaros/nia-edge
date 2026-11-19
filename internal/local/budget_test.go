package local

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/GetKlaros/nia-edge/internal/turn"
)

// fakeBudgets answers from a budget and records what it is told.
type fakeBudgets struct {
	mu      sync.Mutex
	answer  Budget
	down    bool
	usedErr error
	asked   []string
	used    []turn.Usage
}

func (b *fakeBudgets) Check(_ context.Context, _, model string) (Budget, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asked = append(b.asked, model)
	if b.down {
		return Budget{}, errors.New("unreachable")
	}
	return b.answer, nil
}

func (b *fakeBudgets) Used(_ context.Context, _, _ string, usage turn.Usage) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used = append(b.used, usage)
	return b.usedErr
}

const chatWithUsage = `{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`

func TestAModelCallPastTheBudgetIsNotMade(t *testing.T) {
	h, p, _ := setup(t)
	budgets := &fakeBudgets{answer: Budget{Allowed: false, Metered: true, Message: "This agent reached its budget: a reviewer was asked."}}
	h.Budgets = budgets
	got := post(h, "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`)
	if got.Code != 200 || !strings.Contains(got.Body.String(), "reached its budget") || p.calls != 0 {
		t.Fatalf("%d %s, provider called %d times", got.Code, got.Body.String(), p.calls)
	}
	if len(budgets.asked) != 1 || budgets.asked[0] != "gpt-5" {
		t.Errorf("asked %v", budgets.asked)
	}
	budgets.down = true
	if got := post(h, "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`); got.Code != 503 || p.calls != 0 {
		t.Fatalf("Nia out of reach: %d", got.Code)
	}
}

func TestWhatACallUsedReachesNia(t *testing.T) {
	h, p, _ := setup(t)
	budgets := &fakeBudgets{answer: Budget{Allowed: true, Metered: true}}
	h.Budgets = budgets
	p.answer = chatWithUsage
	got := post(h, "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`)
	if got.Code != 200 || got.Body.String() != chatWithUsage {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if len(budgets.used) != 1 || budgets.used[0] != (turn.Usage{InputTokens: 12, OutputTokens: 3}) {
		t.Fatalf("used %v", budgets.used)
	}
	// A stream is asked for its usage.
	p.answer, p.contentType = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":1}}\n\ndata: [DONE]\n\n", "text/event-stream"
	if got := post(h, "/v1/chat/completions", `{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"x"}]}`); got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if !strings.Contains(p.lastBody, `"stream_options":{"include_usage":true}`) || len(budgets.used) != 2 || budgets.used[1].InputTokens != 4 {
		t.Fatalf("%s %v", p.lastBody, budgets.used)
	}
}

func TestAMeteredCallThatCannotBeCountedIsNotReleased(t *testing.T) {
	h, p, _ := setup(t)
	budgets := &fakeBudgets{answer: Budget{Allowed: true, Metered: true}}
	h.Budgets = budgets
	p.answer = `{"choices":[{"message":{"content":"hi"}}]}`
	if got := post(h, "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`); got.Code != 502 || !strings.Contains(got.Body.String(), "usage_unknown") {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	p.answer = chatWithUsage
	budgets.usedErr = errors.New("unreachable")
	if got := post(h, "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`); got.Code != 503 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	// Without a budget, a call is released whatever becomes of its count.
	budgets.answer = Budget{Allowed: true}
	if got := post(h, "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`); got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	p.answer = `{"choices":[{"message":{"content":"hi"}}]}`
	if got := post(h, "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`); got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
}

func TestRemoteBudgetAnswers(t *testing.T) {
	answers := map[string]string{}
	var paths, bodies []string
	server := newProvider(t)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		paths, bodies = append(paths, r.URL.Path), append(bodies, string(raw))
		_, _ = io.WriteString(w, answers[r.URL.Path])
	})
	base, _ := url.Parse(server.URL)
	remote := &Remote{Base: base, Key: "nia_machine", HTTP: server.Client()}
	for answer, want := range map[string]Budget{
		`{"allowed":true}`: {Allowed: true},
		`{"allowed":true,"spent":"0.10 EUR","budget":"1.00 EUR"}`:                   {Allowed: true, Metered: true},
		`{"allowed":false,"reason":"budget","message":"reached","approval_id":"x"}`: {Allowed: false, Metered: true, Message: "reached"},
	} {
		answers["/v1/model/check"] = answer
		got, err := remote.Check(context.Background(), "s", "gpt-5")
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", answer, got, err)
		}
	}
	answers["/v1/model/check"] = `{"spent":"x"}`
	if _, err := remote.Check(context.Background(), "s", "gpt-5"); err == nil {
		t.Error("an answer without a decision is not one")
	}
	answers["/v1/model/usage"] = `{"recorded":true}`
	if err := remote.Used(context.Background(), "s", "gpt-5", turn.Usage{InputTokens: 10, CachedInputTokens: 4, OutputTokens: 2}); err != nil {
		t.Fatal(err)
	}
	if last := bodies[len(bodies)-1]; last != `{"cached_input_tokens":4,"input_tokens":10,"model":"gpt-5","output_tokens":2}` {
		t.Fatalf("%s", last)
	}
	answers["/v1/model/usage"] = `{}`
	if err := remote.Used(context.Background(), "s", "gpt-5", turn.Usage{}); err == nil {
		t.Error("not recorded is an error")
	}
}
