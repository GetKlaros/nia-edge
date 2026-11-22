package paymcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/near"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

type sent struct {
	contract, method string
	args             map[string]any
}

type fakeChain struct {
	calls   []sent
	refuse  string
	unreach bool
}

func (f *fakeChain) Call(_ context.Context, account Account, contract string, call near.FunctionCall, _ string) (near.Outcome, error) {
	if f.unreach {
		return near.Outcome{}, errors.New("down")
	}
	var args map[string]any
	_ = json.Unmarshal(call.Args, &args)
	f.calls = append(f.calls, sent{contract, call.Method, args})
	if call.Method == "prepare" {
		if f.refuse != "" {
			return near.Outcome{Hash: "h1", Failure: f.refuse}, nil
		}
		id := make([]int, 32)
		for i := range id {
			id[i] = 0x11
		}
		value, _ := json.Marshal(map[string]any{"op_id": id, "state": "Prepared"})
		return near.Outcome{Hash: "h1", Value: value}, nil
	}
	return near.Outcome{Hash: "h2", Value: []byte("null")}, nil
}

type fakeVisas struct {
	answer *VisaAnswer
	asked  []string
}

func (f *fakeVisas) Visa(_ context.Context, tool string, arguments json.RawMessage, opID string) (*VisaAnswer, error) {
	f.asked = append(f.asked, tool+" "+opID+" "+string(arguments))
	if f.answer == nil {
		return nil, errors.New("unreachable")
	}
	return f.answer, nil
}

const args = `{"vault":"vault.example.testnet","role":"payments","request":{"chain_id":84532,"target":"0x0101010101010101010101010101010101010101","value":"0","calldata":"0xa9059cbb","allowance_amount":"10","reference":"invoice-42","gas_limit":"60000","max_fee_per_gas":"2","max_priority_fee_per_gas":"1"}}`

func setup(account bool) (*Handler, *fakeChain, *fakeVisas, *local.Releases) {
	chain := &fakeChain{}
	visas := &fakeVisas{answer: &VisaAnswer{Decision: "allow", Approval: json.RawMessage(`{"visa":{"visa_nonce":7},"signature":"c2ln"}`)}}
	releases := &local.Releases{Prefix: "mcp__"}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	return &Handler{
		Account: func() (Account, error) {
			if !account {
				return Account{}, errors.New("none")
			}
			return Account{ID: "agent.testnet", Key: key}, nil
		},
		Releases: releases, Chain: chain, Visas: visas, Version: "test", Now: func() time.Time { return now },
	}, chain, visas, releases
}

func pay(t *testing.T, h http.Handler, arguments string) map[string]any {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":` + arguments + `}}`
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/pay/mcp", strings.NewReader(body)))
	var answer map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatal(recorder.Body.String())
	}
	result, _ := answer["result"].(map[string]any)
	return result
}

func textOf(result map[string]any) string {
	return result["content"].([]any)[0].(map[string]any)["text"].(string)
}

func TestItPaysOnlyTheReleasedCallOncePreparedVisaedAndAuthorized(t *testing.T) {
	h, chain, visas, releases := setup(true)
	if result := pay(t, h, args); result["isError"] != true || len(chain.calls) != 0 {
		t.Fatalf("paid without a release: %v %v", result, chain.calls)
	}
	releases.Release("mcp__nia-pay__pay", args, now)
	result := pay(t, h, args)
	if result["isError"] != false || !strings.Contains(textOf(result), "authorized") {
		t.Fatalf("%v", result)
	}
	if len(chain.calls) != 2 || chain.calls[0].method != "prepare" || chain.calls[1].method != "authorize" || chain.calls[0].contract != "vault.example.testnet" {
		t.Fatalf("%+v", chain.calls)
	}
	request := chain.calls[0].args["request"].(map[string]any)
	if len(request["target"].([]any)) != 20 || len(request["calldata"].([]any)) != 4 || request["value"] != "0" || chain.calls[0].args["role"] != "payments" {
		t.Fatalf("prepare args %v", chain.calls[0].args)
	}
	if approval := chain.calls[1].args["approval"].(map[string]any); approval["signature"] != "c2ln" {
		t.Fatalf("authorize args %v", chain.calls[1].args)
	}
	if len(visas.asked) != 1 || !strings.HasPrefix(visas.asked[0], "mcp__nia-pay__pay "+strings.Repeat("11", 32)+" ") {
		t.Fatalf("%v", visas.asked)
	}
	// The release is spent.
	if result := pay(t, h, args); result["isError"] != true || len(chain.calls) != 2 {
		t.Fatal("paid twice on one release")
	}
}

func TestWithoutAVisaTheOperationIsCancelled(t *testing.T) {
	for _, answer := range []*VisaAnswer{nil, {Decision: "deny", Message: "not allowed"}, {Decision: "require_approval"}} {
		h, chain, visas, releases := setup(true)
		visas.answer = answer
		releases.Release("mcp__nia-pay__pay", args, now)
		result := pay(t, h, args)
		if result["isError"] != true || len(chain.calls) != 2 || chain.calls[1].method != "cancel_prepared" {
			t.Fatalf("%v %+v", result, chain.calls)
		}
	}
}

func TestNothingIsSentWhenItCannotPay(t *testing.T) {
	h, chain, _, releases := setup(false)
	releases.Release("mcp__nia-pay__pay", args, now)
	if result := pay(t, h, args); result["isError"] != true || len(chain.calls) != 0 {
		t.Fatal("paid without an account")
	}
	h, chain, visas, releases := setup(true)
	chain.refuse = "Smart contract panicked: ERR_PERMISSION_DENIED:NoPermission"
	releases.Release("mcp__nia-pay__pay", args, now)
	if result := pay(t, h, args); result["isError"] != true || !strings.Contains(textOf(result), "ERR_PERMISSION_DENIED") || len(visas.asked) != 0 {
		t.Fatal("asked a visa for a refused operation")
	}
	for _, bad := range []string{
		`{"vault":"vault.testnet","role":"r","request":{}}`,
		strings.Replace(args, `"value":"0"`, `"value":"-1"`, 1),
		strings.Replace(args, `"role":"payments"`, `"role":"payments","extra":1`, 1),
		strings.Replace(args, `0x0101010101010101010101010101010101010101`, `0x01`, 1),
	} {
		h, chain, _, releases := setup(true)
		releases.Release("mcp__nia-pay__pay", bad, now)
		if result := pay(t, h, bad); result["isError"] != true || len(chain.calls) != 0 {
			t.Fatalf("paid %s", bad)
		}
	}
}

func TestAPageElsewhereCannotPay(t *testing.T) {
	h, _, _, _ := setup(true)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/pay/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	request.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatal(recorder.Code)
	}
}
