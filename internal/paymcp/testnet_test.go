package paymcp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/niaclient"
)

// TestTestnetPayment pays on NEAR testnet through a Nia that signs visas for
// the vault. It runs only when NIA_E2E_NIA, NIA_E2E_KEY_FILE, NIA_E2E_VAULT,
// NIA_E2E_ACCOUNT and NIA_E2E_SEED are set.
func TestTestnetPayment(t *testing.T) {
	niaURL, keyFile, vault, accountID, seedText := os.Getenv("NIA_E2E_NIA"), os.Getenv("NIA_E2E_KEY_FILE"), os.Getenv("NIA_E2E_VAULT"), os.Getenv("NIA_E2E_ACCOUNT"), os.Getenv("NIA_E2E_SEED")
	if niaURL == "" || keyFile == "" || vault == "" || accountID == "" || seedText == "" {
		t.Skip("testnet run not configured")
	}
	seed, err := base64.StdEncoding.DecodeString(seedText)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("NIA_E2E_SEED is a base64 ed25519 seed")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	base, err := niaclient.ParseBaseURL(niaURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &niaclient.Client{Base: base, HTTP: niaclient.NewHTTPClient(2 * time.Minute)}
	releases := &local.Releases{Prefix: "mcp__"}
	h := &Handler{
		Account:  func() (Account, error) { return Account{ID: accountID, Key: ed25519.NewKeyFromSeed(seed)}, nil },
		Releases: releases,
		Chain:    &NearChain{HTTP: niaclient.NewHTTPClient(3 * time.Minute)},
		Visas:    e2eVisas{client: client, key: strings.TrimSpace(string(key))},
		Version:  "e2e",
	}
	reference := fmt.Sprintf("e2e-%d", time.Now().Unix())
	// NIA_E2E_TO is the recipient (40 hex digits), NIA_E2E_ALLOWANCE what the
	// role's allowance counts: the amount when the role has one, else 0.
	to := strings.Repeat("0", 24) + envOr("NIA_E2E_TO", "000000000000000000000000000000000000dead")
	calldata := "0xa9059cbb" + to + fmt.Sprintf("%064x", amountOf())
	arguments, _ := json.Marshal(map[string]any{"vault": vault, "role": "payments", "request": map[string]any{
		"chain_id": 84532, "target": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "value": "0", "calldata": calldata,
		"allowance_amount": envOr("NIA_E2E_ALLOWANCE", "0"), "reference": reference, "gas_limit": "60000", "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
	}})
	releases.Release("mcp__nia-pay__pay", string(arguments), time.Now())
	result, rpcErr := h.call(context.Background(), json.RawMessage(`{"name":"pay","arguments":`+string(arguments)+`}`))
	if rpcErr != nil {
		t.Fatal(rpcErr.Message)
	}
	t.Log(result["content"].([]map[string]any)[0]["text"])
	if want := os.Getenv("NIA_E2E_REFUSED") == ""; (result["isError"] == false) != want {
		t.Fatalf("paid: %v, expected %v", result["isError"] == false, want)
	}
}

type e2eVisas struct {
	client *niaclient.Client
	key    string
}

func (v e2eVisas) Visa(ctx context.Context, tool string, arguments json.RawMessage, opID string) (*VisaAnswer, error) {
	raw, err := v.client.Visa(ctx, v.key, "e2e", "", tool, arguments, opID)
	if err != nil {
		return nil, err
	}
	var answer VisaAnswer
	return &answer, json.Unmarshal(raw, &answer)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// amountOf is NIA_E2E_AMOUNT, in the token's smallest unit; 1 by default.
func amountOf() uint64 {
	var amount uint64 = 1
	if _, err := fmt.Sscan(envOr("NIA_E2E_AMOUNT", "1"), &amount); err != nil {
		return 1
	}
	return amount
}
