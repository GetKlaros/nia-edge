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
	to := "0x" + envOr("NIA_E2E_TO", "000000000000000000000000000000000000dead")
	arguments, _ := json.Marshal(map[string]any{"to": to, "amount": envOr("NIA_E2E_AMOUNT", "0.000001"), "reference": reference})
	h.Plans = e2ePlans{vault: vault}
	releases.Release("mcp__nia_pay__pay", string(arguments), time.Now())
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

// e2ePlans plans as Nia does for Base Sepolia's USDC: the run has no
// machine key to ask Nia's plan with, and Nia plans it again for the visa.
type e2ePlans struct{ vault string }

func (p e2ePlans) Plan(_ context.Context, arguments json.RawMessage) (*Payment, error) {
	var ask Ask
	if err := json.Unmarshal(arguments, &ask); err != nil {
		return nil, err
	}
	whole, fraction, _ := strings.Cut(ask.Amount, ".")
	var units uint64
	fmt.Sscan(whole+(fraction + "000000")[:6], &units)
	return &Payment{Vault: p.vault, Role: "payments", Request: Request{ChainID: 84532, Target: "0x036cbd53842c5426634e7929541ec2318f3dcf7e", Value: "0",
		Calldata:        fmt.Sprintf("0xa9059cbb%064s%064x", strings.ToLower(ask.To[2:]), units),
		AllowanceAmount: fmt.Sprint(units), Reference: ask.Reference, GasLimit: "100000", MaxFeePerGas: "1000000000", MaxPriorityFeePerGas: "1000000"}}, nil
}
