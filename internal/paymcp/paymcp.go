// Package paymcp is Nia's payment tool for the agent, nia-pay: an MCP server
// on nia-edge's own address with one tool, pay. A payment is an operation of
// the tenant's vault on NEAR: nia-edge prepares it with the agent's payment
// account, asks Nia for its visa, and authorizes it with that visa. The vault
// checks the operation against the role it gives the agent, and accepts a
// visa once.
//
// A call runs only when the model path released that exact call (same tool,
// same canonical arguments, once). The payment key is in the state file; the
// agent never holds it, and nothing here logs it.
package paymcp

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/near"
)

// Account is the agent's payment account: its NEAR account and key.
type Account struct {
	ID  string
	Key ed25519.PrivateKey
}

// Chain sends the account's function calls to NEAR.
type Chain interface {
	Call(ctx context.Context, account Account, contract string, call near.FunctionCall, waitUntil string) (near.Outcome, error)
}

// VisaAnswer is Nia's answer to a visa request.
type VisaAnswer struct {
	Decision string          `json:"decision"`
	Reason   string          `json:"reason"`
	Message  string          `json:"message"`
	Approval json.RawMessage `json:"approval"`
}

// Plans asks Nia which vault operation a payment is.
type Plans interface {
	Plan(ctx context.Context, arguments json.RawMessage) (*Payment, error)
}

// Visas asks Nia for the visa of one prepared operation.
type Visas interface {
	Visa(ctx context.Context, tool string, arguments json.RawMessage, opID string) (*VisaAnswer, error)
}

// Handler serves the MCP endpoint.
type Handler struct {
	// Account is the agent's payment account; an error means none yet.
	Account  func() (Account, error)
	Releases *local.Releases
	// Prefix is how the agent names this server's tools; empty is
	// mcp__nia_pay__ (the server nia_pay of Hermes and OpenClaw).
	Prefix  string
	Chain   Chain
	Plans   Plans
	Visas   Visas
	Version string
	Now     func() time.Time
}

// Gas of the vault's calls: authorize also pays the MPC signature request.
const (
	prepareGas   = 100_000_000_000_000
	authorizeGas = 200_000_000_000_000
	cancelGas    = 50_000_000_000_000
)

var versions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

var (
	hexBytes = regexp.MustCompile(`^0x([0-9a-fA-F]{2})*$`)
	amount   = regexp.MustCompile(`^\d{1,39}$`)
)

// Request is a payment, as the vault takes it: an EVM transaction of the
// vault's wallet on one chain.
type Request struct {
	ChainID              uint64 `json:"chain_id"`
	Target               string `json:"target"`
	Value                string `json:"value"`
	Calldata             string `json:"calldata"`
	AllowanceAmount      string `json:"allowance_amount"`
	Reference            string `json:"reference"`
	GasLimit             string `json:"gas_limit"`
	MaxFeePerGas         string `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas"`
}

// Payment is a vault operation, as Nia plans it from the tool's arguments.
type Payment struct {
	Vault   string  `json:"vault"`
	Role    string  `json:"role"`
	Request Request `json:"request"`
}

// Ask is the pay tool's arguments: who, how much, why.
type Ask struct {
	To        string `json:"to"`
	Amount    string `json:"amount"`
	Reference string `json:"reference"`
}

var (
	address = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	usdc    = regexp.MustCompile(`^\d{1,9}(\.\d{1,6})?$`)
)

func parse(raw json.RawMessage) (*Ask, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var ask Ask
	if err := decoder.Decode(&ask); err != nil || decoder.More() {
		return nil, errors.New("pay takes to, amount and reference, and nothing else")
	}
	switch {
	case !address.MatchString(ask.To):
		return nil, errors.New("to is the 0x address that receives the payment")
	case !usdc.MatchString(ask.Amount):
		return nil, errors.New("amount is in USDC, as a decimal string such as \"12.5\"")
	case strings.TrimSpace(ask.Reference) == "" || len(ask.Reference) > 120:
		return nil, errors.New("reference says what the payment is for")
	}
	return &ask, nil
}

// checkPlan refuses a plan nia-edge could not prepare as it reads.
func checkPlan(p *Payment) error {
	r := p.Request
	switch {
	case !near.ValidAccount(p.Vault):
		return errors.New("the plan's vault is not a NEAR account")
	case p.Role == "" || len(p.Role) > 64:
		return errors.New("the plan names no role")
	case !hexBytes.MatchString(r.Target) || len(r.Target) != 42 || !hexBytes.MatchString(r.Calldata):
		return errors.New("the plan's transaction cannot be read")
	}
	for _, value := range []string{r.Value, r.AllowanceAmount, r.GasLimit, r.MaxFeePerGas, r.MaxPriorityFeePerGas} {
		if !amount.MatchString(value) {
			return errors.New("the plan's amounts cannot be read")
		}
	}
	return nil
}

// numbers writes bytes as the vault's JSON takes them: an array of numbers.
func numbers(hexText string) []int {
	raw, _ := hex.DecodeString(strings.TrimPrefix(hexText, "0x"))
	out := make([]int, len(raw))
	for i, b := range raw {
		out[i] = int(b)
	}
	return out
}

func prepareArgs(p *Payment) []byte {
	r := p.Request
	args, _ := json.Marshal(map[string]any{
		"role": p.Role,
		"request": map[string]any{
			"chain_id":                 r.ChainID,
			"target":                   numbers(r.Target),
			"value":                    r.Value,
			"calldata":                 numbers(r.Calldata),
			"allowance_amount":         r.AllowanceAmount,
			"reference":                r.Reference,
			"gas_limit":                r.GasLimit,
			"max_fee_per_gas":          r.MaxFeePerGas,
			"max_priority_fee_per_gas": r.MaxPriorityFeePerGas,
		},
	})
	return args
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func localOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !localOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "this MCP server answers POST only", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var msg message
	if err != nil || json.Unmarshal(raw, &msg) != nil || msg.JSONRPC != "2.0" || msg.Method == "" {
		reply(w, nil, nil, &rpcError{Code: -32600, Message: "not a JSON-RPC 2.0 request"})
		return
	}
	if len(msg.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch msg.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &params)
		version := versions[0]
		if slices.Contains(versions, params.ProtocolVersion) {
			version = params.ProtocolVersion
		}
		reply(w, msg.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "nia-pay", "version": h.Version},
			"instructions":    "Payments from the organization's vault. Each payment runs only once Nia allowed it, and the vault checks it again.",
		}, nil)
	case "ping":
		reply(w, msg.ID, map[string]any{}, nil)
	case "tools/list":
		reply(w, msg.ID, map[string]any{"tools": []map[string]any{tool}}, nil)
	case "tools/call":
		result, rpcErr := h.call(r.Context(), msg.Params)
		reply(w, msg.ID, result, rpcErr)
	default:
		reply(w, msg.ID, nil, &rpcError{Code: -32601, Message: "method not found"})
	}
}

var tool = map[string]any{
	"name": "pay",
	"description": "Pay someone in USDC from the organization's vault. Give only who receives it, how much and why: " +
		"Nia knows the vault, its chain and its fees, and the vault checks the payment against the rule the organization set " +
		"(who may be paid, how much per day). A payment outside that rule is refused, and nothing is paid.",
	"inputSchema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"to":        map[string]any{"type": "string", "pattern": "^0x[0-9a-fA-F]{40}$", "description": "Who receives it: an 0x address."},
			"amount":    map[string]any{"type": "string", "pattern": `^\d{1,9}(\.\d{1,6})?$`, "description": "How much, in USDC, as a decimal: \"12.5\"."},
			"reference": map[string]any{"type": "string", "minLength": 1, "maxLength": 120, "description": "Why: an invoice, an order. One per payment."},
		},
		"required":             []string{"to", "amount", "reference"},
		"additionalProperties": false,
	},
	"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
}

func text(content string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": content}}, "isError": isError}
}

func (h *Handler) call(ctx context.Context, params json.RawMessage) (map[string]any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(params, &p) != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}
	if p.Name != "pay" {
		return nil, &rpcError{Code: -32602, Message: "unknown tool " + p.Name}
	}
	if _, err := parse(p.Arguments); err != nil {
		return text(err.Error(), true), nil
	}
	// A part missing is a machine set up wrong: refused before the release is spent.
	if h.Account == nil || h.Chain == nil || h.Plans == nil || h.Visas == nil {
		return text("[Nia agent firewall] This machine's payment tool is not set up: nothing was paid.", true), nil
	}
	prefix := h.Prefix
	if prefix == "" {
		prefix = "mcp__nia_pay__"
	}
	if h.Releases == nil || !h.Releases.Take(prefix+"pay", string(p.Arguments), h.now()) {
		return text("[Nia agent firewall] This payment was not released by Nia: it runs only as the model proposed it and Nia allowed it, once.", true), nil
	}
	account, err := h.Account()
	if err != nil {
		return text("[Nia agent firewall] This agent has no payment account yet: nothing was paid.", true), nil
	}
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// Nia knows the vault, its chain and its fees; it plans the payment again
	// before signing a visa, so a plan changed on the way gets none.
	payment, err := h.Plans.Plan(runCtx, p.Arguments)
	if err != nil {
		return text("[Nia agent firewall] Nothing was paid: "+err.Error(), true), nil
	}
	if err := checkPlan(payment); err != nil {
		return text("Nothing was paid: "+err.Error(), true), nil
	}

	prepared, err := h.Chain.Call(runCtx, account, payment.Vault, near.FunctionCall{Method: "prepare", Args: prepareArgs(payment), Gas: prepareGas}, "FINAL")
	if err != nil {
		return text("The vault could not be reached, so nothing was paid: "+err.Error(), true), nil
	}
	if strings.Contains(prepared.Failure, "ERR_REFERENCE_ALREADY_USED") {
		// The vault keeps one payment per reference: a retry never pays twice.
		return text("A payment with the reference \""+payment.Request.Reference+"\" was already made from this vault, so it was not paid again. Use a new reference for a new payment.", true), nil
	}
	if prepared.Failure != "" || prepared.Pending {
		return text("The vault refused the payment: "+orUnknown(prepared.Failure)+" (transaction "+prepared.Hash+"). Nothing was paid.", true), nil
	}
	var operation struct {
		OpID []int `json:"op_id"`
	}
	if json.Unmarshal(prepared.Value, &operation) != nil || len(operation.OpID) != 32 {
		return text("The vault's answer to prepare cannot be read (transaction "+prepared.Hash+"). Nothing was authorized.", true), nil
	}
	id := make([]byte, 32)
	for i, b := range operation.OpID {
		if b < 0 || b > 255 {
			return text("The vault's answer to prepare cannot be read. Nothing was authorized.", true), nil
		}
		id[i] = byte(b)
	}
	opID := hex.EncodeToString(id)
	opArgs, _ := json.Marshal(map[string]any{"op_id": operation.OpID})

	answer, err := h.Visas.Visa(runCtx, prefix+"pay", p.Arguments, opID)
	if err != nil || answer.Decision != "allow" || len(answer.Approval) == 0 {
		// The prepared operation holds the role's allowance: give it back.
		_, _ = h.Chain.Call(context.WithoutCancel(runCtx), account, payment.Vault, near.FunctionCall{Method: "cancel_prepared", Args: opArgs, Gas: cancelGas}, "INCLUDED_FINAL")
		why := "Nia could not be reached"
		if err != nil {
			why = err.Error()
		} else if answer.Message != "" {
			why = answer.Message
		} else if answer.Reason != "" {
			why = answer.Reason
		}
		return text("[Nia agent firewall] No visa for operation "+opID+": "+why+". The operation was cancelled; nothing was paid.", true), nil
	}

	authorizeArgs, _ := json.Marshal(map[string]any{"op_id": operation.OpID, "approval": answer.Approval})
	authorized, err := h.Chain.Call(runCtx, account, payment.Vault, near.FunctionCall{Method: "authorize", Args: authorizeArgs, Gas: authorizeGas, Deposit: new(big.Int)}, "EXECUTED_OPTIMISTIC")
	if err != nil {
		return text("Operation "+opID+" has its visa, but authorize did not reach NEAR: "+err.Error(), true), nil
	}
	if authorized.Failure != "" {
		return text("The vault refused to authorize operation "+opID+": "+authorized.Failure+" (transaction "+authorized.Hash+").", true), nil
	}
	if authorized.Pending {
		return text("Operation "+opID+" was authorized (transaction "+authorized.Hash+"); its signature is not known yet.", false), nil
	}
	return text("Operation "+opID+" was authorized and signed by the vault (transaction "+authorized.Hash+").", false), nil
}

func orUnknown(s string) string {
	if s == "" {
		return "no outcome yet"
	}
	return s
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func reply(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *rpcError) {
	body := map[string]any{"jsonrpc": "2.0", "id": id}
	if id == nil {
		body["id"] = nil
	}
	if rpcErr != nil {
		body["error"] = rpcErr
	} else {
		body["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// NearChain sends calls through the RPC of the account's network, one at a
// time: each takes the access key's next nonce.
type NearChain struct {
	HTTP *http.Client
	mu   sync.Mutex
}

func (c *NearChain) Call(ctx context.Context, account Account, contract string, call near.FunctionCall, waitUntil string) (near.Outcome, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	client := &near.Client{URL: near.RPCFor(account.ID), HTTP: c.HTTP}
	public := account.Key.Public().(ed25519.PublicKey)
	nonce, block, err := client.AccessKey(ctx, account.ID, public)
	if err != nil {
		return near.Outcome{}, err
	}
	transaction, err := near.Transaction(account.ID, public, nonce+1, contract, block, []near.FunctionCall{call})
	if err != nil {
		return near.Outcome{}, err
	}
	signed, hash := near.Sign(transaction, account.Key)
	return client.Send(ctx, signed, hash, waitUntil)
}
