// Package near signs and sends the NEAR transactions of the agent's payment
// account: function calls to its vault, with the payment key nia-edge made
// on this machine. The key is in the state file only; nothing here logs it.
//
// A transaction is the protocol's Transaction (V0), borsh-encoded: signer,
// public key, nonce, receiver, block hash, actions. It is signed over the
// SHA-256 of those bytes.
package near

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58 writes bytes in NEAR's (Bitcoin's) base58.
func Base58(data []byte) string {
	n := new(big.Int).SetBytes(data)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		out = append(out, alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// DecodeBase58 reads base58; anything outside the alphabet is an error.
func DecodeBase58(text string) ([]byte, error) {
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, r := range text {
		i := strings.IndexRune(alphabet, r)
		if i < 0 {
			return nil, errors.New("not base58")
		}
		n.Mul(n, radix).Add(n, big.NewInt(int64(i)))
	}
	zeros := 0
	for zeros < len(text) && text[zeros] == alphabet[0] {
		zeros++
	}
	return append(make([]byte, zeros), n.Bytes()...), nil
}

// PublicKey is how NEAR writes an ed25519 public key.
func PublicKey(key ed25519.PublicKey) string { return "ed25519:" + Base58(key) }

var account = regexp.MustCompile(`^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`)

// ValidAccount reports whether a NEAR account ID is well formed.
func ValidAccount(id string) bool { return len(id) >= 2 && len(id) <= 64 && account.MatchString(id) }

// RPCFor is the RPC of the network an account belongs to.
func RPCFor(id string) string {
	if strings.HasSuffix(id, ".testnet") {
		return "https://rpc.testnet.near.org"
	}
	return "https://rpc.mainnet.near.org"
}

// FunctionCall is one call to a contract.
type FunctionCall struct {
	Method string
	Args   []byte
	Gas    uint64
	// Deposit is in yoctoNEAR; nil is none.
	Deposit *big.Int
}

type encoder struct{ bytes.Buffer }

func (e *encoder) u8(v byte) { e.WriteByte(v) }
func (e *encoder) u32(v uint32) {
	_ = binary.Write(&e.Buffer, binary.LittleEndian, v)
}
func (e *encoder) u64(v uint64) {
	_ = binary.Write(&e.Buffer, binary.LittleEndian, v)
}
func (e *encoder) bytes(v []byte) {
	e.u32(uint32(len(v)))
	e.Write(v)
}
func (e *encoder) str(v string) { e.bytes([]byte(v)) }

// u128 writes a value below 2^128, little-endian.
func (e *encoder) u128(v *big.Int) error {
	if v == nil {
		v = new(big.Int)
	}
	if v.Sign() < 0 || v.BitLen() > 128 {
		return errors.New("deposit out of range")
	}
	var be [16]byte
	v.FillBytes(be[:])
	for i := 15; i >= 0; i-- {
		e.WriteByte(be[i])
	}
	return nil
}

// Transaction is the borsh encoding of a transaction of function calls.
func Transaction(signer string, key ed25519.PublicKey, nonce uint64, receiver string, blockHash [32]byte, calls []FunctionCall) ([]byte, error) {
	if !ValidAccount(signer) || !ValidAccount(receiver) || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid transaction")
	}
	var e encoder
	e.str(signer)
	e.u8(0) // ED25519
	e.Write(key)
	e.u64(nonce)
	e.str(receiver)
	e.Write(blockHash[:])
	e.u32(uint32(len(calls)))
	for _, call := range calls {
		e.u8(2) // Action::FunctionCall
		e.str(call.Method)
		e.bytes(call.Args)
		e.u64(call.Gas)
		if err := e.u128(call.Deposit); err != nil {
			return nil, err
		}
	}
	return e.Bytes(), nil
}

// Sign makes the signed transaction and its hash.
func Sign(transaction []byte, key ed25519.PrivateKey) (signed []byte, hash [32]byte) {
	hash = sha256.Sum256(transaction)
	signature := ed25519.Sign(key, hash[:])
	signed = append(append(append([]byte{}, transaction...), 0), signature...)
	return signed, hash
}

// Client calls a NEAR RPC.
type Client struct {
	URL  string
	HTTP *http.Client
}

// RPCError is the node's refusal.
type RPCError struct{ Text string }

func (e *RPCError) Error() string { return "NEAR refused: " + e.Text }

func (c *Client) call(ctx context.Context, method string, params any, result any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "nia-edge", "method": method, "params": params})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return fmt.Errorf("cannot reach NEAR: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return fmt.Errorf("NEAR's answer cannot be read (HTTP %d)", response.StatusCode)
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return &RPCError{Text: rpcErrorText(envelope.Error)}
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("NEAR answered HTTP %d", response.StatusCode)
	}
	return json.Unmarshal(envelope.Result, result)
}

func rpcErrorText(raw json.RawMessage) string {
	var e struct {
		Name  string          `json:"name"`
		Cause json.RawMessage `json:"cause"`
		Data  json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &e)
	text := strings.TrimSpace(e.Name + " " + string(e.Cause))
	if len(text) > 400 {
		text = text[:400]
	}
	return text
}

// AccessKey is the nonce of a key and the hash of the block the node read
// it at: what the next transaction needs.
func (c *Client) AccessKey(ctx context.Context, account string, key ed25519.PublicKey) (nonce uint64, blockHash [32]byte, err error) {
	var result struct {
		Nonce     uint64 `json:"nonce"`
		BlockHash string `json:"block_hash"`
		Error     string `json:"error"`
	}
	params := map[string]any{"request_type": "view_access_key", "finality": "final", "account_id": account, "public_key": PublicKey(key)}
	if err = c.call(ctx, "query", params, &result); err != nil {
		return 0, blockHash, err
	}
	if result.Error != "" {
		return 0, blockHash, &RPCError{Text: result.Error}
	}
	hash, err := DecodeBase58(result.BlockHash)
	if err != nil || len(hash) != 32 {
		return 0, blockHash, errors.New("NEAR's block hash cannot be read")
	}
	copy(blockHash[:], hash)
	return result.Nonce, blockHash, nil
}

// Outcome is what a sent transaction did.
type Outcome struct {
	Hash string
	// Value is the function's return value, when it succeeded.
	Value []byte
	// Failure is the protocol's failure, when it failed.
	Failure string
	// Pending is true when the transaction was included but its outcome
	// was not known when the wait ended.
	Pending bool
}

// Send sends a signed transaction and waits until it has been executed.
func (c *Client) Send(ctx context.Context, signed []byte, hash [32]byte, waitUntil string) (Outcome, error) {
	outcome := Outcome{Hash: Base58(hash[:])}
	var result struct {
		Status json.RawMessage `json:"status"`
	}
	params := map[string]any{"signed_tx_base64": base64.StdEncoding.EncodeToString(signed), "wait_until": waitUntil}
	if err := c.call(ctx, "send_tx", params, &result); err != nil {
		return outcome, err
	}
	var status map[string]json.RawMessage
	if json.Unmarshal(result.Status, &status) != nil {
		outcome.Pending = true
		return outcome, nil
	}
	if failure, ok := status["Failure"]; ok {
		outcome.Failure = rpcFailure(failure)
		return outcome, nil
	}
	if value, ok := status["SuccessValue"]; ok {
		var encoded string
		if json.Unmarshal(value, &encoded) != nil {
			return outcome, errors.New("NEAR's return value cannot be read")
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return outcome, errors.New("NEAR's return value cannot be read")
		}
		outcome.Value = decoded
		return outcome, nil
	}
	outcome.Pending = true
	return outcome, nil
}

// rpcFailure is the contract's panic message when there is one.
func rpcFailure(raw json.RawMessage) string {
	var f struct {
		ActionError struct {
			Kind struct {
				FunctionCallError struct {
					ExecutionError string `json:"ExecutionError"`
				} `json:"FunctionCallError"`
			} `json:"kind"`
		} `json:"ActionError"`
	}
	if json.Unmarshal(raw, &f) == nil && f.ActionError.Kind.FunctionCallError.ExecutionError != "" {
		return f.ActionError.Kind.FunctionCallError.ExecutionError
	}
	text := string(raw)
	if len(text) > 400 {
		text = text[:400]
	}
	return text
}
