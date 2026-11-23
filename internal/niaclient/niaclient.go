// Package niaclient is how nia-edge talks to Nia about itself: enrollment
// with a one-time token, then a heartbeat with the key it received.
package niaclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GetKlaros/nia-edge/internal/policy"
)

// maxAnswer bounds what is read from Nia: these answers are small.
const maxAnswer = 64 * 1024

// Report is what a machine says about itself. Nia shows it to admins and
// never uses it to decide anything.
type Report struct {
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	// ModelPath says where the agent's model calls go: provider, none or
	// relay. Heartbeats only; Nia shows it and decides nothing on it.
	ModelPath string `json:"model_path,omitempty"`
	// Journal is the head of nia-hostd's journal, and the hash of the entry
	// Nia last saw as its head. Heartbeats only, when nia-hostd answers.
	Journal *Journal `json:"journal,omitempty"`
	// Agents is the last report of nia-edge agents run as root: the agents
	// found on the machine, shown to admins, deciding nothing. Sent only to a
	// Nia that says it accepts it.
	Agents json.RawMessage `json:"agents,omitempty"`
}

// Journal anchors nia-hostd's hash chain in Nia (hostd.Anchor).
type Journal struct {
	Seq    int64  `json:"seq"`
	Hash   string `json:"hash,omitempty"`
	At     int64  `json:"at,omitempty"`
	AtHash string `json:"at_hash,omitempty"`
	Broken string `json:"broken,omitempty"`
}

// Enrollment is Nia's answer to a successful enrollment.
type Enrollment struct {
	MachineID        string    `json:"machine_id"`
	Key              string    `json:"key"`
	KeyExpiresAt     time.Time `json:"key_expires_at"`
	Role             string    `json:"role"`
	Upstream         string    `json:"upstream"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	// PolicyKey signs this machine's policy; nil when the server signs nothing.
	PolicyKey *policy.Key `json:"policy_key"`
}

// Policy names the policy version a machine is to apply.
type Policy struct {
	// Version is a number, or "file" for a policy kept in Nia's configuration.
	Version json.RawMessage `json:"version"`
	Digest  string          `json:"digest"`
}

// Beat is Nia's answer to a heartbeat.
type Beat struct {
	MachineID        string    `json:"machine_id"`
	Role             string    `json:"role"`
	RoleInPolicy     bool      `json:"role_in_policy"`
	Policy           *Policy   `json:"policy"`
	KeyExpiresAt     time.Time `json:"key_expires_at"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	// PolicyKeyID is the key the server signs with now; empty when it signs nothing.
	PolicyKeyID string    `json:"policy_key_id"`
	ServerTime  time.Time `json:"server_time"`
	// JournalSeq is the number of the head Nia last saw of nia-hostd's
	// journal; the next heartbeat shows the hash of that entry.
	JournalSeq int64 `json:"journal_seq"`
	// Accepts names the optional reports this Nia takes in a heartbeat.
	Accepts []string `json:"accepts"`
}

// Refused is an answer from Nia other than success. The message is Nia's;
// it never contains the token or the key that was presented.
type Refused struct {
	Status  int
	Code    string
	Message string
}

func (r *Refused) Error() string {
	if r.Code == "" {
		return fmt.Sprintf("Nia answered %d", r.Status)
	}
	return fmt.Sprintf("Nia answered %d %s: %s", r.Status, r.Code, r.Message)
}

// ParseBaseURL checks the URL of a Nia instance: https, or http for a Nia on
// this machine or on the local Docker network only, since the key travels in
// every request.
func ParseBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("the Nia URL must look like https://nia.example")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		switch parsed.Hostname() {
		case "localhost", "127.0.0.1", "::1", "nia":
		default:
			return nil, errors.New("the Nia URL must use https outside this machine")
		}
	default:
		return nil, errors.New("the Nia URL must use https")
	}
	return parsed, nil
}

// Client calls the machine routes of one Nia.
type Client struct {
	Base *url.URL
	// HTTP is the client to use; it must not follow redirects with the
	// Authorization header to another host. NewHTTPClient returns one.
	HTTP *http.Client
}

// NewHTTPClient returns a client that goes straight to Nia: no proxy from
// the environment (the agent's proxy is nia-edge itself), no redirects, and
// a time limit on the whole exchange.
func NewHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Enroll exchanges a one-time token for this machine's key.
func (c *Client) Enroll(ctx context.Context, token string, report Report) (*Enrollment, error) {
	var answer Enrollment
	if err := c.post(ctx, "/edge/v1/enroll", token, report, http.StatusCreated, &answer); err != nil {
		return nil, err
	}
	if answer.MachineID == "" || answer.Key == "" {
		return nil, errors.New("Nia's answer holds no machine key")
	}
	return &answer, nil
}

// Heartbeat tells Nia this machine is alive and learns the policy to apply.
// policyDigest is the digest of the policy applied locally, or "" for none.
func (c *Client) Heartbeat(ctx context.Context, key string, report Report, policyDigest string) (*Beat, error) {
	body := struct {
		Report
		PolicyDigest *string `json:"policy_digest"`
	}{Report: report}
	// The host name is fixed at enrollment; a heartbeat does not carry it.
	body.Hostname = ""
	if policyDigest != "" {
		body.PolicyDigest = &policyDigest
	}
	var answer Beat
	if err := c.post(ctx, "/edge/v1/heartbeat", key, body, http.StatusOK, &answer); err != nil {
		return nil, err
	}
	return &answer, nil
}

// Inventory sends what the machine found on itself (internal/inventory), as
// written, to a Nia that said it takes it. Nia shows it; it decides nothing.
func (c *Client) Inventory(ctx context.Context, key string, inventory json.RawMessage) error {
	return c.post(ctx, "/edge/v1/inventory", key, inventory, http.StatusNoContent, nil)
}

// SignedPolicy fetches the policy this machine is to apply, signed. It is not
// verified here: policy.Open does that, with the key pinned at enrollment.
func (c *Client) SignedPolicy(ctx context.Context, key string) (policy.Signed, error) {
	var answer policy.Signed
	if err := c.call(ctx, http.MethodGet, "/edge/v1/policy", key, nil, http.StatusOK, &answer); err != nil {
		return policy.Signed{}, err
	}
	return answer, nil
}

func (c *Client) post(ctx context.Context, path, bearer string, body any, want int, answer any) error {
	return c.call(ctx, http.MethodPost, path, bearer, body, want, answer)
}

// PaymentKey reports the agent's payment public key, which Nia records once,
// and answers the account Nia linked to it, if any.
func (c *Client) PaymentKey(ctx context.Context, key, publicKey string) (account string, err error) {
	var answer struct {
		AccountID *string `json:"account_id"`
	}
	if err := c.post(ctx, "/edge/v1/payment-key", key, map[string]string{"public_key": publicKey}, http.StatusOK, &answer); err != nil {
		return "", err
	}
	if answer.AccountID == nil {
		return "", nil
	}
	return *answer.AccountID, nil
}

// PaymentPlan asks Nia which vault operation a payment the agent asked for
// is: the agent names a recipient, an amount and a reason, Nia the rest.
func (c *Client) PaymentPlan(ctx context.Context, key string, arguments json.RawMessage) (json.RawMessage, error) {
	var answer json.RawMessage
	if err := c.post(ctx, "/edge/v1/payment-plan", key, map[string]any{"arguments": arguments}, http.StatusOK, &answer); err != nil {
		return nil, err
	}
	return answer, nil
}

// PaymentRefused tells Nia the vault refused the agent's call: Nia records it
// only once NEAR shows that transaction failing, so a reviewer sees it.
func (c *Client) PaymentRefused(ctx context.Context, key, vault, transaction string) error {
	return c.post(ctx, "/edge/v1/payment-refused", key, map[string]string{"vault": vault, "transaction": transaction}, http.StatusOK, nil)
}

// Visa asks Nia for the visa of an operation the agent prepared in its
// vault. Nia signs it only for the call its model path allowed.
func (c *Client) Visa(ctx context.Context, key, session, run, tool string, arguments json.RawMessage, opID string) (json.RawMessage, error) {
	var answer json.RawMessage
	headers := map[string]string{"x-nia-session-id": session}
	if run != "" {
		headers["x-nia-run-id"] = run
	}
	body := map[string]any{"tool": tool, "arguments": arguments, "op_id": opID}
	if err := c.callWith(ctx, http.MethodPost, "/v1/payments/visa", key, headers, body, http.StatusOK, &answer); err != nil {
		return nil, err
	}
	return answer, nil
}

func (c *Client) call(ctx context.Context, method, path, bearer string, body any, want int, answer any) error {
	return c.callWith(ctx, method, path, bearer, nil, body, want, answer)
}

func (c *Client) callWith(ctx context.Context, method, path, bearer string, headers map[string]string, body any, want int, answer any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.Base.JoinPath(path).String(), payload)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		// A *url.Error names the URL and the cause, never the headers.
		return fmt.Errorf("cannot reach Nia: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer+1))
	if err != nil {
		return fmt.Errorf("reading Nia's answer: %w", err)
	}
	if len(raw) > maxAnswer {
		return errors.New("Nia's answer is too large")
	}
	if response.StatusCode != want {
		refused := &Refused{Status: response.StatusCode}
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &envelope) == nil {
			refused.Code, refused.Message = envelope.Error.Code, envelope.Error.Message
		}
		return refused
	}
	if answer == nil {
		return nil
	}
	if err := json.Unmarshal(raw, answer); err != nil {
		return fmt.Errorf("Nia's answer is not what was expected: %w", err)
	}
	return nil
}

// PinTools reports the tools an MCP server hosted by its vendor lists, as
// this machine saw them: Nia pins them for the tenant and names back those
// the agent may see.
func (c *Client) PinTools(ctx context.Context, key, server string, tools []json.RawMessage) ([]string, error) {
	if tools == nil {
		tools = []json.RawMessage{}
	}
	var answer struct {
		Visible []string `json:"visible"`
	}
	if err := c.post(ctx, "/edge/v1/mcp/pins", key, map[string]any{"server": server, "tools": tools}, http.StatusOK, &answer); err != nil {
		return nil, err
	}
	if answer.Visible == nil {
		return nil, errors.New("Nia's answer names no tool list")
	}
	return answer.Visible, nil
}
