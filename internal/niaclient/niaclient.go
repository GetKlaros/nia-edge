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
}

// Enrollment is Nia's answer to a successful enrollment.
type Enrollment struct {
	MachineID        string    `json:"machine_id"`
	Key              string    `json:"key"`
	KeyExpiresAt     time.Time `json:"key_expires_at"`
	Role             string    `json:"role"`
	Upstream         string    `json:"upstream"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
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
	ServerTime       time.Time `json:"server_time"`
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

func (c *Client) post(ctx context.Context, path, bearer string, body any, want int, answer any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base.JoinPath(path).String(), bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
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
	if err := json.Unmarshal(raw, answer); err != nil {
		return fmt.Errorf("Nia's answer is not what was expected: %w", err)
	}
	return nil
}
