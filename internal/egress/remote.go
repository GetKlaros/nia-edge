package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Remote asks a Nia server to decide every connection, through its decision
// API, with the machine's key.
type Remote struct {
	Base *url.URL
	Key  string
	// HTTP reaches Nia; it must not follow redirects.
	HTTP *http.Client
	// Wait is how many seconds a held connection waits for a reviewer.
	Wait   int
	Logger *slog.Logger
}

const maxVerdict = 64 * 1024

func (r *Remote) post(ctx context.Context, path string, request Request, body any, timeout time.Duration, answer any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	call, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Base.JoinPath(path).String(), bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	call.Header.Set("Authorization", "Bearer "+r.Key)
	call.Header.Set("Content-Type", "application/json")
	call.Header.Set("X-Nia-Session-Id", request.Session)
	if request.Run != "" {
		call.Header.Set("X-Nia-Run-Id", request.Run)
	}
	response, err := r.HTTP.Do(call)
	if err != nil {
		return fmt.Errorf("cannot reach Nia: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxVerdict+1))
	if err != nil {
		return fmt.Errorf("reading Nia's answer: %w", err)
	}
	// Anything but a plain success is not a decision.
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Nia answered %d", response.StatusCode)
	}
	if len(raw) > maxVerdict {
		return fmt.Errorf("Nia's answer is too large")
	}
	if err := json.Unmarshal(raw, answer); err != nil {
		return fmt.Errorf("Nia's answer is not what was expected: %w", err)
	}
	return nil
}

// Decide asks Nia about one connection. Only the answer "allow" allows it.
func (r *Remote) Decide(ctx context.Context, request Request) (Verdict, error) {
	arguments := map[string]any{
		"url":    request.URL,
		"host":   request.Host,
		"port":   request.Port,
		"method": request.Method,
	}
	if request.Server != "" {
		// A role's rules can match it: each MCP server, its own hosts.
		arguments["server"] = request.Server
	}
	body := map[string]any{"tool": "egress", "arguments": arguments}
	if r.Wait > 0 {
		body["wait"] = r.Wait
	}
	var answer struct {
		Decision   string `json:"decision"`
		Message    string `json:"message"`
		ApprovalID string `json:"approval_id"`
	}
	if err := r.post(ctx, "/v1/tools/decide", request, body, 15*time.Second+time.Duration(r.Wait)*time.Second, &answer); err != nil {
		return Verdict{}, err
	}
	switch answer.Decision {
	case "allow":
		return Verdict{Allowed: true}, nil
	case "require_approval":
		return Verdict{Held: true, Message: answer.Message, ApprovalID: answer.ApprovalID}, nil
	case "deny":
		return Verdict{Message: answer.Message}, nil
	}
	return Verdict{}, fmt.Errorf("Nia's answer holds no decision")
}

// Connected reports that content is about to come back from the network, so
// that Nia hardens the session. If Nia cannot record it, the connection is
// refused.
func (r *Remote) Connected(ctx context.Context, request Request) error {
	output := "connection to " + request.Host + ":" + strconv.Itoa(request.Port)
	if request.Server != "" {
		output += " (MCP server " + request.Server + ")"
	}
	body := map[string]any{"tool": "egress", "output": output}
	var answer struct {
		Action string `json:"action"`
	}
	return r.post(ctx, "/v1/tools/result", request, body, 15*time.Second, &answer)
}

// Refused logs an address refused without a decision.
func (r *Remote) Refused(request Request, problem string) {
	if r.Logger != nil {
		r.Logger.Warn("egress refused", "method", request.Method, "host", request.Host, "port", request.Port, "server", request.Server, "problem", problem)
	}
}
