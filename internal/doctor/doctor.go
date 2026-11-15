// Package doctor checks, from where the agent runs, that nia-edge is its
// only way out.
//
// It starts a check on Nia through nia-edge, then tries every other way out:
// the check's canary URL without the proxy, raw TCP, the system resolver, a
// DNS query over UDP. Nia sees the canary hit itself, so a breach is recorded
// even when this program is lied to.
package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result of a run, as an exit code.
const (
	Isolated      = 0
	Breached      = 1
	CouldNotCheck = 2
)

// Options configures a run.
type Options struct {
	// Edge is the relay of nia-edge, as the agent reaches it.
	Edge string
	// Timeout bounds each attempt to get out.
	Timeout time.Duration
	Out     io.Writer
	// Probes replaces the attempts to get out; nil uses the real ones.
	Probes []Probe
}

// Probe is one attempt to get out without nia-edge. It reports whether the
// way is open, and a short detail.
type Probe struct {
	Name string
	Try  func(ctx context.Context, canaryURL string) (open bool, detail string)
}

// direct is a client that ignores any proxy: the point is to go around it.
func direct(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func reason(err error) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return fmt.Sprintf("%T", err)
}

// DefaultProbes are the ways out that are tried.
func DefaultProbes(timeout time.Duration) []Probe {
	tcp := func(address string) Probe {
		return Probe{Name: "tcp_" + address, Try: func(ctx context.Context, _ string) (bool, string) {
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
			if err != nil {
				return false, reason(err)
			}
			conn.Close()
			return true, "connected to " + address
		}}
	}
	return []Probe{
		{Name: "direct_http", Try: func(ctx context.Context, canaryURL string) (bool, string) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, canaryURL, nil)
			if err != nil {
				return false, "bad canary URL"
			}
			response, err := direct(timeout).Do(request)
			if err != nil {
				return false, reason(err)
			}
			response.Body.Close()
			// Any answer, whatever its status, means the request got out.
			return true, fmt.Sprintf("HTTP %d without the proxy", response.StatusCode)
		}},
		tcp("1.1.1.1:443"),
		tcp("8.8.8.8:53"),
		{Name: "public_dns", Try: func(ctx context.Context, _ string) (bool, string) {
			lookup, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			addresses, err := net.DefaultResolver.LookupHost(lookup, "example.com")
			if err != nil || len(addresses) == 0 {
				return false, "example.com does not resolve"
			}
			return true, "example.com -> " + strings.Join(addresses, ", ")
		}},
		{Name: "udp_dns_1.1.1.1", Try: func(ctx context.Context, _ string) (bool, string) {
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", "1.1.1.1:53")
			if err != nil {
				return false, reason(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(timeout))
			if _, err := conn.Write(dnsQuery("example.com")); err != nil {
				return false, reason(err)
			}
			if _, err := conn.Read(make([]byte, 512)); err != nil {
				return false, reason(err)
			}
			return true, "answer from 1.1.1.1:53"
		}},
	}
}

// dnsQuery is a DNS query for the A records of name (RFC 1035, section 4.1).
func dnsQuery(name string) []byte {
	query := []byte{0x4e, 0x1a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, part := range strings.Split(name, ".") {
		query = append(query, byte(len(part)))
		query = append(query, part...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

type started struct {
	CheckID   string `json:"check_id"`
	CanaryURL string `json:"canary_url"`
}

type verdict struct {
	Status        string `json:"status"`
	CanaryReached bool   `json:"canary_reached"`
}

type finding struct {
	Open   bool   `json:"open"`
	Detail string `json:"detail"`
}

// Run performs a check and returns Isolated, Breached or CouldNotCheck.
func Run(ctx context.Context, options Options) int {
	out := options.Out
	edge := strings.TrimRight(options.Edge, "/")
	client := direct(3 * options.Timeout)
	call := func(method, path string, body, answer any) error {
		var payload io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			if err != nil {
				return err
			}
			payload = bytes.NewReader(encoded)
		}
		request, err := http.NewRequestWithContext(ctx, method, edge+path, payload)
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Nia-Session-Id", "nia-doctor")
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", response.StatusCode)
		}
		if answer == nil {
			return nil
		}
		return json.Unmarshal(raw, answer)
	}

	var check started
	if err := call(http.MethodGet, "/edge/health", nil, nil); err != nil {
		fmt.Fprintf(out, "✗ nia-edge unreachable at %s, or it cannot reach Nia: %v\n", edge, err)
		return CouldNotCheck
	}
	if err := call(http.MethodPost, "/v1/doctor/start", struct{}{}, &check); err != nil || check.CheckID == "" || check.CanaryURL == "" {
		fmt.Fprintf(out, "✗ Nia refused the check: %v\n", err)
		return CouldNotCheck
	}

	probes := options.Probes
	if probes == nil {
		probes = DefaultProbes(options.Timeout)
	}
	findings := map[string]finding{}
	for _, probe := range probes {
		open, detail := probe.Try(ctx, check.CanaryURL)
		if len(detail) > 500 {
			detail = detail[:500]
		}
		findings[probe.Name] = finding{Open: open, Detail: detail}
		mark := "✓ closed"
		if open {
			mark = "✗ OPEN  "
		}
		fmt.Fprintf(out, "%s %-18s %s\n", mark, probe.Name, detail)
	}

	var result verdict
	if err := call(http.MethodPost, "/v1/doctor/report", map[string]any{"check_id": check.CheckID, "checks": findings}, &result); err != nil {
		fmt.Fprintf(out, "✗ Nia refused the report: %v\n", err)
		return CouldNotCheck
	}
	if result.CanaryReached {
		fmt.Fprintln(out, "✗ Nia received the canary directly: there is a route around nia-edge.")
	}
	// Nia's verdict, not this program's: it also knows about the canary.
	if result.Status == "isolated" {
		fmt.Fprintln(out, "✓ Isolated: nia-edge is the only way out. Status recorded on the machine in Nia.")
		return Isolated
	}
	fmt.Fprintln(out, "✗ BREACHED: this user has a way out that does not go through nia-edge.")
	return Breached
}
