// Package relay is the door of an agent's sandbox: the agent sends its model
// and MCP calls to nia-edge, which forwards them to Nia with the machine's
// key. Nia decides; nothing is decided here.
//
// Three rules hold whatever the agent sends:
//
//   - The machine's key replaces any credential in the request. The sandbox
//     never holds a key, and cannot pick another one.
//   - The run that links this machine's conversations is nia-edge's, not the
//     agent's.
//   - Only Nia's agent routes are reachable (/v1/ and /mcp/). A failure to
//     reach Nia refuses the call.
package relay

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Options configures a relay.
type Options struct {
	// Nia is the base URL of the Nia instance.
	Nia *url.URL
	// Key is the machine's agent key.
	Key string
	// Run names the run sent with every call; empty sends none.
	Run string
	// Transport reaches Nia. Nil uses a transport without a proxy.
	Transport http.RoundTripper
	// Status reports what the last heartbeat learned, for the health route.
	Status func() string
	Logger *slog.Logger
}

// runPattern is the form Nia accepts for a run id.
var runPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ValidRun reports whether Nia would accept this run id.
func ValidRun(run string) bool { return runPattern.MatchString(run) }

// encodedSeparator matches an escaped dot, slash or backslash. A path that
// carries one could name another route once a server decodes it.
var encodedSeparator = regexp.MustCompile(`(?i)%2e|%2f|%5c`)

// allowed reports whether a request path is one of Nia's agent routes,
// written plainly: no dot segment, no empty segment, no escaped separator.
func allowed(u *url.URL) bool {
	escaped := u.EscapedPath()
	if strings.Contains(escaped, `\`) || encodedSeparator.MatchString(escaped) {
		return false
	}
	p := u.Path
	if clean := path.Clean(p); clean != p && clean+"/" != p {
		return false
	}
	return strings.HasPrefix(p, "/v1/") || strings.HasPrefix(p, "/mcp/")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// New returns the relay's handler.
func New(options Options) http.Handler {
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	transport := options.Transport
	if transport == nil {
		direct := http.DefaultTransport.(*http.Transport).Clone()
		// Straight to Nia: the proxy in the environment, if any, is the
		// agent's, and that is nia-edge.
		direct.Proxy = nil
		transport = direct
	}
	proxy := &httputil.ReverseProxy{
		// Rewrite, not Director: hop-by-hop headers are removed before it
		// runs, so a request cannot have the headers set here stripped by
		// listing them in its Connection header.
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(options.Nia)
			r.Out.Header.Del("X-Api-Key")
			r.Out.Header.Del("Proxy-Authorization")
			r.Out.Header.Set("Authorization", "Bearer "+options.Key)
			r.Out.Header.Del("X-Nia-Run-Id")
			if options.Run != "" {
				r.Out.Header.Set("X-Nia-Run-Id", options.Run)
			}
		},
		Transport: transport,
		// Model answers stream: pass each write on at once.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				logger.Error("cannot reach Nia", "path", r.URL.Path, "error", err.Error())
			}
			writeJSON(w, http.StatusBadGateway, map[string]apiError{"error": {Code: "nia_unreachable", Message: "nia-edge cannot reach Nia"}})
		},
	}
	health := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/edge/health" {
			ready := niaReady(r.Context(), health, options.Nia)
			status, nia := http.StatusOK, "ready"
			if !ready {
				status, nia = http.StatusServiceUnavailable, "unreachable"
			}
			body := map[string]string{"edge": "ok", "nia": nia}
			if options.Status != nil {
				body["machine"] = options.Status()
			}
			writeJSON(w, status, body)
			return
		}
		if !allowed(r.URL) {
			writeJSON(w, http.StatusNotFound, map[string]apiError{"error": {Code: "not_found"}})
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func niaReady(ctx context.Context, client *http.Client, nia *url.URL) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, nia.JoinPath("/health/ready").String(), nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusOK
}
