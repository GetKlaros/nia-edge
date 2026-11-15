package relay

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const machineKey = "nia_machine-key"

// fakeNia records what reaches Nia.
type fakeNia struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	handler  http.HandlerFunc
}

func newFakeNia(t *testing.T) *fakeNia {
	t.Helper()
	nia := &fakeNia{}
	nia.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		nia.mu.Lock()
		nia.requests = append(nia.requests, r)
		nia.bodies = append(nia.bodies, string(body))
		handler := nia.handler
		nia.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		if r.URL.Path == "/health/ready" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"decision":"allow"}`)
	}))
	t.Cleanup(nia.Close)
	return nia
}

func (n *fakeNia) last(t *testing.T) (*http.Request, string) {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.requests) == 0 {
		t.Fatal("nothing reached Nia")
	}
	return n.requests[len(n.requests)-1], n.bodies[len(n.bodies)-1]
}

func (n *fakeNia) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.requests)
}

func newEdge(t *testing.T, nia *fakeNia, run string) *httptest.Server {
	t.Helper()
	base, err := url.Parse(nia.URL)
	if err != nil {
		t.Fatal(err)
	}
	edge := httptest.NewServer(New(Options{Nia: base, Key: machineKey, Run: run, Status: func() string { return "active" }}))
	t.Cleanup(edge.Close)
	return edge
}

func do(t *testing.T, request *http.Request) (*http.Response, string) {
	t.Helper()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response, string(body)
}

func TestTheMachineKeyReplacesWhateverTheAgentSends(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "run-1")
	for name, headers := range map[string]http.Header{
		"no credential":      {},
		"its own bearer key": {"Authorization": {"Bearer nia_agent-chosen"}},
		"an x-api-key":       {"X-Api-Key": {"nia_agent-chosen"}},
		"both, and a run":    {"Authorization": {"Bearer nia_agent-chosen"}, "X-Api-Key": {"nia_agent-chosen"}, "X-Nia-Run-Id": {"agent-run"}},
		// Naming a header in Connection makes a proxy drop it as hop-by-hop.
		"headers named in Connection": {"Authorization": {"Bearer nia_agent-chosen"}, "X-Nia-Run-Id": {"agent-run"}, "Connection": {"Authorization, X-Nia-Run-Id"}},
		"proxy credentials":           {"Proxy-Authorization": {"Basic YWdlbnQ6c2VjcmV0"}},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, edge.URL+"/v1/tools/decide?x=1", strings.NewReader(`{"tool":"terminal"}`))
			request.Header = headers.Clone()
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Nia-Session-Id", "s1")
			response, body := do(t, request)
			if response.StatusCode != http.StatusOK || body != `{"decision":"allow"}` {
				t.Fatalf("answer %d %q", response.StatusCode, body)
			}
			got, sent := nia.last(t)
			if auth := got.Header.Values("Authorization"); len(auth) != 1 || auth[0] != "Bearer "+machineKey {
				t.Errorf("Authorization reaching Nia = %q, want the machine key alone", auth)
			}
			if got.Header.Get("X-Api-Key") != "" || got.Header.Get("Proxy-Authorization") != "" {
				t.Errorf("a credential of the agent reached Nia: %v", got.Header)
			}
			if run := got.Header.Values("X-Nia-Run-Id"); len(run) != 1 || run[0] != "run-1" {
				t.Errorf("X-Nia-Run-Id reaching Nia = %q, want the edge's run alone", run)
			}
			if got.Header.Get("X-Nia-Session-Id") != "s1" || got.URL.Path != "/v1/tools/decide" || got.URL.RawQuery != "x=1" || sent != `{"tool":"terminal"}` {
				t.Errorf("the call was not relayed as it was: %s %s %q %v", got.URL.Path, got.URL.RawQuery, sent, got.Header)
			}
			if strings.Contains(fmt.Sprint(got.Header), "agent-chosen") || strings.Contains(fmt.Sprint(got.Header), "agent-run") {
				t.Errorf("something the agent chose reached Nia: %v", got.Header)
			}
		})
	}
}

func TestNoRunIsSentWhenTheEdgeHasNone(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "")
	request, _ := http.NewRequest(http.MethodGet, edge.URL+"/v1/models", nil)
	request.Header.Set("X-Nia-Run-Id", "agent-run")
	do(t, request)
	if got, _ := nia.last(t); len(got.Header.Values("X-Nia-Run-Id")) != 0 {
		t.Errorf("a run reached Nia: %q", got.Header.Values("X-Nia-Run-Id"))
	}
}

// rawRequest sends a request line exactly as written, which http.Client
// would normalise.
func rawRequest(t *testing.T, edge *httptest.Server, line string) int {
	t.Helper()
	conn, err := net.Dial("tcp", edge.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "%s HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n", line)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	response.Body.Close()
	return response.StatusCode
}

func TestOnlyTheAgentRoutesLeaveTheEdge(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "run-1")
	for _, target := range []string{
		"/admin/api-keys", "/console", "/", "/v1", "/mcp", "/approvals/x", "/edge/v1/enroll", "/metrics", "/health/ready",
		"/v1/../admin/api-keys", "/v1/./../admin", "/mcp/../admin", "/v1//admin", "//v1/models",
		"/v1/%2e%2e/admin/api-keys", "/v1/%2E%2E/admin", "/v1/..%2fadmin", "/v1/%2Fadmin", "/v1/a%5c..%5cadmin", `/v1/..\admin`,
		"/V1/models", "/v1x/models", "/mcpx/a",
	} {
		before := nia.count()
		if status := rawRequest(t, edge, "GET "+target); status != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", target, status)
		}
		if nia.count() != before {
			got, _ := nia.last(t)
			t.Errorf("GET %s reached Nia as %s", target, got.URL.Path)
		}
	}
	for _, target := range []string{"/v1/models", "/v1/chat/completions", "/v1/tools/decide", "/mcp/github", "/v1/models/", "/v1/a%20b"} {
		before := nia.count()
		if status := rawRequest(t, edge, "GET "+target); status != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", target, status)
		}
		if nia.count() != before+1 {
			t.Errorf("GET %s did not reach Nia", target)
		}
	}
}

func TestARequestForAnotherHostStillGoesToNia(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "run-1")
	// The absolute form a client uses with a proxy.
	if status := rawRequest(t, edge, "GET http://attacker.test/v1/models"); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	got, _ := nia.last(t)
	if got.Host == "attacker.test" || got.Header.Get("Authorization") != "Bearer "+machineKey {
		t.Errorf("host %q, authorization %q", got.Host, got.Header.Get("Authorization"))
	}
	if status := rawRequest(t, edge, "GET http://attacker.test/admin"); status != http.StatusNotFound {
		t.Errorf("absolute form outside the agent routes: status %d, want 404", status)
	}
}

func TestAnUnreachableNiaRefusesTheCall(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "run-1")
	nia.Close()
	request, _ := http.NewRequest(http.MethodPost, edge.URL+"/v1/chat/completions", strings.NewReader(`{}`))
	response, body := do(t, request)
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(body, `"nia_unreachable"`) {
		t.Errorf("answer %d %q, want 502 nia_unreachable", response.StatusCode, body)
	}
	health, body := do(t, mustGet(edge.URL+"/edge/health"))
	if health.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, `"nia":"unreachable"`) {
		t.Errorf("health %d %q", health.StatusCode, body)
	}
}

func mustGet(target string) *http.Request {
	request, _ := http.NewRequest(http.MethodGet, target, nil)
	return request
}

func TestHealth(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "run-1")
	response, body := do(t, mustGet(edge.URL+"/edge/health"))
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `"nia":"ready"`) || !strings.Contains(body, `"machine":"active"`) {
		t.Errorf("health %d %q", response.StatusCode, body)
	}
	// The health check carries no key.
	if got, _ := nia.last(t); got.Header.Get("Authorization") != "" {
		t.Errorf("the health check sent a credential: %q", got.Header.Get("Authorization"))
	}
}

func TestNiaAnswersPassThroughAsTheyAre(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "run-1")
	nia.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.test/")
		w.Header().Set("X-Nia-Decision", "deny")
		w.WriteHeader(http.StatusFound)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := noRedirect.Do(mustGet(edge.URL + "/v1/models"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	// A redirect is handed back, not followed with the key.
	if response.StatusCode != http.StatusFound || response.Header.Get("X-Nia-Decision") != "deny" || nia.count() != 1 {
		t.Errorf("status %d, header %q, %d requests to Nia", response.StatusCode, response.Header.Get("X-Nia-Decision"), nia.count())
	}
}

func TestStreamedAnswersArriveAsTheyAreWritten(t *testing.T) {
	nia := newFakeNia(t)
	edge := newEdge(t, nia, "run-1")
	release := make(chan struct{})
	nia.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: [DONE]\n\n")
	}
	response, err := http.DefaultClient.Do(mustGet(edge.URL + "/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	first := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		first <- line
	}()
	select {
	case line := <-first:
		if line != "data: first\n" {
			t.Errorf("first line %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first event was held back until the stream ended")
	}
	close(release)
	rest, _ := io.ReadAll(reader)
	if !strings.Contains(string(rest), "data: [DONE]") {
		t.Errorf("rest of the stream %q", rest)
	}
}

func TestValidRun(t *testing.T) {
	for run, want := range map[string]bool{"edge-host": true, "a.b_c:d-1": true, "": false, "bad id!": false, strings.Repeat("a", 129): false, "é": false} {
		if ValidRun(run) != want {
			t.Errorf("ValidRun(%q) = %v", run, !want)
		}
	}
}
