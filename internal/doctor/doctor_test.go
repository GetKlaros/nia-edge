package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeEdge answers the routes the doctor uses, as nia-edge relays them.
type fakeEdge struct {
	*httptest.Server
	canaryHits int
	report     map[string]map[string]any
	healthCode int
	startCode  int
	reportCode int
	// lie makes the server call a breached machine isolated, to check whose verdict is used.
	sessions []string
}

func newFakeEdge(t *testing.T) *fakeEdge {
	t.Helper()
	edge := &fakeEdge{healthCode: 200, startCode: 200, reportCode: 200}
	edge.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		edge.sessions = append(edge.sessions, r.Header.Get("X-Nia-Session-Id"))
		switch r.URL.Path {
		case "/edge/health":
			w.WriteHeader(edge.healthCode)
			fmt.Fprint(w, `{"edge":"ok"}`)
		case "/v1/doctor/start":
			w.WriteHeader(edge.startCode)
			fmt.Fprintf(w, `{"check_id":"check-1","canary_url":%q}`, edge.URL+"/doctor/canary/check-1")
		case "/doctor/canary/check-1":
			edge.canaryHits++
			w.WriteHeader(http.StatusNoContent)
		case "/v1/doctor/report":
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				CheckID string                    `json:"check_id"`
				Checks  map[string]map[string]any `json:"checks"`
			}
			_ = json.Unmarshal(raw, &body)
			edge.report = body.Checks
			open := edge.canaryHits > 0
			for _, check := range body.Checks {
				if check["open"] == true {
					open = true
				}
			}
			status := "isolated"
			if open {
				status = "breached"
			}
			w.WriteHeader(edge.reportCode)
			fmt.Fprintf(w, `{"status":%q,"canary_reached":%v}`, status, edge.canaryHits > 0)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(edge.Close)
	return edge
}

func closed(name string) Probe {
	return Probe{Name: name, Try: func(context.Context, string) (bool, string) { return false, "refused" }}
}

func run(edge *fakeEdge, probes ...Probe) (int, string) {
	var out bytes.Buffer
	code := Run(context.Background(), Options{Edge: edge.URL + "/", Timeout: 2 * time.Second, Out: &out, Probes: probes})
	return code, out.String()
}

func TestIsolatedWhenEveryWayOutIsClosed(t *testing.T) {
	edge := newFakeEdge(t)
	code, out := run(edge, closed("direct_http"), closed("tcp_1.1.1.1:443"))
	if code != Isolated || !strings.Contains(out, "✓ Isolated") || strings.Count(out, "✓ closed") != 2 {
		t.Errorf("exit %d\n%s", code, out)
	}
	if edge.report["direct_http"]["open"] != false || edge.report["tcp_1.1.1.1:443"]["detail"] != "refused" {
		t.Errorf("report %v", edge.report)
	}
	for _, session := range edge.sessions {
		if session != "nia-doctor" {
			t.Errorf("session %q", session)
		}
	}
}

func TestBreachedWhenOneWayOutIsOpen(t *testing.T) {
	edge := newFakeEdge(t)
	open := Probe{Name: "tcp_8.8.8.8:53", Try: func(context.Context, string) (bool, string) { return true, strings.Repeat("x", 900) }}
	code, out := run(edge, closed("direct_http"), open)
	if code != Breached || !strings.Contains(out, "✗ OPEN") || !strings.Contains(out, "BREACHED") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if detail, _ := edge.report["tcp_8.8.8.8:53"]["detail"].(string); len(detail) != 500 {
		t.Errorf("detail of %d characters sent, want it cut to 500", len(detail))
	}
}

// The real probe reaches the canary when nothing stops it, and Nia's own
// count of that hit decides, whatever this program reports.
func TestTheCanaryIsReachedWithoutAProxyAndNiaDecides(t *testing.T) {
	edge := newFakeEdge(t)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	direct := DefaultProbes(2 * time.Second)[0]
	if direct.Name != "direct_http" {
		t.Fatalf("first probe is %q", direct.Name)
	}
	code, out := run(edge, direct)
	if code != Breached || edge.canaryHits != 1 || !strings.Contains(out, "HTTP 204 without the proxy") || !strings.Contains(out, "received the canary") {
		t.Errorf("exit %d, %d canary hits\n%s", code, edge.canaryHits, out)
	}
	// A program that claims every way is closed is still breached: Nia saw the canary.
	lying := Probe{Name: "direct_http", Try: func(ctx context.Context, canary string) (bool, string) {
		direct.Try(ctx, canary)
		return false, "nothing to see"
	}}
	edge2 := newFakeEdge(t)
	if code, out := run(edge2, lying); code != Breached {
		t.Errorf("a lying probe: exit %d\n%s", code, out)
	}
}

func TestCouldNotCheck(t *testing.T) {
	for name, change := range map[string]func(*fakeEdge){
		"nia-edge cannot reach Nia": func(e *fakeEdge) { e.healthCode = 503 },
		"Nia refuses the check":     func(e *fakeEdge) { e.startCode = 401 },
		"Nia refuses the report":    func(e *fakeEdge) { e.reportCode = 404 },
	} {
		edge := newFakeEdge(t)
		change(edge)
		if code, out := run(edge, closed("direct_http")); code != CouldNotCheck {
			t.Errorf("%s: exit %d\n%s", name, code, out)
		}
	}
	var out bytes.Buffer
	if code := Run(context.Background(), Options{Edge: "http://127.0.0.1:1", Timeout: time.Second, Out: &out}); code != CouldNotCheck {
		t.Errorf("no nia-edge: exit %d\n%s", code, out.String())
	}
}

func TestDNSQuery(t *testing.T) {
	want := []byte{0x4e, 0x1a, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if got := dnsQuery("example.com"); !bytes.Equal(got, want) {
		t.Errorf("dnsQuery = % x", got)
	}
}

func TestTheProbesHaveTheNamesNiaExpects(t *testing.T) {
	var names []string
	for _, probe := range DefaultProbes(time.Second) {
		names = append(names, probe.Name)
	}
	if got := strings.Join(names, " "); got != "direct_http tcp_1.1.1.1:443 tcp_8.8.8.8:53 public_dns udp_dns_1.1.1.1" {
		t.Errorf("probes: %s", got)
	}
}
