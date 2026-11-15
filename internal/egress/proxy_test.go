package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAuthority answers decisions and records what was asked.
type fakeAuthority struct {
	mu        sync.Mutex
	verdict   Verdict
	decideErr error
	connErr   error
	asked     []Request
	connected []Request
	refused   []string
}

func (a *fakeAuthority) Decide(_ context.Context, request Request) (Verdict, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, request)
	return a.verdict, a.decideErr
}

func (a *fakeAuthority) Connected(_ context.Context, request Request) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connected = append(a.connected, request)
	return a.connErr
}

func (a *fakeAuthority) Refused(request Request, problem string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refused = append(a.refused, request.Host+": "+problem)
}

func (a *fakeAuthority) counts() (asked, connected, refused int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.asked), len(a.connected), len(a.refused)
}

// world is a target server, a proxy in front of it, and a resolver that
// knows a few names. Dials are recorded.
type world struct {
	authority *fakeAuthority
	target    *httptest.Server
	proxy     *httptest.Server
	names     map[string][]netip.Addr
	mu        sync.Mutex
	resolved  []string
	dialed    []netip.AddrPort
}

func newWorld(t *testing.T, allowPrivate ...string) *world {
	t.Helper()
	w := &world{authority: &fakeAuthority{verdict: Verdict{Allowed: true}}, names: map[string][]netip.Addr{}}
	w.target = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rw.Header().Set("X-Seen-Host", r.Host)
		rw.Header().Set("X-Seen-Proxy-Auth", r.Header.Get("Proxy-Authorization"))
		rw.Header().Set("X-Seen-Forwarded", r.Header.Get("X-Forwarded-For"))
		fmt.Fprintf(rw, "%s %s %s", r.Method, r.URL.RequestURI(), body)
	}))
	t.Cleanup(w.target.Close)
	real := netip.MustParseAddrPort(w.target.Listener.Addr().String())
	w.proxy = httptest.NewServer(New(Options{
		Authority:    w.authority,
		Session:      "edge-test",
		Run:          "run-1",
		AllowPrivate: allowPrivate,
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.resolved = append(w.resolved, host)
			if addresses, ok := w.names[host]; ok {
				return addresses, nil
			}
			return nil, errors.New("no such host")
		},
		// Whatever public address was checked, the test target answers.
		Dial: func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
			w.mu.Lock()
			w.dialed = append(w.dialed, address)
			w.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, "tcp", real.String())
		},
	}))
	t.Cleanup(w.proxy.Close)
	return w
}

func (w *world) client() *http.Client {
	proxyURL, _ := url.Parse(w.proxy.URL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 10 * time.Second}
}

func (w *world) get(t *testing.T, target string) (*http.Response, string) {
	t.Helper()
	response, err := w.client().Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response, string(body)
}

func (w *world) dials() []netip.AddrPort {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]netip.AddrPort(nil), w.dialed...)
}

var public = netip.MustParseAddr("93.184.216.34")

func TestAnAllowedRequestGoesToTheAddressThatWasChecked(t *testing.T) {
	w := newWorld(t)
	w.names["example.com"] = []netip.Addr{public, netip.MustParseAddr("2606:2800:220:1::1")}
	request, _ := http.NewRequest(http.MethodPost, "http://Example.com:8080/a%20b?x=1", strings.NewReader("payload"))
	request.Header.Set("Proxy-Authorization", "Basic YWdlbnQ6c2VjcmV0")
	request.Header.Set("X-Forwarded-For", "10.9.9.9")
	response, err := w.client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "POST /a%20b?x=1 payload" {
		t.Fatalf("answer %d %q", response.StatusCode, body)
	}
	if response.Header.Get("X-Seen-Host") != "Example.com:8080" || response.Header.Get("X-Seen-Proxy-Auth") != "" || response.Header.Get("X-Seen-Forwarded") != "" {
		t.Errorf("the target saw host %q, proxy credentials %q, forwarded %q", response.Header.Get("X-Seen-Host"), response.Header.Get("X-Seen-Proxy-Auth"), response.Header.Get("X-Seen-Forwarded"))
	}
	asked := w.authority.asked[0]
	want := Request{Session: "edge-test", Run: "run-1", Host: "example.com", Port: 8080, Method: "POST", URL: "http://example.com:8080/a%20b?x=1"}
	if asked != want {
		t.Errorf("Nia was asked %+v, want %+v", asked, want)
	}
	if dials := w.dials(); len(dials) != 1 || dials[0] != netip.AddrPortFrom(public, 8080) {
		t.Errorf("dialed %v, want the first checked address", dials)
	}
	if len(w.resolved) != 1 {
		t.Errorf("the name was resolved %d times, want once", len(w.resolved))
	}
	if _, connected, _ := w.authority.counts(); connected != 1 {
		t.Errorf("Connected called %d times", connected)
	}
}

func TestAnInternalLiteralIsRefusedBeforeAnyDecision(t *testing.T) {
	w := newWorld(t)
	for _, target := range []string{
		"http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5:8080/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
		"http://[fd00::1]/", "http://[64:ff9b::7f00:1]/", "http://[2002:7f00:1::1]/", "http://0.0.0.0/", "http://192.168.1.1/",
	} {
		response, body := w.get(t, target)
		if response.StatusCode != http.StatusForbidden || !strings.Contains(body, "private or internal address") {
			t.Errorf("%s: %d %q", target, response.StatusCode, body)
		}
	}
	asked, connected, refused := w.authority.counts()
	if asked != 0 || connected != 0 || refused != 10 || len(w.dials()) != 0 || len(w.resolved) != 0 {
		t.Errorf("asked %d, connected %d, refused %d, dials %d, lookups %d", asked, connected, refused, len(w.dials()), len(w.resolved))
	}
}

func TestANameIsNotResolvedBeforeItIsAllowed(t *testing.T) {
	w := newWorld(t)
	w.names["secret-data.attacker.test"] = []netip.Addr{public}
	w.authority.verdict = Verdict{Message: "Nia denied egress (untrusted_session)."}
	response, body := w.get(t, "http://secret-data.attacker.test/")
	if response.StatusCode != http.StatusForbidden || !strings.Contains(body, "untrusted_session") {
		t.Errorf("%d %q", response.StatusCode, body)
	}
	w.authority.verdict = Verdict{Held: true, Message: "held", ApprovalID: "ap1"}
	response, _ = w.get(t, "http://secret-data.attacker.test/")
	if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Nia-Approval-Id") != "ap1" {
		t.Errorf("held: %d, approval %q", response.StatusCode, response.Header.Get("X-Nia-Approval-Id"))
	}
	if len(w.resolved) != 0 || len(w.dials()) != 0 {
		t.Errorf("a refused name was resolved (%v) or dialed (%v)", w.resolved, w.dials())
	}
}

func TestANameThatResolvesToAnInternalAddressIsRefused(t *testing.T) {
	w := newWorld(t)
	w.names["rebind.attacker.test"] = []netip.Addr{public, netip.MustParseAddr("127.0.0.1")}
	w.names["metadata.attacker.test"] = []netip.Addr{netip.MustParseAddr("169.254.169.254")}
	w.names["mapped.attacker.test"] = []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1")}
	w.names["zoned.attacker.test"] = []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}
	w.names["empty.attacker.test"] = nil
	for _, host := range []string{"rebind.attacker.test", "metadata.attacker.test", "mapped.attacker.test", "zoned.attacker.test", "empty.attacker.test", "unknown.attacker.test"} {
		response, body := w.get(t, "http://"+host+"/")
		if response.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d %q", host, response.StatusCode, body)
		}
	}
	if _, connected, refused := w.authority.counts(); connected != 0 || refused != 6 || len(w.dials()) != 0 {
		t.Errorf("connected %d, refused %d, dials %v", connected, refused, w.dials())
	}
}

func TestAllowPrivateExemptsOnlyTheListedHosts(t *testing.T) {
	w := newWorld(t, "db.internal", "*.svc.local", "127.0.0.1")
	internal := netip.MustParseAddr("10.1.2.3")
	w.names["db.internal"] = []netip.Addr{internal}
	w.names["api.svc.local"] = []netip.Addr{internal}
	w.names["other.internal"] = []netip.Addr{internal}
	for target, want := range map[string]int{
		"http://db.internal/":    200,
		"http://DB.Internal/":    200,
		"http://api.svc.local/":  200,
		"http://127.0.0.1/":      200,
		"http://other.internal/": 403,
		"http://127.0.0.2/":      403,
	} {
		if response, body := w.get(t, target); response.StatusCode != want {
			t.Errorf("%s: %d %q, want %d", target, response.StatusCode, body, want)
		}
	}
	// An exempt host is still decided by Nia.
	w.authority.verdict = Verdict{}
	if response, _ := w.get(t, "http://db.internal/"); response.StatusCode != http.StatusForbidden {
		t.Errorf("an exempt host was not decided: %d", response.StatusCode)
	}
}

func TestEverythingFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.names["example.com"] = []netip.Addr{public}
	w.authority.decideErr = errors.New("Nia answered 500")
	if response, body := w.get(t, "http://example.com/"); response.StatusCode != http.StatusBadGateway || !strings.Contains(body, "failed closed") {
		t.Errorf("decision error: %d %q", response.StatusCode, body)
	}
	w.authority.decideErr = nil
	w.authority.connErr = errors.New("Nia did not record the connection")
	if response, body := w.get(t, "http://example.com/"); response.StatusCode != http.StatusBadGateway || !strings.Contains(body, "failed closed") {
		t.Errorf("record error: %d %q", response.StatusCode, body)
	}
	if len(w.dials()) != 0 {
		t.Errorf("a connection was opened: %v", w.dials())
	}
	// An empty verdict is not an allow.
	w.authority.connErr = nil
	w.authority.verdict = Verdict{}
	if response, _ := w.get(t, "http://example.com/"); response.StatusCode != http.StatusForbidden {
		t.Errorf("an empty verdict: %d", response.StatusCode)
	}
}

// raw sends one request exactly as written and returns the status line and
// the rest of what the proxy answered.
func (w *world) raw(t *testing.T, request string) (string, *bufio.Reader, net.Conn) {
	t.Helper()
	conn, err := net.Dial("tcp", w.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, request)
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("%q: %v", request, err)
	}
	return strings.TrimSpace(status), reader, conn
}

func TestRequestsThatAreNotProxyRequestsAreRefused(t *testing.T) {
	w := newWorld(t)
	w.names["example.com"] = []netip.Addr{public}
	for request, want := range map[string]string{
		"GET /etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n":           "400",
		"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n":  "400",
		"GET ftp://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n":    "400",
		"GET http://example.com:0/ HTTP/1.1\r\nHost: example.com\r\n\r\n": "400",
		"GET http://example.com:99999/ HTTP/1.1\r\nHost: x\r\n\r\n":       "400",
		"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n":       "400",
		"CONNECT example.com:0 HTTP/1.1\r\nHost: example.com\r\n\r\n":     "400",
		"CONNECT example.com:70000 HTTP/1.1\r\nHost: example.com\r\n\r\n": "400",
		"CONNECT ::1:443 HTTP/1.1\r\nHost: x\r\n\r\n":                     "400",
		// Names some resolvers read as an address, each in its own way.
		"GET http://127.1/ HTTP/1.1\r\nHost: x\r\n\r\n":                        "400",
		"GET http://2130706433/ HTTP/1.1\r\nHost: x\r\n\r\n":                   "400",
		"GET http://0x7f.0.0.1/ HTTP/1.1\r\nHost: x\r\n\r\n":                   "400",
		"GET http://0177.0.0.1/ HTTP/1.1\r\nHost: x\r\n\r\n":                   "400",
		"CONNECT 0x7f000001:443 HTTP/1.1\r\nHost: x\r\n\r\n":                   "400",
		"CONNECT exa_mple.com.:443 HTTP/1.1\r\nHost: x\r\n\r\n":                "403",
		"CONNECT -bad-.example:443 HTTP/1.1\r\nHost: x\r\n\r\n":                "400",
		"CONNECT xn--e1afmkfd.example%00.evil:443 HTTP/1.1\r\nHost: x\r\n\r\n": "400",
	} {
		status, _, _ := w.raw(t, request)
		if !strings.Contains(status, " "+want+" ") {
			t.Errorf("%q: %s, want %s", strings.SplitN(request, "\r\n", 2)[0], status, want)
		}
	}
	if len(w.dials()) != 0 {
		t.Errorf("a connection was opened: %v", w.dials())
	}
}

func TestATunnelCarriesBytesBothWaysToTheCheckedAddress(t *testing.T) {
	w := newWorld(t)
	w.names["example.com"] = []netip.Addr{public}
	// The tunnel request and the first bytes for the target in one write.
	status, reader, conn := w.raw(t, "CONNECT Example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic YWdlbnQ6c2VjcmV0\r\n\r\nGET /through-the-tunnel HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if status != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status %q", status)
	}
	if line, _ := reader.ReadString('\n'); line != "\r\n" {
		t.Fatalf("after the status line: %q", line)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if string(body) != "GET /through-the-tunnel " {
		t.Errorf("through the tunnel: %q", body)
	}
	conn.Close()
	asked := w.authority.asked[0]
	want := Request{Session: "edge-test", Run: "run-1", Host: "example.com", Port: 443, Method: "CONNECT", URL: "https://example.com:443/"}
	if asked != want {
		t.Errorf("Nia was asked %+v, want %+v", asked, want)
	}
	if dials := w.dials(); len(dials) != 1 || dials[0] != netip.AddrPortFrom(public, 443) {
		t.Errorf("dialed %v", dials)
	}
}

func TestATunnelToAnInternalAddressIsRefused(t *testing.T) {
	w := newWorld(t)
	w.names["rebind.attacker.test"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	for _, target := range []string{"127.0.0.1:22", "[::1]:22", "169.254.169.254:80", "[::ffff:10.0.0.1]:443", "rebind.attacker.test:443"} {
		status, _, _ := w.raw(t, "CONNECT "+target+" HTTP/1.1\r\nHost: x\r\n\r\n")
		if status != "HTTP/1.1 403 Forbidden" {
			t.Errorf("CONNECT %s: %q", target, status)
		}
	}
	if len(w.dials()) != 0 {
		t.Errorf("a connection was opened: %v", w.dials())
	}
}

func TestATunnelEndsWhenTheTargetCloses(t *testing.T) {
	w := newWorld(t)
	w.names["example.com"] = []netip.Addr{public}
	status, reader, conn := w.raw(t, "CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(status, " 200 ") {
		t.Fatal(status)
	}
	reader.ReadString('\n')
	w.target.CloseClientConnections()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(reader); err != nil {
		t.Errorf("the client was not told the tunnel ended: %v", err)
	}
}
