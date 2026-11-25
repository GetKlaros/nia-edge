package hostd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// scripted answers each probe by name: up before the change, then what
// after says.
type scripted struct {
	mu      sync.Mutex
	changed bool
	before  map[string]bool
	after   map[string]bool
	asked   []string
}

func (p *scripted) Probe(_ context.Context, pr probe) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, pr.name)
	if p.changed {
		up, ok := p.after[pr.name]
		return !ok || up
	}
	return p.before[pr.name]
}

func TestAHealthCheckReachesTheLoopbackOnly(t *testing.T) {
	for _, h := range []HealthCheck{
		{HTTP: "http://127.0.0.1/"},
		{HTTP: "https://localhost:8443/health", Host: "blog.example.com"},
		{HTTP: "http://[::1]:8080/"},
		{TCP: "127.0.0.1:5432"},
	} {
		if why := h.validate(); why != "" {
			t.Errorf("%+v refused: %s", h, why)
		}
	}
	for _, h := range []HealthCheck{
		{},
		{HTTP: "http://example.com/"},
		{HTTP: "http://10.0.0.1/"},
		{HTTP: "ftp://127.0.0.1/"},
		{HTTP: "http://user:pw@127.0.0.1/"},
		{HTTP: "http://127.0.0.1/", TCP: "127.0.0.1:80"},
		{HTTP: "http://127.0.0.1/", Host: "bad host"},
		{TCP: "8.8.8.8:53"},
		{TCP: "127.0.0.1"},
		{TCP: "127.0.0.1:22", Host: "x"},
	} {
		if why := h.validate(); why == "" {
			t.Errorf("%+v accepted", h)
		}
	}
	raw, _ := json.Marshal(map[string]any{"health": []HealthCheck{{HTTP: "http://192.168.1.1/"}}})
	if _, err := ParseCatalogue(raw); err == nil {
		t.Error("a catalogue with a check off the loopback was read")
	}
}

func TestTheSystemProberAsksTheLoopback(t *testing.T) {
	var host string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		if r.URL.Path == "/broken" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "http://example.com/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer site.Close()
	sp := systemProber{&Server{}}
	ctx := context.Background()
	if !sp.Probe(ctx, probe{http: site.URL + "/", host: "blog.example.com"}) || host != "blog.example.com" {
		t.Errorf("a site that answers 404 under its name: host %q", host)
	}
	if !sp.Probe(ctx, probe{http: site.URL + "/moved"}) {
		t.Error("a redirect is an answer, not followed")
	}
	if sp.Probe(ctx, probe{http: site.URL + "/broken"}) {
		t.Error("a 502 passed")
	}
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	if !sp.Probe(ctx, probe{tcp: addr}) {
		t.Error("an open port did not pass")
	}
	listener.Close()
	if sp.Probe(ctx, probe{tcp: addr}) {
		t.Error("a closed port passed")
	}
}

func TestOnlyWhatPassedBeforeMustPassAfter(t *testing.T) {
	raw := `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],` +
		`"host":{"services":["nginx","postgresql@16-main"],"health":[{"http":"http://127.0.0.1/","host":"blog.example.com"}]}}`
	s, _, _ := machine(t, raw)
	c, err := s.Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	p := &scripted{before: map[string]bool{"ssh (127.0.0.1:22)": true, "service nginx": true, "http http://127.0.0.1/ (blog.example.com)": true}}
	s.Probe, s.HealthWait = p, 10*time.Millisecond
	before := s.baseline(context.Background(), c)
	if len(before) != 3 {
		t.Fatalf("baseline %+v", before)
	}
	// postgresql was down before: the change is not blamed for it.
	p.changed, p.after = true, map[string]bool{"service postgresql@16-main": false}
	if names := s.healthy(context.Background(), before); names != nil {
		t.Errorf("blamed for %v", names)
	}
	p.after = map[string]bool{"http http://127.0.0.1/ (blog.example.com)": false}
	if names := s.healthy(context.Background(), before); strings.Join(names, ",") != "http http://127.0.0.1/ (blog.example.com)" {
		t.Errorf("unhealthy %v", names)
	}
}

func TestAPackageThatBreaksTheMachineIsRemoved(t *testing.T) {
	s, run, _ := machine(t, role)
	s.Probe, s.HealthWait = &scripted{
		before: map[string]bool{"ssh (127.0.0.1:22)": true, "service nginx": true},
		after:  map[string]bool{"service nginx": false},
	}, 10*time.Millisecond
	p := s.Probe.(*scripted)
	run.After = func(argv []string) {
		if strings.Join(argv[:2], " ") == "apt-get install" {
			p.changed = true
		}
	}
	resp := s.Do(context.Background(), Request{Action: PackageInstall, Name: "fail2ban"})
	if resp.OK || !strings.Contains(resp.Error, "service nginx no longer answers") || !strings.Contains(resp.Error, "it was removed") {
		t.Fatalf("%+v", resp)
	}
	last := run.Calls[len(run.Calls)-1]
	if strings.Join(last, " ") != "apt-get remove -y -q -- fail2ban" {
		t.Errorf("calls %q", run.Calls)
	}
	entries, _ := s.Journal()
	if len(entries) != 1 || entries[0].OK || entries[0].Undo != nil {
		t.Errorf("journal %+v", entries)
	}
}
