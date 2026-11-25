package hostd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// HealthCheck is how nia-hostd knows the machine still works after a change:
// a page of a site served on the machine, or a port open on the loopback. A
// check reaches the loopback only, so it sends nothing out of the machine.
type HealthCheck struct {
	// HTTP is a URL on the loopback (http or https). Any answer under 500
	// is healthy: a 404 is a site that answers.
	HTTP string `json:"http,omitempty"`
	// Host is the Host header sent with HTTP, for a site served under its
	// name (blog.example.com), when the loopback serves several.
	Host string `json:"host,omitempty"`
	// TCP is host:port on the loopback.
	TCP string `json:"tcp,omitempty"`
}

// MaxHealth bounds a catalogue's health checks.
const MaxHealth = 16

// sshProbe is checked after every change whatever the catalogue says: the
// person must keep their way in.
var sshProbe = probe{name: "ssh (127.0.0.1:22)", tcp: "127.0.0.1:22"}

// healthWait is how long a change has to come back healthy.
const healthWait = 30 * time.Second

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostName is a DNS name, as a Host header carries it.
var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// validate says why a check cannot be run, or "".
func (h HealthCheck) validate() string {
	switch {
	case h.HTTP != "" && h.TCP != "", h.HTTP == "" && h.TCP == "":
		return "a health check is one http URL or one tcp address"
	case h.TCP != "":
		if h.Host != "" {
			return "host goes with http only"
		}
		host, port, err := net.SplitHostPort(h.TCP)
		if err != nil || !loopbackHost(host) || port == "" {
			return fmt.Sprintf("%q is not a loopback host:port", h.TCP)
		}
	default:
		u, err := url.Parse(h.HTTP)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || !loopbackHost(u.Hostname()) {
			return fmt.Sprintf("%q is not an http(s) URL on the loopback", h.HTTP)
		}
		if h.Host != "" && !hostName.MatchString(h.Host) {
			return fmt.Sprintf("%q is not a host name", h.Host)
		}
	}
	return ""
}

// probe is one thing to check: a check of the catalogue, ssh, or a service
// of the catalogue that must stay active.
type probe struct {
	name string
	http string
	host string
	tcp  string
	unit string
}

// Prober answers whether a probe passes. Tests set their own.
type Prober interface {
	Probe(ctx context.Context, p probe) bool
}

// probes are what is checked around a change: ssh, every service of the
// catalogue, every health check of the catalogue.
func probes(c *Catalogue) []probe {
	list := []probe{sshProbe}
	for _, name := range c.Services {
		list = append(list, probe{name: "service " + name, unit: unit(name)})
	}
	for _, h := range c.Health {
		if h.TCP != "" {
			list = append(list, probe{name: "tcp " + h.TCP, tcp: h.TCP})
			continue
		}
		name := "http " + h.HTTP
		if h.Host != "" {
			name += " (" + h.Host + ")"
		}
		list = append(list, probe{name: name, http: h.HTTP, host: h.Host})
	}
	return list
}

// baseline is what passes before a change: only that must pass after it. A
// site already down is not the change's doing.
func (s *Server) baseline(ctx context.Context, c *Catalogue) []probe {
	var passing []probe
	for _, p := range probes(c) {
		if s.prober().Probe(ctx, p) {
			passing = append(passing, p)
		}
	}
	return passing
}

// healthy waits up to healthWait for every probe that passed before to pass
// again, and names those that do not.
func (s *Server) healthy(ctx context.Context, before []probe) []string {
	wait := s.HealthWait
	if wait == 0 {
		wait = healthWait
	}
	deadline := time.Now().Add(wait)
	pending := before
	for {
		var still []probe
		for _, p := range pending {
			if !s.prober().Probe(ctx, p) {
				still = append(still, p)
			}
		}
		if len(still) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			var names []string
			for _, p := range still {
				names = append(names, p.name)
			}
			return names
		}
		pending = still
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Server) prober() Prober {
	if s.Probe != nil {
		return s.Probe
	}
	return systemProber{s}
}

// systemProber checks for real: a TCP connection, an HTTP request, or
// systemctl is-active. It follows no redirect: an answer is an answer.
type systemProber struct{ s *Server }

func (sp systemProber) Probe(ctx context.Context, p probe) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch {
	case p.tcp != "":
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.tcp)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	case p.http != "":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.http, nil)
		if err != nil {
			return false
		}
		if p.host != "" {
			req.Host = p.host
		}
		client := &http.Client{
			// The loopback's certificate names the site, not 127.0.0.1: the
			// check asks whether the site answers, not who it is.
			Transport: &http.Transport{
				Proxy:           nil,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: p.host}, //nolint:gosec // loopback liveness only
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode < 500
	case p.unit != "":
		_, err := sp.s.Run.Run(ctx, baseEnv, "systemctl", "is-active", "--quiet", "--", p.unit)
		return err == nil
	}
	return false
}

// unhealthy is the error of a change that broke what worked before it.
func unhealthy(names []string) error {
	return errors.New("the machine is not as healthy as before: " + strings.Join(names, ", ") + " no longer answers")
}

// reload reloads one service, its output kept with the apply's.
func (s *Server) reload(ctx context.Context, name string, output *strings.Builder) {
	runCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := s.Run.Run(runCtx, baseEnv, "systemctl", "reload-or-restart", "--", unit(name))
	fmt.Fprintf(output, "$ systemctl reload-or-restart %s\n%s", unit(name), out)
	if err != nil {
		fmt.Fprintf(output, "(%s)\n", err)
	}
}
