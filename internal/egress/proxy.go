package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	connectTimeout = 10 * time.Second
	idleTimeout    = 5 * time.Minute
)

// Request is one outbound connection, as Nia is asked about it.
type Request struct {
	Session string
	// Run links this connection to the machine's conversations; empty for none.
	Run    string
	Host   string
	Port   int
	Method string
	// URL is the full URL for plain HTTP, https://host:port/ for a tunnel.
	URL string
}

// Verdict is Nia's answer for a connection.
type Verdict struct {
	// Allowed is true only for an explicit "allow".
	Allowed bool
	// Held is true when a reviewer may still approve the connection.
	Held       bool
	Message    string
	ApprovalID string
}

// Authority is where decisions come from. An error from Decide or Connected
// refuses the connection.
type Authority interface {
	Decide(ctx context.Context, request Request) (Verdict, error)
	// Connected is called once an allowed connection is about to open:
	// content comes back through it, which taints the session.
	Connected(ctx context.Context, request Request) error
	// Refused is called when a rule that needs no decision refuses an address.
	Refused(request Request, problem string)
}

// Options configures the proxy.
type Options struct {
	Authority Authority
	Session   string
	Run       string
	// AllowPrivate lists the hosts allowed on internal addresses: exact
	// names or addresses, or "*.suffix".
	AllowPrivate []string
	// Resolve looks a name up. Nil uses the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Dial opens a connection to an address. Nil dials TCP.
	Dial   func(ctx context.Context, address netip.AddrPort) (net.Conn, error)
	Logger *slog.Logger
}

type outcome struct {
	address    netip.Addr
	status     int
	message    string
	approvalID string
}

type pinnedKey struct{}

// connectTarget is the form of a CONNECT target: host:port, the host being a
// name, an IPv4 address or a bracketed IPv6 address.
var connectTarget = regexp.MustCompile(`^(\[[0-9a-fA-F:.]+\]|[^:\s]+):(\d{1,5})$`)

var label = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
var numericLabel = regexp.MustCompile(`^([0-9]+|0[xX][0-9a-fA-F]*)$`)

// validName reports whether host is a DNS name written plainly. A name whose
// last label is a number ("127.1", "0x7f.0.0.1", "2130706433") is refused:
// some resolvers read it as an IP address, in ways that differ.
func validName(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, part := range labels {
		if !label.MatchString(part) {
			return false
		}
	}
	return !numericLabel.MatchString(labels[len(labels)-1])
}

// New returns the proxy's handler. It serves HTTP/1 proxy requests only:
// CONNECT host:port for tunnels, and absolute http:// URLs.
func New(options Options) http.Handler {
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	resolve := options.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	dial := options.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: connectTimeout}
		dial = func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address.String())
		}
	}

	decide := func(ctx context.Context, request Request) outcome {
		target := net.JoinHostPort(request.Host, strconv.Itoa(request.Port))
		literal, parseErr := netip.ParseAddr(request.Host)
		isLiteral := parseErr == nil
		exempt := HostMatches(request.Host, options.AllowPrivate)
		// An internal IP literal never reaches a decision or a reviewer.
		if isLiteral && IsPrivateAddr(literal) && !exempt {
			options.Authority.Refused(request, "private or internal address")
			return outcome{status: http.StatusForbidden, message: fmt.Sprintf("Nia denied the connection to %s (private or internal address).", target)}
		}
		if !isLiteral && !validName(request.Host) {
			options.Authority.Refused(request, "not a host name")
			return outcome{status: http.StatusBadRequest, message: "Nia egress proxy: not a host name"}
		}
		verdict, err := options.Authority.Decide(ctx, request)
		if err != nil {
			logger.Error("egress failed closed", "target", target, "error", err.Error())
			return outcome{status: http.StatusBadGateway, message: "Nia egress proxy failed closed"}
		}
		if !verdict.Allowed {
			message := verdict.Message
			if message == "" {
				if verdict.Held {
					message = fmt.Sprintf("Nia is holding the connection to %s.", target)
				} else {
					message = fmt.Sprintf("Nia denied the connection to %s.", target)
				}
			}
			return outcome{status: http.StatusForbidden, message: message, approvalID: verdict.ApprovalID}
		}
		// Resolved only now, once, and the connection goes to what was checked.
		addresses := []netip.Addr{literal}
		if !isLiteral {
			addresses, err = resolve(ctx, request.Host)
			if err != nil {
				addresses = nil
			}
		}
		problem := ""
		switch {
		case len(addresses) == 0:
			problem = "the name does not resolve"
		case !exempt:
			for _, address := range addresses {
				if IsPrivateAddr(address) {
					problem = "private or internal address"
					break
				}
			}
		}
		if problem != "" {
			options.Authority.Refused(request, problem)
			return outcome{status: http.StatusForbidden, message: fmt.Sprintf("Nia denied the connection to %s (%s).", target, problem)}
		}
		if err := options.Authority.Connected(ctx, request); err != nil {
			logger.Error("egress failed closed", "target", target, "error", err.Error())
			return outcome{status: http.StatusBadGateway, message: "Nia egress proxy failed closed"}
		}
		return outcome{address: addresses[0].Unmap().WithZone("")}
	}

	refuse := func(w http.ResponseWriter, result outcome) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Connection", "close")
		if result.approvalID != "" {
			w.Header().Set("X-Nia-Approval-Id", result.approvalID)
		}
		w.WriteHeader(result.status)
		fmt.Fprintln(w, result.message)
	}

	transport := &http.Transport{
		// Never through another proxy, and one connection per request: each
		// request has its own decision and its own checked address.
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			pinned, ok := ctx.Value(pinnedKey{}).(netip.AddrPort)
			if !ok {
				return nil, errors.New("egress: no checked address for this request")
			}
			return dial(ctx, pinned)
		},
	}
	forward := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.Host = r.Out.URL.Host
			// The target must not learn that a proxy holds credentials.
			r.Out.Header.Del("Proxy-Authorization")
			r.Out.URL.User = nil
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			refuse(w, outcome{status: http.StatusBadGateway, message: "Nia egress proxy: upstream unreachable"})
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := Request{Session: options.Session, Run: options.Run, Method: r.Method}
		if r.Method == http.MethodConnect {
			match := connectTarget.FindStringSubmatch(r.RequestURI)
			if match == nil {
				refuse(w, outcome{status: http.StatusBadRequest, message: "Nia egress proxy: CONNECT host:port expected"})
				return
			}
			request.Host = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(match[1], "["), "]"))
			request.Port, _ = strconv.Atoi(match[2])
			if request.Port < 1 || request.Port > 65535 {
				refuse(w, outcome{status: http.StatusBadRequest, message: "Nia egress proxy: bad port"})
				return
			}
			request.URL = "https://" + net.JoinHostPort(request.Host, match[2]) + "/"
			result := decide(r.Context(), request)
			if result.status != 0 {
				refuse(w, result)
				return
			}
			tunnel(w, r, dial, netip.AddrPortFrom(result.address, uint16(request.Port)), refuse)
			return
		}

		if !r.URL.IsAbs() || r.URL.Host == "" {
			refuse(w, outcome{status: http.StatusBadRequest, message: "Nia egress proxy: absolute URL expected"})
			return
		}
		if r.URL.Scheme != "http" {
			refuse(w, outcome{status: http.StatusBadRequest, message: "Nia egress proxy: use CONNECT for https"})
			return
		}
		request.Host = strings.ToLower(r.URL.Hostname())
		request.Port = 80
		if port := r.URL.Port(); port != "" {
			parsed, err := strconv.Atoi(port)
			if err != nil || parsed < 1 || parsed > 65535 {
				refuse(w, outcome{status: http.StatusBadRequest, message: "Nia egress proxy: bad port"})
				return
			}
			request.Port = parsed
		}
		shown := url.URL{Scheme: "http", Host: strings.ToLower(r.URL.Host), Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		request.URL = shown.String()
		result := decide(r.Context(), request)
		if result.status != 0 {
			refuse(w, result)
			return
		}
		pinned := netip.AddrPortFrom(result.address, uint16(request.Port))
		forward.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), pinnedKey{}, pinned)))
	})
}

// tunnel connects the client to the checked address and copies bytes both
// ways until one side ends or nothing moves for idleTimeout.
func tunnel(w http.ResponseWriter, r *http.Request, dial func(context.Context, netip.AddrPort) (net.Conn, error), address netip.AddrPort, refuse func(http.ResponseWriter, outcome)) {
	dialContext, cancel := context.WithTimeout(r.Context(), connectTimeout)
	upstream, err := dial(dialContext, address)
	cancel()
	if err != nil {
		refuse(w, outcome{status: http.StatusBadGateway, message: "Nia egress proxy: upstream unreachable"})
		return
	}
	defer upstream.Close()
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		refuse(w, outcome{status: http.StatusInternalServerError, message: "Nia egress proxy: this connection cannot be tunnelled"})
		return
	}
	defer client.Close()
	// The server may have left deadlines on the connection.
	_ = client.SetDeadline(time.Time{})
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// Bytes the client sent right after its request are already read.
	if pending := buffered.Reader.Buffered(); pending > 0 {
		early, _ := buffered.Reader.Peek(pending)
		if _, err := upstream.Write(early); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { copyUntilIdle(upstream, client); done <- struct{}{} }()
	go func() { copyUntilIdle(client, upstream); done <- struct{}{} }()
	// When one direction ends, the other is given the idle time to finish.
	<-done
	select {
	case <-done:
	case <-time.After(idleTimeout):
	}
}

// copyUntilIdle copies src to dst, and gives up when nothing was read for
// idleTimeout. When src ends, the writing side of dst is closed so the peer
// sees the end.
func copyUntilIdle(dst, src net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buffer)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, writeErr := dst.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if half, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
					return
				}
			}
			_ = dst.Close()
			return
		}
	}
}
