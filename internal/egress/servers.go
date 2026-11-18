package egress

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/peer"
)

var serverHeader = regexp.MustCompile(`^server ([a-z][a-z0-9_]{0,31})\n$`)

// ServeServers serves the MCP servers' connections, which nia-mcp hands
// over on a Unix socket: each starts with "server <name>\n", written by
// nia-mcp from the container's own socket, then is a proxy connection like
// the agent's. Only nia-mcp's user is served (allowed reports it from the
// peer's uid). proxyFor returns the proxy of one server; a name it does not
// know (nil) is refused.
func ServeServers(ctx context.Context, listener *net.UnixListener, allowed func(uid uint32) bool, proxyFor func(server string) http.Handler, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			uid, err := peer.UID(conn)
			if err != nil || !allowed(uid) {
				logger.Warn("egress of MCP servers: connection refused", "uid", uid)
				conn.Close()
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			header, err := readHeader(conn)
			_ = conn.SetReadDeadline(time.Time{})
			match := serverHeader.FindStringSubmatch(header)
			if err != nil || match == nil {
				conn.Close()
				return
			}
			handler := proxyFor(match[1])
			if handler == nil {
				logger.Warn("egress of an unknown MCP server refused", "server", match[1])
				conn.Close()
				return
			}
			serveOne(conn, handler)
		}()
	}
}

// readHeader reads one line byte by byte: what follows is the proxy
// connection, and must not be read here.
func readHeader(conn net.Conn) (string, error) {
	var line []byte
	one := make([]byte, 1)
	for len(line) < 64 {
		if _, err := conn.Read(one); err != nil {
			return "", err
		}
		line = append(line, one[0])
		if one[0] == '\n' {
			return string(line), nil
		}
	}
	return "", errors.New("header too long")
}

// serveOne serves HTTP on one connection, as the proxy does on its port.
func serveOne(conn net.Conn, handler http.Handler) {
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	listener := &single{conn: &closing{Conn: conn, closed: make(chan struct{})}}
	_ = server.Serve(listener)
}

// single is a listener of one connection: it gives it once, then waits
// until that connection is closed.
type single struct {
	conn *closing
	gave bool
	mu   sync.Mutex
}

func (s *single) Accept() (net.Conn, error) {
	s.mu.Lock()
	if !s.gave {
		s.gave = true
		s.mu.Unlock()
		return s.conn, nil
	}
	s.mu.Unlock()
	<-s.conn.closed
	return nil, net.ErrClosed
}

func (s *single) Close() error   { return nil }
func (s *single) Addr() net.Addr { return s.conn.LocalAddr() }

type closing struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closing) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}
