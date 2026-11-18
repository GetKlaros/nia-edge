package mcpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/peer"
)

// Server is nia-mcp: it starts one container per connection of nia-edge,
// and stops it when the connection ends.
type Server struct {
	Podman Podman
	// Sockets is the directory of the containers' egress sockets: nia-mcp's
	// alone (0700).
	Sockets string
	// Upstream is nia-edge's socket for the servers' connections.
	Upstream string
	// Max bounds the containers that run at once; zero is 32.
	Max int
	// Grace is how long a server has to end once its input closed, before
	// it is stopped, then killed; zero is five seconds.
	Grace  time.Duration
	Logger *slog.Logger

	mu      sync.Mutex
	running int
}

func (s *Server) log(msg string, args ...any) {
	if s.Logger != nil {
		s.Logger.Info(msg, args...)
	}
}

func (s *Server) take() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := s.Max
	if limit <= 0 {
		limit = 32
	}
	if s.running >= limit {
		return false
	}
	s.running++
	return true
}

func (s *Server) give() {
	s.mu.Lock()
	s.running--
	s.mu.Unlock()
}

// Serve starts a server for each connection whose peer is allowed, until
// ctx ends. The containers end with ctx.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener, allowed func(uid uint32) bool) error {
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
		go s.serveConn(ctx, conn, allowed)
	}
}

func refuse(conn net.Conn, why string) {
	_ = json.NewEncoder(conn).Encode(Ack{Error: why})
}

func (s *Server) serveConn(ctx context.Context, conn *net.UnixConn, allowed func(uid uint32) bool) {
	defer conn.Close()
	uid, err := peer.UID(conn)
	if err != nil || !allowed(uid) {
		s.log("connection refused", "uid", uid, "error", fmt.Sprint(err))
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(conn, 64<<10)
	line, err := readLine(reader, maxLaunchLen)
	if err != nil {
		refuse(conn, "not a launch")
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var launch Launch
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&launch) != nil {
		refuse(conn, "not a launch")
		return
	}
	if err := launch.Validate(); err != nil {
		refuse(conn, err.Error())
		return
	}
	if !s.take() {
		refuse(conn, "too many MCP servers run at once")
		return
	}
	defer s.give()
	if err := s.run(ctx, launch, reader, conn); err != nil {
		s.log("server ended", "server", launch.Name, "error", err.Error())
	}
}

// readLine reads up to the first newline, at most limit bytes.
func readLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > limit {
			return nil, errors.New("line too long")
		}
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func randomID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// run starts the container, detached: once it runs, podman is gone, and
// the server's stream comes back on a socket. It copies the stream until
// either side ends, then stops the container.
func (s *Server) run(ctx context.Context, launch Launch, input io.Reader, conn net.Conn) error {
	container := "nia-mcp-" + launch.Name + "-" + randomID()
	dir := filepath.Join(s.Sockets, container)
	// nia-mcp's alone: the container gets the two sockets, mounted one by one.
	if err := os.Mkdir(dir, 0o700); err != nil {
		refuse(conn, "its sockets could not be prepared")
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		refuse(conn, "its sockets could not be prepared")
		return err
	}
	defer os.RemoveAll(dir)
	egress, err := s.egress(ctx, launch.Name, filepath.Join(dir, egressName))
	if err != nil {
		refuse(conn, "its way out could not be prepared")
		return err
	}
	defer egress.Close()
	streams, err := listen(filepath.Join(dir, streamName))
	if err != nil {
		refuse(conn, "its stream could not be prepared")
		return err
	}
	defer streams.Close()

	startCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	output, err := s.podman(startCtx, launch, s.Podman.Args(launch, container, dir)...)
	cancel()
	if err != nil {
		s.log("server not started", "server", launch.Name, "error", err.Error(), "podman", output)
		refuse(conn, "the server could not be started")
		s.remove(container)
		return err
	}
	_ = streams.SetDeadline(time.Now().Add(30 * time.Second))
	stream, err := streams.AcceptUnix()
	streams.Close()
	if err != nil {
		refuse(conn, "the server did not start")
		s.stopContainer(container)
		return err
	}
	defer stream.Close()
	s.log("server started", "server", launch.Name, "container", container, "image", launch.Image)
	if err := json.NewEncoder(conn).Encode(Ack{OK: true}); err != nil {
		s.stopContainer(container)
		return err
	}

	inputEnded := make(chan struct{})
	go func() {
		_, _ = io.Copy(stream, input)
		_ = stream.CloseWrite()
		close(inputEnded)
	}()
	outputEnded := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, stream)
		close(outputEnded)
	}()
	select {
	case <-outputEnded:
	case <-inputEnded:
		// nia-edge is done with it: the server has its grace to end.
		select {
		case <-outputEnded:
		case <-time.After(s.grace()):
		case <-ctx.Done():
		}
	case <-ctx.Done():
	}
	stream.Close()
	s.stopContainer(container)
	s.log("server stopped", "server", launch.Name, "container", container)
	return nil
}

func (s *Server) grace() time.Duration {
	if s.Grace > 0 {
		return s.Grace
	}
	return 5 * time.Second
}

// podman runs podman as nia-mcp and returns what it wrote, trimmed.
func (s *Server) podman(ctx context.Context, launch Launch, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, s.Podman.binary(), args...)
	cmd.Env = s.Podman.Environ(launch)
	cmd.Dir = "/"
	output := &tail{max: 4096}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	return output.String(), err
}

// stopContainer stops a container, then removes it: whatever is left of
// it once the server ended or was told to.
func (s *Server) stopContainer(container string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.grace()+30*time.Second)
	defer cancel()
	seconds := int(s.grace() / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	_, _ = s.podman(ctx, Launch{}, "--cgroup-manager=cgroupfs", "--events-backend=file", "stop", "--ignore", "-t", strconv.Itoa(seconds), container)
	s.remove(container)
}

func (s *Server) remove(container string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = s.podman(ctx, Launch{}, "--cgroup-manager=cgroupfs", "--events-backend=file", "rm", "--ignore", "-f", "-t", "0", container)
}

func listen(path string) (*net.UnixListener, error) {
	_ = os.Remove(path)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// egress listens on the container's socket and hands each connection to
// nia-edge, after a first line that names the server: nia-edge knows it
// from this socket, whatever the server writes.
func (s *Server) egress(ctx context.Context, name, socket string) (net.Listener, error) {
	listener, err := listen(socket)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			client, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go s.forward(ctx, name, client)
		}
	}()
	return listener, nil
}

func (s *Server) forward(ctx context.Context, name string, client *net.UnixConn) {
	defer client.Close()
	var dialer net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	upstream, err := dialer.DialContext(dialCtx, "unix", s.Upstream)
	cancel()
	if err != nil {
		s.log("nia-edge's egress cannot be reached", "server", name, "error", err.Error())
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(upstream, "server "+name+"\n"); err != nil {
		return
	}
	splice(client, upstream.(*net.UnixConn))
}

// splice copies both ways until both directions end.
func splice(a, b *net.UnixConn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); _ = a.CloseWrite(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); _ = b.CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
}

// tail keeps the last bytes written to it.
type tail struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(bytes.TrimSpace(t.buf))
}
