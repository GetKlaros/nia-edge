package mcpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Relay runs in the container, as its entry point. It connects to the
// stream socket nia-mcp listens on, and runs the server with that
// connection as its standard input and output; it listens on the
// container's own loopback and hands each connection to the egress socket;
// it gives the server the proxy variables that point there. It returns the
// server's exit status.
//
// The container has no network: going around the proxy reaches nothing.
func Relay(ctx context.Context, listen, run string, command []string, stderr io.Writer) int {
	if len(command) == 0 {
		fmt.Fprintln(stderr, "nia-edge mcp relay: no command")
		return 2
	}
	stream, err := dialRetry(filepath.Join(run, streamName), 10*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "nia-edge mcp relay: the stream: %v\n", err)
		return 1
	}
	// The server reads and writes the socket itself: nothing copies here.
	streamFile, err := stream.(*net.UnixConn).File()
	stream.Close()
	if err != nil {
		fmt.Fprintf(stderr, "nia-edge mcp relay: the stream: %v\n", err)
		return 1
	}
	defer streamFile.Close()

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(stderr, "nia-edge mcp relay: %v\n", err)
		return 1
	}
	defer listener.Close()
	egress := filepath.Join(run, egressName)
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go relayOne(client, egress)
		}
	}()

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = proxied(os.Environ(), "http://"+listen)
	cmd.Stdin = streamFile
	cmd.Stdout = streamFile
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "nia-edge mcp relay: %v\n", err)
		return 127
	}
	// Only the server holds the stream now: when it ends, nia-mcp sees it.
	streamFile.Close()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for {
		select {
		case sig := <-signals:
			_ = cmd.Process.Signal(sig)
		case <-ctx.Done():
			_ = cmd.Process.Signal(syscall.SIGTERM)
		case err := <-exited:
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				if code := exit.ExitCode(); code >= 0 {
					return code
				}
				return 1
			}
			if err != nil {
				return 1
			}
			return 0
		}
	}
}

func dialRetry(path string, within time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(within)
	for {
		conn, err := net.Dial("unix", path)
		if err == nil || time.Now().After(deadline) {
			return conn, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func relayOne(client net.Conn, socket string) {
	defer client.Close()
	upstream, err := net.Dial("unix", socket)
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		if half, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		if half, ok := client.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// proxied is env with every proxy variable pointing at proxy, for clients
// that read the lower-case or the upper-case names, and Node's fetch.
func proxied(env []string, proxy string) []string {
	out := make([]string, 0, len(env)+9)
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if reserved[name] && name != "PATH" && name != "HOME" {
			continue
		}
		out = append(out, entry)
	}
	return append(out,
		"HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy,
		"http_proxy="+proxy, "https_proxy="+proxy, "all_proxy="+proxy,
		"NO_PROXY=", "no_proxy=", "NODE_USE_ENV_PROXY=1",
	)
}

// RelayDefaults are where the relay listens and the directory of its
// sockets, in the container.
func RelayDefaults() (listen, run string) { return proxyAddr, runDir }
