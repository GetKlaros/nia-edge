package mcpd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const image = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func valid() Launch {
	return Launch{Name: "mail", Image: image, Command: []string{"node", "/app/index.js"}, Env: map[string]string{"MAIL_TOKEN": "tok-1"}}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	refused := map[string]func(*Launch){
		"no name":           func(l *Launch) { l.Name = "" },
		"upper name":        func(l *Launch) { l.Name = "Mail" },
		"dash in name":      func(l *Launch) { l.Name = "my-mail" },
		"double underscore": func(l *Launch) { l.Name = "my__mail" },
		"host":              func(l *Launch) { l.Name = "host" },
		"long name":         func(l *Launch) { l.Name = strings.Repeat("a", 33) },
		"tag":               func(l *Launch) { l.Image = "docker.io/mcp/mail:latest" },
		"digest of a ref":   func(l *Launch) { l.Image = "docker.io/mcp/mail@" + image },
		"short id":          func(l *Launch) { l.Image = "sha256:0123" },
		"upper id":          func(l *Launch) { l.Image = strings.ToUpper(image) },
		"no command":        func(l *Launch) { l.Command = nil },
		"empty word":        func(l *Launch) { l.Command = []string{"node", ""} },
		"NUL":               func(l *Launch) { l.Command = []string{"node\x00x"} },
		"bad UTF-8":         func(l *Launch) { l.Command = []string{"\xff"} },
		"proxy variable":    func(l *Launch) { l.Env = map[string]string{"HTTPS_PROXY": "http://evil:1"} },
		"lower proxy":       func(l *Launch) { l.Env = map[string]string{"https_proxy": "http://evil:1"} },
		"node proxy":        func(l *Launch) { l.Env = map[string]string{"NODE_USE_ENV_PROXY": "0"} },
		"PATH":              func(l *Launch) { l.Env = map[string]string{"PATH": "/evil"} },
		"NIA_":              func(l *Launch) { l.Env = map[string]string{"NIA_SERVER": "other"} },
		"storage conf":      func(l *Launch) { l.Env = map[string]string{"CONTAINERS_STORAGE_CONF": "/x"} },
		"bad env name":      func(l *Launch) { l.Env = map[string]string{"A=B": "c"} },
		"NUL in value":      func(l *Launch) { l.Env = map[string]string{"TOKEN": "a\x00b"} },
		"huge value":        func(l *Launch) { l.Env = map[string]string{"TOKEN": strings.Repeat("a", maxEnvValue+1)} },
	}
	for name, change := range refused {
		launch := valid()
		change(&launch)
		if launch.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestArgs(t *testing.T) {
	p := Podman{Binary: "/usr/bin/podman", Relay: "/usr/local/bin/nia-edge", Home: "/var/lib/nia-mcp", Runtime: "/run/nia-mcp"}
	args := p.Args(valid(), "nia-mcp-mail-x", "/run/nia-mcp/egress/x")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"run --rm --detach", "--pull never", "--network none", "--cap-drop all", "--security-opt no-new-privileges", "--read-only",
		"--mount type=bind,src=/usr/local/bin/nia-edge,dst=/nia/nia-edge,ro=true",
		"--mount type=bind,src=/run/nia-mcp/egress/x/stream.sock,dst=/nia/run/stream.sock",
		"--mount type=bind,src=/run/nia-mcp/egress/x/egress.sock,dst=/nia/run/egress.sock",
		"--env MAIL_TOKEN",
		"--entrypoint /nia/nia-edge " + strings.TrimPrefix(image, "sha256:") + " mcp relay -- node /app/index.js",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	// A value is never on the command line, and nothing else of the machine is mounted.
	if strings.Contains(joined, "tok-1") {
		t.Fatal("a variable's value is on the command line")
	}
	mounts := 0
	for i, arg := range args {
		if arg == "-v" || arg == "--volume" || strings.HasPrefix(arg, "--volume=") || arg == "--privileged" || arg == "--network=host" || strings.HasPrefix(arg, "--device") {
			t.Fatalf("argument %q", arg)
		}
		if arg == "--mount" {
			mounts++
			_ = args[i+1]
		}
	}
	if mounts != 3 {
		t.Fatalf("%d mounts", mounts)
	}
	// The command comes after the image: podman reads none of it as its own.
	image := slices.Index(args, strings.TrimPrefix(valid().Image, "sha256:"))
	if image < 0 || slices.Index(args, "--env") > image {
		t.Fatal("options after the image")
	}
	env := p.Environ(valid())
	if !slices.Contains(env, "MAIL_TOKEN=tok-1") || !slices.Contains(env, "XDG_RUNTIME_DIR=/run/nia-mcp") {
		t.Fatalf("environ %v", env)
	}
	for _, entry := range env {
		if strings.HasPrefix(entry, "HTTPS_PROXY") {
			t.Fatal("proxy in podman's environment")
		}
	}
}

func TestProxied(t *testing.T) {
	env := proxied([]string{"PATH=/bin", "HTTPS_PROXY=http://evil:1", "no_proxy=*", "TOKEN=x", "NODE_USE_ENV_PROXY=0"}, "http://127.0.0.1:3128")
	want := map[string]string{"PATH": "/bin", "TOKEN": "x", "HTTPS_PROXY": "http://127.0.0.1:3128", "https_proxy": "http://127.0.0.1:3128", "no_proxy": "", "NODE_USE_ENV_PROXY": "1"}
	seen := map[string]int{}
	got := map[string]string{}
	for _, entry := range env {
		name, value, _ := strings.Cut(entry, "=")
		seen[name]++
		got[name] = value
	}
	for name, value := range want {
		if got[name] != value || seen[name] != 1 {
			t.Errorf("%s = %q (%d times)", name, got[name], seen[name])
		}
	}
}

// TestMain lets the test binary play podman (MCPD_FAKE_PODMAN) and the
// relay in its container (MCPD_FAKE_RELAY).
func TestMain(m *testing.M) {
	switch {
	case os.Getenv("MCPD_FAKE_PODMAN") == "1":
		os.Exit(fakePodmanMain(os.Args[1:]))
	case os.Getenv("MCPD_FAKE_RELAY") != "":
		free, _ := net.Listen("tcp", "127.0.0.1:0")
		listen := free.Addr().String()
		free.Close()
		os.Exit(Relay(context.Background(), listen, os.Getenv("MCPD_FAKE_RELAY"), os.Args[1:], os.Stderr))
	}
	os.Exit(m.Run())
}

// fakePodmanMain runs the server of "run" as a detached process (the
// relay, with the run directory of the --mount), and kills it on "stop" and
// "rm". Each call is logged.
func fakePodmanMain(args []string) int {
	state := os.Getenv("FAKE_STATE")
	logFile, _ := os.OpenFile(filepath.Join(state, "calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintln(logFile, strings.Join(args, " "))
	logFile.Close()
	verb := ""
	for _, arg := range args {
		if arg == "run" || arg == "stop" || arg == "rm" {
			verb = arg
			break
		}
	}
	name := args[len(args)-1]
	switch verb {
	case "run":
		if os.Getenv("FAKE_FAIL") == "1" {
			fmt.Fprintln(os.Stderr, "Error: image not known")
			return 125
		}
		var run string
		for i, arg := range args {
			if arg == "--name" {
				name = args[i+1]
			}
			if arg == "--mount" && strings.HasSuffix(args[i+1], ",dst=/nia/run/stream.sock") {
				run = filepath.Dir(strings.TrimSuffix(strings.TrimPrefix(args[i+1], "type=bind,src="), ",dst=/nia/run/stream.sock"))
			}
		}
		command := args[slices.Index(args, "--")+1:]
		self, _ := os.Executable()
		relay := exec.Command(self, command...)
		relay.Env = append(os.Environ(), "MCPD_FAKE_PODMAN=", "MCPD_FAKE_RELAY="+run)
		relay.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := relay.Start(); err != nil {
			return 125
		}
		os.WriteFile(filepath.Join(state, name+".pid"), []byte(strconv.Itoa(relay.Process.Pid)), 0o600)
		fmt.Println(name)
		return 0
	case "stop", "rm":
		if raw, err := os.ReadFile(filepath.Join(state, name+".pid")); err == nil {
			pid, _ := strconv.Atoi(string(raw))
			signal := syscall.SIGTERM
			if verb == "rm" {
				signal = syscall.SIGKILL
			}
			_ = syscall.Kill(pid, signal)
		}
		return 0
	}
	return 0
}

// fakePodman is a podman that runs the server on this machine: the test
// binary, as above.
func fakePodman(t *testing.T, state string, fail bool) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "podman")
	failing := ""
	if fail {
		failing = "FAKE_FAIL=1 "
	}
	script := "#!/bin/sh\nMCPD_FAKE_PODMAN=1 FAKE_STATE=" + state + " " + failing + "exec " + self + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func serve(t *testing.T, s *Server, allowed func(uint32) bool) (string, context.CancelFunc) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("peer credentials are read on Linux only")
	}
	dir, err := os.MkdirTemp("/tmp", "mcpd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "mcpd.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Sockets == "" {
		s.Sockets = dir
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Serve(ctx, listener, allowed)
	t.Cleanup(cancel)
	return socket, cancel
}

func me(uid uint32) bool { return uid == uint32(os.Getuid()) }

func running(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !check(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

func TestServeRunsTheServerDetachedOnItsStream(t *testing.T) {
	state := t.TempDir()
	// The server answers each line with its variable, the proxy it was given and the line.
	launch := valid()
	launch.Command = []string{"sh", "-c", `while IFS= read -r line; do printf '%s %s %s\n' "$MAIL_TOKEN" "$NODE_USE_ENV_PROXY" "$line"; done`}
	s := &Server{Podman: Podman{Binary: fakePodman(t, state, false)}, Grace: 300 * time.Millisecond}
	socket, _ := serve(t, s, me)
	stream, err := (&Client{Socket: socket}).Launch(context.Background(), launch)
	if err != nil {
		t.Fatal(err)
	}
	// podman is gone: it ran, detached, and ended.
	calls, _ := os.ReadFile(filepath.Join(state, "calls"))
	if !strings.Contains(string(calls), " run --rm --detach ") {
		t.Fatalf("%s", calls)
	}
	if _, err := io.WriteString(stream, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil || line != "tok-1 1 ping\n" {
		t.Fatalf("%q %v", line, err)
	}
	// nia-edge closes the stream: the server ends, the container is stopped and removed.
	stream.Close()
	eventually(t, "the container was not stopped", func() bool {
		calls, _ := os.ReadFile(filepath.Join(state, "calls"))
		return strings.Contains(string(calls), " stop --ignore") && strings.Contains(string(calls), " rm --ignore -f")
	})
	eventually(t, "still counted as running", func() bool { return running(s) == 0 })
	entries, _ := os.ReadDir(s.Sockets)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "nia-mcp-") {
			t.Fatalf("its sockets are left: %s", entry.Name())
		}
	}
}

func TestServeStopsAServerThatIgnoresTheEndOfItsStream(t *testing.T) {
	state := t.TempDir()
	marker := filepath.Join(state, "ended")
	launch := valid()
	launch.Command = []string{"sh", "-c", `trap 'echo stopped > ` + marker + `; exit 0' TERM; exec 0<&-; while true; do sleep 0.05; done`}
	s := &Server{Podman: Podman{Binary: fakePodman(t, state, false)}, Grace: 200 * time.Millisecond}
	socket, _ := serve(t, s, me)
	stream, err := (&Client{Socket: socket}).Launch(context.Background(), launch)
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	eventually(t, "the container was not stopped", func() bool {
		calls, _ := os.ReadFile(filepath.Join(state, "calls"))
		return strings.Contains(string(calls), " stop --ignore -t 1 ")
	})
	eventually(t, "still counted as running", func() bool { return running(s) == 0 })
}

func TestServeSaysWhenTheServerCannotStart(t *testing.T) {
	state := t.TempDir()
	s := &Server{Podman: Podman{Binary: fakePodman(t, state, true)}}
	socket, _ := serve(t, s, me)
	if _, err := (&Client{Socket: socket}).Launch(context.Background(), valid()); err == nil || !strings.Contains(err.Error(), "could not be started") {
		t.Fatalf("%v", err)
	}
	eventually(t, "still counted as running", func() bool { return running(s) == 0 })
}

func TestServeRefuses(t *testing.T) {
	state := t.TempDir()
	launch := valid()
	launch.Command = []string{"cat"}
	socket, _ := serve(t, &Server{Podman: Podman{Binary: fakePodman(t, state, false)}, Max: 1}, me)
	client := &Client{Socket: socket}
	bad := valid()
	bad.Env = map[string]string{"HTTPS_PROXY": "http://evil:1"}
	if _, err := client.Launch(context.Background(), bad); err == nil {
		t.Fatal("a launch that sets the proxy was accepted")
	}
	// The client checks too: send it raw.
	raw, _ := json.Marshal(bad)
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(append(raw, '\n'))
	var ack Ack
	if json.NewDecoder(conn).Decode(&ack) != nil || ack.OK || !strings.Contains(ack.Error, "HTTPS_PROXY") {
		t.Fatalf("%+v", ack)
	}
	conn.Close()
	// Unknown fields are refused, not ignored.
	conn, _ = net.Dial("unix", socket)
	conn.Write([]byte(`{"name":"mail","image":"` + image + `","command":["x"],"privileged":true}` + "\n"))
	ack = Ack{}
	if json.NewDecoder(conn).Decode(&ack) != nil || ack.OK {
		t.Fatalf("%+v", ack)
	}
	conn.Close()
	// Bounded: one at a time here.
	first, err := client.Launch(context.Background(), launch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Launch(context.Background(), launch); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("second launch: %v", err)
	}
	first.Close()
	calls, _ := os.ReadFile(filepath.Join(state, "calls"))
	if strings.Count(string(calls), " run ") != 1 {
		t.Fatalf("podman ran %d times:\n%s", strings.Count(string(calls), " run "), calls)
	}
}

func TestServeServesOnlyItsUser(t *testing.T) {
	state := t.TempDir()
	socket, _ := serve(t, &Server{Podman: Podman{Binary: fakePodman(t, state, false)}}, func(uint32) bool { return false })
	if _, err := (&Client{Socket: socket}).Launch(context.Background(), valid()); err == nil {
		t.Fatal("served another user")
	}
	if calls, _ := os.ReadFile(filepath.Join(state, "calls")); len(calls) != 0 {
		t.Fatalf("podman ran: %s", calls)
	}
}

func TestEgressNamesTheServer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	dir, _ := os.MkdirTemp("/tmp", "mcpd")
	defer os.RemoveAll(dir)
	upstream := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", upstream)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		header, _ := reader.ReadString('\n')
		body, _ := reader.ReadString('\n')
		got <- header + body
		io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\n")
	}()
	s := &Server{Upstream: upstream}
	egress, err := s.egress(context.Background(), "mail", filepath.Join(dir, "c.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer egress.Close()
	if info, _ := os.Stat(filepath.Join(dir, "c.sock")); info.Mode().Perm() != 0o666 {
		t.Fatalf("mode %v", info.Mode())
	}
	conn, err := net.Dial("unix", filepath.Join(dir, "c.sock"))
	if err != nil {
		t.Fatal(err)
	}
	// What the server writes cannot change the name nia-edge reads first.
	io.WriteString(conn, "server other\nCONNECT x:443 HTTP/1.1\r\n")
	select {
	case header := <-got:
		if !strings.HasPrefix(header, "server mail\n") {
			t.Fatalf("%q", header)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached nia-edge")
	}
	answer, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(answer, "403") {
		t.Fatalf("%q", answer)
	}
}

func TestRelay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	dir, _ := os.MkdirTemp("/tmp", "relay")
	defer os.RemoveAll(dir)
	// nia-mcp's two sockets: the server's way out, and its stream.
	egress, err := net.Listen("unix", filepath.Join(dir, egressName))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := egress.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				io.WriteString(conn, "seen "+line)
			}()
		}
	}()
	streams, err := net.Listen("unix", filepath.Join(dir, streamName))
	if err != nil {
		t.Fatal(err)
	}
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	listen := free.Addr().String()
	free.Close()
	// The server reaches its proxy on the loopback, and answers on its stream.
	script := `read -r line; printf '%s %s %s\n' "$HTTPS_PROXY" "$NODE_USE_ENV_PROXY" "$line"; exit 7`
	done := make(chan int, 1)
	var stderr strings.Builder
	go func() { done <- Relay(context.Background(), listen, dir, []string{"sh", "-c", script}, &stderr) }()
	stream, err := streams.Accept()
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if conn, err = net.Dial("tcp", listen); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
	}
	io.WriteString(conn, "CONNECT a:443\n")
	reply, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if reply != "seen CONNECT a:443\n" {
		t.Fatalf("%q", reply)
	}
	io.WriteString(stream, "hello\n")
	answer, _ := bufio.NewReader(stream).ReadString('\n')
	if answer != "http://"+listen+" 1 hello\n" {
		t.Fatalf("%q", answer)
	}
	if code := <-done; code != 7 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}
