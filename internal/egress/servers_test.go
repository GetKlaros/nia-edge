package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func serversSocket(t *testing.T, allowed func(uint32) bool, authority Authority) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("peer credentials are read on Linux only")
	}
	dir, err := os.MkdirTemp("/tmp", "egress")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "servers.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	proxies := map[string]http.Handler{}
	for _, name := range []string{"mail", "github"} {
		proxies[name] = New(Options{Authority: authority, Session: "edge-box", Server: name})
	}
	go ServeServers(ctx, listener, allowed, func(name string) http.Handler { return proxies[name] }, nil)
	return socket
}

func me(uid uint32) bool { return uid == uint32(os.Getuid()) }

// through sends a header and a CONNECT, and returns the proxy's status line.
func through(t *testing.T, socket, header, host string) string {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "%sCONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", header, host, host)
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(line)
}

func TestEachServerIsDecidedUnderItsName(t *testing.T) {
	authority := &fakeAuthority{verdict: Verdict{Message: "denied"}}
	socket := serversSocket(t, me, authority)
	if line := through(t, socket, "server mail\n", "exfil.example"); !strings.Contains(line, "403") {
		t.Fatalf("%q", line)
	}
	if line := through(t, socket, "server github\n", "api.github.com"); !strings.Contains(line, "403") {
		t.Fatalf("%q", line)
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if len(authority.asked) != 2 || authority.asked[0].Server != "mail" || authority.asked[0].Host != "exfil.example" || authority.asked[1].Server != "github" {
		t.Fatalf("%+v", authority.asked)
	}
}

func TestServersSocketRefuses(t *testing.T) {
	authority := &fakeAuthority{verdict: Verdict{Allowed: true}}
	socket := serversSocket(t, me, authority)
	for name, header := range map[string]string{
		"unknown server": "server other\n",
		"no header":      "",
		"upper case":     "server Mail\n",
		"two names":      "server mail github\n",
		"no newline":     "server mail",
		"carriage":       "server mail\r\n",
	} {
		if line := through(t, socket, header, "exfil.example"); line != "" {
			t.Errorf("%s: answered %q", name, line)
		}
	}
	if asked, _, _ := authority.counts(); asked != 0 {
		t.Fatalf("%d decisions asked", asked)
	}
	// Another user: nothing read, nothing decided.
	other := serversSocket(t, func(uint32) bool { return false }, authority)
	if line := through(t, other, "server mail\n", "exfil.example"); line != "" {
		t.Fatalf("answered another user: %q", line)
	}
	if asked, _, _ := authority.counts(); asked != 0 {
		t.Fatal("decided for another user")
	}
}

func TestDecideNamesTheServer(t *testing.T) {
	var body map[string]any
	var output string
	r := remote(t, func(w http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		if request.URL.Path == "/v1/tools/result" {
			var result map[string]any
			_ = json.Unmarshal(raw, &result)
			output, _ = result["output"].(string)
			fmt.Fprint(w, `{"action":"none"}`)
			return
		}
		_ = json.Unmarshal(raw, &body)
		fmt.Fprint(w, `{"decision":"deny"}`)
	})
	request := sample
	request.Server = "mail"
	if _, err := r.Decide(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if arguments, _ := body["arguments"].(map[string]any); arguments["server"] != "mail" {
		t.Fatalf("%v", body)
	}
	if err := r.Connected(context.Background(), request); err != nil || !strings.Contains(output, "MCP server mail") {
		t.Fatalf("%q %v", output, err)
	}
	// The agent's own connections carry no server.
	if _, err := r.Decide(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if arguments, _ := body["arguments"].(map[string]any); arguments["server"] != nil {
		t.Fatalf("%v", body)
	}
}
