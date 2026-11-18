package localmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/mcpd"
)

const image = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeLauncher runs an MCP server in a goroutine for each launch.
type fakeLauncher struct {
	launches atomic.Int32
	calls    atomic.Int32
	mu       sync.Mutex
	got      []mcpd.Launch
	fail     error
	// asks makes the server send a request and a notification before each answer.
	asks bool
}

func (f *fakeLauncher) Launch(_ context.Context, launch mcpd.Launch) (mcpd.Stream, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	f.launches.Add(1)
	f.mu.Lock()
	f.got = append(f.got, launch)
	f.mu.Unlock()
	client, server := net.Pipe()
	go f.serve(server)
	return client, nil
}

func (f *fakeLauncher) serve(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	var write sync.Mutex
	send := func(v any) {
		raw, _ := json.Marshal(v)
		write.Lock()
		conn.Write(append(raw, '\n'))
		write.Unlock()
	}
	for scanner.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
			Error *rpcError `json:"error"`
		}
		if json.Unmarshal(scanner.Bytes(), &msg) != nil || msg.Method == "" {
			continue
		}
		if f.asks {
			send(map[string]any{"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage", "params": map[string]any{}})
			send(map[string]any{"jsonrpc": "2.0", "method": "notifications/message", "params": map[string]any{"level": "info"}})
		}
		switch msg.Method {
		case "initialize":
			send(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"protocolVersion": protocol, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "fake"}}})
		case "tools/list":
			send(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"tools": []map[string]any{
				{"name": "send_email", "inputSchema": map[string]any{"type": "object"}},
				{"name": "slow", "inputSchema": map[string]any{"type": "object"}},
				{"name": "die", "inputSchema": map[string]any{"type": "object"}},
				{"name": "bad name!", "inputSchema": map[string]any{"type": "object"}},
			}}})
		case "tools/call":
			f.calls.Add(1)
			id, name, args := msg.ID, msg.Params.Name, string(msg.Params.Arguments)
			switch name {
			case "die":
				return
			case "slow":
				go func() {
					time.Sleep(200 * time.Millisecond)
					send(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"content": []map[string]any{{"type": "text", "text": "slow " + args}}}})
				}()
			default:
				send(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"content": []map[string]any{{"type": "text", "text": name + " " + args}}}})
			}
		}
	}
}

type world struct {
	launcher *fakeLauncher
	releases *local.Releases
	server   *Server
	handler  *Handler
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{launcher: &fakeLauncher{}, releases: &local.Releases{Prefix: "mcp__"}}
	w.server = &Server{Launch: mcpd.Launch{Name: "mail", Image: image, Command: []string{"node", "x"}, Env: map[string]string{"TOKEN": "t"}}, Launcher: w.launcher, Cache: t.TempDir()}
	t.Cleanup(w.server.Close)
	w.handler = &Handler{Servers: map[string]*Server{"mail": w.server}, Releases: w.releases, Version: "test"}
	return w
}

func (w *world) rpc(t *testing.T, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
	recorder := httptest.NewRecorder()
	w.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/local/mail/mcp", bytes.NewReader(body)))
	var answer map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
	return answer
}

func text(answer map[string]any) (string, bool) {
	result, _ := answer["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return "", false
	}
	first, _ := content[0].(map[string]any)
	isError, _ := result["isError"].(bool)
	s, _ := first["text"].(string)
	return s, isError
}

func TestListingStartsTheServerOnceAndIsKeptByImage(t *testing.T) {
	w := newWorld(t)
	answer := w.rpc(t, "tools/list", nil)
	tools := answer["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools %v", tools)
	}
	w.rpc(t, "tools/list", nil)
	if w.launcher.launches.Load() != 1 {
		t.Fatalf("%d launches", w.launcher.launches.Load())
	}
	// The variables given to nia-mcp are the server's own.
	if got := w.launcher.got[0]; got.Env["TOKEN"] != "t" || got.Image != image {
		t.Fatalf("%+v", got)
	}
	// Another nia-edge (a restart): the kept list, nothing started.
	again := &Server{Launch: w.server.Launch, Launcher: &fakeLauncher{fail: errors.New("must not start")}, Cache: w.server.Cache}
	if tools, err := again.Tools(context.Background()); err != nil || len(tools) != 3 {
		t.Fatalf("%d %v", len(tools), err)
	}
	// Another image: listed again.
	other := w.server.Launch
	other.Image = "sha256:" + strings.Repeat("f", 64)
	changed := &Server{Launch: other, Launcher: &fakeLauncher{}, Cache: w.server.Cache}
	defer changed.Close()
	if _, err := changed.Tools(context.Background()); err != nil || changed.Launcher.(*fakeLauncher).launches.Load() != 1 {
		t.Fatal("a new image was not listed again")
	}
}

func TestACallRunsOnlyOnceReleased(t *testing.T) {
	w := newWorld(t)
	args := map[string]any{"to": "client@example.com", "body": "invoice"}
	got, isError := text(w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": args}))
	if !isError || !strings.Contains(got, "not released") || w.launcher.calls.Load() != 0 {
		t.Fatalf("%q %v", got, isError)
	}
	// Released by the model path, keys in another order: the same call.
	w.releases.Release("mcp__mail__send_email", `{"body":"invoice","to":"client@example.com"}`, time.Now())
	got, isError = text(w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": args}))
	if isError || !strings.HasPrefix(got, "send_email ") || w.launcher.calls.Load() != 1 {
		t.Fatalf("%q %v", got, isError)
	}
	// Once.
	if _, isError := text(w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": args})); !isError || w.launcher.calls.Load() != 1 {
		t.Fatal("a release was spent twice")
	}
	// Another server's release does not run this one, nor other arguments.
	w.releases.Release("mcp__other__send_email", `{"body":"invoice","to":"client@example.com"}`, time.Now())
	w.releases.Release("mcp__mail__send_email", `{"body":"invoice","to":"attacker@example.com"}`, time.Now())
	if _, isError := text(w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": args})); !isError || w.launcher.calls.Load() != 1 {
		t.Fatal("ran on another call's release")
	}
	// A tool the server does not list.
	w.releases.Release("mcp__mail__hidden", `{}`, time.Now())
	if answer := w.rpc(t, "tools/call", map[string]any{"name": "hidden", "arguments": map[string]any{}}); answer["error"] == nil {
		t.Fatalf("%v", answer)
	}
}

func TestTheServerGetsNothingItAsks(t *testing.T) {
	w := newWorld(t)
	w.launcher.asks = true
	w.releases.Release("mcp__mail__send_email", `{}`, time.Now())
	got, isError := text(w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": map[string]any{}}))
	if isError || got != "send_email {}" {
		t.Fatalf("%q %v", got, isError)
	}
}

func TestConcurrentCallsGetTheirOwnAnswers(t *testing.T) {
	w := newWorld(t)
	w.releases.Release("mcp__mail__slow", `{"n":1}`, time.Now())
	w.releases.Release("mcp__mail__send_email", `{"n":2}`, time.Now())
	var wg sync.WaitGroup
	results := make([]string, 2)
	for i, call := range []map[string]any{{"name": "slow", "arguments": map[string]any{"n": 1}}, {"name": "send_email", "arguments": map[string]any{"n": 2}}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = text(w.rpc(t, "tools/call", call))
		}()
	}
	wg.Wait()
	if results[0] != `slow {"n":1}` || results[1] != `send_email {"n":2}` {
		t.Fatalf("%q", results)
	}
}

func TestAServerThatEndsFailsTheCallAndStartsAgain(t *testing.T) {
	w := newWorld(t)
	w.releases.Release("mcp__mail__die", `{}`, time.Now())
	got, isError := text(w.rpc(t, "tools/call", map[string]any{"name": "die", "arguments": map[string]any{}}))
	if !isError || !strings.Contains(got, "could not run") {
		t.Fatalf("%q %v", got, isError)
	}
	w.releases.Release("mcp__mail__send_email", `{}`, time.Now())
	if got, isError := text(w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": map[string]any{}})); isError {
		t.Fatalf("%q", got)
	}
	if w.launcher.launches.Load() != 2 {
		t.Fatalf("%d launches", w.launcher.launches.Load())
	}
}

func TestAnIdleServerIsStopped(t *testing.T) {
	w := newWorld(t)
	w.server.Idle = 50 * time.Millisecond
	w.releases.Release("mcp__mail__send_email", `{}`, time.Now())
	w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": map[string]any{}})
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		w.server.mu.Lock()
		stopped := w.server.proc == nil
		w.server.mu.Unlock()
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("still running")
		}
	}
}

func TestAServerThatCannotStartFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.launcher.fail = errors.New("nia-mcp cannot be reached")
	w.releases.Release("mcp__mail__send_email", `{}`, time.Now())
	if answer := w.rpc(t, "tools/list", nil); answer["error"] == nil {
		t.Fatalf("%v", answer)
	}
	if got, isError := text(w.rpc(t, "tools/call", map[string]any{"name": "send_email", "arguments": map[string]any{}})); !isError {
		t.Fatalf("%q", got)
	}
}

func TestRoutes(t *testing.T) {
	w := newWorld(t)
	for _, c := range []struct {
		method, path, origin string
		want                 int
	}{
		{http.MethodPost, "/local/other/mcp", "", http.StatusNotFound},
		{http.MethodPost, "/local/mail/mcp/x", "", http.StatusNotFound},
		{http.MethodPost, "/local/mail%2Fx/mcp", "", http.StatusNotFound},
		{http.MethodGet, "/local/mail/mcp", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/local/mail/mcp", "https://evil.example", http.StatusForbidden},
	} {
		request := httptest.NewRequest(c.method, c.path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		if c.origin != "" {
			request.Header.Set("Origin", c.origin)
		}
		recorder := httptest.NewRecorder()
		w.handler.ServeHTTP(recorder, request)
		if recorder.Code != c.want {
			t.Errorf("%s %s: %d", c.method, c.path, recorder.Code)
		}
	}
	if Route("/local/mail/mcp") != "mail" || Route("/host/mcp") != "" || Route("/local/mail") != "" {
		t.Fatal("routes")
	}
	if answer := w.rpc(t, "initialize", map[string]any{"protocolVersion": "2025-06-18"}); answer["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("%v", answer)
	}
	// initialize starts nothing.
	if w.launcher.launches.Load() != 0 {
		t.Fatal("initialize started the server")
	}
}
