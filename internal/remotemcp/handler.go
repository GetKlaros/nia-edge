package remotemcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/inspect"
	"github.com/GetKlaros/nia-edge/internal/local"
)

// Pinner is Nia's pinning of a server's tools for the tenant: it names back
// the tools the agent may see.
type Pinner interface {
	Pin(ctx context.Context, server string, tools []json.RawMessage) (visible []string, err error)
}

// Handler serves /remote/<name>/mcp for each server.
type Handler struct {
	Clients map[string]*Client
	Nia     Pinner
	// Taint tells Nia that the machine's run now holds content of this
	// source (a resource read, a prompt got): no content is sent.
	Taint    func(ctx context.Context, session, source string) error
	Releases *local.Releases
	Version  string
	Now      func() time.Time

	mu     sync.Mutex
	pinned map[string]map[string]bool
}

// Route returns the server a path names, or "".
func Route(path string) string {
	rest, ok := strings.CutPrefix(path, "/remote/")
	if !ok {
		return ""
	}
	name, tail, ok := strings.Cut(rest, "/")
	if !ok || tail != "mcp" {
		return ""
	}
	return name
}

var toolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func localOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := Route(r.URL.Path)
	client := h.Clients[name]
	if client == nil || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	if !localOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "this MCP server answers POST only", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var msg message
	if err != nil || json.Unmarshal(raw, &msg) != nil || msg.JSONRPC != "2.0" || msg.Method == "" {
		reply(w, nil, nil, &rpcError{Code: -32600, Message: "not a JSON-RPC 2.0 request"})
		return
	}
	if len(msg.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch msg.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &params)
		version := Versions[0]
		if slices.Contains(Versions, params.ProtocolVersion) {
			version = params.ProtocolVersion
		}
		reply(w, msg.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}, "resources": map[string]any{}, "prompts": map[string]any{}},
			"serverInfo":      map[string]any{"name": "nia-remote-" + name, "version": h.Version},
			"instructions":    "This MCP server is " + client.Endpoint.URL.Host + ", reached through nia-edge, which holds its token. Each call runs only once Nia allowed it.",
		}, nil)
	case "ping":
		reply(w, msg.ID, map[string]any{}, nil)
	case "tools/list":
		tools, err := h.visible(r.Context(), name, client)
		if err != nil {
			reply(w, msg.ID, nil, &rpcError{Code: -32603, Message: "[Nia agent firewall] " + err.Error()})
			return
		}
		reply(w, msg.ID, map[string]any{"tools": tools}, nil)
	case "tools/call":
		result, rpcErr := h.call(r.Context(), name, client, msg.Params)
		reply(w, msg.ID, result, rpcErr)
	case "resources/list", "resources/templates/list", "prompts/list":
		result, rpcErr := h.relay(r.Context(), client, msg.Method, msg.Params, "")
		reply(w, msg.ID, result, rpcErr)
	case "resources/read", "prompts/get":
		// What they return enters the agent's context, as a tool's output
		// does: the run is told, then a secret in it is redacted.
		result, rpcErr := h.relay(r.Context(), client, msg.Method, msg.Params, "mcp:"+name+":"+msg.Method)
		reply(w, msg.ID, result, rpcErr)
	default:
		reply(w, msg.ID, nil, &rpcError{Code: -32601, Message: "method not found"})
	}
}

// visible lists the server's tools and keeps those Nia pinned.
func (h *Handler) visible(ctx context.Context, name string, client *Client) ([]json.RawMessage, error) {
	tools, err := client.Tools(ctx)
	if err != nil {
		return nil, err
	}
	names, err := h.Nia.Pin(ctx, name, tools)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, tool := range names {
		allowed[tool] = true
	}
	kept := []json.RawMessage{}
	for _, tool := range tools {
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(tool, &named) == nil && allowed[named.Name] {
			kept = append(kept, tool)
		}
	}
	h.mu.Lock()
	if h.pinned == nil {
		h.pinned = map[string]map[string]bool{}
	}
	h.pinned[name] = allowed
	h.mu.Unlock()
	return kept, nil
}

// relay passes a request of the resources or prompts on; with a source, its
// result is content the run must know it holds, or it is withheld.
func (h *Handler) relay(ctx context.Context, client *Client, method string, params json.RawMessage, source string) (any, *rpcError) {
	result, rpcErr, err := client.Request(ctx, method, params)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: "[Nia agent firewall] " + err.Error()}
	}
	if rpcErr != nil {
		return nil, &rpcError{Code: rpcErr.Code, Message: inspect.RedactSecrets(rpcErr.Message)}
	}
	var answer any
	if json.Unmarshal(result, &answer) != nil {
		return nil, &rpcError{Code: -32603, Message: "[Nia agent firewall] the server's answer cannot be read"}
	}
	if source != "" {
		if h.Taint == nil {
			return nil, &rpcError{Code: -32603, Message: "[Nia agent firewall] Nia cannot record what this brings, so it is withheld"}
		}
		if err := h.Taint(ctx, "m:"+client.Endpoint.Name, source); err != nil {
			return nil, &rpcError{Code: -32603, Message: "[Nia agent firewall] Nia could not record what this brings, so it is withheld"}
		}
	}
	return redact(answer), nil
}

func failed(text string) (any, *rpcError) {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": true}, nil
}

func (h *Handler) call(ctx context.Context, name string, client *Client, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(params, &p) != nil || !toolName.MatchString(p.Name) {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}
	arguments := string(p.Arguments)
	if arguments == "" || arguments == "null" {
		arguments = "{}"
	}
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(arguments), &object) != nil {
		return failed("[Nia agent firewall] The arguments of a tool are a JSON object.")
	}
	// A tool runs only as Nia pinned it: listed again when this process has
	// not seen the server's tools yet.
	h.mu.Lock()
	allowed, known := h.pinned[name]
	h.mu.Unlock()
	if !known {
		if _, err := h.visible(ctx, name, client); err != nil {
			return failed("[Nia agent firewall] " + err.Error())
		}
		h.mu.Lock()
		allowed = h.pinned[name]
		h.mu.Unlock()
	}
	if !allowed[p.Name] {
		return failed("[Nia agent firewall] " + p.Name + " is not among the tools Nia pinned for " + name + ": a tool that changed or appeared waits for an admin.")
	}
	// Only a call the model path or the agent's hooks released runs, once.
	full := "mcp__" + name + "__" + p.Name
	if h.Releases == nil || !h.Releases.Take(full, arguments, h.now()) {
		return failed("[Nia agent firewall] This call was not released by Nia: it runs only as the agent proposed it and Nia allowed it, once.")
	}
	result, rpcErr, err := client.Call(ctx, p.Name, json.RawMessage(arguments))
	if err != nil {
		return failed("[Nia agent firewall] " + name + " could not run the call: " + err.Error())
	}
	if rpcErr != nil {
		return nil, &rpcError{Code: rpcErr.Code, Message: inspect.RedactSecrets(rpcErr.Message)}
	}
	var answer any
	if json.Unmarshal(result, &answer) != nil {
		return failed("[Nia agent firewall] " + name + " answered in a form that cannot be read.")
	}
	// A secret the server sent back does not reach the agent.
	return redact(answer), nil
}

func redact(value any) any {
	switch v := value.(type) {
	case string:
		return inspect.RedactSecrets(v)
	case []any:
		for i := range v {
			v[i] = redact(v[i])
		}
	case map[string]any:
		for key, item := range v {
			v[key] = redact(item)
		}
	}
	return value
}

func reply(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *rpcError) {
	body := map[string]any{"jsonrpc": "2.0", "id": id}
	if id == nil {
		body["id"] = nil
	}
	if rpcErr != nil {
		body["error"] = rpcErr
	} else {
		body["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}
