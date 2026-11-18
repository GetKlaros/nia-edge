package localmcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/GetKlaros/nia-edge/internal/local"
)

// Handler serves /local/<name>/mcp for each server.
type Handler struct {
	Servers  map[string]*Server
	Releases *local.Releases
	Version  string
	Now      func() time.Time
}

// Route returns the server a path names, or "" when it names none.
func Route(path string) string {
	rest, ok := strings.CutPrefix(path, "/local/")
	if !ok {
		return ""
	}
	name, tail, ok := strings.Cut(rest, "/")
	if !ok || tail != "mcp" {
		return ""
	}
	return name
}

var versions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
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

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	server := h.Servers[Route(r.URL.Path)]
	if server == nil || r.URL.RawPath != "" {
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
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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
		version := versions[0]
		if slices.Contains(versions, params.ProtocolVersion) {
			version = params.ProtocolVersion
		}
		reply(w, msg.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "nia-local-" + server.Launch.Name, "version": h.Version},
			"instructions":    "This MCP server runs in a container on this machine. Each call runs only once Nia allowed it.",
		}, nil)
	case "ping":
		reply(w, msg.ID, map[string]any{}, nil)
	case "tools/list":
		tools, err := server.Tools(r.Context())
		if err != nil {
			reply(w, msg.ID, nil, &rpcError{Code: -32603, Message: "[Nia agent firewall] " + err.Error()})
			return
		}
		reply(w, msg.ID, map[string]any{"tools": tools}, nil)
	case "tools/call":
		result, rpcErr := h.call(r, server, msg.Params)
		reply(w, msg.ID, result, rpcErr)
	default:
		reply(w, msg.ID, nil, &rpcError{Code: -32601, Message: "method not found"})
	}
}

func failed(text string) (any, *rpcError) {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": true}, nil
}

func (h *Handler) call(r *http.Request, server *Server, params json.RawMessage) (any, *rpcError) {
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
	tools, err := server.Tools(r.Context())
	if err != nil {
		return failed("[Nia agent firewall] " + err.Error())
	}
	listed := false
	for _, tool := range tools {
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(tool, &named) == nil && named.Name == p.Name {
			listed = true
			break
		}
	}
	if !listed {
		return nil, &rpcError{Code: -32602, Message: "unknown tool " + p.Name}
	}
	// Only a call the model path released runs, once.
	name := "mcp__" + server.Launch.Name + "__" + p.Name
	if h.Releases == nil || !h.Releases.Take(name, arguments, h.now()) {
		return failed("[Nia agent firewall] This call was not released by Nia: it runs only as the model proposed it and Nia allowed it, once.")
	}
	result, rpcErr, err := server.Call(r.Context(), p.Name, json.RawMessage(arguments))
	if err != nil {
		return failed("[Nia agent firewall] The MCP server " + server.Launch.Name + " could not run the call: " + err.Error())
	}
	if rpcErr != nil {
		return nil, rpcErr
	}
	var answer map[string]json.RawMessage
	if json.Unmarshal(result, &answer) != nil {
		return failed("[Nia agent firewall] The MCP server " + server.Launch.Name + " answered in a form that cannot be read.")
	}
	return json.RawMessage(result), nil
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
