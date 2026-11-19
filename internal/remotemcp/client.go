// Package remotemcp serves the agent the MCP servers hosted by their vendor
// (GitHub, Notion…) whose token nia-edge holds: the agent reaches
// /remote/<name>/mcp on nia-edge, which is an MCP server to it and an MCP
// client to the vendor, over Streamable HTTP, with the token added there.
//
// The token is in the state file only: never with the agent, never logged,
// never sent but to the server's own URL, over HTTPS, without following a
// redirect. The agent sees only the tools Nia pinned for the tenant (a tool
// whose definition changed, or that appeared since, is hidden until an admin
// approves it), and a call runs only against an unused release of the model
// path, or of the agent's hooks, for the same tool and canonical arguments.
// A secret in a result is redacted before the agent sees it.
package remotemcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxResponse bounds one answer of the vendor.
const maxResponse = 16 << 20

// Versions are the protocol versions nia-edge speaks, newest first.
var Versions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// Endpoint is a vendor's MCP server, as the state file keeps it.
type Endpoint struct {
	Name string
	URL  *url.URL
	// Header carries the token: Authorization by default.
	Header string
	// Value is the header's whole value (Bearer …): a secret.
	Value string
}

// ValidURL checks a server's URL: HTTPS, or HTTP on the loopback (tests and
// a server on this machine), no user information, no fragment.
func ValidURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errors.New("the server's URL is not an absolute http(s) URL without credentials")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(parsed.Hostname()); ip == nil || !ip.IsLoopback() {
			return nil, errors.New("the server's URL must be https: the token would travel in clear")
		}
	default:
		return nil, errors.New("the server's URL must be https")
	}
	return parsed, nil
}

// rpcError is a JSON-RPC error.
type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Client speaks to one server. It initializes a session at first use, and
// again once if the server forgot it.
type Client struct {
	Endpoint Endpoint
	HTTP     *http.Client
	Version  string
	// Renewer renews a signed-in server's access token; nil for a token
	// given as it is.
	Renewer *Renewer

	mu       sync.Mutex
	session  string
	protocol string
	ready    bool
	next     int64
}

// NewHTTPClient reaches the vendors: no proxy of the environment, no
// redirect followed (it would carry the token elsewhere).
func NewHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var (
	errSessionGone = errors.New("the server forgot the session")
	errRefused     = errors.New("the server refused the token")
)

// renew puts a new access token in place.
func (c *Client) renew(ctx context.Context) error {
	access, err := c.Renewer.Renew(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.Endpoint.Value = "Bearer " + access
	c.mu.Unlock()
	return nil
}

// call sends one request and returns its result.
func (c *Client) call(ctx context.Context, method string, params any) (json.RawMessage, *rpcError, error) {
	if c.Renewer != nil && c.Renewer.due(time.Now()) {
		if err := c.renew(ctx); err != nil {
			return nil, nil, err
		}
	}
	result, rpcErr, err := c.attempt(ctx, method, params)
	// A signed-in server's token may have been revoked or expired early:
	// renewed once, then tried once more.
	if errors.Is(err, errRefused) && c.Renewer != nil {
		if err := c.renew(ctx); err != nil {
			return nil, nil, err
		}
		result, rpcErr, err = c.attempt(ctx, method, params)
	}
	if errors.Is(err, errRefused) {
		err = fmt.Errorf("%s refused the token: renew it with nia-edge mcp remote add, or sign in again with nia-edge mcp remote login", c.Endpoint.URL.Host)
	}
	return result, rpcErr, err
}

func (c *Client) attempt(ctx context.Context, method string, params any) (json.RawMessage, *rpcError, error) {
	if err := c.initialize(ctx); err != nil {
		return nil, nil, err
	}
	result, rpcErr, err := c.request(ctx, method, params, true)
	if errors.Is(err, errSessionGone) {
		c.mu.Lock()
		c.ready = false
		c.session = ""
		c.mu.Unlock()
		if err := c.initialize(ctx); err != nil {
			return nil, nil, err
		}
		result, rpcErr, err = c.request(ctx, method, params, true)
	}
	return result, rpcErr, err
}

func (c *Client) initialize(ctx context.Context) error {
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if ready {
		return nil
	}
	result, rpcErr, err := c.request(ctx, "initialize", map[string]any{
		"protocolVersion": Versions[0],
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "nia-edge", "version": c.Version},
	}, false)
	if err != nil {
		return err
	}
	if rpcErr != nil {
		return fmt.Errorf("the server refused to start a session: %s", rpcErr.Message)
	}
	var answer struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(result, &answer) != nil {
		return errors.New("the server's answer to initialize cannot be read")
	}
	known := false
	for _, version := range Versions {
		known = known || version == answer.ProtocolVersion
	}
	if !known {
		return fmt.Errorf("the server speaks protocol %q, which nia-edge does not", answer.ProtocolVersion)
	}
	c.mu.Lock()
	c.protocol = answer.ProtocolVersion
	c.ready = true
	c.mu.Unlock()
	// Notifications are answered 202; whatever it says, the session is open.
	_ = c.notify(ctx, "notifications/initialized")
	return nil
}

func (c *Client) headers(request *http.Request) {
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	c.mu.Lock()
	request.Header.Set(c.Endpoint.Header, c.Endpoint.Value)
	if c.session != "" {
		request.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.protocol != "" {
		request.Header.Set("Mcp-Protocol-Version", c.protocol)
	}
	c.mu.Unlock()
}

func (c *Client) notify(ctx context.Context, method string) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint.URL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.headers(request)
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	return nil
}

func (c *Client) request(ctx context.Context, method string, params any, inSession bool) (json.RawMessage, *rpcError, error) {
	c.mu.Lock()
	c.next++
	id := c.next
	c.mu.Unlock()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint.URL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	c.headers(request)
	response, err := c.HTTP.Do(request)
	if err != nil {
		// The URL only: an error never carries the token.
		return nil, nil, fmt.Errorf("cannot reach %s", c.Endpoint.URL.Host)
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound && inSession:
		return nil, nil, errSessionGone
	case response.StatusCode == http.StatusUnauthorized:
		return nil, nil, errRefused
	case response.StatusCode == http.StatusForbidden:
		return nil, nil, fmt.Errorf("%s refused the call (403): the token lacks a permission", c.Endpoint.URL.Host)
	case response.StatusCode != http.StatusOK:
		return nil, nil, fmt.Errorf("%s answered %d", c.Endpoint.URL.Host, response.StatusCode)
	}
	if method == "initialize" {
		if session := response.Header.Get("Mcp-Session-Id"); session != "" {
			c.mu.Lock()
			c.session = session
			c.mu.Unlock()
		}
	}
	reply, err := readReply(response, id)
	if err != nil {
		return nil, nil, err
	}
	return reply.Result, reply.Error, nil
}

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

// readReply reads the answer to the request id: a JSON body, or the event
// that carries it in a stream. Anything else is not an answer.
func readReply(response *http.Response, id int64) (*rpcReply, error) {
	want := strconv.FormatInt(id, 10)
	matches := func(raw []byte) (*rpcReply, bool) {
		var reply rpcReply
		if json.Unmarshal(raw, &reply) != nil || reply.JSONRPC != "2.0" || string(reply.ID) != want {
			return nil, false
		}
		if reply.Error == nil && len(reply.Result) == 0 {
			return nil, false
		}
		return &reply, true
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	limited := io.LimitReader(response.Body, maxResponse+1)
	switch mediaType {
	case "application/json":
		raw, err := io.ReadAll(limited)
		if err != nil || len(raw) > maxResponse {
			return nil, errors.New("the server's answer is too large or cut")
		}
		if reply, ok := matches(raw); ok {
			return reply, nil
		}
		return nil, errors.New("the server's answer cannot be read")
	case "text/event-stream":
		reader := bufio.NewReader(limited)
		var data bytes.Buffer
		read := 0
		for {
			line, err := reader.ReadString('\n')
			read += len(line)
			if read > maxResponse {
				return nil, errors.New("the server's answer is too large")
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if value, ok := strings.CutPrefix(trimmed, "data:"); ok {
				data.WriteString(strings.TrimPrefix(value, " "))
				data.WriteByte('\n')
			} else if trimmed == "" && data.Len() > 0 {
				if reply, ok := matches(data.Bytes()); ok {
					return reply, nil
				}
				// A notification or a request of the server: not the answer.
				data.Reset()
			}
			if err != nil {
				if data.Len() > 0 {
					if reply, ok := matches(data.Bytes()); ok {
						return reply, nil
					}
				}
				return nil, errors.New("the server's stream ended without the answer")
			}
		}
	}
	return nil, fmt.Errorf("the server answered %q, not JSON", mediaType)
}

// Tools lists every tool of the server, page by page (at most 2,000).
func (c *Client) Tools(ctx context.Context) ([]json.RawMessage, error) {
	var tools []json.RawMessage
	cursor := ""
	for page := 0; page < 50; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, rpcErr, err := c.call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		if rpcErr != nil {
			return nil, fmt.Errorf("the server refused to list its tools: %s", rpcErr.Message)
		}
		var listed struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if json.Unmarshal(result, &listed) != nil {
			return nil, errors.New("the server's list of tools cannot be read")
		}
		tools = append(tools, listed.Tools...)
		if len(tools) > 2000 {
			return nil, errors.New("the server lists more than 2,000 tools")
		}
		if listed.NextCursor == "" {
			return tools, nil
		}
		cursor = listed.NextCursor
	}
	return nil, errors.New("the server's list of tools does not end")
}

// Request sends one request of another method (resources, prompts).
func (c *Client) Request(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *rpcError, error) {
	if len(params) == 0 || string(params) == "null" {
		params = json.RawMessage("{}")
	}
	return c.call(ctx, method, params)
}

// Call runs one tool.
func (c *Client) Call(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, *rpcError, error) {
	return c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": arguments})
}
