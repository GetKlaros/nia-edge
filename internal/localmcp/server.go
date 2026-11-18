// Package localmcp serves the agent's MCP servers that run on this machine,
// each in its own container started by nia-mcp, at /local/<name>/mcp on
// nia-edge's address. The agent holds neither their command nor their
// token: nia-edge keeps both, and nia-mcp gives the token to that server
// alone.
//
// A tool call runs only when the model path released that exact call (same
// tool, same canonical arguments, once). A server is started at its first
// call and stopped when idle; its list of tools is kept, by image, so that
// listing them starts nothing.
package localmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/mcpd"
)

// Launcher starts a server: nia-mcp's client.
type Launcher interface {
	Launch(ctx context.Context, launch mcpd.Launch) (mcpd.Stream, error)
}

// protocol is the MCP version nia-edge speaks to the servers.
const protocol = "2025-06-18"

// maxTools bounds a server's list of tools, and maxPages its pages.
const (
	maxTools = 256
	maxPages = 16
)

var toolName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Server is one of the agent's MCP servers.
type Server struct {
	Launch   mcpd.Launch
	Launcher Launcher
	// Cache is the directory of the lists of tools, nia-edge's own.
	Cache string
	// Idle is how long a server runs without a call; zero is ten minutes.
	Idle time.Duration

	mu    sync.Mutex
	proc  *process
	timer *time.Timer
	tools []json.RawMessage
}

func (s *Server) idle() time.Duration {
	if s.Idle > 0 {
		return s.Idle
	}
	return 10 * time.Minute
}

// running returns the server's process, started if need be. Called with
// s.mu held.
func (s *Server) running(ctx context.Context) (*process, error) {
	if s.proc != nil && !s.proc.ended() {
		return s.proc, nil
	}
	startCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stream, err := s.Launcher.Launch(startCtx, s.Launch)
	if err != nil {
		return nil, err
	}
	proc := start(stream)
	result, rpcErr, err := proc.call(startCtx, "initialize", map[string]any{
		"protocolVersion": protocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "nia-edge", "version": "1"},
	})
	if err == nil && rpcErr == nil && json.Valid(result) {
		err = proc.notify("notifications/initialized")
	} else if err == nil {
		err = errors.New("it refused to start a session")
	}
	if err != nil {
		proc.close()
		return nil, fmt.Errorf("the MCP server %s did not start: %w", s.Launch.Name, err)
	}
	s.proc = proc
	return proc, nil
}

// touch restarts the idle timer. Called with s.mu held.
func (s *Server) touch() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.idle(), s.stopIfIdle)
}

func (s *Server) stopIfIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc == nil {
		return
	}
	if s.proc.busy() {
		s.timer = time.AfterFunc(s.idle(), s.stopIfIdle)
		return
	}
	s.proc.close()
	s.proc = nil
}

// Close stops the server.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.proc != nil {
		s.proc.close()
		s.proc = nil
	}
}

type cached struct {
	Image string            `json:"image"`
	Tools []json.RawMessage `json:"tools"`
}

func (s *Server) cacheFile() string {
	if s.Cache == "" {
		return ""
	}
	return filepath.Join(s.Cache, s.Launch.Name+".json")
}

// Tools is the server's list of tools: kept from an earlier start of the
// same image, or listed now.
func (s *Server) Tools(ctx context.Context) ([]json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tools != nil {
		return s.tools, nil
	}
	if file := s.cacheFile(); file != "" {
		if raw, err := os.ReadFile(file); err == nil {
			var kept cached
			if json.Unmarshal(raw, &kept) == nil && kept.Image == s.Launch.Image && kept.Tools != nil {
				s.tools = kept.Tools
				return s.tools, nil
			}
		}
	}
	proc, err := s.running(ctx)
	if err != nil {
		return nil, err
	}
	defer s.touch()
	var tools []json.RawMessage
	var cursor string
	for page := 0; page < maxPages; page++ {
		var params any
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		listCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		result, rpcErr, err := proc.call(listCtx, "tools/list", params)
		cancel()
		if err != nil {
			return nil, err
		}
		if rpcErr != nil {
			return nil, fmt.Errorf("the MCP server %s did not list its tools: %s", s.Launch.Name, rpcErr.Message)
		}
		var listed struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if json.Unmarshal(result, &listed) != nil {
			return nil, fmt.Errorf("the MCP server %s listed its tools in a form that cannot be read", s.Launch.Name)
		}
		for _, tool := range listed.Tools {
			var named struct {
				Name string `json:"name"`
			}
			// A name that cannot be a tool of the agent is left out.
			if json.Unmarshal(tool, &named) == nil && toolName.MatchString(named.Name) && len(tools) < maxTools {
				tools = append(tools, tool)
			}
		}
		if listed.NextCursor == "" {
			break
		}
		cursor = listed.NextCursor
	}
	if tools == nil {
		tools = []json.RawMessage{}
	}
	s.tools = tools
	if file := s.cacheFile(); file != "" {
		if raw, err := json.Marshal(cached{Image: s.Launch.Image, Tools: tools}); err == nil {
			temp := file + ".tmp"
			if os.WriteFile(temp, raw, 0o600) == nil {
				_ = os.Rename(temp, file)
			}
		}
	}
	return tools, nil
}

// Call runs one tool, and returns the server's result as it gave it.
func (s *Server) Call(ctx context.Context, tool string, arguments json.RawMessage) (json.RawMessage, *rpcError, error) {
	s.mu.Lock()
	proc, err := s.running(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, nil, err
	}
	s.touch()
	s.mu.Unlock()
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	result, rpcErr, err := proc.call(callCtx, "tools/call", map[string]any{"name": tool, "arguments": arguments})
	s.mu.Lock()
	s.touch()
	s.mu.Unlock()
	return result, rpcErr, err
}
