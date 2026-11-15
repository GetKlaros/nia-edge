package turn

import (
	"errors"
	"regexp"

	"github.com/GetKlaros/nia-edge/canon"
)

// Provider-hosted tools run inside the provider, during the model call: by
// the time the response is read, the provider has already fetched the URL or
// run the code. They are decided on the request: one that is not allowed is
// removed before the request leaves.
//
// Names given to the role: hosted:<type> (OpenAI, such as
// hosted:web_search_preview), hosted:<name> (Anthropic server tools, such as
// hosted:web_fetch), hosted:mcp:<server> (remote MCP servers the provider
// calls), hosted:web_search (Chat Completions web_search_options). Tool
// types the client runs itself pass through; any other type is hosted.

var (
	openAIClientTypes   = map[string]bool{"function": true, "custom": true, "local_shell": true, "shell": true, "apply_patch": true, "computer_use_preview": true, "computer_use": true}
	anthropicClientType = regexp.MustCompile(`^(custom|computer_[0-9]+|bash_[0-9]+|text_editor_[0-9]+|memory_[0-9]+)$`)
)

// Gate is what was decided about the provider-run tools of a request.
type Gate struct {
	// Removed are the tools taken out of the request; Kept those left in it.
	// A tool declared twice is named twice.
	Removed []string `json:"removed"`
	Kept    []string `json:"kept"`
}

// HostedTools names the provider-run tools a request declares, each once, in
// order, without changing the request.
func HostedTools(format Format, body *canon.Value) ([]string, error) {
	copied, err := canon.Parse(body.JSON())
	if err != nil {
		return nil, errors.Join(ErrUndecidable, err)
	}
	gate, err := GateHosted(format, copied, func(string) bool { return true })
	if err != nil {
		return nil, err
	}
	var names []string
	seen := map[string]bool{}
	for _, name := range gate.Kept {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names, nil
}

// GateHosted removes from a request body the provider-run tools for which
// allowed is false, as the server does, and reports what it kept and removed.
func GateHosted(format Format, body *canon.Value, allowed func(name string) bool) (Gate, error) {
	gate := Gate{Removed: []string{}, Kept: []string{}}
	if format != ChatCompletions && format != Responses && format != AnthropicMessages {
		return gate, errors.Join(ErrUndecidable, errors.New("unknown format"))
	}
	r := &reader{}
	decide := func(name string) bool {
		if allowed(name) {
			gate.Kept = append(gate.Kept, name)
			return true
		}
		gate.Removed = append(gate.Removed, name)
		return false
	}
	isArray := func(v *canon.Value) bool { return v.Kind() == canon.Array }

	if format == ChatCompletions {
		if body.Get("web_search_options").Present() && !decide("hosted:web_search") {
			body.Delete("web_search_options")
		}
	} else if tools := body.Get("tools"); isArray(tools) {
		removedTypes := map[string]bool{}
		tools.Keep(func(tool *canon.Value) bool {
			if !isRecord(tool) {
				return true
			}
			kind, typed := r.str(tool.Get("type"))
			var name string
			if format == Responses {
				if !typed || kind == "" || openAIClientTypes[kind] {
					return true
				}
				if kind == "mcp" {
					name = "hosted:mcp:" + r.orDefault(tool.Get("server_label"), "unnamed")
				} else {
					name = "hosted:" + kind
				}
			} else {
				// mcp_toolset entries belong to an mcp_servers entry, decided below.
				if !typed || kind == "" || anthropicClientType.MatchString(kind) || kind == "mcp_toolset" {
					return true
				}
				name = "hosted:" + r.orDefault(tool.Get("name"), kind)
			}
			if decide(name) {
				return true
			}
			removedTypes[kind] = true
			if toolName, ok := r.str(tool.Get("name")); ok {
				removedTypes[toolName] = true
			}
			return false
		})
		// A tool_choice that forces a removed tool falls back to letting the model choose.
		if choice := body.Get("tool_choice"); isRecord(choice) && len(removedTypes) > 0 {
			target, named := r.str(choice.Get("name"))
			if !named {
				target, _ = r.str(choice.Get("type"))
			}
			if removedTypes[target] {
				auto := `{"type":"auto"}`
				if format == Responses {
					auto = `"auto"`
				}
				value, _ := canon.Parse(auto)
				body.Set("tool_choice", value)
			}
		}
	}

	if servers := body.Get("mcp_servers"); format == AnthropicMessages && isArray(servers) {
		gone := map[string]bool{}
		servers.Keep(func(server *canon.Value) bool {
			label := "unnamed"
			if name, ok := r.str(server.Get("name")); ok && isRecord(server) {
				label = name
			}
			if decide("hosted:mcp:" + label) {
				return true
			}
			gone[label] = true
			return false
		})
		if tools := body.Get("tools"); isArray(tools) && len(gone) > 0 {
			tools.Keep(func(tool *canon.Value) bool {
				if kind, _ := r.str(tool.Get("type")); !isRecord(tool) || kind != "mcp_toolset" {
					return true
				}
				// String(tool.mcp_server_name): a missing name reads "undefined".
				server := "undefined"
				if tool.Get("mcp_server_name").Present() {
					server = r.jsString(tool.Get("mcp_server_name"))
				}
				return !gone[server]
			})
		}
		if servers.Len() == 0 {
			body.Delete("mcp_servers")
		}
	}

	if tools := body.Get("tools"); isArray(tools) && tools.Len() == 0 {
		body.Delete("tools")
		body.Delete("tool_choice")
	}
	if r.err != nil {
		return Gate{}, r.err
	}
	return gate, nil
}
