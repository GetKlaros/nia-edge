package turn

import (
	"errors"
	"strings"

	"github.com/GetKlaros/nia-edge/canon"
)

// The two sources of what a request brings into a conversation.
const (
	UserPrompt = "user_prompt"
	ToolOutput = "tool_output"
)

// Segment is a piece of text that is new in a request.
type Segment struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

// Input is what a request holds, as far as deciding goes.
type Input struct {
	// Segments are new in this turn (after the last model turn), in order.
	Segments []Segment `json:"segments"`
	// IngestedTools are the tools whose results appear anywhere in the history.
	IngestedTools []string `json:"ingested_tools"`
	// FirstUserText is the first user text of the conversation; nil when there is none.
	FirstUserText *string `json:"first_user_text"`
}

// ReadInput reads a request body, as the server does: what is new in it,
// and which tools' results it carries. The error is ErrUndecidable when this
// code cannot be sure to read what the server would.
func ReadInput(format Format, body *canon.Value) (Input, error) {
	r := &reader{}
	in := inputReader{reader: r, names: map[string]string{}}
	if isRecord(body) {
		switch format {
		case ChatCompletions:
			in.chat(body)
		case AnthropicMessages:
			in.anthropic(body)
		case Responses:
			in.responses(body)
		default:
			return Input{}, errors.Join(ErrUndecidable, errors.New("unknown format"))
		}
	}
	if r.err != nil {
		return Input{}, r.err
	}
	out := in.out
	if out.Segments == nil {
		out.Segments = []Segment{}
	}
	if out.IngestedTools == nil {
		out.IngestedTools = []string{}
	}
	return out, nil
}

type inputReader struct {
	*reader
	out Input
	// names maps the identifier of a call to the tool it called.
	names map[string]string
}

func (in *inputReader) ingest(tool string) {
	in.out.IngestedTools = append(in.out.IngestedTools, tool)
}

// nameOf is the tool of the call a result answers, or fallback.
func (in *inputReader) nameOf(id *canon.Value, fallback string) string {
	if key, ok := in.str(id); ok {
		if name, known := in.names[key]; known {
			return name
		}
	}
	return fallback
}

// texts is the text of a content: a string, or the text of each part of a
// list. Text that is only white space is not text.
func (in *inputReader) texts(content *canon.Value) []string {
	var found []string
	keep := func(v *canon.Value) {
		if text, ok := in.str(v); ok && !jsTrimmedEmpty(text) {
			found = append(found, text)
		}
	}
	if content.Kind() == canon.String {
		keep(content)
		return found
	}
	for _, part := range content.Items() {
		if isRecord(part) {
			keep(part.Get("text"))
		}
	}
	return found
}

func (in *inputReader) push(source string, content *canon.Value) {
	for _, text := range in.texts(content) {
		in.out.Segments = append(in.out.Segments, Segment{Source: source, Text: text})
	}
}

func (in *inputReader) firstUser(content *canon.Value) {
	if in.out.FirstUserText == nil {
		text := strings.Join(in.texts(content), "\n")
		in.out.FirstUserText = &text
	}
}

func (in *inputReader) role(v *canon.Value) string {
	role, _ := in.str(v.Get("role"))
	return role
}

// records are the items of a list that are objects.
func records(list *canon.Value) []*canon.Value {
	var kept []*canon.Value
	for _, item := range list.Items() {
		if isRecord(item) {
			kept = append(kept, item)
		}
	}
	return kept
}

func lastIndex(items []*canon.Value, is func(*canon.Value) bool) int {
	for i := len(items) - 1; i >= 0; i-- {
		if is(items[i]) {
			return i
		}
	}
	return -1
}

func (in *inputReader) chat(body *canon.Value) {
	messages := records(body.Get("messages"))
	lastAssistant := lastIndex(messages, func(m *canon.Value) bool { return in.role(m) == "assistant" })
	for index, message := range messages {
		fresh := index > lastAssistant
		switch in.role(message) {
		case "assistant":
			for _, call := range message.Get("tool_calls").Items() {
				id, ok := in.str(call.Get("id"))
				if !isRecord(call) || !ok {
					continue
				}
				var name *canon.Value
				if fn := call.Get("function"); isRecord(fn) {
					name = fn.Get("name")
				}
				in.names[id] = in.toolName(name)
			}
		case "user":
			in.firstUser(message.Get("content"))
			if fresh {
				in.push(UserPrompt, message.Get("content"))
			}
		case "tool":
			in.ingest(in.nameOf(message.Get("tool_call_id"), unknownTool))
			if fresh {
				in.push(ToolOutput, message.Get("content"))
			}
		case "function":
			in.ingest(in.toolName(message.Get("name")))
			if fresh {
				in.push(ToolOutput, message.Get("content"))
			}
		}
		// system / developer: operator-owned instructions, not untrusted input.
	}
}

func (in *inputReader) anthropic(body *canon.Value) {
	messages := records(body.Get("messages"))
	lastAssistant := lastIndex(messages, func(m *canon.Value) bool { return in.role(m) == "assistant" })
	for index, message := range messages {
		fresh := index > lastAssistant
		blocks := records(message.Get("content"))
		switch in.role(message) {
		case "assistant":
			for _, block := range blocks {
				kind, isText := in.typeOf(block)
				if id, ok := in.str(block.Get("id")); ok && anthropicToolUse(kind) {
					in.names[id] = in.anthropicCall(block, kind).Name
				}
				// Results of provider-run tools sit in the assistant's own
				// content: still untrusted input.
				if isText && strings.HasSuffix(kind, "_tool_result") {
					in.ingest(in.nameOf(block.Get("tool_use_id"), "hosted:unknown"))
				}
			}
		case "user":
			in.firstUser(message.Get("content"))
			if message.Get("content").Kind() == canon.String {
				if fresh {
					in.push(UserPrompt, message.Get("content"))
				}
				continue
			}
			for _, block := range blocks {
				if kind, _ := in.typeOf(block); kind == "tool_result" {
					in.ingest(in.nameOf(block.Get("tool_use_id"), unknownTool))
					if fresh {
						in.push(ToolOutput, block.Get("content"))
					}
				} else if text, ok := in.str(block.Get("text")); ok && fresh && !jsTrimmedEmpty(text) {
					in.out.Segments = append(in.out.Segments, Segment{Source: UserPrompt, Text: text})
				}
			}
		}
	}
}

func (in *inputReader) responses(body *canon.Value) {
	input := body.Get("input")
	if text, ok := in.str(input); ok {
		in.push(UserPrompt, input)
		in.out.FirstUserText = &text
		return
	}
	items := records(input)
	isModelItem := func(item *canon.Value) bool {
		kind, ok := in.typeOf(item)
		return in.role(item) == "assistant" || (ok && strings.HasSuffix(kind, "_call") && !strings.HasSuffix(kind, "_call_output"))
	}
	lastModel := lastIndex(items, isModelItem)
	for index, item := range items {
		fresh := index > lastModel
		kind, typed := in.typeOf(item)
		switch {
		case isModelItem(item):
			hosted := ""
			if typed && strings.HasSuffix(kind, "_call") && !openAIClientCalls[kind] {
				// A provider-run call carries its own result (search hits, MCP output).
				if kind == "mcp_call" {
					hosted = "hosted:mcp:" + in.orDefault(item.Get("server_label"), "unnamed")
				} else {
					hosted = "hosted:" + strings.TrimSuffix(kind, "_call")
				}
				in.ingest(hosted)
			}
			id, ok := in.str(item.Get("call_id"))
			if !ok {
				continue
			}
			switch {
			case hosted != "":
				in.names[id] = hosted
			case present(item.Get("name")):
				in.names[id] = in.toolName(item.Get("name"))
			default:
				// String(item.type): the type itself, or how JavaScript writes what is there instead.
				spelled := "undefined"
				if item.Get("type").Present() {
					spelled = in.jsString(item.Get("type"))
				}
				in.names[id] = in.cutName(utf16Of(strings.TrimSuffix(spelled, "_call")))
			}
		case typed && strings.HasSuffix(kind, "_call_output"):
			in.ingest(in.nameOf(item.Get("call_id"), unknownTool))
			if fresh {
				in.push(ToolOutput, item.Get("output"))
			}
		case in.role(item) == "user":
			in.firstUser(item.Get("content"))
			if fresh {
				in.push(UserPrompt, item.Get("content"))
			}
		}
	}
}
