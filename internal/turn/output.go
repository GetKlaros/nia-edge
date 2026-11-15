// Package turn reads what a model answered: its text and the tool calls it
// proposes, in the three APIs Nia understands.
//
// The Nia server is the reference: conformance/outputs.json holds what it
// reads from a response, and this package's tests replay it. A response the
// server refuses is refused here with the same reason (ParseError). Where
// this code cannot be sure to read what the server would, it returns
// ErrUndecidable: the response is not released on a guess.
package turn

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/GetKlaros/nia-edge/canon"
)

// Format is one of the model APIs.
type Format string

// The three model APIs.
const (
	ChatCompletions   Format = "chat-completions"
	Responses         Format = "responses"
	AnthropicMessages Format = "anthropic-messages"
)

// ToolCall is a call the model proposes.
type ToolCall struct {
	// ID is the provider's identifier of the call; nil when it gave none.
	ID        *string `json:"id"`
	Name      string  `json:"name"`
	Arguments string  `json:"arguments"`
	// Kind is the Responses API item type (function_call, local_shell_call…).
	Kind string `json:"kind,omitempty"`
}

// Output is what a model response holds.
type Output struct {
	// Text is all model text, tool-call arguments included, for inspection.
	Text      string     `json:"text"`
	ToolCalls []ToolCall `json:"toolCalls"`
}

// ParseError is a response that is refused, with the reason the agent is
// told. A truncated stream, a provider error and an unknown framing are
// refused: nothing of such a response is released.
type ParseError struct{ Reason string }

func (e *ParseError) Error() string { return e.Reason }

func refused(reason string) error { return &ParseError{Reason: reason} }

// ErrUndecidable reports a response this code cannot be sure to read as the
// server would. The caller refuses it.
var ErrUndecidable = errors.New("turn: not read on this machine")

// errUnpaired is text with a surrogate without its pair. JavaScript holds
// such text; a Go string cannot.
var errUnpaired = errors.Join(ErrUndecidable, errors.New("text with a surrogate without its pair"))

const (
	unknownTool  = "unknown"
	maxSSEEvents = 100_000
)

// Decode reads the bytes of a response as the server does: strict UTF-8,
// without a leading byte order mark.
func Decode(body []byte) (string, error) {
	if !utf8.Valid(body) {
		return "", canon.ErrInvalidUTF8
	}
	return strings.TrimPrefix(string(body), "\xef\xbb\xbf"), nil
}

// ReadOutput reads a complete model response: one JSON document, or a
// buffered event stream when stream is true. A stream without its protocol
// success terminal is refused.
func ReadOutput(format Format, stream bool, body string) (Output, error) {
	if !utf8.ValidString(body) {
		return Output{}, canon.ErrInvalidUTF8
	}
	if format != ChatCompletions && format != Responses && format != AnthropicMessages {
		return Output{}, errors.Join(ErrUndecidable, errors.New("unknown format"))
	}
	r := &reader{}
	var out Output
	if stream {
		out = r.sse(format, body)
	} else {
		value, err := canon.Parse(body)
		switch {
		case errors.Is(err, canon.ErrNotJSON):
			return Output{}, refused("unparseable response")
		case err != nil:
			return Output{}, errors.Join(ErrUndecidable, err)
		}
		out = r.json(format, value)
	}
	if r.err != nil {
		return Output{}, r.err
	}
	if out.ToolCalls == nil {
		out.ToolCalls = []ToolCall{}
	}
	return out, nil
}

// reader keeps the first reason a response cannot be read, so the reading
// code stays as plain as the server's.
type reader struct{ err error }

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

// str returns a string value; ok is false for anything else.
func (r *reader) str(v *canon.Value) (string, bool) {
	units, ok := v.Units()
	if !ok {
		return "", false
	}
	text, well := canon.WellFormed(units)
	if !well {
		r.fail(errUnpaired)
	}
	return text, true
}

func isRecord(v *canon.Value) bool { return v.Kind() == canon.Object }

// present is JavaScript's `value ?? other`: null and a missing key are both absent.
func present(v *canon.Value) bool { return v.Kind() != canon.Null }

func firstPresent(values ...*canon.Value) *canon.Value {
	for _, v := range values {
		if present(v) {
			return v
		}
	}
	return nil
}

// toolName is a non-empty string cut to 256 UTF-16 units, or "unknown".
func (r *reader) toolName(v *canon.Value) string {
	units, ok := v.Units()
	if !ok || len(units) == 0 {
		return unknownTool
	}
	return r.cutName(units)
}

func (r *reader) cutName(units []uint16) string {
	if len(units) == 0 {
		return unknownTool
	}
	if len(units) > 256 {
		units = units[:256]
	}
	text, well := canon.WellFormed(units)
	if !well {
		r.fail(errUnpaired)
	}
	return text
}

// stringify is the arguments of a call as text: a string as it is, nothing
// as "", anything else as JSON.stringify writes it.
func (r *reader) stringify(v *canon.Value) string {
	if text, ok := r.str(v); ok {
		return text
	}
	if !present(v) {
		return ""
	}
	// JSON.stringify writes a lone surrogate as an escape: the text is well formed.
	return v.JSON()
}

// jsString is JavaScript's String(value) for a JSON value.
func (r *reader) jsString(v *canon.Value) string {
	switch v.Kind() {
	case canon.String:
		text, _ := r.str(v)
		return text
	case canon.Number, canon.Bool:
		return v.JSON()
	case canon.Object:
		return "[object Object]"
	case canon.Array:
		parts := make([]string, 0, v.Len())
		for _, item := range v.Items() {
			if present(item) {
				parts = append(parts, r.jsString(item))
			} else {
				parts = append(parts, "")
			}
		}
		return strings.Join(parts, ",")
	}
	return "null"
}

// orDefault is String(value ?? fallback).
func (r *reader) orDefault(v *canon.Value, fallback string) string {
	if !present(v) {
		return fallback
	}
	return r.jsString(v)
}

func (r *reader) typeOf(v *canon.Value) (string, bool) { return r.str(v.Get("type")) }

// partsText is the text of a content: a string, or the text, refusal and
// thinking of each part of a list.
func (r *reader) partsText(content *canon.Value) []string {
	if text, ok := r.str(content); ok {
		return []string{text}
	}
	var texts []string
	for _, part := range content.Items() {
		texts = append(texts, r.partText(part)...)
	}
	return texts
}

func (r *reader) partText(part *canon.Value) []string {
	var texts []string
	if !isRecord(part) {
		return nil
	}
	for _, key := range []string{"text", "refusal", "thinking"} {
		if text, ok := r.str(part.Get(key)); ok {
			texts = append(texts, text)
		}
	}
	return texts
}

func (r *reader) id(values ...*canon.Value) *string {
	for _, v := range values {
		if text, ok := r.str(v); ok {
			return &text
		}
	}
	return nil
}

// Tool types of the Responses API that the client runs itself.
var openAIClientCalls = map[string]bool{
	"function_call": true, "custom_tool_call": true, "local_shell_call": true, "shell_call": true, "apply_patch_call": true, "computer_call": true,
}

// anthropicHostedName is the role name of a block the provider ran, or "".
func (r *reader) anthropicHostedName(block *canon.Value, kind string) (string, bool) {
	switch kind {
	case "server_tool_use":
		return "hosted:" + r.orDefault(block.Get("name"), "unknown"), true
	case "mcp_tool_use":
		return "hosted:mcp:" + r.orDefault(block.Get("server_name"), "unnamed"), true
	}
	return "", false
}

func (r *reader) anthropicCall(block *canon.Value, kind string) ToolCall {
	name, hosted := r.anthropicHostedName(block, kind)
	if !hosted {
		name = r.toolName(block.Get("name"))
	}
	return ToolCall{ID: r.id(block.Get("id")), Name: name}
}

func anthropicToolUse(kind string) bool {
	return kind == "tool_use" || kind == "server_tool_use" || kind == "mcp_tool_use"
}

func (r *reader) responsesOutput(output *canon.Value) Output {
	var texts []string
	var calls []ToolCall
	for _, item := range output.Items() {
		if !isRecord(item) {
			continue
		}
		kind, ok := r.typeOf(item)
		if !ok {
			continue
		}
		switch {
		case kind == "message":
			texts = append(texts, r.partsText(item.Get("content"))...)
		case kind == "reasoning":
			texts = append(texts, r.partsText(item.Get("summary"))...)
		case strings.HasSuffix(kind, "_call"):
			// function_call, custom_tool_call, local_shell_call, computer_call,
			// mcp_call and provider-run tools such as web_search_call.
			bare := strings.TrimSuffix(kind, "_call")
			var name string
			switch {
			case openAIClientCalls[kind]:
				if present(item.Get("name")) {
					name = r.toolName(item.Get("name"))
				} else {
					name = r.cutName(utf16Of(bare))
				}
			case kind == "mcp_call":
				name = "hosted:mcp:" + r.orDefault(item.Get("server_label"), "unnamed")
			default:
				name = "hosted:" + bare
			}
			call := ToolCall{
				ID:        r.id(item.Get("call_id"), item.Get("id")),
				Name:      name,
				Arguments: r.stringify(firstPresent(item.Get("arguments"), item.Get("action"), item.Get("input"))),
				Kind:      kind,
			}
			calls = append(calls, call)
			texts = append(texts, call.Arguments)
		}
	}
	return Output{Text: strings.Join(texts, "\n"), ToolCalls: calls}
}

func utf16Of(text string) []uint16 {
	units := make([]uint16, 0, len(text))
	for _, r := range text {
		if r > 0xffff {
			r -= 0x10000
			units = append(units, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		} else {
			units = append(units, uint16(r))
		}
	}
	return units
}

func (r *reader) json(format Format, payload *canon.Value) Output {
	if !isRecord(payload) {
		r.fail(refused("response is not a JSON object"))
		return Output{}
	}
	if format == Responses {
		return r.responsesOutput(payload.Get("output"))
	}
	var texts []string
	var calls []ToolCall
	if format == ChatCompletions {
		for _, choice := range payload.Get("choices").Items() {
			message := choice.Get("message")
			if !isRecord(choice) || !isRecord(message) {
				continue
			}
			texts = append(texts, r.partsText(message.Get("content"))...)
			if text, ok := r.str(message.Get("reasoning_content")); ok {
				texts = append(texts, text)
			}
			for _, call := range message.Get("tool_calls").Items() {
				if !isRecord(call) {
					continue
				}
				// A function that is not an object is read as an empty one.
				fn := call.Get("function")
				if !isRecord(fn) {
					fn = nil
				}
				calls = append(calls, ToolCall{ID: r.id(call.Get("id")), Name: r.toolName(fn.Get("name")), Arguments: r.stringify(fn.Get("arguments"))})
			}
			if legacy := message.Get("function_call"); isRecord(legacy) {
				calls = append(calls, ToolCall{Name: r.toolName(legacy.Get("name")), Arguments: r.stringify(legacy.Get("arguments"))})
			}
		}
	} else {
		for _, block := range payload.Get("content").Items() {
			if !isRecord(block) {
				continue
			}
			if kind, _ := r.typeOf(block); anthropicToolUse(kind) {
				call := r.anthropicCall(block, kind)
				call.Arguments = r.stringify(block.Get("input"))
				calls = append(calls, call)
			} else {
				texts = append(texts, r.partText(block)...)
			}
		}
	}
	for _, call := range calls {
		texts = append(texts, call.Arguments)
	}
	return Output{Text: strings.Join(texts, "\n"), ToolCalls: calls}
}

type sseEvent struct{ data string }

// jsTrimmedEmpty reports whether JavaScript's trim leaves nothing: white
// space and line terminators, the byte order mark included.
func jsTrimmedEmpty(text string) bool {
	for _, c := range text {
		switch {
		case c >= 0x9 && c <= 0xd, c == 0x20, c == 0xa0, c == 0x1680, c >= 0x2000 && c <= 0x200a,
			c == 0x2028, c == 0x2029, c == 0x202f, c == 0x205f, c == 0x3000, c == 0xfeff:
		default:
			return false
		}
	}
	return true
}

// parseSSE reads a complete event stream. A field that is not one of the
// protocol's is refused.
func (r *reader) parseSSE(body string) []sseEvent {
	var events []sseEvent
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
	for _, block := range strings.Split(body, "\n\n") {
		if jsTrimmedEmpty(block) {
			continue
		}
		var data []string
		for _, line := range strings.Split(block, "\n") {
			if line == "" || strings.HasPrefix(line, ":") {
				continue
			}
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "data":
				data = append(data, value)
			case "event", "id", "retry":
			default:
				r.fail(refused("unsupported SSE field " + field))
				return nil
			}
		}
		if len(data) == 0 {
			continue
		}
		events = append(events, sseEvent{data: strings.Join(data, "\n")})
		if len(events) > maxSSEEvents {
			r.fail(refused("too many SSE events"))
			return nil
		}
	}
	return events
}

// event reads the JSON object of an event; nil once the response is refused.
func (r *reader) event(data string) *canon.Value {
	value, err := canon.Parse(data)
	switch {
	case errors.Is(err, canon.ErrNotJSON):
		r.fail(refused("invalid JSON in SSE event"))
		return nil
	case err != nil:
		r.fail(errors.Join(ErrUndecidable, err))
		return nil
	}
	if !isRecord(value) {
		r.fail(refused("SSE event is not a JSON object"))
		return nil
	}
	return value
}

// index is the key a piece of a call is gathered under: JavaScript's
// Number(value), written as text. A number is itself; missing is what the
// caller says. Any other type converts in ways not reproduced here.
func (r *reader) index(v *canon.Value, missing, null string) string {
	switch {
	case !v.Present():
		return missing
	case v.Kind() == canon.Null:
		return null
	case v.Kind() == canon.Number:
		return v.JSON()
	}
	r.fail(errors.Join(ErrUndecidable, errors.New("an index that is not a number")))
	return ""
}

// accumulator gathers the pieces of calls in the order they first appear.
type accumulator struct {
	order []string
	calls map[string]*piece
}

type piece struct {
	id        *string
	name      []uint16
	fixedName string
	arguments strings.Builder
}

func (a *accumulator) get(key string) (*piece, bool) {
	p, ok := a.calls[key]
	return p, ok
}

func (a *accumulator) set(key string, p *piece) {
	if a.calls == nil {
		a.calls = map[string]*piece{}
	}
	if _, known := a.calls[key]; !known {
		a.order = append(a.order, key)
	}
	a.calls[key] = p
}

func (r *reader) sse(format Format, body string) Output {
	events := r.parseSSE(body)
	if r.err != nil {
		return Output{}
	}
	switch format {
	case ChatCompletions:
		return r.chatStream(events)
	case AnthropicMessages:
		return r.anthropicStream(events)
	}
	// Responses: the success terminal carries the complete output.
	var completed *canon.Value
	for _, e := range events {
		event := r.event(e.data)
		if r.err != nil {
			return Output{}
		}
		if kind, _ := r.typeOf(event); kind == "response.completed" && completed == nil {
			completed = event
		}
	}
	if completed == nil || !isRecord(completed.Get("response")) {
		r.fail(refused("stream missing response.completed"))
		return Output{}
	}
	return r.responsesOutput(completed.Get("response").Get("output"))
}

func (r *reader) chatStream(events []sseEvent) Output {
	if len(events) == 0 || events[len(events)-1].data != "[DONE]" {
		r.fail(refused("stream missing [DONE]"))
		return Output{}
	}
	var text strings.Builder
	var calls accumulator
	for _, e := range events[:len(events)-1] {
		event := r.event(e.data)
		if r.err != nil {
			return Output{}
		}
		if isRecord(event.Get("error")) {
			r.fail(refused("stream reported an error"))
			return Output{}
		}
		for _, choice := range event.Get("choices").Items() {
			delta := choice.Get("delta")
			if !isRecord(choice) || !isRecord(delta) {
				continue
			}
			choiceIndex := r.index(choice.Get("index"), "0", "0")
			if content, ok := r.str(delta.Get("content")); ok {
				text.WriteString(content)
			}
			if reasoning, ok := r.str(delta.Get("reasoning_content")); ok {
				text.WriteString(reasoning)
			}
			gather := func(key string, id, fn *canon.Value) {
				current, known := calls.get(key)
				if !known {
					current = &piece{}
				}
				if !isRecord(fn) {
					fn = nil
				}
				if value := r.id(id); value != nil {
					current.id = value
				}
				if units, ok := fn.Get("name").Units(); ok {
					current.name = append(current.name, units...)
				}
				if arguments, ok := r.str(fn.Get("arguments")); ok {
					current.arguments.WriteString(arguments)
				}
				calls.set(key, current)
			}
			for _, call := range delta.Get("tool_calls").Items() {
				if !isRecord(call) {
					continue
				}
				gather(choiceIndex+":"+r.index(call.Get("index"), "0", "0"), call.Get("id"), call.Get("function"))
			}
			if legacy := delta.Get("function_call"); isRecord(legacy) {
				gather(choiceIndex+":fn", nil, legacy)
			}
		}
	}
	out := Output{}
	for _, key := range calls.order {
		p := calls.calls[key]
		out.ToolCalls = append(out.ToolCalls, ToolCall{ID: p.id, Name: r.cutName(p.name), Arguments: p.arguments.String()})
	}
	for _, call := range out.ToolCalls {
		text.WriteString(call.Arguments)
	}
	out.Text = text.String()
	return out
}

func (r *reader) anthropicStream(events []sseEvent) Output {
	parsed := make([]*canon.Value, 0, len(events))
	for _, e := range events {
		event := r.event(e.data)
		if r.err != nil {
			return Output{}
		}
		parsed = append(parsed, event)
	}
	last := ""
	for _, event := range parsed {
		kind, _ := r.typeOf(event)
		if kind == "error" {
			r.fail(refused("stream reported an error"))
			return Output{}
		}
		last = kind
	}
	if last != "message_stop" {
		r.fail(refused("stream missing message_stop"))
		return Output{}
	}
	var text strings.Builder
	var calls accumulator
	for _, event := range parsed {
		kind, _ := r.typeOf(event)
		switch {
		case kind == "content_block_start" && isRecord(event.Get("content_block")):
			block := event.Get("content_block")
			blockKind, _ := r.typeOf(block)
			if !anthropicToolUse(blockKind) {
				for _, part := range r.partText(block) {
					text.WriteString(part)
				}
				continue
			}
			call := r.anthropicCall(block, blockKind)
			p := &piece{id: call.ID, fixedName: call.Name}
			if input := block.Get("input"); isRecord(input) && input.Len() > 0 {
				p.arguments.WriteString(input.JSON())
			}
			calls.set(r.index(event.Get("index"), "NaN", "0"), p)
		case kind == "content_block_delta" && isRecord(event.Get("delta")):
			delta := event.Get("delta")
			deltaKind, _ := r.typeOf(delta)
			partial, isText := r.str(delta.Get("partial_json"))
			if deltaKind == "input_json_delta" && isText {
				if p, ok := calls.get(r.index(event.Get("index"), "NaN", "0")); ok {
					p.arguments.WriteString(partial)
				}
			} else {
				for _, part := range r.partText(delta) {
					text.WriteString(part)
				}
			}
		}
	}
	out := Output{}
	for _, key := range calls.order {
		p := calls.calls[key]
		out.ToolCalls = append(out.ToolCalls, ToolCall{ID: p.id, Name: p.fixedName, Arguments: p.arguments.String()})
	}
	for _, call := range out.ToolCalls {
		text.WriteString(call.Arguments)
	}
	out.Text = text.String()
	return out
}
