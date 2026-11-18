// Package local is the model path on the machine: the agent's model calls go
// from here straight to the provider, and only the tool calls the model
// proposes are sent to Nia to be decided.
//
// What Nia receives: the names of the tools whose results the conversation
// holds (which is what taints a session), and for each proposed call its
// name, the hash of its arguments and what the signed policy decides for each
// state of the session. The arguments themselves go to Nia only when a
// reviewer must see them, when the call goes through a dispatcher, or when
// this machine cannot be sure of the server's answer. What it never receives:
// the prompts, the tool results and the model's text.
//
// Nia stays the one place that holds the session state and the approvals,
// picks the decision and keeps the log.
// Nothing is released on a guess: a request or a response that cannot be read
// as Nia reads it, a provider that cannot be reached, a decision that cannot
// be obtained, all refuse the turn.
package local

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/canon"
	"github.com/GetKlaros/nia-edge/internal/engine"
	"github.com/GetKlaros/nia-edge/internal/inspect"
	"github.com/GetKlaros/nia-edge/internal/turn"
)

// Verdict is Nia's answer for one proposed call.
type Verdict struct {
	// Allowed is true only for an explicit "allow".
	Allowed bool
	// Message is what the agent is told when the call is not allowed.
	Message string
}

// Authority is Nia, as far as this path needs it. An error refuses the turn.
type Authority interface {
	// Ingested records that the session holds a result of this tool.
	Ingested(ctx context.Context, session, tool string) error
	// Hosted says which provider-run tools the role allows in the session.
	Hosted(ctx context.Context, session string, tools []string) (allowed []string, err error)
	// Decide answers for one proposed call, from its arguments.
	Decide(ctx context.Context, session, tool, arguments string) (Verdict, error)
	// DecideHashed answers for one proposed call this machine decided: Nia
	// picks the decision its session state calls for. needsArguments is true
	// when Nia must see the arguments, and then the verdict is empty.
	DecideHashed(ctx context.Context, session string, call Hashed) (verdict Verdict, needsArguments bool, err error)
}

// Hashed is a call decided on this machine, as Nia receives it.
type Hashed struct {
	Tool string
	// Hash is canon.ArgumentsHash of the call.
	Hash string
	// Digest names the policy that decided.
	Digest string
	// Clean, Tainted, Exposed and Both are the decisions for each state of
	// the session: neither tainted nor exposed, tainted, exposed, both.
	Clean, Tainted, Exposed, Both engine.Decision
}

// Rules is the signed policy in force on this machine, ready to decide.
type Rules struct {
	Role        *engine.Role
	Dispatchers engine.Dispatchers
	Digest      string
}

// Handler serves the three model routes.
type Handler struct {
	// Provider is the base URL of the model provider, as its clients use it.
	Provider *url.URL
	// Key is the provider's API key.
	Key string
	// Anthropic selects the x-api-key header; otherwise Authorization: Bearer.
	Anthropic bool
	// SessionHeader, when set, carries an opaque id of the conversation to
	// the provider: OpenCode Go refuses a request without x-opencode-session.
	SessionHeader string
	// HTTP reaches the provider. It must not follow redirects.
	HTTP *http.Client
	Nia  Authority
	// Rules returns the policy in force, or nil: then Nia decides from the
	// arguments.
	Rules func() *Rules
	// MaxRequest and MaxResponse bound what is read; zero means 4 MiB and 16 MiB.
	MaxRequest, MaxResponse int64
	Logger                  *slog.Logger

	mu       sync.Mutex
	recorded map[string]bool
}

// Format returns the API a path speaks, or false when it is not a model route.
func Format(path string) (turn.Format, bool) {
	switch path {
	case "/v1/chat/completions":
		return turn.ChatCompletions, true
	case "/v1/responses":
		return turn.Responses, true
	case "/v1/messages":
		return turn.AnthropicMessages, true
	}
	return "", false
}

// Client headers forwarded to the provider. Credentials never are.
var forwarded = []string{"Anthropic-Version", "Anthropic-Beta", "Openai-Beta", "Accept"}

func (h *Handler) limit(value, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}

// Refuse answers the agent in the shape its API uses for errors.
func Refuse(w http.ResponseWriter, format turn.Format, status int, code, message string) {
	var body any
	if format == turn.AnthropicMessages {
		body = map[string]any{"type": "error", "error": map[string]string{"type": code, "message": message}}
	} else {
		body = map[string]any{"error": map[string]string{"message": message, "type": "nia_policy_error", "code": code}}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (h *Handler) log(message string, args ...any) {
	if h.Logger != nil {
		h.Logger.Warn(message, args...)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	format, ok := Format(r.URL.Path)
	if !ok || r.Method != http.MethodPost {
		http.Error(w, "not a model route", http.StatusNotFound)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, h.limit(h.MaxRequest, 4<<20)+1))
	if err != nil || int64(len(raw)) > h.limit(h.MaxRequest, 4<<20) {
		Refuse(w, format, http.StatusRequestEntityTooLarge, "request_too_large", "The request exceeds the inspection limit")
		return
	}
	text, err := turn.Decode(raw)
	if err != nil {
		Refuse(w, format, http.StatusBadRequest, "invalid_request", "The request is not UTF-8")
		return
	}
	body, err := canon.Parse(text)
	if err != nil || body.Kind() != canon.Object {
		Refuse(w, format, http.StatusBadRequest, "invalid_request", "The request is not a JSON object this machine can read")
		return
	}
	input, err := turn.ReadInput(format, body)
	if err != nil {
		h.log("request refused", "reason", err.Error())
		Refuse(w, format, http.StatusUnprocessableEntity, "unreadable_request", "Nia could not read this request the way it must")
		return
	}
	session := sessionOf(input.FirstUserText)
	for _, tool := range input.IngestedTools {
		if err := h.ingest(r.Context(), session, tool); err != nil {
			h.log("taint not recorded", "error", err.Error())
			Refuse(w, format, http.StatusServiceUnavailable, "nia_unavailable", "Nia could not be reached, so nothing was sent to the model")
			return
		}
	}
	// Tools the provider would run during the call are decided now: one the
	// role does not allow in this session is removed from the request.
	rewritten := false
	hosted, err := turn.HostedTools(format, body)
	if err != nil {
		h.log("request refused", "reason", err.Error())
		Refuse(w, format, http.StatusUnprocessableEntity, "unreadable_request", "Nia could not read the tools of this request the way it must")
		return
	}
	if len(hosted) > 0 {
		allowed, err := h.Nia.Hosted(r.Context(), session, hosted)
		if err != nil {
			h.log("no decision", "tools", strings.Join(hosted, ","), "error", err.Error())
			Refuse(w, format, http.StatusServiceUnavailable, "nia_unavailable", "Nia could not be reached, so nothing was sent to the model")
			return
		}
		gate, err := turn.GateHosted(format, body, func(name string) bool { return slices.Contains(hosted, name) && slices.Contains(allowed, name) })
		if err != nil {
			Refuse(w, format, http.StatusUnprocessableEntity, "unreadable_request", "Nia could not read the tools of this request the way it must")
			return
		}
		rewritten = len(gate.Removed) > 0
	}
	// A secret in what is new in this turn does not leave the machine.
	for i := range input.Segments {
		segment := &input.Segments[i]
		if redacted := inspect.RedactSecrets(segment.Text); redacted != segment.Text {
			segment.Replace(redacted)
			rewritten = true
		}
	}
	outbound := raw
	if rewritten {
		outbound = []byte(body.JSON())
	}

	answer, contentType, status, err := h.call(r, outbound, session)
	if err != nil {
		h.log("provider call failed", "error", err.Error())
		code, message := "upstream_unavailable", "The model provider is unavailable"
		if errors.Is(err, errTooLarge) {
			code, message = "response_too_large", "The model response exceeds the inspection limit"
		}
		Refuse(w, format, http.StatusBadGateway, code, message)
		return
	}
	if status < 200 || status > 299 {
		// Provider errors carry no model output; pass them through.
		release(w, status, contentType, answer)
		return
	}
	answerText, err := turn.Decode(answer)
	var output turn.Output
	if err == nil {
		output, err = turn.ReadOutput(format, strings.Contains(strings.ToLower(contentType), "text/event-stream"), answerText)
	}
	if err != nil {
		reason := "unparseable response"
		var parse *turn.ParseError
		if errors.As(err, &parse) {
			reason = parse.Reason
		}
		h.log("model response refused", "reason", err.Error())
		Refuse(w, format, http.StatusBadGateway, "upstream_invalid", "Nia could not verify the model response: "+reason)
		return
	}
	if found := inspect.Secrets(output.Text); len(found) > 0 {
		h.log("model response refused", "reason", "it holds a secret", "category", found[0].Category)
		Refuse(w, format, http.StatusBadGateway, "output_blocked", "The model response holds a secret and was not released")
		return
	}
	var refusals []string
	for _, call := range output.ToolCalls {
		verdict, err := h.decide(r.Context(), session, call.Name, call.Arguments)
		if err != nil {
			h.log("no decision", "tool", call.Name, "error", err.Error())
			Refuse(w, format, http.StatusServiceUnavailable, "nia_unavailable", "Nia could not be reached, so the model's actions were not released")
			return
		}
		if !verdict.Allowed {
			message := verdict.Message
			if message == "" {
				message = "Nia did not allow " + call.Name + "."
			}
			refusals = append(refusals, "- "+message)
		}
	}
	if len(refusals) == 0 {
		release(w, status, contentType, answer)
		return
	}
	said := "[Nia agent firewall] This action was not run:\n" + strings.Join(refusals, "\n") + "\nIt must not be attempted another way."
	model, _, _ := body.Get("model").Text()
	streaming, _ := body.Get("stream").Truth()
	synthetic, syntheticType := syntheticText(format, streaming, model, said)
	release(w, http.StatusOK, syntheticType, synthetic)
}

// decide answers for one proposed call: decided here when the policy in force
// can, so that its arguments stay on this machine, else by Nia.
func (h *Handler) decide(ctx context.Context, session, tool, arguments string) (Verdict, error) {
	if h.Rules != nil {
		if rules := h.Rules(); rules != nil {
			if call, ok := decideHere(rules, tool, arguments); ok {
				verdict, needsArguments, err := h.Nia.DecideHashed(ctx, session, call)
				if err != nil || !needsArguments {
					return verdict, err
				}
			}
		}
	}
	return h.Nia.Decide(ctx, session, tool, arguments)
}

// decideHere decides a call for each state of the session. It declines,
// leaving it to Nia, a call through a dispatcher and anything the engine
// cannot be sure of.
func decideHere(rules *Rules, tool, arguments string) (Hashed, bool) {
	if rules.Role == nil || rules.Digest == "" {
		return Hashed{}, false
	}
	if _, dispatcher, err := rules.Dispatchers.Expand(engine.Call{Name: tool, Arguments: arguments}); err != nil || dispatcher {
		return Hashed{}, false
	}
	hash, err := canon.ArgumentsHash(tool, arguments)
	if err != nil {
		return Hashed{}, false
	}
	call := Hashed{Tool: tool, Hash: hash, Digest: rules.Digest}
	for _, state := range []struct {
		into             *engine.Decision
		tainted, exposed bool
	}{{&call.Clean, false, false}, {&call.Tainted, true, false}, {&call.Exposed, false, true}, {&call.Both, true, true}} {
		decided, err := rules.Role.Decide(tool, state.tainted, arguments, state.exposed)
		if err != nil {
			return Hashed{}, false
		}
		*state.into = decided
	}
	return call, true
}

func release(w http.ResponseWriter, status int, contentType string, body []byte) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// sessionOf names the conversation as Nia does when the agent names none:
// from its first user text.
func sessionOf(firstUserText *string) string {
	text := ""
	if firstUserText != nil {
		text = *firstUserText
	}
	sum := sha256.Sum256([]byte(text))
	return "c-" + hex.EncodeToString(sum[:])[:32]
}

// ingest tells Nia, once per conversation and tool for the life of this
// process, that the conversation holds a result of the tool.
func (h *Handler) ingest(ctx context.Context, session, tool string) error {
	key := session + "\x00" + tool
	h.mu.Lock()
	known := h.recorded[key]
	h.mu.Unlock()
	if known {
		return nil
	}
	if err := h.Nia.Ingested(ctx, session, tool); err != nil {
		return err
	}
	h.mu.Lock()
	if h.recorded == nil || len(h.recorded) > 100_000 {
		h.recorded = map[string]bool{}
	}
	h.recorded[key] = true
	h.mu.Unlock()
	return nil
}

var errTooLarge = errors.New("the model response is too large")

// call sends the request to the provider and reads its whole answer.
func (h *Handler) call(r *http.Request, body []byte, session string) (answer []byte, contentType string, status int, err error) {
	target := h.Provider.JoinPath(strings.TrimPrefix(r.URL.Path, "/v1"))
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, "", 0, err
	}
	for _, name := range forwarded {
		if value := r.Header.Get(name); value != "" {
			request.Header.Set(name, value)
		}
	}
	request.Header.Set("Content-Type", "application/json")
	if h.SessionHeader != "" {
		// The id of the conversation, hashed again: stable for the provider's
		// routing and cache, and not the id Nia knows it by.
		sum := sha256.Sum256([]byte("provider-session\x00" + session))
		request.Header.Set(h.SessionHeader, "nia-"+hex.EncodeToString(sum[:16]))
	}
	if h.Anthropic {
		request.Header.Set("X-Api-Key", h.Key)
		if request.Header.Get("Anthropic-Version") == "" {
			request.Header.Set("Anthropic-Version", "2023-06-01")
		}
	} else {
		request.Header.Set("Authorization", "Bearer "+h.Key)
	}
	response, err := h.HTTP.Do(request)
	if err != nil {
		// The error of net/http names the URL, never the headers.
		return nil, "", 0, err
	}
	defer response.Body.Close()
	limit := h.limit(h.MaxResponse, 16<<20)
	answer, err = io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, "", 0, err
	}
	if int64(len(answer)) > limit {
		return nil, "", 0, errTooLarge
	}
	return answer, response.Header.Get("Content-Type"), response.StatusCode, nil
}

// NewProviderClient returns a client for the provider: no proxy from the
// environment (the agent's proxy is nia-edge itself), no redirects.
func NewProviderClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// syntheticText is a complete model response that says one thing, in the
// shape the agent expects, streamed or not.
func syntheticText(format turn.Format, stream bool, model, text string) ([]byte, string) {
	seed := make([]byte, 16)
	_, _ = rand.Read(seed)
	id := hex.EncodeToString(seed)
	created := time.Now().Unix()
	if model == "" {
		model = "unknown"
	}
	marshal := func(value any) string {
		raw, _ := json.Marshal(value)
		return string(raw)
	}
	type object = map[string]any
	var frames []string
	data := func(value any) { frames = append(frames, "data: "+marshal(value)+"\n\n") }
	event := func(kind string, payload object) {
		payload["type"] = kind
		frames = append(frames, "event: "+kind+"\ndata: "+marshal(payload)+"\n\n")
	}
	const sse = "text/event-stream; charset=utf-8"

	switch format {
	case turn.ChatCompletions:
		if !stream {
			return []byte(marshal(object{
				"id": "chatcmpl-nia" + id, "object": "chat.completion", "created": created, "model": model,
				"choices": []object{{"index": 0, "finish_reason": "stop", "message": object{"role": "assistant", "content": text}}},
				"usage":   object{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
			})), "application/json"
		}
		chunk := func(delta object, finish any) object {
			return object{"id": "chatcmpl-nia" + id, "object": "chat.completion.chunk", "created": created, "model": model,
				"choices": []object{{"index": 0, "delta": delta, "finish_reason": finish}}}
		}
		data(chunk(object{"role": "assistant", "content": text}, nil))
		data(chunk(object{}, "stop"))
		frames = append(frames, "data: [DONE]\n\n")
	case turn.AnthropicMessages:
		message := func(content []object, stop any) object {
			return object{"id": "msg_nia" + id, "type": "message", "role": "assistant", "model": model, "content": content,
				"stop_reason": stop, "stop_sequence": nil, "usage": object{"input_tokens": 0, "output_tokens": 0}}
		}
		if !stream {
			return []byte(marshal(message([]object{{"type": "text", "text": text}}, "end_turn"))), "application/json"
		}
		event("message_start", object{"message": message([]object{}, nil)})
		event("content_block_start", object{"index": 0, "content_block": object{"type": "text", "text": ""}})
		event("content_block_delta", object{"index": 0, "delta": object{"type": "text_delta", "text": text}})
		event("content_block_stop", object{"index": 0})
		event("message_delta", object{"delta": object{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": object{"output_tokens": 0}})
		event("message_stop", object{})
	default:
		part := func(value string) object { return object{"type": "output_text", "text": value, "annotations": []any{}} }
		item := func(status string, content []object) object {
			return object{"id": "msg_nia" + id, "type": "message", "status": status, "role": "assistant", "content": content}
		}
		response := func(status string, output []object) object {
			return object{"id": "resp_nia" + id, "object": "response", "created_at": created, "status": status, "model": model, "output": output,
				"usage": object{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}
		}
		done := item("completed", []object{part(text)})
		if !stream {
			return []byte(marshal(response("completed", []object{done}))), "application/json"
		}
		sequence := 0
		step := func(kind string, payload object) {
			payload["sequence_number"] = sequence
			sequence++
			event(kind, payload)
		}
		itemID := "msg_nia" + id
		step("response.created", object{"response": response("in_progress", []object{})})
		step("response.output_item.added", object{"output_index": 0, "item": item("in_progress", []object{})})
		step("response.content_part.added", object{"item_id": itemID, "output_index": 0, "content_index": 0, "part": part("")})
		step("response.output_text.delta", object{"item_id": itemID, "output_index": 0, "content_index": 0, "delta": text})
		step("response.output_text.done", object{"item_id": itemID, "output_index": 0, "content_index": 0, "text": text})
		step("response.content_part.done", object{"item_id": itemID, "output_index": 0, "content_index": 0, "part": part(text)})
		step("response.output_item.done", object{"output_index": 0, "item": done})
		step("response.completed", object{"response": response("completed", []object{done})})
	}
	return []byte(strings.Join(frames, "")), sse
}

// Remote is Nia's decision API, called with the machine's key.
type Remote struct {
	Base *url.URL
	Key  string
	// Run links this machine's conversations; empty sends none.
	Run  string
	HTTP *http.Client
	// Wait is how many seconds a held call waits for a reviewer.
	Wait int
}

func (n *Remote) post(ctx context.Context, path, session string, body any, timeout time.Duration, answer any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	call, err := http.NewRequestWithContext(ctx, http.MethodPost, n.Base.JoinPath(path).String(), bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	call.Header.Set("Authorization", "Bearer "+n.Key)
	call.Header.Set("Content-Type", "application/json")
	call.Header.Set("X-Nia-Session-Id", session)
	if n.Run != "" {
		call.Header.Set("X-Nia-Run-Id", n.Run)
	}
	response, err := n.HTTP.Do(call)
	if err != nil {
		return fmt.Errorf("cannot reach Nia: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil {
		return fmt.Errorf("reading Nia's answer: %w", err)
	}
	// Anything but a plain success is not a decision.
	if response.StatusCode != http.StatusOK || len(raw) > 64<<10 {
		return fmt.Errorf("Nia answered %d", response.StatusCode)
	}
	if err := json.Unmarshal(raw, answer); err != nil {
		return fmt.Errorf("Nia's answer is not what was expected: %w", err)
	}
	return nil
}

// Ingested taints the session by the name of a tool. No content is sent.
func (n *Remote) Ingested(ctx context.Context, session, tool string) error {
	var answer struct {
		Action string `json:"action"`
	}
	if err := n.post(ctx, "/v1/tools/result", session, map[string]any{"tool": tool, "output": ""}, 15*time.Second, &answer); err != nil {
		return err
	}
	if answer.Action == "" {
		return errors.New("Nia's answer records nothing")
	}
	return nil
}

// Hosted asks Nia which provider-run tools the role allows in the session.
func (n *Remote) Hosted(ctx context.Context, session string, tools []string) ([]string, error) {
	var answer struct {
		Allowed *[]string `json:"allowed"`
	}
	if err := n.post(ctx, "/v1/tools/hosted", session, map[string]any{"tools": tools}, 15*time.Second, &answer); err != nil {
		return nil, err
	}
	if answer.Allowed == nil {
		return nil, errors.New("Nia's answer holds no decision")
	}
	return *answer.Allowed, nil
}

// Decide asks Nia about one proposed call. Only the answer "allow" allows it.
func (n *Remote) Decide(ctx context.Context, session, tool, arguments string) (Verdict, error) {
	body := map[string]any{"tool": tool, "arguments": arguments}
	if n.Wait > 0 {
		body["wait"] = n.Wait
	}
	verdict, needsArguments, err := n.decide(ctx, session, body)
	if err == nil && needsArguments {
		err = errors.New("Nia asked again for the arguments it was sent")
	}
	return verdict, err
}

// DecideHashed sends a call decided on this machine: its hash, never its
// arguments.
func (n *Remote) DecideHashed(ctx context.Context, session string, call Hashed) (Verdict, bool, error) {
	body := map[string]any{
		"tool":           call.Tool,
		"arguments_hash": call.Hash,
		"policy_digest":  call.Digest,
		"local":          map[string]engine.Decision{"clean": call.Clean, "tainted": call.Tainted, "exposed": call.Exposed, "both": call.Both},
	}
	if n.Wait > 0 {
		body["wait"] = n.Wait
	}
	return n.decide(ctx, session, body)
}

func (n *Remote) decide(ctx context.Context, session string, body map[string]any) (Verdict, bool, error) {
	var answer struct {
		Decision string `json:"decision"`
		Message  string `json:"message"`
	}
	if err := n.post(ctx, "/v1/tools/decide", session, body, 15*time.Second+time.Duration(n.Wait)*time.Second, &answer); err != nil {
		return Verdict{}, false, err
	}
	switch answer.Decision {
	case "allow":
		return Verdict{Allowed: true}, false, nil
	case "require_approval", "deny":
		return Verdict{Message: answer.Message}, false, nil
	case "arguments_required":
		return Verdict{}, true, nil
	}
	return Verdict{}, false, errors.New("Nia's answer holds no decision")
}
