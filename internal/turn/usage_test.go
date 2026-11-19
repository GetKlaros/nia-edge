package turn

import (
	"strings"
	"testing"

	"github.com/GetKlaros/nia-edge/canon"
)

func TestReadUsage(t *testing.T) {
	for name, c := range map[string]struct {
		format Format
		stream bool
		body   string
		want   Usage
	}{
		"chat": {ChatCompletions, false,
			`{"choices":[],"usage":{"prompt_tokens":120,"completion_tokens":30,"prompt_tokens_details":{"cached_tokens":100}}}`,
			Usage{120, 100, 30}},
		"chat stream": {ChatCompletions, true,
			"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n",
			Usage{9, 0, 2}},
		"responses": {Responses, false,
			`{"output":[],"usage":{"input_tokens":50,"output_tokens":5,"input_tokens_details":{"cached_tokens":40}}}`,
			Usage{50, 40, 5}},
		"responses stream": {Responses, true,
			"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\n\n",
			Usage{7, 0, 3}},
		// Anthropic counts cache reads and writes apart from input_tokens.
		"anthropic": {AnthropicMessages, false,
			`{"content":[],"usage":{"input_tokens":21,"cache_creation_input_tokens":1000,"cache_read_input_tokens":5000,"output_tokens":393}}`,
			Usage{6021, 5000, 393}},
		"anthropic stream": {AnthropicMessages, true,
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":15,\"cache_read_input_tokens\":200,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":64}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			Usage{215, 200, 64}},
	} {
		got, ok := ReadUsage(c.format, c.stream, c.body)
		if !ok || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", name, got, ok, c.want)
		}
	}
	for name, c := range map[string]struct {
		format Format
		stream bool
		body   string
	}{
		"no usage":          {ChatCompletions, false, `{"choices":[]}`},
		"stream, no usage":  {ChatCompletions, true, "data: {\"choices\":[]}\n\ndata: [DONE]\n\n"},
		"half a usage":      {Responses, false, `{"usage":{"input_tokens":3}}`},
		"anthropic no end":  {AnthropicMessages, true, "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":15}}}\n\n"},
		"not json":          {AnthropicMessages, false, `nope`},
		"responses created": {Responses, true, "data: {\"type\":\"response.created\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"},
	} {
		if got, ok := ReadUsage(c.format, c.stream, c.body); ok {
			t.Errorf("%s: read %+v", name, got)
		}
	}
}

func TestAskUsage(t *testing.T) {
	for name, c := range map[string]struct {
		format  Format
		body    string
		changed bool
		want    string
	}{
		"stream":       {ChatCompletions, `{"model":"m","stream":true}`, true, `{"model":"m","stream":true,"stream_options":{"include_usage":true}}`},
		"other option": {ChatCompletions, `{"stream":true,"stream_options":{"include_obfuscation":false}}`, true, `{"stream":true,"stream_options":{"include_obfuscation":false,"include_usage":true}}`},
		"already":      {ChatCompletions, `{"stream":true,"stream_options":{"include_usage":true}}`, false, ``},
		"not a stream": {ChatCompletions, `{"stream":false}`, false, ``},
		"responses":    {Responses, `{"stream":true}`, false, ``},
	} {
		body, err := canon.Parse(c.body)
		if err != nil {
			t.Fatal(err)
		}
		if changed := AskUsage(c.format, body); changed != c.changed || (changed && body.JSON() != c.want) {
			t.Errorf("%s: %v %s", name, changed, body.JSON())
		}
	}
}

// The chunk the provider adds for the usage, with no choice, is read as the
// rest of the stream.
func TestTheUsageChunkIsPartOfAStream(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"id":"c","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}],"usage":null}`,
		`data: {"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}`,
		`data: {"id":"c","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}`,
		`data: [DONE]`,
	}, "\n\n") + "\n\n"
	out, err := ReadOutput(ChatCompletions, true, stream)
	if err != nil || out.Text != "hi" {
		t.Fatalf("%+v %v", out, err)
	}
}
