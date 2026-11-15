package turn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/GetKlaros/nia-edge/canon"
)

func conformanceDir() string {
	if dir := os.Getenv("NIA_CONFORMANCE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "..", "conformance")
}

func show(v any) string {
	text, _ := json.Marshal(v)
	return string(text)
}

// Every response of the conformance file is read, or refused, as the server does.
func TestOutputsOfTheServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(conformanceDir(), "outputs.json"))
	if err != nil {
		t.Fatalf("reading the conformance cases: %v", err)
	}
	var file struct {
		Cases []struct {
			Name   string  `json:"name"`
			Format Format  `json:"format"`
			Stream bool    `json:"stream"`
			Body   string  `json:"body"`
			Output *Output `json:"output"`
			Error  *string `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 79 {
		t.Fatalf("%d cases", len(file.Cases))
	}
	read, refusedCount, undecided := 0, 0, 0
	for _, c := range file.Cases {
		got, err := ReadOutput(c.Format, c.Stream, c.Body)
		var refusal *ParseError
		switch {
		case errors.Is(err, ErrUndecidable):
			undecided++
			// The one case whose answer no Go string can hold: a name cut between the halves of a pair.
			if c.Name != "chat: a name cut in the middle of a pair" {
				t.Errorf("%s: not read here (%v)", c.Name, err)
			}
		case errors.As(err, &refusal):
			refusedCount++
			if c.Error == nil {
				t.Errorf("%s: refused (%s); the server reads %s", c.Name, refusal.Reason, show(c.Output))
			} else if refusal.Reason != *c.Error {
				t.Errorf("%s: refused for %q, the server says %q", c.Name, refusal.Reason, *c.Error)
			}
		case err != nil:
			t.Errorf("%s: %v", c.Name, err)
		case c.Output == nil:
			t.Errorf("%s: read %s; the server refuses it (%s)", c.Name, show(got), *c.Error)
		default:
			read++
			if c.Output.ToolCalls == nil {
				c.Output.ToolCalls = []ToolCall{}
			}
			if !reflect.DeepEqual(got, *c.Output) {
				t.Errorf("%s:\n got %s\nwant %s", c.Name, show(got), show(*c.Output))
			}
		}
	}
	t.Logf("%d read as the server, %d refused as the server, %d not read here", read, refusedCount, undecided)
	if undecided != 1 {
		t.Errorf("%d cases not read here", undecided)
	}
}

func TestWhatIsNotReadHere(t *testing.T) {
	for name, c := range map[string]struct {
		format Format
		stream bool
		body   string
	}{
		"text with a lone surrogate":      {ChatCompletions, false, `{"choices":[{"message":{"content":"a\ud800"}}]}`},
		"arguments with a lone surrogate": {ChatCompletions, false, `{"choices":[{"message":{"tool_calls":[{"function":{"name":"a","arguments":"\udc00"}}]}}]}`},
		"an index that is text":           {ChatCompletions, true, "data: {\"choices\":[{\"index\":\"1\",\"delta\":{\"content\":\"a\"}}]}\n\ndata: [DONE]\n\n"},
		"a call index that is a list":     {ChatCompletions, true, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":[5],\"function\":{\"name\":\"a\"}}]}}]}\n\ndata: [DONE]\n\n"},
		"a block index that is true":      {AnthropicMessages, true, "data: {\"type\":\"content_block_start\",\"index\":true,\"content_block\":{\"type\":\"tool_use\",\"name\":\"a\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n"},
		"a document nested too deep":      {Responses, false, `{"output":` + strings.Repeat("[", canon.ParseDepth+1) + strings.Repeat("]", canon.ParseDepth+1) + `}`},
		"an unknown format":               {Format("completions"), false, `{}`},
	} {
		if _, err := ReadOutput(c.format, c.stream, c.body); !errors.Is(err, ErrUndecidable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadOutput(ChatCompletions, false, "{\"a\":\"\xff\"}"); !errors.Is(err, canon.ErrInvalidUTF8) {
		t.Errorf("bytes that are not UTF-8: %v", err)
	}
}

func TestDecode(t *testing.T) {
	if text, err := Decode([]byte("\xef\xbb\xbf{}")); err != nil || text != "{}" {
		t.Errorf("a byte order mark is not part of the text: %q, %v", text, err)
	}
	if _, err := Decode([]byte("{\"a\":\"\xc3\"}")); !errors.Is(err, canon.ErrInvalidUTF8) {
		t.Errorf("bytes that are not UTF-8: %v", err)
	}
}

func TestTooManyEvents(t *testing.T) {
	body := strings.Repeat("data: {}\n\n", maxSSEEvents) + "data: [DONE]\n\n"
	var refusal *ParseError
	if _, err := ReadOutput(ChatCompletions, true, body); !errors.As(err, &refusal) || refusal.Reason != "too many SSE events" {
		t.Errorf("%d events: %v", maxSSEEvents+1, err)
	}
}
