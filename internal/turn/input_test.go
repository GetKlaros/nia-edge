package turn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/GetKlaros/nia-edge/canon"
)

// Every request of the conformance file is read as the server reads it.
func TestInputsOfTheServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(conformanceDir(), "inputs.json"))
	if err != nil {
		t.Fatalf("reading the conformance cases: %v", err)
	}
	var file struct {
		Cases []struct {
			Name   string `json:"name"`
			Format Format `json:"format"`
			Body   string `json:"body"`
			Input
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 35 {
		t.Fatalf("%d cases", len(file.Cases))
	}
	for _, c := range file.Cases {
		body, err := canon.Parse(c.Body)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got, err := ReadInput(c.Format, body)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		for i := range got.Segments {
			got.Segments[i].at = nil
		}
		if !reflect.DeepEqual(got, c.Input) {
			t.Errorf("%s:\n got %s\nwant %s", c.Name, show(got), show(c.Input))
		}
	}
}

func TestInputsNotReadHere(t *testing.T) {
	for name, c := range map[string]struct {
		format Format
		body   string
	}{
		"a prompt with a lone surrogate":  {ChatCompletions, `{"messages":[{"role":"user","content":"a\ud800"}]}`},
		"a result with a lone surrogate":  {AnthropicMessages, `{"messages":[{"role":"user","content":[{"type":"tool_result","content":"\udc00"}]}]}`},
		"a call id with a lone surrogate": {Responses, `{"input":[{"type":"function_call","call_id":"\ud800","name":"a"}]}`},
		"an unknown format":               {Format("completions"), `{}`},
	} {
		body, err := canon.Parse(c.body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadInput(c.format, body); !errors.Is(err, ErrUndecidable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestASegmentIsRewrittenInTheBody(t *testing.T) {
	body, err := canon.Parse(`{"model":"m","messages":[{"role":"user","content":"keep"},{"role":"assistant","content":"x"},{"role":"tool","content":[{"type":"text","text":"secret here"}]},{"role":"user","content":"and this"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ReadInput(ChatCompletions, body)
	if err != nil || len(in.Segments) != 2 {
		t.Fatalf("%v, %d segments", err, len(in.Segments))
	}
	in.Segments[0].Replace("[REDACTED] \"quoted\" é")
	want := `{"model":"m","messages":[{"role":"user","content":"keep"},{"role":"assistant","content":"x"},{"role":"tool","content":[{"type":"text","text":"[REDACTED] \"quoted\" é"}]},{"role":"user","content":"and this"}]}`
	if got := body.JSON(); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}
