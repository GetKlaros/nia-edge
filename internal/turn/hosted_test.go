package turn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/GetKlaros/nia-edge/canon"
)

// Every request of the conformance file comes out as the server leaves it.
func TestHostedToolsOfTheServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(conformanceDir(), "hosted.json"))
	if err != nil {
		t.Fatalf("reading the conformance cases: %v", err)
	}
	var file struct {
		Cases []struct {
			Name    string   `json:"name"`
			Format  Format   `json:"format"`
			Body    string   `json:"body"`
			Allowed []string `json:"allowed"`
			Result  string   `json:"result"`
			Gate
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 28 {
		t.Fatalf("%d cases", len(file.Cases))
	}
	for _, c := range file.Cases {
		body, err := canon.Parse(c.Body)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		names, err := HostedTools(c.Format, body)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		// Naming the tools changes nothing, and names every tool that is decided.
		if again, _, _ := canon.Stringify(c.Body); body.JSON() != again {
			t.Errorf("%s: naming the tools changed the request", c.Name)
		}
		for _, name := range append(slices.Clone(c.Kept), c.Removed...) {
			if !slices.Contains(names, name) {
				t.Errorf("%s: %s is decided but was not named (%v)", c.Name, name, names)
			}
		}
		gate, err := GateHosted(c.Format, body, func(name string) bool { return slices.Contains(c.Allowed, name) })
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if !reflect.DeepEqual(gate, c.Gate) {
			t.Errorf("%s:\n got %s\nwant %s", c.Name, show(gate), show(c.Gate))
		}
		if got := body.JSON(); got != c.Result {
			t.Errorf("%s:\n got %s\nwant %s", c.Name, got, c.Result)
		}
	}
}

func TestHostedToolsNotReadHere(t *testing.T) {
	for name, c := range map[string]struct {
		format Format
		body   string
	}{
		"a type with a lone surrogate":  {Responses, `{"tools":[{"type":"web\ud800"}]}`},
		"a label with a lone surrogate": {Responses, `{"tools":[{"type":"mcp","server_label":"\udc00"}]}`},
		"an unknown format":             {Format("completions"), `{}`},
	} {
		body, _ := canon.Parse(c.body)
		if _, err := GateHosted(c.format, body, func(string) bool { return true }); !errors.Is(err, ErrUndecidable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
