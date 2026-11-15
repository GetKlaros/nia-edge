package engine

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/GetKlaros/nia-edge/canon"
)

type decisionFile struct {
	Roles []json.RawMessage `json:"roles"`
	Cases []struct {
		Name      string   `json:"name"`
		Role      string   `json:"role"`
		Tool      string   `json:"tool"`
		Tainted   bool     `json:"tainted"`
		Exposed   bool     `json:"exposed"`
		Arguments string   `json:"arguments"`
		Decision  Decision `json:"decision"`
	} `json:"cases"`
}

func show(d Decision) string {
	text, _ := json.Marshal(d)
	return string(text)
}

// The calls of the conformance file this engine declines to decide, and why.
// Everything else it must decide as the server did.
func expectedUndecided(role, tool, arguments string, tainted bool) bool {
	if role != "edges" {
		return false
	}
	switch tool {
	case "shell":
		// `.` on text outside the BMP: two units to JavaScript, one character here.
		return tainted && (strings.Contains(arguments, "\U0001f600") || strings.Contains(arguments, `\ud83d\ude00`))
	case "http":
		// A look-ahead on the method, in any session; punycode once the hosts are read.
		return strings.Contains(arguments, `"method"`) || (tainted && strings.Contains(strings.ToLower(arguments), "xn--"))
	case "open":
		// An allowed host outside ASCII, needed to answer when no other entry matches.
		return tainted && !strings.Contains(arguments, "plain.example")
	}
	return false
}

func TestDecisionsOfTheServer(t *testing.T) {
	var file decisionFile
	readCases(t, "decisions.json", &file)
	roles := map[string]*Role{}
	for _, raw := range file.Roles {
		role, err := ParseRole(raw)
		if err != nil {
			t.Fatal(err)
		}
		roles[role.Name] = role
	}
	if len(roles) < 5 || len(file.Cases) < 600 {
		t.Fatalf("%d roles, %d cases", len(roles), len(file.Cases))
	}
	decided, undecided := 0, 0
	for _, c := range file.Cases {
		role := roles[c.Role]
		if role == nil {
			t.Fatalf("%s: no role %q", c.Name, c.Role)
		}
		got, err := role.Decide(c.Tool, c.Tainted, c.Arguments, c.Exposed)
		want := expectedUndecided(c.Role, c.Tool, c.Arguments, c.Tainted)
		switch {
		case errors.Is(err, ErrUndecidable):
			undecided++
			if !want {
				t.Errorf("%s: not decided (%v); the server answers %s", c.Name, err, show(c.Decision))
			}
		case err != nil:
			t.Errorf("%s: %v", c.Name, err)
		case want:
			t.Errorf("%s: decided %s where this engine cannot be sure", c.Name, show(got))
		default:
			decided++
			if !reflect.DeepEqual(got, c.Decision) {
				t.Errorf("%s:\n got %s\nwant %s", c.Name, show(got), show(c.Decision))
			}
		}
	}
	t.Logf("%d decided as the server, %d left to the server", decided, undecided)
	if undecided == 0 || undecided > len(file.Cases)/10 {
		t.Errorf("%d of %d cases not decided", undecided, len(file.Cases))
	}
}

func TestDispatchesOfTheServer(t *testing.T) {
	var file struct {
		Dispatchers json.RawMessage `json:"dispatchers"`
		Cases       []struct {
			Name      string  `json:"name"`
			Tool      string  `json:"tool"`
			Arguments string  `json:"arguments"`
			Inner     *[]Call `json:"inner"`
		} `json:"cases"`
	}
	readCases(t, "dispatch.json", &file)
	dispatchers, err := ParseDispatchers(file.Dispatchers)
	if err != nil {
		t.Fatal(err)
	}
	if len(dispatchers) != 3 || len(file.Cases) < 40 {
		t.Fatalf("%d dispatchers, %d cases", len(dispatchers), len(file.Cases))
	}
	undecided := 0
	for _, c := range file.Cases {
		inner, dispatcher, err := dispatchers.Expand(Call{Name: c.Tool, Arguments: c.Arguments})
		if errors.Is(err, ErrUndecidable) {
			undecided++
			// The file cannot hold a lone surrogate; its escape becomes U+FFFD here.
			if !strings.Contains(c.Arguments, `{"name":"a\ud800"}`) {
				t.Errorf("%s: not decided: %v", c.Name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if dispatcher != (c.Inner != nil) {
			t.Errorf("%s: dispatcher %v", c.Name, dispatcher)
			continue
		}
		if c.Inner == nil {
			continue
		}
		if len(inner) != len(*c.Inner) {
			t.Errorf("%s: %d inner calls, want %d", c.Name, len(inner), len(*c.Inner))
			continue
		}
		for i, call := range inner {
			want := (*c.Inner)[i]
			if call != want {
				t.Errorf("%s: inner %d\n got %+v\nwant %+v", c.Name, i, call, want)
			}
		}
	}
	if undecided != 1 {
		t.Errorf("%d dispatches not decided, want the one with a lone surrogate in a name", undecided)
	}
}

func role(t *testing.T, text string) *Role {
	t.Helper()
	parsed, err := ParseRole(json.RawMessage(text))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

const base = `"mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval"`

func TestARoleThisEngineDoesNotKnowIsRefusedWhole(t *testing.T) {
	for name, text := range map[string]string{
		"an unknown field":             `{"name":"r",` + base + `,"tools":[],"quota":1}`,
		"an unknown field of a tool":   `{"name":"r",` + base + `,"tools":[{"name":"a","when_untrusted":"allow","output":"trusted","sensitive":false,"effect":"none","arguments":[],"rate":1}]}`,
		"an unknown condition":         `{"name":"r",` + base + `,"tools":[{"name":"a","when_untrusted":"allow","output":"trusted","sensitive":false,"effect":"none","arguments":[{"applies":"always","decision":"deny","size":{"max":1}}]}]}`,
		"an unknown decision":          `{"name":"r",` + base + `,"tools":[{"name":"a","when_untrusted":"ask","output":"trusted","sensitive":false,"effect":"none","arguments":[]}]}`,
		"an unknown mode":              `{"name":"r","mode":"audit","rule_of_two":"deny","destructive":"deny","tools":[]}`,
		"an unknown effect":            `{"name":"r",` + base + `,"tools":[{"name":"a","when_untrusted":"allow","output":"trusted","sensitive":false,"effect":"financial","arguments":[]}]}`,
		"a rule with no condition":     `{"name":"r",` + base + `,"tools":[{"name":"a","when_untrusted":"allow","output":"trusted","sensitive":false,"effect":"none","arguments":[{"applies":"always","decision":"allow"}]}]}`,
		"no decision for the role":     `{"name":"r","mode":"enforce","tools":[]}`,
		"text after the role":          `{"name":"r",` + base + `,"tools":[]} {}`,
		"not a role":                   `[]`,
		"an output that is not known":  `{"name":"r",` + base + `,"tools":[{"name":"a","when_untrusted":"allow","output":"signed","sensitive":false,"effect":"none","arguments":[]}]}`,
		"a tool rule without its name": `{"name":"r",` + base + `,"tools":[{"when_untrusted":"allow","output":"trusted","sensitive":false,"effect":"none","arguments":[]}]}`,
	} {
		if _, err := ParseRole(json.RawMessage(text)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func TestTextThatIsNotUTF8IsRefused(t *testing.T) {
	r := role(t, `{"name":"r",`+base+`,"tools":[{"name":"*","when_untrusted":"allow","output":"trusted","sensitive":false,"effect":"none","arguments":[]}]}`)
	if _, err := r.Decide("a\xff", false, "{}", false); !errors.Is(err, canon.ErrInvalidUTF8) {
		t.Errorf("tool name: %v", err)
	}
	if _, err := r.Decide("a", false, "{\"a\":\"\xff\"}", false); !errors.Is(err, canon.ErrInvalidUTF8) {
		t.Errorf("arguments: %v", err)
	}
	if _, _, err := (Dispatchers{{Tool: "batch", Calls: "calls", Name: "name", Arguments: "arguments"}}).Expand(Call{Name: "batch", Arguments: "\xff"}); !errors.Is(err, canon.ErrInvalidUTF8) {
		t.Errorf("dispatch: %v", err)
	}
}

// JavaScript reads JSON of any depth; encoding/json does not.
func TestArgumentsNestedDeeperThanThisMachineReads(t *testing.T) {
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	withRule := role(t, `{"name":"r",`+base+`,"tools":[{"name":"a","when_untrusted":"deny","output":"untrusted","sensitive":false,"effect":"none","arguments":[{"applies":"always","decision":"allow","shell_safe":{"path":"c"}}]},{"name":"b","when_untrusted":"deny","output":"untrusted","sensitive":false,"effect":"none","arguments":[]}]}`)
	if _, err := withRule.Decide("a", false, deep, false); !errors.Is(err, ErrUndecidable) {
		t.Errorf("a rule that reads the arguments: %v", err)
	}
	// No rule reads them: the decision does not depend on what they hold.
	if got, err := withRule.Decide("b", true, deep, false); err != nil || got.Decision != Deny || got.Reason != "untrusted_session" {
		t.Errorf("no rule reads the arguments: %s, %v", show(got), err)
	}
	dispatchers := Dispatchers{{Tool: "batch", Calls: "calls", Name: "name", Arguments: "arguments"}}
	if _, _, err := dispatchers.Expand(Call{Name: "batch", Arguments: `{"calls":` + deep + `}`}); !errors.Is(err, ErrUndecidable) {
		t.Errorf("dispatch: %v", err)
	}
	// Brackets inside a string are text.
	quoted, _ := json.Marshal(deep)
	if got, err := withRule.Decide("a", false, `{"c":`+string(quoted)+`}`, false); err != nil || got.Reason != "argument_rule" {
		t.Errorf("brackets in a string: %s, %v", show(got), err)
	}
}

func TestADispatcherFieldEveryJavaScriptObjectHas(t *testing.T) {
	for _, field := range []string{"constructor", "toString", "__proto__", "valueOf"} {
		dispatchers := Dispatchers{{Tool: "batch", Calls: "calls", Name: "name", Arguments: field}}
		if _, _, err := dispatchers.Expand(Call{Name: "batch", Arguments: `{"calls":[{"name":"a"}]}`}); !errors.Is(err, ErrUndecidable) {
			t.Errorf("%s: %v", field, err)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pattern, value string
		want           bool
	}{
		{"*", "", true}, {"*", "a\nb", false}, {"**", "ab", true}, {"a*b*c", "abc", true}, {"a*b*c", "aXbXbXc", true}, {"a*b*c", "aXbXb", false},
		{"*a", "ba\na", false}, {"a\n*", "a\nb", true}, {"*\n*", "a\nb", true}, {"*\n*", "a\n\nb", false}, {"a?c", "abc", false}, {"a?c", "a?c", true},
		{"é*", "éa", true}, {"*\U0001f600", "x\U0001f600", true}, {"", "", true}, {"", "a", false},
	} {
		if got := globMatches(c.pattern, c.value); got != c.want {
			t.Errorf("glob %q on %q: %v", c.pattern, c.value, got)
		}
	}
}

// A role and its dispatchers as they come down in a signed policy.
func TestTheRoleOfASignedPolicyIsRead(t *testing.T) {
	var file struct {
		Cases []struct {
			Payload string `json:"payload"`
			Valid   bool   `json:"valid"`
		} `json:"cases"`
	}
	readCases(t, "signatures.json", &file)
	read := 0
	for _, c := range file.Cases {
		if !c.Valid {
			continue
		}
		var payload struct {
			Role        json.RawMessage `json:"role"`
			Dispatchers json.RawMessage `json:"dispatchers"`
		}
		if err := json.Unmarshal([]byte(c.Payload), &payload); err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRole(payload.Role)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseDispatchers(payload.Dispatchers); err != nil {
			t.Fatal(err)
		}
		got, err := parsed.Decide("terminal", true, `{"command":"ls"}`, false)
		if err != nil || got.Decision != RequireApproval {
			t.Errorf("terminal in a tainted session: %s, %v", show(got), err)
		}
		read++
	}
	if read < 2 {
		t.Fatalf("%d signed policies read", read)
	}
}
