package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/GetKlaros/nia-edge/canon"
)

// Dispatcher declares a tool that carries other calls in its arguments.
type Dispatcher struct {
	Tool string `json:"tool"`
	// Calls is the dotted path to the inner call, or list of inner calls.
	Calls     string `json:"calls"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Call is a tool call: its name and its arguments as JSON text.
type Call struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Dispatchers are the dispatcher tools of a policy.
type Dispatchers []Dispatcher

// The server reads a field of an inner call as a JavaScript property, so a
// field named like one every object has is found where there is none.
var inherited = map[string]bool{
	"constructor": true, "__proto__": true, "hasOwnProperty": true, "isPrototypeOf": true, "propertyIsEnumerable": true,
	"toLocaleString": true, "toString": true, "valueOf": true, "__defineGetter__": true, "__defineSetter__": true,
	"__lookupGetter__": true, "__lookupSetter__": true,
}

// ParseDispatchers reads the dispatchers of a policy.
func ParseDispatchers(raw json.RawMessage) (Dispatchers, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var list Dispatchers
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&list); err != nil {
		return nil, fmt.Errorf("engine: the dispatchers cannot be read by this nia-edge: %w", err)
	}
	for _, d := range list {
		if d.Tool == "" || d.Calls == "" || d.Name == "" || d.Arguments == "" {
			return nil, errors.New("engine: a dispatcher lacks a field")
		}
	}
	return list, nil
}

func (list Dispatchers) find(tool string) *Dispatcher {
	for i := range list {
		if list[i].Tool == tool {
			return &list[i]
		}
	}
	return nil
}

func object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, false
	}
	return fields, true
}

// Expand returns the inner calls of a dispatcher tool, with canonical
// arguments. dispatcher is false when the tool is not one. An empty list is
// a dispatch that cannot be read: the caller denies it.
func (list Dispatchers) Expand(call Call) (inner []Call, dispatcher bool, err error) {
	if !utf8.ValidString(call.Name) || !utf8.ValidString(call.Arguments) {
		return nil, false, canon.ErrInvalidUTF8
	}
	d := list.find(call.Name)
	if d == nil {
		return nil, false, nil
	}
	if inherited[d.Arguments] || inherited[d.Name] {
		return nil, true, notDecided("a dispatcher field named %q or %q", d.Name, d.Arguments)
	}
	duplicate, err := canon.HasDuplicateKeys(call.Arguments)
	if err != nil {
		return nil, true, err
	}
	text := call.Arguments
	if text == "" {
		text = "null"
	}
	if tooDeep(text) {
		return nil, true, notDecided("a dispatch nested deeper than this machine reads")
	}
	if duplicate || !json.Valid([]byte(text)) {
		return nil, true, nil
	}
	current := json.RawMessage(text)
	for _, part := range strings.Split(d.Calls, ".") {
		fields, ok := object(current)
		if !ok {
			return nil, true, nil
		}
		current, ok = fields[part]
		if !ok {
			return nil, true, nil
		}
	}
	items := []json.RawMessage{current}
	if strings.HasPrefix(strings.TrimLeft(string(current), " \t\r\n"), "[") {
		if err := json.Unmarshal(current, &items); err != nil {
			return nil, true, notDecided("a dispatch this machine cannot read: %v", err)
		}
	}
	for _, item := range items {
		record, ok := object(item)
		if !ok {
			return nil, true, nil
		}
		var name string
		rawName, ok := record[d.Name]
		if !ok || !strings.HasPrefix(string(rawName), `"`) || json.Unmarshal(rawName, &name) != nil || name == "" || name == call.Name {
			return nil, true, nil
		}
		// A dispatcher that dispatches another dispatcher is not unwrapped twice.
		if list.find(name) != nil {
			return nil, true, nil
		}
		if strings.ContainsRune(name, utf8.RuneError) {
			return nil, true, notDecided("an inner tool name that may hold a lone surrogate")
		}
		arguments := "{}"
		if rawArguments, ok := record[d.Arguments]; ok && string(rawArguments) != "null" {
			canonical, ok, err := canon.Canonical(string(rawArguments))
			if err != nil {
				return nil, true, err
			}
			if !ok {
				// Nested too deep to canonicalise: the dispatch is unreadable.
				return nil, true, nil
			}
			arguments = canonical
		}
		inner = append(inner, Call{Name: name, Arguments: arguments})
	}
	return inner, true, nil
}
