package canon

import (
	"errors"
	"slices"
	"unicode/utf16"
	"unicode/utf8"
)

// A Value is a JSON value as JavaScript holds it after JSON.parse: strings
// are UTF-16, numbers are doubles, a repeated key keeps its last value at
// its first place. The model's output and the agent's requests are read
// through it wherever the server reads them with JSON.parse.
type Value struct{ n *node }

// Kind is the type of a Value.
type Kind uint8

// The kinds of JSON values.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// ParseDepth is how deep a document may nest and be read by Parse.
// JavaScript has no such limit: a deeper document is ErrTooDeep, and what it
// holds is not known here.
const ParseDepth = 9000

// Errors of Parse, besides ErrInvalidUTF8.
var (
	ErrNotJSON = errors.New("canon: not JSON")
	ErrTooDeep = errors.New("canon: nested deeper than this machine reads")
)

// Parse reads a JSON document as JSON.parse does.
func Parse(text string) (*Value, error) {
	if !utf8.ValidString(text) {
		return nil, ErrInvalidUTF8
	}
	p := parser{data: text, deepest: ParseDepth}
	root, err := p.document()
	switch {
	case errors.Is(err, errTooDeep):
		return nil, ErrTooDeep
	case err != nil:
		return nil, ErrNotJSON
	}
	return &Value{n: root}, nil
}

// Kind returns the type of the value. A nil Value, which is what Get
// returns for a key that is not there, is Null.
func (v *Value) Kind() Kind {
	if v == nil {
		return Null
	}
	switch v.n.kind {
	case kindFalse, kindTrue:
		return Bool
	case kindNumber:
		return Number
	case kindString:
		return String
	case kindArray:
		return Array
	case kindObject:
		return Object
	}
	return Null
}

// Present reports whether the value exists: Get returns nil for a missing
// key, which JavaScript calls undefined, while a JSON null is present.
func (v *Value) Present() bool { return v != nil }

// Text returns a string value. wellFormed is false when the string holds a
// surrogate without its pair, which a Go string cannot: it is then replaced
// by U+FFFD, and the text is not what JavaScript holds.
func (v *Value) Text() (text string, wellFormed bool, ok bool) {
	if v == nil || v.n.kind != kindString {
		return "", false, false
	}
	wellFormed = true
	units := v.n.text
	for i := 0; i < len(units); i++ {
		switch {
		case utf16.IsSurrogate(rune(units[i])) && i+1 < len(units) && units[i] < 0xdc00 && units[i+1] >= 0xdc00 && units[i+1] <= 0xdfff:
			i++
		case utf16.IsSurrogate(rune(units[i])):
			wellFormed = false
		}
	}
	return string(utf16.Decode(units)), wellFormed, true
}

// Truth returns a boolean value.
func (v *Value) Truth() (value bool, ok bool) {
	if v == nil || (v.n.kind != kindTrue && v.n.kind != kindFalse) {
		return false, false
	}
	return v.n.kind == kindTrue, true
}

// Float returns a number value.
func (v *Value) Float() (value float64, ok bool) {
	if v == nil || v.n.kind != kindNumber {
		return 0, false
	}
	return v.n.number, true
}

// Get returns the value of a key of an object, or nil when the value is not
// an object or has no such key.
func (v *Value) Get(key string) *Value {
	if v == nil || v.n.kind != kindObject {
		return nil
	}
	units := utf16.Encode([]rune(key))
	for _, m := range v.n.members {
		if slices.Equal(m.key, units) {
			return &Value{n: m.value}
		}
	}
	return nil
}

// Len returns the number of items of an array, or of keys of an object.
func (v *Value) Len() int {
	if v == nil {
		return 0
	}
	if v.n.kind == kindObject {
		return len(v.n.members)
	}
	return len(v.n.items)
}

// Items returns the items of an array, and nil for anything else.
func (v *Value) Items() []*Value {
	if v == nil || v.n.kind != kindArray {
		return nil
	}
	items := make([]*Value, len(v.n.items))
	for i, item := range v.n.items {
		items[i] = &Value{n: item}
	}
	return items
}

// JSON writes the value as JSON.stringify does: no space, numbers as
// JavaScript spells them, and the keys of an object in JavaScript's order.
func (v *Value) JSON() string {
	if v == nil {
		return "null"
	}
	return string(appendJS(nil, v.n))
}

// Canonical writes the value in canonical form: as JSON, keys sorted.
// ok is false when it nests deeper than MaxDepth.
func (v *Value) Canonical() (canonical string, ok bool) {
	if v == nil {
		return "null", true
	}
	if depth(v.n) > MaxDepth {
		return "", false
	}
	return string(appendNode(nil, v.n)), true
}

func depth(n *node) int {
	deepest := 0
	for _, item := range n.items {
		deepest = max(deepest, depth(item))
	}
	for _, m := range n.members {
		deepest = max(deepest, depth(m.value))
	}
	if n.kind == kindArray || n.kind == kindObject {
		return deepest + 1
	}
	return 0
}

// Stringify is JSON.stringify(JSON.parse(text)). ok is false for text that
// is not JSON.
func Stringify(text string) (written string, ok bool, err error) {
	value, err := Parse(text)
	switch {
	case errors.Is(err, ErrNotJSON):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return value.JSON(), true, nil
}

// arrayIndex reports whether a key is an array index to JavaScript, which
// lists such keys first and in ascending order: the decimal spelling of an
// integer from 0 to 2^32-2.
func arrayIndex(key []uint16) (uint32, bool) {
	if len(key) == 0 || len(key) > 10 || (key[0] == '0' && len(key) > 1) {
		return 0, false
	}
	var value uint64
	for _, unit := range key {
		if unit < '0' || unit > '9' {
			return 0, false
		}
		value = value*10 + uint64(unit-'0')
	}
	if value > 4294967294 {
		return 0, false
	}
	return uint32(value), true
}

// jsOrder returns the members of an object in the order JavaScript lists
// its keys: array indices ascending, then the others as first written.
func jsOrder(members []member) []member {
	type indexed struct {
		index uint32
		m     member
	}
	var indices []indexed
	var others []member
	for _, m := range members {
		if index, ok := arrayIndex(m.key); ok {
			indices = append(indices, indexed{index, m})
		} else {
			others = append(others, m)
		}
	}
	if len(indices) == 0 {
		return members
	}
	slices.SortFunc(indices, func(a, b indexed) int {
		switch {
		case a.index < b.index:
			return -1
		case a.index > b.index:
			return 1
		}
		return 0
	})
	ordered := make([]member, 0, len(members))
	for _, item := range indices {
		ordered = append(ordered, item.m)
	}
	return append(ordered, others...)
}

func appendJS(out []byte, n *node) []byte {
	switch n.kind {
	case kindArray:
		out = append(out, '[')
		for index, item := range n.items {
			if index > 0 {
				out = append(out, ',')
			}
			out = appendJS(out, item)
		}
		return append(out, ']')
	case kindObject:
		out = append(out, '{')
		for index, m := range jsOrder(n.members) {
			if index > 0 {
				out = append(out, ',')
			}
			out = appendQuoted(out, m.key)
			out = append(out, ':')
			out = appendJS(out, m.value)
		}
		return append(out, '}')
	}
	return appendNode(out, n)
}
