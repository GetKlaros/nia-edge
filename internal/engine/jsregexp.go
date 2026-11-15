package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// A role's `match` patterns are JavaScript regular expressions: the server
// evaluates them with `new RegExp(pattern).test(value)`. Go's regexp package
// is another language. This file reads the part of JavaScript's syntax whose
// meaning is known to be the same once rewritten for Go, and refuses the
// rest: a pattern outside it is not decided here.
//
// What is rewritten:
//   - `.` excludes the four JavaScript line terminators, not only \n;
//   - \s and \S follow JavaScript's white space, which Go's \s does not;
//   - every literal and class member is written as \x{…}, so nothing of Go's
//     own syntax (POSIX classes, \Q, flags) can be reached from a pattern.
//
// What is refused: look-around, back-references, named groups, flags,
// \p, \c, octal escapes, letters escaped for no reason, empty classes, and
// anything JavaScript reads only through its legacy rules.
//
// JavaScript matches UTF-16 code units and Go matches code points. The two
// differ on text outside the Basic Multilingual Plane for the constructs
// that can consume or look at any character; such a pattern does not decide
// such a value. See jsPattern.test.

// errUndecidable wraps the reason a pattern or a value is not decided here.
type undecidable struct{ why string }

func (u *undecidable) Error() string { return "not decided on this machine: " + u.why }

// ErrUndecidable is matched by errors.Is for every answer this engine
// declines to give. The caller asks the server, or refuses.
var ErrUndecidable = &undecidable{why: "unknown"}

func (u *undecidable) Is(target error) bool { return target == ErrUndecidable }

func notDecided(format string, args ...any) error {
	return &undecidable{why: fmt.Sprintf(format, args...)}
}

// jsSpace is what JavaScript's \s matches, as members of a Go class.
const jsSpace = `\x{9}-\x{d}\x{20}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// jsDot is JavaScript's `.` without the s flag.
const jsDot = `[^\x{a}\x{d}\x{2028}\x{2029}]`

type jsPattern struct {
	source string
	re     *regexp.Regexp
	// wide: the pattern can consume, or look at, a character it does not
	// name. On text outside the BMP JavaScript sees two units there.
	wide bool
	// high: a class holds U+FFFD, which is what a lone surrogate became when
	// the arguments were decoded here.
	high bool
}

// compileJS translates a JavaScript pattern. The error is ErrUndecidable
// when the pattern is outside what is read here.
func compileJS(source string) (*jsPattern, error) {
	t := &translator{src: []rune(source)}
	if err := t.alternation(0); err != nil {
		return nil, err
	}
	if t.pos != len(t.src) {
		return nil, notDecided("pattern %q: unbalanced )", source)
	}
	re, err := regexp.Compile(t.out.String())
	if err != nil {
		return nil, notDecided("pattern %q: %v", source, err)
	}
	return &jsPattern{source: source, re: re, wide: t.wide, high: t.high}, nil
}

// test is `new RegExp(pattern).test(value)`.
func (p *jsPattern) test(value string) (bool, error) {
	for _, r := range value {
		if r > 0xffff && p.wide {
			return false, notDecided("pattern %q on text outside the BMP", p.source)
		}
		if r == 0xfffd && p.high {
			return false, notDecided("pattern %q on text that may have held a lone surrogate", p.source)
		}
	}
	return p.re.MatchString(value), nil
}

type translator struct {
	src  []rune
	pos  int
	out  strings.Builder
	wide bool
	high bool
}

const maxGroupDepth = 64

func (t *translator) refuse(what string) error {
	return notDecided("pattern %q: %s", string(t.src), what)
}

func (t *translator) peek() (rune, bool) {
	if t.pos < len(t.src) {
		return t.src[t.pos], true
	}
	return 0, false
}

// literal checks that a character means the same to both engines.
func (t *translator) literal(r rune) (rune, error) {
	if r > 0xffff || (r >= 0xd800 && r <= 0xdfff) || r == 0xfffd {
		return 0, t.refuse("a character outside the BMP, or one that may have been a surrogate")
	}
	return r, nil
}

func (t *translator) emit(r rune) { fmt.Fprintf(&t.out, `\x{%x}`, r) }

func (t *translator) alternation(depth int) error {
	if depth > maxGroupDepth {
		return t.refuse("groups nested too deep")
	}
	for {
		if err := t.sequence(depth); err != nil {
			return err
		}
		if r, ok := t.peek(); !ok || r != '|' {
			return nil
		}
		t.pos++
		t.out.WriteByte('|')
	}
}

func (t *translator) sequence(depth int) error {
	for {
		r, ok := t.peek()
		if !ok || r == '|' || r == ')' {
			return nil
		}
		t.pos++
		assertion := false
		switch r {
		case '^', '$':
			t.out.WriteRune(r)
			assertion = true
		case '.':
			t.out.WriteString(jsDot)
			t.wide = true
		case '(':
			if next, ok := t.peek(); ok && next == '?' {
				if t.pos+1 >= len(t.src) || t.src[t.pos+1] != ':' {
					return t.refuse("look-around, named groups and flags are not read here")
				}
				t.pos += 2
			}
			t.out.WriteString("(?:")
			if err := t.alternation(depth + 1); err != nil {
				return err
			}
			if next, ok := t.peek(); !ok || next != ')' {
				return t.refuse("unbalanced (")
			}
			t.pos++
			t.out.WriteByte(')')
		case '[':
			if err := t.class(); err != nil {
				return err
			}
		case '\\':
			var err error
			if assertion, err = t.escape(); err != nil {
				return err
			}
		case '*', '+', '?', '{', '}', ']':
			return t.refuse(fmt.Sprintf("%q where JavaScript's legacy rules decide", r))
		default:
			lit, err := t.literal(r)
			if err != nil {
				return err
			}
			t.emit(lit)
		}
		if err := t.quantifier(assertion); err != nil {
			return err
		}
	}
}

func (t *translator) quantifier(assertion bool) error {
	r, ok := t.peek()
	if !ok {
		return nil
	}
	switch r {
	case '*', '+', '?':
		t.pos++
		t.out.WriteRune(r)
	case '{':
		start := t.pos
		t.pos++
		low, ok := t.number()
		if !ok {
			return t.refuse("{ that is not a repetition")
		}
		high, bounded := low, true
		if next, ok := t.peek(); ok && next == ',' {
			t.pos++
			if high, ok = t.number(); !ok {
				bounded = false
			}
		}
		if next, ok := t.peek(); !ok || next != '}' {
			return t.refuse("{ that is not a repetition")
		}
		t.pos++
		if low > 1000 || (bounded && (high > 1000 || high < low)) {
			return t.refuse("a repetition count Go does not accept")
		}
		t.out.WriteString(string(t.src[start:t.pos]))
	default:
		return nil
	}
	if assertion {
		return t.refuse("a repeated assertion")
	}
	if next, ok := t.peek(); ok && next == '?' {
		t.pos++
		t.out.WriteByte('?')
	}
	if next, ok := t.peek(); ok && (next == '*' || next == '+' || next == '?' || next == '{') {
		return t.refuse("a repetition of a repetition")
	}
	return nil
}

// number reads decimal digits; ok is false when there are none or too many.
func (t *translator) number() (int, bool) {
	start, value := t.pos, 0
	for t.pos < len(t.src) && t.src[t.pos] >= '0' && t.src[t.pos] <= '9' {
		if t.pos-start >= 5 {
			return 0, false
		}
		value = value*10 + int(t.src[t.pos]-'0')
		t.pos++
	}
	return value, t.pos > start
}

func (t *translator) hex(digits int) (rune, bool) {
	if t.pos+digits > len(t.src) {
		return 0, false
	}
	var value rune
	for _, r := range t.src[t.pos : t.pos+digits] {
		switch {
		case r >= '0' && r <= '9':
			value = value<<4 | (r - '0')
		case r >= 'a' && r <= 'f':
			value = value<<4 | (r - 'a' + 10)
		case r >= 'A' && r <= 'F':
			value = value<<4 | (r - 'A' + 10)
		default:
			return 0, false
		}
	}
	t.pos += digits
	return value, true
}

func isASCIIPunct(r rune) bool {
	return r > ' ' && r < 0x7f && !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z')
}

// character reads the escapes that name one character, in or out of a class.
// The backslash is already consumed.
func (t *translator) character(r rune) (rune, error) {
	switch r {
	case 't':
		return '\t', nil
	case 'n':
		return '\n', nil
	case 'v':
		return '\v', nil
	case 'f':
		return '\f', nil
	case 'r':
		return '\r', nil
	case '0':
		if next, ok := t.peek(); ok && next >= '0' && next <= '9' {
			return 0, t.refuse("an octal escape")
		}
		return 0, nil
	case 'x':
		value, ok := t.hex(2)
		if !ok {
			return 0, t.refuse(`\x without two hexadecimal digits`)
		}
		return value, nil
	case 'u':
		value, ok := t.hex(4)
		if !ok {
			return 0, t.refuse(`\u without four hexadecimal digits`)
		}
		return t.literal(value)
	}
	if isASCIIPunct(r) {
		return r, nil
	}
	return 0, t.refuse(fmt.Sprintf(`the escape \%c`, r))
}

// escape reads an escape outside a class and reports whether it is an assertion.
func (t *translator) escape() (bool, error) {
	r, ok := t.peek()
	if !ok {
		return false, t.refuse("a pattern that ends in a backslash")
	}
	t.pos++
	switch r {
	case 'd', 'w':
		fmt.Fprintf(&t.out, `\%c`, r)
	case 'D', 'W':
		fmt.Fprintf(&t.out, `\%c`, r)
		t.wide = true
	case 's':
		t.out.WriteString("[" + jsSpace + "]")
	case 'S':
		t.out.WriteString("[^" + jsSpace + "]")
		t.wide = true
	case 'b':
		t.out.WriteString(`\b`)
		return true, nil
	case 'B':
		// True between the two halves of a pair in JavaScript.
		t.out.WriteString(`\B`)
		t.wide = true
		return true, nil
	default:
		value, err := t.character(r)
		if err != nil {
			return false, err
		}
		t.emit(value)
	}
	return false, nil
}

// classAtom reads one member of a class: a character, or a set (\d, \w, \s,
// \D, \W) returned as Go class text.
func (t *translator) classAtom() (single rune, set string, err error) {
	r := t.src[t.pos]
	t.pos++
	if r != '\\' {
		single, err = t.literal(r)
		return single, "", err
	}
	next, ok := t.peek()
	if !ok {
		return 0, "", t.refuse("a pattern that ends in a backslash")
	}
	t.pos++
	switch next {
	case 'd':
		return 0, `0-9`, nil
	case 'w':
		return 0, `0-9A-Za-z_`, nil
	case 's':
		return 0, jsSpace, nil
	case 'D', 'W':
		t.wide = true
		return 0, `\` + string(next), nil
	case 'S':
		return 0, "", t.refuse(`\S inside a class`)
	case 'b':
		return '\b', "", nil
	}
	single, err = t.character(next)
	return single, "", err
}

func (t *translator) class() error {
	t.out.WriteByte('[')
	if r, ok := t.peek(); ok && r == '^' {
		t.pos++
		t.out.WriteByte('^')
		t.wide = true
	}
	if r, ok := t.peek(); ok && r == ']' {
		return t.refuse("an empty class")
	}
	for {
		r, ok := t.peek()
		if !ok {
			return t.refuse("unbalanced [")
		}
		if r == ']' {
			t.pos++
			t.out.WriteByte(']')
			return nil
		}
		low, set, err := t.classAtom()
		if err != nil {
			return err
		}
		dash := t.pos+1 < len(t.src) && t.src[t.pos] == '-' && t.src[t.pos+1] != ']'
		if set != "" {
			if dash {
				return t.refuse("a set next to - in a class")
			}
			t.out.WriteString(set)
			continue
		}
		high := low
		if dash {
			t.pos++
			var highSet string
			if high, highSet, err = t.classAtom(); err != nil {
				return err
			}
			if highSet != "" || high < low {
				return t.refuse("a range that is not between two characters")
			}
		}
		if low <= 0xdfff && high >= 0xd800 {
			return t.refuse("a range over the surrogates")
		}
		if low <= 0xfffd && high >= 0xfffd {
			t.high = true
		}
		t.emit(low)
		if high != low {
			t.out.WriteByte('-')
			t.emit(high)
		}
	}
}
