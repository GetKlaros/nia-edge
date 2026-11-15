// Package inspect finds what must not travel in a conversation: secrets
// first. It answers as the Nia server does; conformance/secrets.json holds
// the server's answers and this package's tests replay them.
//
// The server's detectors are JavaScript regular expressions with
// look-behind, which Go's regexp package does not have. Each is written here
// as a scanner that tries every position in turn, as a regular expression
// engine does, so the same spans are found in the same order.
package inspect

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// Finding is one thing a detector found in a text.
type Finding struct {
	Detector string  `json:"detector,omitempty"`
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	// Start and End are the span in UTF-16 code units, as the server counts.
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Replacement string `json:"replacement"`
	// from and to are the same span in bytes of the Go string.
	from, to int
}

func upperOrDigit(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') }
func alnum(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
func word(c byte) bool     { return alnum(c) || c == '_' }
func token(c byte) bool    { return alnum(c) || c == '_' || c == '-' }
func credChar(c byte) bool { return alnum(c) || strings.IndexByte("_./+=-", c) >= 0 }

// run returns the length of the longest prefix of s made of bytes in class.
func run(s string, class func(byte) bool) int {
	n := 0
	for n < len(s) && class(s[n]) {
		n++
	}
	return n
}

// before reports whether the byte before position i is in class: the
// look-behind of a pattern. A byte of a character outside ASCII is in none.
func before(s string, i int, class func(byte) bool) bool {
	return i > 0 && class(s[i-1])
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xffff {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// jsSpace is what JavaScript's \s matches.
func jsSpace(r rune) bool {
	switch {
	case r >= 0x9 && r <= 0xd, r == 0x20, r == 0xa0, r == 0x1680, r >= 0x2000 && r <= 0x200a,
		r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000, r == 0xfeff:
		return true
	}
	return false
}

func skipSpace(s string) int {
	n := 0
	for n < len(s) {
		r, size := utf8.DecodeRuneInString(s[n:])
		if !jsSpace(r) {
			break
		}
		n += size
	}
	return n
}

// hasPrefixFold compares with an ASCII lower-case prefix, ignoring ASCII
// case only: JavaScript's i flag does not fold ſ to s or K (kelvin) to k.
func hasPrefixFold(s, lower string) bool {
	if len(s) < len(lower) {
		return false
	}
	for i := 0; i < len(lower); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// A matcher tries one position: the end of the match, where the secret
// value starts in it, and whether there is a match.
type matcher func(s string, i int) (end, value int, ok bool)

type secretPattern struct {
	category    string
	score       float64
	replacement string
	// match is nil for the private key, whose matcher keeps state for one text.
	match matcher
}

var keyLabels = []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY"}

// nextEnd remembers, for one text, where the next "-----END <label>-----"
// is from a position, so a text made of thousands of headers is still read
// in one pass.
type nextEnd struct {
	from, at map[string]int
}

// find returns the first index of marker in s at or after from, or -1.
func (n *nextEnd) find(s, marker string, from int) int {
	if asked, known := n.from[marker]; known && asked <= from && (n.at[marker] < 0 || n.at[marker] >= from) {
		return n.at[marker]
	}
	at := strings.Index(s[from:], marker)
	if at >= 0 {
		at += from
	}
	n.from[marker], n.at[marker] = from, at
	return at
}

// -----BEGIN <label>-----, 1 to 16384 code units, the first -----END <label>-----.
func privateKeyMatcher() matcher {
	ends := &nextEnd{from: map[string]int{}, at: map[string]int{}}
	return func(s string, i int) (int, int, bool) {
		const begin = "-----BEGIN "
		if !strings.HasPrefix(s[i:], begin) {
			return 0, 0, false
		}
		rest := s[i+len(begin):]
		for _, label := range keyLabels {
			if !strings.HasPrefix(rest, label+"-----") {
				continue
			}
			body := i + len(begin) + len(label) + 5
			if body >= len(s) {
				return 0, 0, false
			}
			_, first := utf8.DecodeRuneInString(s[body:])
			end := "-----END " + label + "-----"
			at := ends.find(s, end, body+first)
			// 16384 code units are at most four times as many bytes.
			if at < 0 || at-body > 4*16384 || utf16Len(s[body:at]) > 16384 {
				return 0, 0, false
			}
			return at + len(end), i, true
		}
		return 0, 0, false
	}
}

func awsAccessKey(s string, i int) (int, int, bool) {
	if before(s, i, upperOrDigit) || !strings.HasPrefix(s[i:], "AKIA") {
		return 0, 0, false
	}
	body := s[i+4:]
	if run(body, upperOrDigit) < 16 || (len(body) > 16 && upperOrDigit(body[16])) {
		return 0, 0, false
	}
	return i + 20, i, true
}

func githubToken(s string, i int) (int, int, bool) {
	if before(s, i, word) {
		return 0, 0, false
	}
	rest := s[i:]
	if len(rest) >= 4 && rest[0] == 'g' && rest[1] == 'h' && strings.IndexByte("pousr", rest[2]) >= 0 && rest[3] == '_' {
		if n := run(rest[4:], alnum); n >= 20 {
			return i + 4 + n, i, true
		}
		return 0, 0, false
	}
	if strings.HasPrefix(rest, "github_pat_") {
		if n := run(rest[11:], word); n >= 20 {
			return i + 11 + n, i, true
		}
	}
	return 0, 0, false
}

// sk- then 20 or more token characters; the provider prefixes (proj-, ant-…)
// are token characters themselves.
func llmKey(s string, i int) (int, int, bool) {
	if before(s, i, token) || !strings.HasPrefix(s[i:], "sk-") {
		return 0, 0, false
	}
	if n := run(s[i+3:], token); n >= 20 {
		return i + 3 + n, i, true
	}
	return 0, 0, false
}

func niaKey(s string, i int) (int, int, bool) {
	if before(s, i, token) || !strings.HasPrefix(s[i:], "nia_") {
		return 0, 0, false
	}
	if n := run(s[i+4:], token); n >= 32 {
		return i + 4 + n, i, true
	}
	return 0, 0, false
}

func jwt(s string, i int) (int, int, bool) {
	if before(s, i, token) || !strings.HasPrefix(s[i:], "eyJ") {
		return 0, 0, false
	}
	at := i + 3
	for part := 0; part < 3; part++ {
		n := run(s[at:], token)
		if n < 8 {
			return 0, 0, false
		}
		at += n
		if part < 2 {
			if at >= len(s) || s[at] != '.' {
				return 0, 0, false
			}
			at++
		}
	}
	return at, i, true
}

var credentialLabels = [][3]string{
	{"api", "_-", "key"}, {"access", "_-", "token"}, {"client", "_-", "secret"}, {"password", "", ""}, {"secret", "_-", "key"},
}

// A label, : or =, an optional quote, then 20 or more credential characters.
func labelledCredential(s string, i int) (int, int, bool) {
	rest := s[i:]
	for _, label := range credentialLabels {
		if !hasPrefixFold(rest, label[0]) {
			continue
		}
		at := len(label[0])
		// The separator is optional; with it or without, the second word follows.
		tails := []int{at}
		if label[1] != "" && at < len(rest) && strings.IndexByte(label[1], rest[at]) >= 0 {
			tails = []int{at + 1}
		}
		for _, tail := range tails {
			if !hasPrefixFold(rest[tail:], label[2]) {
				continue
			}
			at = tail + len(label[2])
			at += skipSpace(rest[at:])
			if at >= len(rest) || (rest[at] != ':' && rest[at] != '=') {
				continue
			}
			at++
			at += skipSpace(rest[at:])
			if at < len(rest) && (rest[at] == '"' || rest[at] == '\'') {
				at++
			}
			if n := run(rest[at:], credChar); n >= 20 {
				return i + at + n, i + at, true
			}
		}
	}
	return 0, 0, false
}

var secretPatterns = []secretPattern{
	{"secret.private_key", 1, "[REDACTED_PRIVATE_KEY]", nil},
	{"secret.aws_access_key", 0.99, "[REDACTED_AWS_ACCESS_KEY]", awsAccessKey},
	{"secret.github_token", 0.99, "[REDACTED_GITHUB_TOKEN]", githubToken},
	// OpenAI, Anthropic (sk-ant-...) and compatible provider keys.
	{"secret.llm_api_key", 0.99, "[REDACTED_API_KEY]", llmKey},
	{"secret.nia_api_key", 0.99, "[REDACTED_API_KEY]", niaKey},
	{"secret.jwt", 0.92, "[REDACTED_JWT]", jwt},
	{"secret.generic_credential", 0.9, "[REDACTED_CREDENTIAL]", labelledCredential},
}

// Secrets returns the secrets found in a text: pattern by pattern, each from
// left to right, matches of one pattern never overlapping.
func Secrets(content string) []Finding {
	findings := []Finding{}
	for _, pattern := range secretPatterns {
		match := pattern.match
		if match == nil {
			match = privateKeyMatcher()
		}
		for i := 0; i < len(content); {
			end, value, ok := match(content, i)
			if !ok {
				i++
				continue
			}
			findings = append(findings, Finding{
				Detector: "secrets", Category: pattern.category, Score: pattern.score, Replacement: pattern.replacement,
				Start: utf16Len(content[:value]), End: utf16Len(content[:end]), from: value, to: end,
			})
			i = end
		}
	}
	return findings
}

// redact replaces each span, from left to right; a span that starts inside
// one already replaced is dropped or cut. ok is false when there is nothing
// to replace.
func redact(content string, findings []Finding) (string, bool) {
	if len(findings) == 0 {
		return "", false
	}
	spans := append([]Finding(nil), findings...)
	sort.SliceStable(spans, func(a, b int) bool { return spans[a].from < spans[b].from })
	var out strings.Builder
	cursor := 0
	for _, span := range spans {
		if span.to <= cursor {
			continue
		}
		out.WriteString(content[cursor:max(cursor, span.from)])
		out.WriteString(span.Replacement)
		cursor = span.to
	}
	out.WriteString(content[cursor:])
	return out.String(), true
}

// RedactSecrets returns a text with every detected secret replaced, for
// storage and display.
func RedactSecrets(content string) string {
	if redacted, ok := redact(content, Secrets(content)); ok {
		return redacted
	}
	return content
}
