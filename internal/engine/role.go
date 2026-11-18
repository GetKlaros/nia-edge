// Package engine decides a tool call from a role, as the Nia server does.
//
// The server is the reference: conformance/decisions.json, dispatch.json and
// regex.json are its answers, and this package's tests replay them. Where
// this code cannot be sure to answer as the server would, it does not answer:
// it returns ErrUndecidable, and the caller asks the server or refuses.
// It never guesses.
package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/GetKlaros/nia-edge/canon"
)

// The three decisions, from the loosest to the strictest.
const (
	Allow           = "allow"
	RequireApproval = "require_approval"
	Deny            = "deny"
)

var strictness = map[string]int{Allow: 0, RequireApproval: 1, Deny: 2}

// Decision is what a role answers for one proposed call.
type Decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	// Rule names the rule that decided: a tool rule, or `tool#n` for its
	// n-th argument rule. Nil when the role does not list the tool.
	Rule *string `json:"rule"`
	// Would is set when an observed role released a call it would have refused.
	Would *Would `json:"would,omitempty"`
}

// Would is the decision an observed role did not enforce.
type Would struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// Role is a role of the policy, ready to decide.
type Role struct {
	Name        string
	Observe     bool
	RuleOfTwo   string
	Destructive string
	Tools       []*Tool
}

// Tool is one tool rule of a role. Name may hold `*`.
type Tool struct {
	Name          string
	WhenUntrusted string
	Trusted       bool
	Sensitive     bool
	// Effect is "none", "external" or "destructive".
	Effect     string
	arguments  []*argumentRule
	categories []*categoryRule
}

// categoryRule refuses, or holds, a call that points to one of its hosts. It
// only ever makes a decision stricter.
type categoryRule struct {
	always   bool
	decision string
	path     string
	hosts    []string
}

type argumentRule struct {
	always   bool
	decision string
	match    []pathPattern
	hosts    *hostsRule
	shell    string // path, or "" when the rule has no shell_safe condition
}

// pathPattern is one `match` condition. A pattern this engine does not read
// is kept with the reason: a value at its path is then not decided here.
type pathPattern struct {
	path    string
	pattern *jsPattern
	unread  error
}

type hostsRule struct {
	path  string
	allow []string
}

// The role as the server writes it in a signed policy.
type roleJSON struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Mode        string  `json:"mode"`
	RuleOfTwo   string  `json:"rule_of_two"`
	Destructive string  `json:"destructive"`
	Tools       []struct {
		Name          string `json:"name"`
		WhenUntrusted string `json:"when_untrusted"`
		Output        string `json:"output"`
		Sensitive     bool   `json:"sensitive"`
		Effect        string `json:"effect"`
		Arguments     []struct {
			Description *string           `json:"description"`
			Applies     string            `json:"applies"`
			Decision    string            `json:"decision"`
			Match       map[string]string `json:"match"`
			Hosts       *struct {
				Path  string   `json:"path"`
				Allow []string `json:"allow"`
			} `json:"hosts"`
			ShellSafe *struct {
				Path string `json:"path"`
			} `json:"shell_safe"`
		} `json:"arguments"`
		Categories []struct {
			Description *string  `json:"description"`
			Applies     string   `json:"applies"`
			Decision    string   `json:"decision"`
			Path        string   `json:"path"`
			In          []string `json:"in"`
			Hosts       []string `json:"hosts"`
		} `json:"categories"`
	} `json:"tools"`
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

// ParseRole reads a role from a policy. A role with a field or a value this
// code does not know is refused whole: a rule that is not understood cannot
// be skipped.
func ParseRole(raw json.RawMessage) (*Role, error) {
	var in roleJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return nil, fmt.Errorf("engine: the role cannot be read by this nia-edge: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("engine: text after the role")
	}
	if in.Name == "" || !oneOf(in.Mode, "enforce", "observe") || !oneOf(in.RuleOfTwo, Allow, RequireApproval, Deny) || !oneOf(in.Destructive, Allow, RequireApproval, Deny) {
		return nil, errors.New("engine: the role has a mode or a decision this nia-edge does not know")
	}
	role := &Role{Name: in.Name, Observe: in.Mode == "observe", RuleOfTwo: in.RuleOfTwo, Destructive: in.Destructive}
	for _, t := range in.Tools {
		if t.Name == "" || !utf8.ValidString(t.Name) || !oneOf(t.WhenUntrusted, Allow, RequireApproval, Deny) || !oneOf(t.Output, "untrusted", "trusted") || !oneOf(t.Effect, "none", "external", "destructive") {
			return nil, fmt.Errorf("engine: the rule of tool %q has a value this nia-edge does not know", t.Name)
		}
		tool := &Tool{Name: t.Name, WhenUntrusted: t.WhenUntrusted, Trusted: t.Output == "trusted", Sensitive: t.Sensitive, Effect: t.Effect}
		for index, a := range t.Arguments {
			if !oneOf(a.Applies, "always", "untrusted") || !oneOf(a.Decision, Allow, RequireApproval, Deny) || (len(a.Match) == 0 && a.Hosts == nil && a.ShellSafe == nil) {
				return nil, fmt.Errorf("engine: argument rule %s#%d has a value this nia-edge does not know", t.Name, index)
			}
			rule := &argumentRule{always: a.Applies == "always", decision: a.Decision}
			for path, source := range a.Match {
				pattern, err := compileJS(source)
				rule.match = append(rule.match, pathPattern{path: path, pattern: pattern, unread: err})
			}
			if a.Hosts != nil {
				if len(a.Hosts.Allow) == 0 {
					return nil, fmt.Errorf("engine: argument rule %s#%d allows no host", t.Name, index)
				}
				rule.hosts = &hostsRule{path: a.Hosts.Path, allow: a.Hosts.Allow}
			}
			if a.ShellSafe != nil {
				if a.ShellSafe.Path == "" {
					return nil, fmt.Errorf("engine: argument rule %s#%d has an empty path", t.Name, index)
				}
				rule.shell = a.ShellSafe.Path
			}
			tool.arguments = append(tool.arguments, rule)
		}
		for index, c := range t.Categories {
			// The server lists the hosts of each category it names: those are
			// what this engine reads.
			if !oneOf(c.Applies, "always", "untrusted") || !oneOf(c.Decision, RequireApproval, Deny) || c.Path == "" || len(c.Hosts) == 0 {
				return nil, fmt.Errorf("engine: category rule %s@%d has a value this nia-edge does not know", t.Name, index)
			}
			tool.categories = append(tool.categories, &categoryRule{always: c.Applies == "always", decision: c.Decision, path: c.Path, hosts: c.Hosts})
		}
		role.Tools = append(role.Tools, tool)
	}
	return role, nil
}

// Rule returns the first tool rule whose name matches, so specific names can
// precede globs. Nil when the role does not list the tool.
func (r *Role) Rule(tool string) *Tool {
	for _, rule := range r.Tools {
		if globMatches(rule.Name, tool) {
			return rule
		}
	}
	return nil
}

// globMatches reports whether a tool name matches a rule name, in which `*`
// stands for any run of characters. As in the server, where `*` is the
// regular expression `.*`, a run does not cross a line terminator.
func globMatches(pattern, value string) bool {
	p, v := []rune(pattern), []rune(value)
	// reach[j]: the pattern read so far can match the first j characters.
	reach := make([]bool, len(v)+1)
	reach[0] = true
	for _, c := range p {
		next := make([]bool, len(v)+1)
		if c == '*' {
			for j := 0; j <= len(v); j++ {
				if reach[j] {
					next[j] = true
				} else if j > 0 && next[j-1] && !lineTerminator(v[j-1]) {
					next[j] = true
				}
			}
		} else {
			for j := 1; j <= len(v); j++ {
				next[j] = reach[j-1] && v[j-1] == c
			}
		}
		reach = next
	}
	return reach[len(v)]
}

func lineTerminator(r rune) bool {
	return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029
}

// Decide answers for one proposed call: the tool, the arguments as the model
// wrote them, and whether the session is tainted and exposed.
//
// Unlisted tools are denied. Argument rules refine a listed tool; otherwise
// it takes its when_untrusted decision once the session is tainted. The two
// role-wide rules only make that stricter. An observed role releases what it
// would have refused and says so, except arguments that are ambiguous.
//
// The error is canon.ErrInvalidUTF8 for text that is not UTF-8, and
// ErrUndecidable when this engine cannot be sure of the server's answer.
func (r *Role) Decide(tool string, tainted bool, rawArguments string, exposed bool) (Decision, error) {
	if !utf8.ValidString(tool) || !utf8.ValidString(rawArguments) {
		return Decision{}, canon.ErrInvalidUTF8
	}
	rule := r.Rule(tool)
	duplicate, err := canon.HasDuplicateKeys(rawArguments)
	if err != nil {
		return Decision{}, err
	}
	decided, err := r.enforced(rule, tainted, rawArguments, duplicate)
	if err != nil {
		return Decision{}, err
	}
	decided = r.stricter(rule, tainted, exposed, decided)
	if decided, err = categorized(rule, tainted, rawArguments, decided); err != nil {
		return Decision{}, err
	}
	if !r.Observe || decided.Decision == Allow {
		return decided, nil
	}
	// Not a role decision: arguments two parsers may read differently are
	// refused whatever the mode, listed tool or not.
	if duplicate {
		return Decision{Decision: Deny, Reason: "ambiguous_arguments", Rule: decided.Rule}, nil
	}
	return Decision{Decision: Allow, Reason: "observed", Rule: decided.Rule, Would: &Would{Decision: decided.Decision, Reason: decided.Reason}}, nil
}

func named(name string) *string { return &name }

func (r *Role) enforced(rule *Tool, tainted bool, rawArguments string, duplicate bool) (Decision, error) {
	if rule == nil {
		return Decision{Decision: Deny, Reason: "tool_not_in_role"}, nil
	}
	// A repeated key could be read differently by the agent's executor.
	if duplicate {
		return Decision{Decision: Deny, Reason: "ambiguous_arguments", Rule: named(rule.Name)}, nil
	}
	var args any
	parsed, readable := false, false
	for index, argumentRule := range rule.arguments {
		if !argumentRule.always && !tainted {
			continue
		}
		if !parsed {
			var err error
			if args, readable, err = parseArguments(rawArguments); err != nil {
				return Decision{}, err
			}
			parsed = true
		}
		if !readable {
			// Arguments that are not JSON match no rule.
			break
		}
		matches, err := argumentRule.matches(args)
		if err != nil {
			return Decision{}, err
		}
		if matches {
			return Decision{Decision: argumentRule.decision, Reason: "argument_rule", Rule: named(rule.Name + "#" + strconv.Itoa(index))}, nil
		}
	}
	if tainted && rule.WhenUntrusted != Allow {
		return Decision{Decision: rule.WhenUntrusted, Reason: "untrusted_session", Rule: named(rule.Name)}, nil
	}
	return Decision{Decision: Allow, Reason: "allowed", Rule: named(rule.Name)}, nil
}

func (r *Role) stricter(rule *Tool, tainted, exposed bool, base Decision) Decision {
	// Unlisted tools and unreadable arguments are already refused.
	if rule == nil || rule.Effect == "none" || base.Reason == "ambiguous_arguments" {
		return base
	}
	decided := base
	if rule.Effect == "destructive" && strictness[r.Destructive] > strictness[decided.Decision] {
		decided = Decision{Decision: r.Destructive, Reason: "destructive", Rule: named(rule.Name)}
	}
	if tainted && exposed && strictness[r.RuleOfTwo] > strictness[decided.Decision] {
		decided = Decision{Decision: r.RuleOfTwo, Reason: "rule_of_two", Rule: named(rule.Name)}
	}
	return decided
}

// categorized applies the tool's category rules after everything else: a
// call that points to one of their hosts takes their decision when it is
// stricter. Arguments that are not JSON, or a value at the path that is not a
// URL read alike by every client, count as such a host.
func categorized(rule *Tool, tainted bool, rawArguments string, base Decision) (Decision, error) {
	if rule == nil || len(rule.categories) == 0 || base.Reason == "ambiguous_arguments" {
		return base, nil
	}
	decided := base
	var args any
	parsed, readable := false, false
	for index, category := range rule.categories {
		if !category.always && !tainted {
			continue
		}
		if strictness[category.decision] <= strictness[decided.Decision] {
			continue
		}
		if !parsed {
			var err error
			if args, readable, err = parseArguments(rawArguments); err != nil {
				return Decision{}, err
			}
			parsed = true
		}
		hit := !readable
		if readable {
			if value, ok := valueAt(args, category.path); ok {
				var err error
				if hit, err = categoryHit(value, category.hosts); err != nil {
					return Decision{}, err
				}
			}
		}
		if hit {
			decided = Decision{Decision: category.decision, Reason: "category", Rule: named(rule.Name + "@" + strconv.Itoa(index))}
		}
	}
	return decided, nil
}

// parseArguments is the server's JSON.parse(raw || '{}'). readable is false
// for text that is not JSON.
func parseArguments(raw string) (value any, readable bool, err error) {
	if raw == "" {
		raw = "{}"
	}
	if tooDeep(raw) {
		return nil, false, notDecided("arguments nested deeper than this machine reads")
	}
	if !json.Valid([]byte(raw)) {
		return nil, false, nil
	}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		// JSON that encoding/json will not hold: nested deeper than it reads.
		return nil, false, notDecided("arguments this machine cannot read: %v", err)
	}
	return value, true, nil
}

// tooDeep reports whether text opens more nested arrays and objects than
// encoding/json reads (10000). JavaScript has no such limit, so what such a
// text holds is not decided here.
func tooDeep(text string) bool {
	depth, inString := 0, false
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case inString:
			if c == '\\' {
				i++
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
		case c == '[' || c == '{':
			if depth++; depth > 9000 {
				return true
			}
		case c == ']' || c == '}':
			depth--
		}
	}
	return false
}

// valueAt follows a dotted path through objects and returns the string
// there. A list of strings is read as one command line.
func valueAt(args any, path string) (string, bool) {
	current := args
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current = object[part]
	}
	switch value := current.(type) {
	case string:
		return value, true
	case []any:
		parts := make([]string, len(value))
		for i, item := range value {
			text, ok := item.(string)
			if !ok {
				return "", false
			}
			parts[i] = text
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}

// matches reports whether every condition of the rule holds. A condition
// that is false settles it; otherwise one that cannot be evaluated here
// leaves the call undecided.
func (rule *argumentRule) matches(args any) (bool, error) {
	var undecided error
	for _, condition := range rule.match {
		value, ok := valueAt(args, condition.path)
		if !ok {
			return false, nil
		}
		if condition.unread != nil {
			undecided = condition.unread
			continue
		}
		matched, err := condition.pattern.test(value)
		if err != nil {
			undecided = err
		} else if !matched {
			return false, nil
		}
	}
	if rule.hosts != nil {
		value, ok := valueAt(args, rule.hosts.path)
		if !ok {
			return false, nil
		}
		allowed, err := hostsAllowed(value, rule.hosts.allow)
		if err != nil {
			undecided = err
		} else if !allowed {
			return false, nil
		}
	}
	if rule.shell != "" {
		value, ok := valueAt(args, rule.shell)
		if !ok || strings.ContainsAny(value, ";&|`$<>\r\n\\") {
			return false, nil
		}
	}
	if undecided != nil {
		return false, undecided
	}
	return true, nil
}
