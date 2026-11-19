package engine

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
)

// EffectTool is the call that judges what a simulated command did, from the
// layer it left: {"deleted": <files deleted>, "paths": [<every path it
// changed>]}. Only a role that simulates allows it.
const EffectTool = "nia:effect"

// EffectPaths bounds the paths of one effect.
const EffectPaths = 2000

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER.
const maxSafeInteger = 1<<53 - 1

var (
	plainDigits    = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	negativeDigits = regexp.MustCompile(`^-[1-9][0-9]*$`)
	// A lone surrogate is kept by JavaScript and replaced by encoding/json.
	surrogateEscape = regexp.MustCompile(`(?i)\\ud[89a-f]`)
)

// effect decides an effect as the server does (effectDecision, src/roles.ts).
func (r *Role) effect(raw string, duplicate bool) (Decision, error) {
	if r.Simulate == nil {
		return Decision{Decision: Deny, Reason: "tool_not_in_role"}, nil
	}
	unreadable := Decision{Decision: Deny, Reason: "ambiguous_arguments", Rule: named("simulate")}
	if duplicate || raw == "" {
		return unreadable, nil
	}
	if tooDeep(raw) || surrogateEscape.MatchString(raw) {
		return Decision{}, notDecided("an effect this machine does not read as the server does")
	}
	if !json.Valid([]byte(raw)) {
		return unreadable, nil
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return Decision{}, notDecided("an effect this machine cannot read: %v", err)
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 {
		return unreadable, nil
	}
	number, ok := object["deleted"].(json.Number)
	paths, listed := object["paths"].([]any)
	if !ok || !listed {
		return unreadable, nil
	}
	var deleted int64
	switch text := number.String(); {
	case plainDigits.MatchString(text):
		parsed, err := strconv.ParseUint(text, 10, 64)
		if err != nil || parsed > maxSafeInteger {
			return unreadable, nil
		}
		deleted = int64(parsed)
	case negativeDigits.MatchString(text):
		return unreadable, nil
	default:
		// A fraction, an exponent or -0: JavaScript's Number decides.
		return Decision{}, notDecided("a number of deleted files this machine does not read as the server does")
	}
	if len(paths) > EffectPaths {
		return unreadable, nil
	}
	texts := make([]string, 0, len(paths))
	for _, path := range paths {
		text, ok := path.(string)
		if !ok {
			return unreadable, nil
		}
		texts = append(texts, text)
	}
	for index, protected := range r.Simulate.Protected {
		if len(texts) == 0 {
			break
		}
		if protected.unread != nil {
			return Decision{}, protected.unread
		}
		for _, text := range texts {
			matched, err := protected.pattern.test(text)
			if err != nil {
				return Decision{}, err
			}
			if matched {
				return Decision{Decision: RequireApproval, Reason: "effect", Rule: named("simulate.protected#" + strconv.Itoa(index))}, nil
			}
		}
	}
	if deleted > r.Simulate.MaxDeleted {
		return Decision{Decision: RequireApproval, Reason: "effect", Rule: named("simulate.max_deleted")}, nil
	}
	return Decision{Decision: Allow, Reason: "allowed", Rule: named("simulate")}, nil
}
