// Package decisions keeps this machine's log of what Nia decided: one JSON
// line per decision, beside the state file, readable by nia-edge's user only
// (0600). It names the path (model, hook, egress, budget), the tool or the
// host, the decision and Nia's reason: never a prompt, an argument, an output
// or a secret. A session is shown by a short hash.
//
// It is for the person who runs the machine; it decides nothing, and a log
// that cannot be written never stops a decision.
package decisions

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GetKlaros/nia-edge/internal/egress"
	"github.com/GetKlaros/nia-edge/internal/inspect"
	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/turn"
)

// MaxSize is the size past which the log moves to <file>.1, replacing it.
const MaxSize = 10 << 20

// Entry is one decision.
type Entry struct {
	Time     time.Time `json:"time"`
	Path     string    `json:"path"`
	Session  string    `json:"session,omitempty"`
	Tool     string    `json:"tool,omitempty"`
	Host     string    `json:"host,omitempty"`
	Decision string    `json:"decision"`
	Reason   string    `json:"reason,omitempty"`
}

// Log appends entries to one file.
type Log struct {
	path string
	mu   sync.Mutex
	now  func() time.Time
	max  int64
}

// Open returns the log at path; it creates the file on the first entry.
func Open(path string) *Log { return &Log{path: path, now: time.Now, max: MaxSize} }

// Record appends an entry. A failure is ignored: the log never stops a call.
func (l *Log) Record(e Entry) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	e.Reason = clip(inspect.RedactSecrets(e.Reason), 300)
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if info, err := os.Stat(l.path); err == nil && info.Size()+int64(len(line)) > l.max {
		_ = os.Rename(l.path, l.path+".1")
	}
	file, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(line, '\n'))
}

// Last returns the last n entries, oldest first, from the file and the one
// it rotated to.
func Last(path string, n int) ([]Entry, error) {
	var entries []Entry
	found := false
	for _, file := range []string{path + ".1", path} {
		handle, err := os.Open(file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		found = true
		scanner := bufio.NewScanner(handle)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			var entry Entry
			if json.Unmarshal(scanner.Bytes(), &entry) == nil {
				entries = append(entries, entry)
			}
		}
		handle.Close()
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, fs.ErrNotExist
	}
	if n > 0 && len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	return entries, nil
}

// Format writes entries as a person reads them.
func Format(w io.Writer, entries []Entry) {
	for _, e := range entries {
		what := e.Tool
		if e.Host != "" {
			what = e.Host
		}
		line := e.Time.Local().Format("2006-01-02 15:04:05") + "  " + pad(e.Path, 6) + "  " + pad(e.Decision, 5) + "  " + what
		if e.Session != "" {
			line += "  [" + e.Session + "]"
		}
		if e.Reason != "" {
			line += "  " + e.Reason
		}
		io.WriteString(w, line+"\n")
	}
}

func pad(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return text + strings.Repeat(" ", width-len(text))
}

func clip(text string, max int) string {
	if len(text) <= max {
		return text
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "…"
}

// Session is how the log shows a conversation: a short hash, so that its
// entries can be followed without its id.
func Session(id string) string {
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:4])
}

func verdict(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

// Authority logs the decisions of a local.Authority, on one path.
type Authority struct {
	local.Authority
	Log  *Log
	Path string
}

func (a Authority) Decide(ctx context.Context, session, tool, arguments string, reviews []json.RawMessage) (local.Verdict, error) {
	v, err := a.Authority.Decide(ctx, session, tool, arguments, reviews)
	a.record(session, tool, v, err)
	return v, err
}

func (a Authority) DecideHashed(ctx context.Context, session string, call local.Hashed) (local.Verdict, bool, error) {
	v, needs, err := a.Authority.DecideHashed(ctx, session, call)
	if !needs {
		a.record(session, call.Tool, v, err)
	}
	return v, needs, err
}

func (a Authority) record(session, tool string, v local.Verdict, err error) {
	entry := Entry{Path: a.Path, Session: Session(session), Tool: tool, Decision: verdict(v.Allowed), Reason: v.Message}
	if err != nil {
		entry.Decision, entry.Reason = "error", "no decision: "+err.Error()
	}
	a.Log.Record(entry)
}

// Egress logs the decisions of the egress proxy.
type Egress struct {
	egress.Authority
	Log *Log
}

func (a Egress) Decide(ctx context.Context, request egress.Request) (egress.Verdict, error) {
	v, err := a.Authority.Decide(ctx, request)
	entry := Entry{Path: "egress", Session: Session(request.Session), Host: request.Host, Decision: verdict(v.Allowed), Reason: v.Message}
	if v.Held {
		entry.Decision = "hold"
	}
	if request.Server != "" {
		entry.Tool = "mcp server " + request.Server
	}
	if err != nil {
		entry.Decision, entry.Reason = "error", "no decision: "+err.Error()
	}
	a.Log.Record(entry)
	return v, err
}

func (a Egress) Refused(request egress.Request, problem string) {
	a.Log.Record(Entry{Path: "egress", Session: Session(request.Session), Host: request.Host, Decision: "deny", Reason: problem})
	a.Authority.Refused(request, problem)
}

// Budgets logs the model calls a budget did not allow.
type Budgets struct {
	local.Budgets
	Log *Log
}

func (b Budgets) Check(ctx context.Context, session, model string) (local.Budget, error) {
	v, err := b.Budgets.Check(ctx, session, model)
	switch {
	case err != nil:
		b.Log.Record(Entry{Path: "budget", Session: Session(session), Tool: model, Decision: "error", Reason: "no answer: " + err.Error()})
	case !v.Allowed:
		b.Log.Record(Entry{Path: "budget", Session: Session(session), Tool: model, Decision: "hold", Reason: v.Message})
	}
	return v, err
}

func (b Budgets) Used(ctx context.Context, session, model string, usage turn.Usage) error {
	return b.Budgets.Used(ctx, session, model, usage)
}
