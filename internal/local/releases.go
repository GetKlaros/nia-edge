package local

import (
	"strings"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/canon"
	"github.com/GetKlaros/nia-edge/internal/engine"
)

// Releases are the calls the model path released, for a tool that runs on
// this machine (the host actions): such a tool runs a call only against an
// unused release of the same tool and canonical arguments, once.
type Releases struct {
	// Prefix names the tools whose calls are kept, as the agent names them
	// (Hermes: mcp__<server>__<tool>).
	Prefix string
	// TTL is how long a release waits for its call; zero means ten minutes.
	TTL time.Duration

	mu    sync.Mutex
	items map[string][]heldRelease
}

// heldRelease is one released call: until when it may run, and the session the
// model path decided it in.
type heldRelease struct {
	until   time.Time
	session string
}

func (r *Releases) ttl() time.Duration {
	if r.TTL > 0 {
		return r.TTL
	}
	return 10 * time.Minute
}

// Release keeps a release of the call tool(arguments), in no known session.
func (r *Releases) Release(tool, arguments string, now time.Time) {
	r.ReleaseIn("", tool, arguments, now)
}

// ReleaseIn keeps a release of the call tool(arguments) decided in a session.
func (r *Releases) ReleaseIn(session, tool, arguments string, now time.Time) {
	if hash, err := canon.ArgumentsHash(tool, arguments); err == nil {
		r.add(hash, session, now)
	}
}

// add keeps a release of one call.
func (r *Releases) add(hash, session string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.items == nil || len(r.items) > 10_000 {
		r.items = map[string][]heldRelease{}
	}
	r.items[hash] = append(r.items[hash], heldRelease{until: now.Add(r.ttl()), session: session})
}

// Take spends one release of the call tool(arguments), if there is one.
func (r *Releases) Take(tool, arguments string, now time.Time) bool {
	_, ok := r.TakeSession(tool, arguments, now)
	return ok
}

// TakeSession spends one release of the call tool(arguments), if there is
// one, and names the session it was decided in ("" when unknown).
func (r *Releases) TakeSession(tool, arguments string, now time.Time) (string, bool) {
	hash, err := canon.ArgumentsHash(tool, arguments)
	if err != nil {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.items[hash]) > 0 {
		item := r.items[hash][0]
		r.items[hash] = r.items[hash][1:]
		if now.Before(item.until) {
			return item.session, true
		}
	}
	delete(r.items, hash)
	return "", false
}

// record keeps the released calls of a turn that are host actions, inner
// calls of a dispatcher included.
func (r *Releases) record(session string, calls []released, dispatchers engine.Dispatchers, now time.Time) {
	if r == nil || r.Prefix == "" {
		return
	}
	for _, call := range calls {
		units := []engine.Call{{Name: call.name, Arguments: call.arguments}}
		if inner, dispatcher, err := dispatchers.Expand(units[0]); err == nil && dispatcher {
			units = inner
		}
		for _, unit := range units {
			if !strings.HasPrefix(unit.Name, r.Prefix) {
				continue
			}
			r.ReleaseIn(session, unit.Name, unit.Arguments, now)
		}
	}
}

type released struct{ name, arguments string }
