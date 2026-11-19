// Package simulate runs an agent's shell command against a layer over its
// user's files, then applies what the command did, as it did it, once Nia
// allowed that effect. The command does not run twice: what was judged is
// what happens.
//
// The command runs in new user, mount, PID, network, IPC and UTS
// namespaces: the user's home (and the working directory, when it is the
// user's and outside it) is an overlay whose upper layer is a scratch
// directory; every other directory of the machine is read only; /tmp,
// /var/tmp, /run and /dev/shm are empty and private; there is no network,
// and no process outside the sandbox can be seen or signalled. When the
// command ends or its time is up, every process it started is killed.
//
// What leaves the sandbox is its output and the layer. The effect judged is
// the number of files deleted and every path changed: a deleted or replaced
// directory counts once, with every file it held deleted; a new directory
// counts once.
package simulate

import (
	"errors"
	"time"
)

// ErrUnsupported is returned where commands cannot be simulated: the caller
// refuses the command, it never runs it without a simulation.
var ErrUnsupported = errors.New("commands cannot be simulated on this machine")

// ErrChanged is returned when the machine no longer holds what the
// simulation saw: nothing is applied.
var ErrChanged = errors.New("the files changed since the simulation: nothing was applied")

// ChildCommand is the hidden command that starts the sandbox's first
// process (nia-edge's own binary, run again).
const ChildCommand = "__simulate-child"

// MaxOutput bounds what is kept of each of the command's outputs.
const MaxOutput = 1 << 20

// MaxPaths bounds the paths of one effect, as the server does.
const MaxPaths = 2000

// Options is one command to simulate.
type Options struct {
	Command string
	// Dir is the working directory; Home the user's home.
	Dir, Home string
	Timeout   time.Duration
	// Env is the command's environment.
	Env []string
}

// Effect is what the command did, as Nia judges it.
type Effect struct {
	Deleted int64    `json:"deleted"`
	Paths   []string `json:"paths"`
}

// Result is a simulated command: its outputs, its exit status and its
// effect. Apply writes the effect; Close forgets it.
type Result struct {
	Stdout, Stderr []byte
	// Truncated is set when an output was longer than MaxOutput.
	Truncated bool
	ExitCode  int
	Effect    Effect
	layer     *layer
}
