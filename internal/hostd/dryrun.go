package hostd

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

// DryRun is the action that runs an agent's script against a layer over
// /etc: the machine is not changed, and what comes back is the plan of the
// changes the script made.
const DryRunAction = "dry_run"

// ApplyAction writes a dry run's plan to the machine's /etc, exactly as the
// run left its layer, then checks the configurations it touched and puts the
// former files back when a check fails.
const ApplyAction = "apply"

// PlanReviewAction answers what a reviewer must see of a kept plan: its
// changes exactly as their hash makes the plan id, and the texts before and
// after of the files it writes. It runs nothing and is not journaled.
const PlanReviewAction = "plan_review"

// RestoreAction puts back what an apply changed, from its backup.
const RestoreAction = "restore"

const (
	scriptLimit = 32 << 10
	// The layer of a dry run lives in memory, bounded: a script cannot fill
	// the machine's disk.
	layerBytes = 64 << 20
	// layerInodes bounds the files of a layer: a script cannot make the
	// walk of its changes as long as it likes.
	layerInodes = 32768
	// A plan changes at most planChanges paths and writes planBytes.
	planChanges = 1000
	planBytes   = 8 << 20
	// decoyLimit bounds the files a dry run sees as decoys.
	decoyLimit = 4096
	dryTimeout = 2 * time.Minute
	// Plans are kept for an apply, the newest few, for a while.
	planTTL   = 30 * time.Minute
	planLimit = 3
)

// visible are the top-level entries of the machine's root a dry run sees:
// the programs and their libraries, and /etc. Every other directory is an
// empty tmpfs there, and every other file /dev/null, whatever its name:
// homes, state, logs, backups, swap files and any directory an admin made
// hold what root can read and a dry run must not. podman mounts its own
// /proc, /sys, /dev and /run.
var visible = map[string]bool{"bin": true, "sbin": true, "lib": true, "lib32": true, "lib64": true, "libx32": true, "usr": true, "etc": true, "proc": true, "sys": true, "dev": true, "run": true}

// masks lists what a dry run must not see of the root: the directories,
// and the other entries (files, sockets) apart; symbolic links resolve
// inside the container, to what it shows.
func masks(root string) (dirs, files []string, err error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		if visible[e.Name()] || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, "/"+e.Name())
		} else {
			files = append(files, "/"+e.Name())
		}
	}
	if !slices.Contains(dirs, "/tmp") {
		dirs = append(dirs, "/tmp")
	}
	return dirs, files, nil
}

// Sandbox runs a script in a container whose /etc is an overlay with the
// given upper and work directories.
type Sandbox interface {
	// Prepare readies scratch, an empty directory, for one dry run, and
	// returns what undoes it.
	Prepare(scratch string) (cleanup func(), err error)
	Run(ctx context.Context, spec SandboxSpec) (output string, err error)
}

// SandboxSpec is one dry run.
type SandboxSpec struct {
	// Root is the machine's root, read only; Etc the /etc it layers over.
	Root, Etc   string
	Upper, Work string
	// Masked are directories seen as empty tmpfs, MaskedFiles files seen as
	// /dev/null.
	Masked, MaskedFiles []string
	Script              string
	Timeout             time.Duration
	PathVariable        string
}

// Change is one path a dry run changed.
type Change struct {
	Path string `json:"path"`
	// Kind is created, modified, deleted or metadata (owner or mode only).
	Kind string `json:"kind"`
	// Type is file, dir or symlink, of what the path is after the run.
	Type string `json:"type,omitempty"`
	Mode uint32 `json:"mode,omitempty"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Size int64  `json:"size,omitempty"`
	// SHA256 is the content's after the run; Target a symlink's.
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
	// Base is the SHA-256 of what the machine held when the run ended, or
	// "absent" or "dir": an apply refuses a path that has moved since.
	Base string `json:"base"`
	// Replaced marks a directory whose former entries are all gone.
	Replaced bool `json:"replaced,omitempty"`
}

// Report is what a dry run found.
type Report struct {
	Plan    string   `json:"plan"`
	Changes []Change `json:"changes"`
	// Protected lists the protected paths the run changed: none, or the
	// plan cannot be applied.
	Protected []string `json:"protected_changed"`
	// Guards are what the guards refuse in the state the plan leaves.
	Guards []Finding `json:"guards"`
	// SecretsRead are the decoys the script opened; SecretsChanged those it
	// changed; SecretsCopied those whose decoy text came out.
	SecretsRead    []string `json:"secrets_read"`
	SecretsChanged []string `json:"secrets_changed"`
	SecretsCopied  []string `json:"secrets_copied"`
	// TooMany is the number of changes when there are more than a plan
	// holds; Changes then lists the first ones.
	TooMany int `json:"too_many,omitempty"`
	// Failed is the script's error, if it did not exit 0.
	Failed string `json:"failed,omitempty"`
	Output string `json:"output,omitempty"`
}

// Applicable reports whether the plan may be applied, and why not.
func (r *Report) Applicable() (bool, string) {
	switch {
	case r.Failed != "":
		return false, "the script failed"
	case len(r.Protected) > 0:
		return false, "it changes protected paths"
	case len(r.Guards) > 0:
		return false, "a guard refuses it: " + r.Guards[0].Detail
	case len(r.SecretsChanged) > 0:
		return false, "it changes secrets, which a dry run only sees as decoys"
	case len(r.SecretsCopied) > 0:
		return false, "a secret's decoy came out of the run"
	case r.TooMany > 0:
		return false, fmt.Sprintf("it makes %d changes, more than %d", r.TooMany, planChanges)
	case len(r.Changes) == 0:
		return false, "it changes nothing"
	}
	written := int64(0)
	for _, c := range r.Changes {
		written += c.Size
	}
	if written > planBytes {
		return false, fmt.Sprintf("it writes %d bytes, more than %d: /etc holds configuration", written, planBytes)
	}
	for _, c := range r.Changes {
		if c.Type == "file" && c.Mode&0o6000 != 0 {
			return false, c.Path + " would be setuid or setgid"
		}
		if c.Kind != "deleted" && c.Type != "symlink" && c.Mode&0o002 != 0 {
			return false, c.Path + " would be writable by every user, the agent's included"
		}
		if c.Type == "symlink" && c.Kind != "deleted" && !linkStaysIn(c.Path, c.Target) {
			return false, c.Path + " would point to " + c.Target + ", outside the system's trees: whoever writes there would write the configuration"
		}
		if c.Replaced {
			return false, c.Path + " was replaced whole: change its files instead"
		}
	}
	return true, ""
}

type plan struct {
	report  Report
	scratch string
	cleanup func()
	made    time.Time
}

// Plans lists the plans kept for an apply, newest first.
func (s *Server) Plans() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.plans))
	for id := range s.plans {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b string) int { return s.plans[b].made.Compare(s.plans[a].made) })
	return ids
}

// linkTrees are where a symbolic link of /etc may point: trees only root
// writes, and the few run-time files the system links to.
var linkTrees = []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/dev/null", "/run/systemd", "/proc/self/mounts"}

// linkStaysIn reports whether a link at p to target points into linkTrees,
// read as the kernel would from p's directory, without following others.
func linkStaysIn(p, target string) bool {
	if target == "" || strings.ContainsRune(target, 0) {
		return false
	}
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(p), target)
	}
	target = path.Clean(target)
	for _, tree := range linkTrees {
		if target == tree || strings.HasPrefix(target, tree+"/") {
			return true
		}
	}
	return false
}
