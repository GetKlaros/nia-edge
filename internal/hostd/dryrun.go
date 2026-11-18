package hostd

import (
	"context"
	"slices"
	"time"
)

// DryRun is the action that runs an agent's script against a layer over
// /etc: the machine is not changed, and what comes back is the plan of the
// changes the script made.
const DryRunAction = "dry_run"

const (
	scriptLimit = 32 << 10
	// The layer of a dry run lives in memory, bounded: a script cannot fill
	// the machine's disk.
	layerBytes = 64 << 20
	// decoyLimit bounds the files a dry run sees as decoys.
	decoyLimit = 4096
	dryTimeout = 2 * time.Minute
	// Plans are kept for an apply, the newest few, for a while.
	planTTL   = 30 * time.Minute
	planLimit = 3
)

// The paths a dry run sees empty: homes, state and logs hold secrets and are
// not what a dry run changes.
var masked = []string{"/root", "/home", "/var", "/srv", "/opt", "/mnt", "/media", "/boot", "/tmp"}

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
	Root, Etc    string
	Upper, Work  string
	Masked       []string
	Script       string
	Timeout      time.Duration
	PathVariable string
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
	// SecretsRead are the decoys the script opened; SecretsChanged those it
	// changed; SecretsCopied those whose decoy text came out.
	SecretsRead    []string `json:"secrets_read"`
	SecretsChanged []string `json:"secrets_changed"`
	SecretsCopied  []string `json:"secrets_copied"`
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
	case len(r.SecretsChanged) > 0:
		return false, "it changes secrets, which a dry run only sees as decoys"
	case len(r.SecretsCopied) > 0:
		return false, "a secret's decoy came out of the run"
	case len(r.Changes) == 0:
		return false, "it changes nothing"
	}
	for _, c := range r.Changes {
		if c.Type == "file" && c.Mode&0o6000 != 0 {
			return false, c.Path + " would be setuid or setgid"
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
