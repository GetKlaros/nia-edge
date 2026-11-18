// Package hostd is nia-hostd: the only part of nia-edge that runs as root,
// and the only way an agent acts on its machine outside its container.
//
// It does not run what an agent writes. It runs a few actions with fixed
// programs and fixed arguments, whose parameters are names taken from the
// role's catalogue: a service from a list, a package from a list, a sync pair
// by its name. What it runs is decided by the signed policy, which nia-hostd
// verifies itself against the key pinned at enrollment: nia-edge, which
// passes the requests, cannot widen it.
package hostd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
)

// Catalogue is what a role lets its agent do on the machine.
type Catalogue struct {
	// Services may be read, restarted and reloaded (systemd units).
	Services []string `json:"services"`
	// Packages may be installed from the machine's package sources.
	Packages []string `json:"packages"`
	// Sync names copies from one directory to another.
	Sync []SyncPair `json:"sync"`
}

// SyncPair copies Source into Destination (rsync -a), deleting what Source
// does not hold when Delete is set.
type SyncPair struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Delete      bool   `json:"delete"`
}

var (
	serviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$`)
	packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
	syncName    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// cleanDir reports whether p is an absolute, clean directory path other than
// the root.
func cleanDir(p string) bool {
	return len(p) > 1 && len(p) <= 4096 && path.IsAbs(p) && path.Clean(p) == p && !bytes.ContainsAny([]byte(p), "\x00\n\r")
}

// ParseCatalogue reads a role's `host` field. A catalogue with a field or a
// value this nia-edge does not know is refused whole; no field is no action.
func ParseCatalogue(raw json.RawMessage) (*Catalogue, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return &Catalogue{}, nil
	}
	var c Catalogue
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("hostd: the host catalogue cannot be read by this nia-edge: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("hostd: text after the host catalogue")
	}
	for _, name := range c.Services {
		if !serviceName.MatchString(name) {
			return nil, fmt.Errorf("hostd: %q is not a service name", name)
		}
	}
	for _, name := range c.Packages {
		if !packageName.MatchString(name) {
			return nil, fmt.Errorf("hostd: %q is not a package name", name)
		}
	}
	seen := map[string]bool{}
	for _, pair := range c.Sync {
		if !syncName.MatchString(pair.Name) || seen[pair.Name] {
			return nil, fmt.Errorf("hostd: sync pair %q has no name of its own", pair.Name)
		}
		seen[pair.Name] = true
		if !cleanDir(pair.Source) || !cleanDir(pair.Destination) || pair.Source == pair.Destination {
			return nil, fmt.Errorf("hostd: sync pair %q needs two distinct absolute directories", pair.Name)
		}
	}
	return &c, nil
}

// HasService reports whether name is one of the catalogue's services.
func (c *Catalogue) HasService(name string) bool { return slices.Contains(c.Services, name) }

// HasPackage reports whether name is one of the catalogue's packages.
func (c *Catalogue) HasPackage(name string) bool { return slices.Contains(c.Packages, name) }

// SyncPair returns the pair of that name, or nil.
func (c *Catalogue) SyncPair(name string) *SyncPair {
	for i := range c.Sync {
		if c.Sync[i].Name == name {
			return &c.Sync[i]
		}
	}
	return nil
}

// unit is the systemd unit of a service name: name.service unless it names
// its own type.
func unit(name string) string {
	for _, suffix := range []string{".service", ".socket", ".timer", ".target", ".path", ".mount"} {
		if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
			return name
		}
	}
	return name + ".service"
}
