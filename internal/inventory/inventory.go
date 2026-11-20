// Package inventory lists what an admin may put in a role's machine
// catalogue: the machine's systemd services by name and state, and the names
// under /etc, each marked private when other users cannot read it. Never the
// content of a file. Nia shows it as suggestions; it decides nothing.
package inventory

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GetKlaros/nia-edge/internal/hostd"
)

// The bounds Nia reads a report within; past them it is truncated.
const (
	MaxServices = 1024
	MaxEtc      = 5000
	// MaxDepth counts the names under /etc: /etc/a/b/c is 3.
	MaxDepth = 4
	maxPath  = 1024
)

// Service is a systemd unit of type service.
type Service struct {
	Name   string `json:"name"`
	Active string `json:"active"`
	Sub    string `json:"sub"`
}

// Entry is a name under /etc.
type Entry struct {
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
	// Private: other users cannot read it.
	Private bool `json:"private"`
}

// Inventory is what goes to Nia.
type Inventory struct {
	ScannedAt time.Time `json:"scanned_at"`
	Services  []Service `json:"services"`
	Etc       []Entry   `json:"etc"`
	// Dirs are directories outside /etc a role's plans may change
	// (hostd.ClosedDir lets them), for the console to offer.
	Dirs      []string `json:"dirs"`
	Truncated bool     `json:"truncated"`
}

// MaxDirs bounds the directories listed.
const MaxDirs = 200

// dirRoots are where an admin keeps sites, apps and their data, and how deep
// their directories are listed.
var dirRoots = []struct {
	path  string
	depth int
}{{"/srv", 2}, {"/opt", 1}, {"/var/www", 2}, {"/var/lib", 1}}

// What Nia accepts; anything else is left out rather than sent and refused.
var (
	serviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._\\-]{0,127}$`)
	state       = regexp.MustCompile(`^[a-z-]{1,32}$`)
)

// Collect lists the services (with systemctl, a fixed program, when there is
// one) and the names under root's /etc. root is "" for this machine.
func Collect(ctx context.Context, root string) Inventory {
	out := Inventory{ScannedAt: time.Now().UTC().Truncate(time.Second), Services: []Service{}, Etc: []Entry{}, Dirs: []string{}}
	if root == "" {
		if raw, err := systemctl(ctx); err == nil {
			out.Services, out.Truncated = ParseUnits(raw)
		}
	}
	etc, truncated := Etc(filepath.Join(root, "/etc"))
	out.Etc = etc
	out.Truncated = out.Truncated || truncated
	dirs, truncated := Dirs(root)
	out.Dirs = dirs
	out.Truncated = out.Truncated || truncated
	return out
}

// Dirs lists, under root, the directories of dirRoots a plan may change:
// never through a symbolic link, never a closed one.
func Dirs(root string) ([]string, bool) {
	dirs := []string{}
	var walk func(p string, depth int) bool
	walk = func(p string, depth int) bool {
		info, err := os.Lstat(filepath.Join(root, p))
		if err != nil || !info.IsDir() {
			return true
		}
		if hostd.ClosedDir(p) == "" && readable(p) {
			if len(dirs) == MaxDirs {
				return false
			}
			dirs = append(dirs, p)
		}
		if depth == 0 {
			return true
		}
		entries, err := os.ReadDir(filepath.Join(root, p))
		if err != nil {
			return true
		}
		for _, entry := range entries {
			if entry.IsDir() && entry.Type()&fs.ModeSymlink == 0 && !strings.HasPrefix(entry.Name(), ".") {
				if !walk(p+"/"+entry.Name(), depth-1) {
					return false
				}
			}
		}
		return true
	}
	for _, r := range dirRoots {
		if !walk(r.path, r.depth) {
			return dirs, true
		}
	}
	return dirs, false
}

func systemctl(ctx context.Context) ([]byte, error) {
	program := ""
	for _, candidate := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			program = candidate
			break
		}
	}
	if program == "" {
		return nil, os.ErrNotExist
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "SYSTEMD_COLORS=0"}
	return command.Output()
}

// ParseUnits reads systemctl list-units --plain --no-legend: UNIT LOAD ACTIVE
// SUB DESCRIPTION. The description is left out.
func ParseUnits(raw []byte) ([]Service, bool) {
	services := []Service{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		if !serviceName.MatchString(fields[0]) || !state.MatchString(fields[2]) || !state.MatchString(fields[3]) {
			continue
		}
		if len(services) == MaxServices {
			return services, true
		}
		services = append(services, Service{Name: fields[0], Active: fields[2], Sub: fields[3]})
	}
	return services, false
}

// Etc lists the names under dir (an /etc), shown as under /etc, to MaxDepth.
// A symbolic link is listed, never followed.
func Etc(dir string) ([]Entry, bool) {
	entries := []Entry{}
	truncated := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A folder it cannot read is listed, not entered.
			if d != nil && d.IsDir() && path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if path == dir {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		shown := "/etc/" + filepath.ToSlash(relative)
		depth := strings.Count(relative, string(filepath.Separator)) + 1
		if !readable(shown) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if len(entries) == MaxEtc {
			truncated = true
			return fs.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		dirEntry := d.IsDir()
		entries = append(entries, Entry{Path: shown, Dir: dirEntry, Private: info.Mode().Type() != fs.ModeSymlink && info.Mode().Perm()&0o004 == 0})
		if dirEntry && depth >= MaxDepth {
			return fs.SkipDir
		}
		return nil
	})
	return entries, truncated
}

// readable is a name Nia reads as one: valid UTF-8, no control character,
// within the length it takes.
func readable(path string) bool {
	if len(path) > maxPath || !utf8.ValidString(path) {
		return false
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
