//go:build linux

package hostd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

type decoy struct {
	rel   string
	token string
	atime time.Time
	mode  fs.FileMode
	uid   uint32
	gid   uint32
}

func (s *Server) etcRoot() string {
	if s.EtcRoot != "" {
		return s.EtcRoot
	}
	return "/etc"
}

func (s *Server) scratchRoot() string {
	if s.ScratchRoot != "" {
		return s.ScratchRoot
	}
	return "/run/nia-hostd/dry"
}

// dryRun runs req.Script in the sandbox and keeps its plan for an apply.
// Called with s.mu held.
func (s *Server) dryRun(ctx context.Context, c *Catalogue, req Request) Response {
	if c.Etc == nil {
		return Response{Error: "this role's catalogue allows no dry run (no etc)"}
	}
	if s.Sandbox == nil {
		return Response{Error: "this nia-hostd has no sandbox for dry runs"}
	}
	if req.Script == "" || len(req.Script) > scriptLimit || !utf8.ValidString(req.Script) || strings.ContainsRune(req.Script, 0) {
		return Response{Error: fmt.Sprintf("a dry run takes a script of 1 to %d bytes of UTF-8 text", scriptLimit)}
	}
	s.expirePlans()
	if err := os.MkdirAll(s.scratchRoot(), 0o700); err != nil {
		return Response{Error: "no scratch directory: " + err.Error()}
	}
	scratch, err := os.MkdirTemp(s.scratchRoot(), "run-")
	if err != nil {
		return Response{Error: "no scratch directory: " + err.Error()}
	}
	cleanup, err := s.Sandbox.Prepare(scratch)
	if err != nil {
		os.RemoveAll(scratch)
		return Response{Error: "the sandbox cannot be prepared: " + err.Error()}
	}
	keep := false
	defer func() {
		if !keep {
			cleanup()
			os.RemoveAll(scratch)
		}
	}()
	upper, work := filepath.Join(scratch, "upper"), filepath.Join(scratch, "work")
	for _, dir := range []string{upper, work} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return Response{Error: "no layer: " + err.Error()}
		}
	}
	// The layer's root is /etc's, as the overlay shows it.
	if info, err := os.Stat(s.etcRoot()); err == nil {
		_ = os.Chmod(upper, info.Mode().Perm())
	}
	decoys, err := s.plantDecoys(c, upper)
	if err != nil {
		return Response{Error: "the secrets cannot be hidden, so nothing ran: " + err.Error()}
	}
	runCtx, cancel := context.WithTimeout(ctx, dryTimeout+30*time.Second)
	output, runErr := s.Sandbox.Run(runCtx, SandboxSpec{
		Root: filepath.Join(scratch, "root"), Etc: s.etcRoot(), Upper: upper, Work: work, Masked: masked,
		Script: req.Script, Timeout: dryTimeout, PathVariable: baseEnv[0],
	})
	cancel()
	report, err := s.readLayer(c, upper, decoys, output)
	if err != nil {
		return Response{Error: "the run's changes cannot be read, so there is no plan: " + err.Error(), Output: tail(output)}
	}
	if runErr != nil {
		report.Failed = runErr.Error()
	}
	report.Plan = planID(report)
	entry := Entry{ID: newID(), At: s.now().UTC(), Action: DryRunAction, Name: report.Plan, Call: req.Call, OK: runErr == nil}
	if runErr != nil {
		entry.Error = runErr.Error()
	}
	if err := s.write(entry); err != nil {
		return Response{Error: "the dry run could not be written to the journal: " + err.Error()}
	}
	if ok, _ := report.Applicable(); ok {
		keep = true
		if s.plans == nil {
			s.plans = map[string]*plan{}
		}
		s.plans[report.Plan] = &plan{report: report, scratch: scratch, cleanup: cleanup, made: s.now()}
		s.trimPlans()
	}
	s.log("dry run", "plan", report.Plan, "changes", len(report.Changes), "journal", entry.ID)
	text, _ := json.Marshal(report)
	return Response{OK: true, Output: string(text), Journal: entry.ID}
}

// plantDecoys puts a decoy in the layer over every file of /etc its other
// users cannot read, and over each secret the catalogue names: the script
// reads a token, never the secret.
func (s *Server) plantDecoys(c *Catalogue, upper string) ([]decoy, error) {
	root := s.etcRoot()
	wanted := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that cannot be read cannot be hidden from.
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o004 == 0 {
			rel, _ := filepath.Rel(root, p)
			wanted[rel] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range c.Etc.Secrets {
		rel := strings.TrimPrefix(strings.TrimPrefix(p, "/etc"), "/")
		if info, err := os.Lstat(filepath.Join(root, rel)); err == nil && info.Mode().IsRegular() {
			wanted[rel] = true
		}
	}
	if len(wanted) > decoyLimit {
		return nil, fmt.Errorf("%d secrets, more than %d", len(wanted), decoyLimit)
	}
	rels := make([]string, 0, len(wanted))
	for rel := range wanted {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	atime := time.Unix(1, 0)
	var decoys []decoy
	for _, rel := range rels {
		info, err := os.Lstat(filepath.Join(root, rel))
		if err != nil {
			return nil, err
		}
		st := info.Sys().(*syscall.Stat_t)
		if err := s.copyDirs(root, upper, filepath.Dir(rel)); err != nil {
			return nil, err
		}
		token := "nia-decoy-" + randomHex(16)
		target := filepath.Join(upper, rel)
		if err := os.WriteFile(target, []byte(token+"\n"), info.Mode().Perm()); err != nil {
			return nil, err
		}
		if err := os.Chmod(target, info.Mode().Perm()); err != nil {
			return nil, err
		}
		_ = os.Lchown(target, int(st.Uid), int(st.Gid))
		if err := os.Chtimes(target, atime, info.ModTime()); err != nil {
			return nil, err
		}
		decoys = append(decoys, decoy{rel: rel, token: token, atime: atime, mode: info.Mode().Perm(), uid: st.Uid, gid: st.Gid})
	}
	return decoys, nil
}

// copyDirs makes the layer's directories down to rel, as /etc has them.
func (s *Server) copyDirs(root, upper, rel string) error {
	if rel == "." || rel == "" {
		return nil
	}
	if err := s.copyDirs(root, upper, filepath.Dir(rel)); err != nil {
		return err
	}
	target := filepath.Join(upper, rel)
	if _, err := os.Lstat(target); err == nil {
		return nil
	}
	info, err := os.Lstat(filepath.Join(root, rel))
	if err != nil {
		return err
	}
	if err := os.Mkdir(target, info.Mode().Perm()); err != nil {
		return err
	}
	_ = os.Chmod(target, info.Mode().Perm())
	st := info.Sys().(*syscall.Stat_t)
	_ = os.Lchown(target, int(st.Uid), int(st.Gid))
	return nil
}

// readLayer turns the overlay's upper layer into the run's report.
func (s *Server) readLayer(c *Catalogue, upper string, decoys []decoy, output string) (Report, error) {
	root := s.etcRoot()
	report := Report{Changes: []Change{}, Guards: []Finding{}, Protected: []string{}, SecretsRead: []string{}, SecretsChanged: []string{}, SecretsCopied: []string{}}
	byRel := map[string]*decoy{}
	for i := range decoys {
		byRel[decoys[i].rel] = &decoys[i]
	}
	var tokens [][]byte
	for _, d := range decoys {
		tokens = append(tokens, []byte(d.token))
	}
	copied := map[string]bool{}
	seeTokens := func(content []byte) {
		for i, token := range tokens {
			if bytes.Contains(content, token) {
				copied[decoys[i].rel] = true
			}
		}
	}
	seeTokens([]byte(output))
	err := filepath.WalkDir(upper, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(upper, p)
		if rel == "." {
			return nil
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		etcPath := "/etc/" + filepath.ToSlash(rel)
		lowerPath := filepath.Join(root, rel)
		lower, lowerErr := os.Lstat(lowerPath)
		if lowerErr != nil && !errors.Is(lowerErr, fs.ErrNotExist) {
			return lowerErr
		}
		base, err := baseOf(lowerPath, lower)
		if err != nil {
			return err
		}
		// A whiteout: a character device 0/0, the path deleted.
		if info.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0 {
			if lower != nil {
				report.Changes = append(report.Changes, Change{Path: etcPath, Kind: "deleted", Base: base})
			}
			return nil
		}
		if info.Mode()&fs.ModeType&^(fs.ModeDir|fs.ModeSymlink) != 0 {
			return fmt.Errorf("%s: a device, pipe or socket cannot be applied", etcPath)
		}
		change := Change{Path: etcPath, Mode: uint32(info.Mode().Perm()) | specialBits(info.Mode()), UID: st.Uid, GID: st.Gid, Base: base}
		if dc, ok := byRel[rel]; ok {
			content, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if !bytes.Equal(content, []byte(dc.token+"\n")) || info.Mode().Perm() != dc.mode || st.Uid != dc.uid || st.Gid != dc.gid || !info.Mode().IsRegular() {
				report.SecretsChanged = append(report.SecretsChanged, etcPath)
			}
			if atime := time.Unix(st.Atim.Sec, st.Atim.Nsec); !atime.Equal(dc.atime) {
				report.SecretsRead = append(report.SecretsRead, etcPath)
			}
			return nil
		}
		switch {
		case info.IsDir():
			change.Type = "dir"
			opaque := make([]byte, 1)
			if n, err := syscall.Getxattr(p, "trusted.overlay.opaque", opaque); err == nil && n == 1 && opaque[0] == 'y' {
				change.Replaced = true
			}
		case info.Mode()&fs.ModeSymlink != 0:
			change.Type = "symlink"
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			change.Target = target
			seeTokens([]byte(target))
		default:
			change.Type = "file"
			content, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			seeTokens(content)
			sum := sha256.Sum256(content)
			change.SHA256 = hex.EncodeToString(sum[:])
			change.Size = int64(len(content))
		}
		switch {
		case lower == nil:
			change.Kind = "created"
		case change.Replaced:
			change.Kind = "modified"
		case lowerType(lower) != change.Type:
			change.Kind = "modified"
		case change.Type == "file" && "sha256:"+change.SHA256 != base,
			change.Type == "symlink" && "link:"+change.Target != base:
			change.Kind = "modified"
		default:
			lst := lower.Sys().(*syscall.Stat_t)
			if uint32(lower.Mode().Perm()) != change.Mode&0o777 || lst.Uid != st.Uid || lst.Gid != st.Gid || specialBits(lower.Mode()) != change.Mode&0o7000 {
				change.Kind = "metadata"
			} else {
				// Copied up and not changed: nothing to apply.
				return nil
			}
		}
		report.Changes = append(report.Changes, change)
		return nil
	})
	if err != nil {
		return report, err
	}
	for rel := range copied {
		report.SecretsCopied = append(report.SecretsCopied, "/etc/"+filepath.ToSlash(rel))
	}
	sort.Strings(report.SecretsCopied)
	if c.Etc != nil {
		for _, protected := range c.Etc.Protected {
			for _, change := range report.Changes {
				if change.Path == protected || strings.HasPrefix(change.Path, protected+"/") || strings.HasPrefix(protected, change.Path+"/") && (change.Replaced || change.Kind == "deleted") {
					report.Protected = append(report.Protected, protected)
					break
				}
			}
		}
	}
	if c.Etc != nil {
		report.Guards = judge(c.Etc.Permit, report.Changes, lowerView{root}, mergedView{lower: lowerView{root}, upper: upper})
	}
	report.Output = tail(output)
	return report, nil
}

func lowerType(info fs.FileInfo) string {
	switch {
	case info.IsDir():
		return "dir"
	case info.Mode()&fs.ModeSymlink != 0:
		return "symlink"
	case info.Mode().IsRegular():
		return "file"
	}
	return "other"
}

func specialBits(mode fs.FileMode) uint32 {
	var bits uint32
	if mode&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

// baseOf is what the machine holds at a path: "absent", "dir", the target of
// a symlink, or the SHA-256 of a file.
func baseOf(p string, info fs.FileInfo) (string, error) {
	switch {
	case info == nil:
		return "absent", nil
	case info.IsDir():
		return "dir", nil
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(p)
		return "link:" + target, err
	case info.Mode().IsRegular():
		file, err := os.Open(p)
		if err != nil {
			return "", err
		}
		defer file.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return "", err
		}
		return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
	}
	return "other", nil
}

// planID names a report by its changes: an apply names exactly these.
func planID(r Report) string {
	changes, _ := json.Marshal(r.Changes)
	sum := sha256.Sum256(changes)
	return hex.EncodeToString(sum[:16])
}

func (s *Server) expirePlans() {
	for id, p := range s.plans {
		if s.now().Sub(p.made) > planTTL {
			s.dropPlan(id)
		}
	}
}

func (s *Server) trimPlans() {
	for len(s.plans) > planLimit {
		oldest := ""
		for id, p := range s.plans {
			if oldest == "" || p.made.Before(s.plans[oldest].made) {
				oldest = id
			}
		}
		s.dropPlan(oldest)
	}
}

func (s *Server) dropPlan(id string) {
	if p, ok := s.plans[id]; ok {
		p.cleanup()
		os.RemoveAll(p.scratch)
		delete(s.plans, id)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// lowerView reads /etc as the machine holds it.
type lowerView struct{ root string }

func (v lowerView) path(p string) (string, bool) {
	if p != "/etc" && !strings.HasPrefix(p, "/etc/") {
		return "", false
	}
	return filepath.Join(v.root, strings.TrimPrefix(p, "/etc")), true
}

func (v lowerView) read(p string) ([]byte, bool) {
	real, ok := v.path(p)
	if !ok {
		return nil, false
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, false
	}
	data, err := os.ReadFile(real)
	return data, err == nil
}

func (v lowerView) list(dir string) []string {
	real, ok := v.path(dir)
	if !ok {
		return nil
	}
	entries, _ := os.ReadDir(real)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// mergedView reads /etc as it would be once the plan is applied: the upper
// layer over the machine's, whiteouts and opaque directories included.
type mergedView struct {
	lower lowerView
	upper string
}

// state says what the layer holds at p: "absent" (a whiteout, or under a
// deleted or opaque directory without an entry of its own), "upper" or
// "lower".
func (v mergedView) state(p string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(p, "/etc"), "/")
	parts := strings.Split(rel, "/")
	for i := range parts {
		prefix := filepath.Join(append([]string{v.upper}, parts[:i+1]...)...)
		info, err := os.Lstat(prefix)
		if err != nil {
			if i < len(parts)-1 {
				continue
			}
			return "lower"
		}
		st := info.Sys().(*syscall.Stat_t)
		if info.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0 {
			return "absent"
		}
		if i == len(parts)-1 {
			return "upper"
		}
		opaque := make([]byte, 1)
		if n, err := syscall.Getxattr(prefix, "trusted.overlay.opaque", opaque); err == nil && n == 1 && opaque[0] == 'y' {
			// Below an opaque directory, only the upper layer counts.
			if _, err := os.Lstat(filepath.Join(append([]string{v.upper}, parts...)...)); err != nil {
				return "absent"
			}
			return "upper"
		}
	}
	return "lower"
}

func (v mergedView) read(p string) ([]byte, bool) {
	if p != "/etc" && !strings.HasPrefix(p, "/etc/") {
		return nil, false
	}
	switch v.state(p) {
	case "absent":
		return nil, false
	case "upper":
		real := filepath.Join(v.upper, strings.TrimPrefix(p, "/etc"))
		info, err := os.Stat(real)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return nil, false
		}
		data, err := os.ReadFile(real)
		return data, err == nil
	}
	return v.lower.read(p)
}

func (v mergedView) list(dir string) []string {
	if v.state(dir) == "absent" {
		return nil
	}
	seen := map[string]bool{}
	for _, name := range v.lower.list(dir) {
		seen[name] = true
	}
	entries, _ := os.ReadDir(filepath.Join(v.upper, strings.TrimPrefix(dir, "/etc")))
	for _, e := range entries {
		seen[e.Name()] = true
	}
	var names []string
	for name := range seen {
		if v.state(path.Join(dir, name)) != "absent" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
