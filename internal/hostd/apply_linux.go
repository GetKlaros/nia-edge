//go:build linux

package hostd

import (
	"bytes"
	"context"
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
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// backupLimit bounds what an apply saves before it writes.
const backupLimit = 64 << 20

// saved is one path as it was before an apply.
type saved struct {
	Rel    string `json:"rel"`
	Type   string `json:"type"` // absent, file, dir, symlink
	Mode   uint32 `json:"mode,omitempty"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Target string `json:"target,omitempty"`
	Blob   string `json:"blob,omitempty"`
}

// backup is what an apply saved, and what it wrote: a restore puts back the
// first only where the machine still holds the second. Saved and After are
// /etc's in a backup made before nia-edge 0.8; Trees holds every tree since.
type backup struct {
	Saved []saved `json:"saved,omitempty"`
	// After is the base of each changed path once applied.
	After map[string]string `json:"after,omitempty"`
	Trees []treeBackup      `json:"trees,omitempty"`
}

// treeBackup is what an apply saved and wrote in one tree.
type treeBackup struct {
	Mount string            `json:"mount"`
	Saved []saved           `json:"saved"`
	After map[string]string `json:"after"`
}

// The checks an apply runs on what it changed: fixed programs, run only
// when installed. A failed check puts the former files back.
var checks = []struct {
	prefixes []string
	argv     []string
}{
	{[]string{"/etc/sudoers", "/etc/sudoers.d"}, []string{"visudo", "-c"}},
	{[]string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"}, []string{"sshd", "-t"}},
	{[]string{"/etc/nginx"}, []string{"nginx", "-t"}},
	{[]string{"/etc/apache2"}, []string{"apache2ctl", "configtest"}},
	{[]string{"/etc/haproxy"}, []string{"haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"}},
	{[]string{"/etc/fstab"}, []string{"findmnt", "--verify", "--tab-file", "/etc/fstab"}},
	{[]string{"/etc/passwd", "/etc/group"}, []string{"pwck", "-r"}},
	{[]string{"/etc/group"}, []string{"grpck", "-r"}},
}

func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/") || strings.HasPrefix(path, prefix+".")
}

func (s *Server) backupRoot() string {
	if s.BackupRoot != "" {
		return s.BackupRoot
	}
	return "/var/lib/nia-hostd/backups"
}

func (s *Server) installed(program string) bool {
	if s.Installed != nil {
		return s.Installed(program)
	}
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if info, err := os.Stat(filepath.Join(dir, program)); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

// opened is one tree of a plan, open for an apply or a restore.
type opened struct {
	tree    tree
	root    *os.Root
	changes []Change
	saved   *backup
	dir     string
}

// openTrees opens the trees a list of changes touches, each change in the
// one that holds it. A catalogue directory is checked again: it must still
// be reached without a symbolic link.
func (s *Server) openTrees(trees []tree, changes []Change) ([]*opened, error) {
	var out []*opened
	byMount := map[string]*opened{}
	fail := func(err error) ([]*opened, error) {
		for _, o := range out {
			o.root.Close()
		}
		return nil, err
	}
	for _, c := range changes {
		t, _, ok := treeOf(trees, c.Path)
		if !ok {
			return fail(fmt.Errorf("%s is in no directory this plan may change", c.Path))
		}
		o := byMount[t.Mount]
		if o == nil {
			lower := t.Lower
			if t.Mount != "/etc" {
				checked, err := s.openDir(t.Mount)
				if err != nil {
					return fail(err)
				}
				lower = checked
			}
			root, err := os.OpenRoot(lower)
			if err != nil {
				return fail(err)
			}
			o = &opened{tree: tree{Mount: t.Mount, Lower: lower, Upper: t.Upper, Work: t.Work}, root: root}
			byMount[t.Mount] = o
			out = append(out, o)
		}
		o.changes = append(o.changes, c)
	}
	return out, nil
}

// relIn is p relative to the tree mounted at mount.
func relIn(mount, p string) string {
	if p == mount {
		return "."
	}
	return strings.TrimPrefix(p, mount+"/")
}

// apply writes plan id, tree by tree. Called with s.mu held.
func (s *Server) apply(ctx context.Context, catalogue *Catalogue, req Request) Response {
	s.expirePlans()
	p, ok := s.plans[req.Name]
	if !ok {
		return Response{Error: "no plan " + req.Name + " is kept: plans live half an hour, the last three, until applied; run the dry run again"}
	}
	if ok, why := p.report.Applicable(); !ok {
		return Response{Error: "this plan cannot be applied: " + why}
	}
	trees, err := s.openTrees(p.trees, p.report.Changes)
	if err != nil {
		return Response{Error: err.Error()}
	}
	defer func() {
		for _, o := range trees {
			o.root.Close()
		}
	}()
	// The machine must hold what the run saw, and the layer what it reported.
	for _, o := range trees {
		for _, c := range o.changes {
			name := relIn(o.tree.Mount, c.Path)
			base, err := baseIn(o.root, name)
			if err != nil {
				return Response{Error: c.Path + ": " + err.Error()}
			}
			if base != c.Base {
				return Response{Error: c.Path + " changed on the machine since the dry run: run it again"}
			}
			if c.Type == "file" && c.Kind != "metadata" {
				data, err := os.ReadFile(filepath.Join(o.tree.Upper, name))
				sum := sha256.Sum256(data)
				if err != nil || hex.EncodeToString(sum[:]) != c.SHA256 {
					return Response{Error: c.Path + ": the plan's layer does not hold what it reported"}
				}
			}
		}
	}
	// What works before the change must work after it.
	before := s.baseline(ctx, catalogue)
	id := newID()
	dir := filepath.Join(s.backupRoot(), id)
	for i, o := range trees {
		o.dir = filepath.Join(dir, fmt.Sprintf("tree%d", i))
		b, err := s.save(o.root, o.tree.Mount, o.changes, o.dir)
		if err != nil {
			os.RemoveAll(dir)
			return Response{Error: "the former files cannot be saved, so nothing was written: " + err.Error()}
		}
		o.saved = b
	}
	entry := Entry{ID: id, At: s.now().UTC(), Action: ApplyAction, Name: req.Name, Call: req.Call}
	var output strings.Builder
	failure := ""
	written := 0
	for _, o := range trees {
		written++
		if err := write(o.root, o.tree.Mount, o.tree.Upper, o.changes); err != nil {
			failure = "writing: " + err.Error()
			break
		}
		for _, c := range o.changes {
			o.saved.After[c.Path], _ = baseIn(o.root, relIn(o.tree.Mount, c.Path))
		}
	}
	if failure == "" {
		failure = s.check(ctx, p.report.Changes, &output)
	}
	reloaded := []string(nil)
	if failure == "" {
		// A service whose configuration changed takes it now, so the health
		// checks see what the change did.
		reloaded = s.reloadTouched(ctx, catalogue, p.report.Changes, before, &output)
		if names := s.healthy(ctx, before); names != nil {
			failure = unhealthy(names).Error()
		}
	}
	if failure != "" {
		var errs []string
		for _, o := range trees[:written] {
			if err := restore(o.root, o.tree.Mount, o.dir, o.saved.Saved); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// The services that took the change take the former files back.
		for _, name := range reloaded {
			s.reload(ctx, name, &output)
		}
		if len(errs) > 0 {
			entry.Error = failure + "; putting the former files back failed: " + strings.Join(errs, "; ") + " (backup " + dir + ")"
		} else {
			entry.Error = failure + "; the former files are back"
		}
	} else {
		manifest := backup{}
		for _, o := range trees {
			manifest.Trees = append(manifest.Trees, treeBackup{Mount: o.tree.Mount, Saved: o.saved.Saved, After: o.saved.After})
		}
		raw, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
			entry.Error = "applied, but its backup cannot be kept: " + err.Error()
		} else {
			entry.Undo = &Request{Action: RestoreAction, Name: id}
		}
	}
	entry.OK = failure == ""
	if entry.OK {
		entry.Reloaded = reloaded
	}
	s.dropPlan(req.Name)
	if err := s.write(entry); err != nil {
		return Response{Error: "the apply could not be written to the journal: " + err.Error(), Output: tail(output.String())}
	}
	s.log("apply", "plan", req.Name, "ok", entry.OK, "journal", entry.ID)
	return Response{OK: entry.OK, Output: tail(output.String()), Error: entry.Error, Journal: entry.ID}
}

// configOf names the services that read a tree of /etc: a change there is
// taken by reloading them.
var configOf = map[string][]string{
	"/etc/nginx":   {"nginx"},
	"/etc/apache2": {"apache2"},
	"/etc/haproxy": {"haproxy"},
}

// reloadTouched reloads the catalogue's services, active before the change,
// whose configuration it changed, and returns those it reloaded.
func (s *Server) reloadTouched(ctx context.Context, c *Catalogue, changes []Change, before []probe, output *strings.Builder) []string {
	var reloaded []string
	for prefix, names := range configOf {
		touched := false
		for _, change := range changes {
			if under(change.Path, prefix) {
				touched = true
			}
		}
		if !touched {
			continue
		}
		for _, name := range names {
			if !c.HasService(name) || !slices.ContainsFunc(before, func(p probe) bool { return p.unit == unit(name) }) {
				continue
			}
			s.reload(ctx, name, output)
			reloaded = append(reloaded, name)
		}
	}
	slices.Sort(reloaded)
	return reloaded
}

// check runs the checks of the paths changed.
func (s *Server) check(ctx context.Context, changes []Change, output *strings.Builder) string {
	for _, c := range checks {
		touched := false
		for _, change := range changes {
			for _, prefix := range c.prefixes {
				if under(change.Path, prefix) {
					touched = true
				}
			}
		}
		if !touched || !s.installed(c.argv[0]) {
			continue
		}
		runCtx, cancel := context.WithTimeout(ctx, time.Minute)
		out, err := s.Run.Run(runCtx, baseEnv, c.argv...)
		cancel()
		fmt.Fprintf(output, "$ %s\n%s", strings.Join(c.argv, " "), out)
		if err != nil {
			return strings.Join(c.argv, " ") + " failed: " + err.Error()
		}
	}
	return ""
}

// baseIn is baseOf, within root.
func baseIn(root *os.Root, name string) (string, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", err
	}
	switch {
	case info.IsDir():
		return "dir", nil
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := root.Readlink(name)
		return "link:" + target, err
	case info.Mode().IsRegular():
		file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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

// save keeps every path the plan changes as it is, a deleted directory with
// all it holds, in dir.
func (s *Server) save(root *os.Root, mount string, changes []Change, dir string) (*backup, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := &backup{After: map[string]string{}}
	total := int64(0)
	var keep func(name string) error
	keep = func(name string) error {
		info, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			b.Saved = append(b.Saved, saved{Rel: name, Type: "absent"})
			return nil
		}
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		one := saved{Rel: name, Mode: uint32(info.Mode().Perm()) | specialBits(info.Mode()), UID: int(st.Uid), GID: int(st.Gid)}
		switch {
		case info.IsDir():
			one.Type = "dir"
			b.Saved = append(b.Saved, one)
			entries, err := fs.ReadDir(root.FS(), name)
			if err != nil {
				return err
			}
			for _, e := range entries {
				if err := keep(filepath.Join(name, e.Name())); err != nil {
					return err
				}
			}
			return nil
		case info.Mode()&fs.ModeSymlink != 0:
			one.Type = "symlink"
			one.Target, err = root.Readlink(name)
			if err != nil {
				return err
			}
		case info.Mode().IsRegular():
			one.Type = "file"
			total += info.Size()
			if total > backupLimit {
				return fmt.Errorf("more than %d bytes to save", backupLimit)
			}
			data, err := root.ReadFile(name)
			if err != nil {
				return err
			}
			one.Blob = fmt.Sprintf("%d", len(b.Saved))
			if err := os.WriteFile(filepath.Join(dir, one.Blob), data, 0o600); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s is neither a file, a directory nor a symlink", path.Join(mount, name))
		}
		b.Saved = append(b.Saved, one)
		return nil
	}
	for _, c := range changes {
		name := relIn(mount, c.Path)
		if c.Kind == "deleted" || c.Kind == "modified" && c.Type != "dir" {
			if err := keep(name); err != nil {
				return nil, err
			}
			continue
		}
		// A created path, or a directory or a mode changed: only itself.
		info, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			b.Saved = append(b.Saved, saved{Rel: name, Type: "absent"})
			continue
		}
		if err != nil {
			return nil, err
		}
		st := info.Sys().(*syscall.Stat_t)
		one := saved{Rel: name, Type: lowerType(info), Mode: uint32(info.Mode().Perm()) | specialBits(info.Mode()), UID: int(st.Uid), GID: int(st.Gid)}
		if one.Type == "file" {
			// A file whose owner or mode alone changes.
			if err := keep(name); err != nil {
				return nil, err
			}
			continue
		}
		if one.Type == "symlink" {
			one.Target, _ = root.Readlink(name)
		}
		b.Saved = append(b.Saved, one)
	}
	return b, nil
}

// write applies the changes: directories first, then files and links, then
// owners and modes, then deletions, deepest first.
func write(root *os.Root, mount, upper string, changes []Change) error {
	ordered := append([]Change{}, changes...)
	rank := func(c Change) int {
		switch {
		case c.Kind == "deleted":
			return 3
		case c.Kind == "metadata":
			return 2
		case c.Type == "dir":
			return 0
		}
		return 1
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, rj := rank(ordered[i]), rank(ordered[j])
		if ri != rj {
			return ri < rj
		}
		if ri == 3 {
			return ordered[i].Path > ordered[j].Path
		}
		return ordered[i].Path < ordered[j].Path
	})
	for _, c := range ordered {
		name := relIn(mount, c.Path)
		var err error
		switch {
		case c.Kind == "deleted":
			err = root.RemoveAll(name)
		case c.Kind == "metadata":
			err = setOwnerMode(root, name, c)
		case c.Type == "dir":
			err = putDir(root, name, c)
		case c.Type == "symlink":
			err = putSymlink(root, name, c)
		default:
			var data []byte
			data, err = os.ReadFile(filepath.Join(upper, name))
			if err == nil {
				err = putFile(root, name, data, c.Mode, c.UID, c.GID)
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %w", c.Path, err)
		}
	}
	return nil
}

func setOwnerMode(root *os.Root, name string, c Change) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return root.Lchown(name, int(c.UID), int(c.GID))
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chown(int(c.UID), int(c.GID)); err != nil {
		return err
	}
	return file.Chmod(fileMode(c.Mode))
}

func putDir(root *os.Root, name string, c Change) error {
	info, err := root.Lstat(name)
	if err == nil && !info.IsDir() {
		if err := root.Remove(name); err != nil {
			return err
		}
		err = fs.ErrNotExist
	}
	if errors.Is(err, fs.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return setOwnerMode(root, name, c)
}

func putSymlink(root *os.Root, name string, c Change) error {
	tmp := filepath.Join(filepath.Dir(name), ".nia-"+randomHex(8))
	if err := root.Symlink(c.Target, tmp); err != nil {
		return err
	}
	if err := root.Lchown(tmp, int(c.UID), int(c.GID)); err != nil {
		root.Remove(tmp)
		return err
	}
	if info, err := root.Lstat(name); err == nil && info.IsDir() {
		if err := root.RemoveAll(name); err != nil {
			root.Remove(tmp)
			return err
		}
	}
	if err := root.Rename(tmp, name); err != nil {
		root.Remove(tmp)
		return err
	}
	return nil
}

// putFile writes a file beside name, gives it its owner and mode through its
// own descriptor, and renames it over name.
func putFile(root *os.Root, name string, data []byte, mode uint32, uid, gid uint32) error {
	tmp := filepath.Join(filepath.Dir(name), ".nia-"+randomHex(8))
	file, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		file.Close()
		root.Remove(tmp)
		return err
	}
	if _, err := file.Write(data); err != nil {
		return fail(err)
	}
	if err := file.Chown(int(uid), int(gid)); err != nil {
		return fail(err)
	}
	if err := file.Chmod(fileMode(mode)); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		root.Remove(tmp)
		return err
	}
	if info, err := root.Lstat(name); err == nil && info.IsDir() {
		if err := root.RemoveAll(name); err != nil {
			root.Remove(tmp)
			return err
		}
	}
	if err := root.Rename(tmp, name); err != nil {
		root.Remove(tmp)
		return err
	}
	return nil
}

func fileMode(mode uint32) fs.FileMode {
	m := fs.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		m |= fs.ModeSetuid
	}
	if mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	if mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// restore puts the saved paths back, the last changed first.
func restore(root *os.Root, mount, dir string, list []saved) error {
	var errs []error
	// Created paths first go away, deepest first; then what existed comes
	// back, shallowest first.
	absent := []string{}
	for _, one := range list {
		if one.Type == "absent" {
			absent = append(absent, one.Rel)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(absent)))
	for _, name := range absent {
		if err := root.RemoveAll(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	present := append([]saved{}, list...)
	sort.SliceStable(present, func(i, j int) bool { return present[i].Rel < present[j].Rel })
	for _, one := range present {
		c := Change{Mode: one.Mode, UID: uint32(one.UID), GID: uint32(one.GID), Target: one.Target}
		var err error
		switch one.Type {
		case "absent":
			continue
		case "dir":
			err = putDir(root, one.Rel, c)
		case "symlink":
			err = putSymlink(root, one.Rel, c)
		case "file":
			var data []byte
			data, err = os.ReadFile(filepath.Join(dir, one.Blob))
			if err == nil {
				err = putFile(root, one.Rel, data, one.Mode, uint32(one.UID), uint32(one.GID))
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path.Join(mount, one.Rel), err))
		}
	}
	return errors.Join(errs...)
}

// restoreEntry undoes an apply from its backup, when the machine still holds
// what the apply wrote. Called with s.mu held.
func (s *Server) restoreEntry(target Entry) Entry {
	entry := Entry{ID: newID(), At: s.now().UTC(), Action: RestoreAction, Name: target.Undo.Name, Of: target.ID}
	dir := filepath.Join(s.backupRoot(), filepath.Base(target.Undo.Name))
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var b backup
	if err == nil {
		err = json.Unmarshal(raw, &b)
	}
	if err != nil {
		entry.Error = "the backup cannot be read: " + fmt.Sprint(err)
		return entry
	}
	trees := b.Trees
	if len(trees) == 0 {
		// A backup from before nia-edge 0.8: /etc's alone.
		trees = []treeBackup{{Mount: "/etc", Saved: b.Saved, After: b.After}}
	}
	type restoring struct {
		tree treeBackup
		root *os.Root
		dir  string
	}
	var open []restoring
	defer func() {
		for _, r := range open {
			r.root.Close()
		}
	}()
	for i, t := range trees {
		lower := s.etcRoot()
		if t.Mount != "/etc" {
			if why := ClosedDir(t.Mount); why != "" {
				entry.Error = t.Mount + ": " + why
				return entry
			}
			checked, err := s.openDir(t.Mount)
			if err != nil {
				entry.Error = err.Error()
				return entry
			}
			lower = checked
		}
		root, err := os.OpenRoot(lower)
		if err != nil {
			entry.Error = err.Error()
			return entry
		}
		treeDir := dir
		if len(b.Trees) > 0 {
			treeDir = filepath.Join(dir, fmt.Sprintf("tree%d", i))
		}
		open = append(open, restoring{tree: t, root: root, dir: treeDir})
	}
	// Nothing is put back unless every tree still holds what the apply wrote.
	for _, r := range open {
		for p, after := range r.tree.After {
			now, err := baseIn(r.root, relIn(r.tree.Mount, p))
			if err != nil || now != after {
				entry.Error = p + " changed since the apply: nothing was put back"
				return entry
			}
		}
	}
	var errs []string
	for _, r := range open {
		if err := restore(r.root, r.tree.Mount, r.dir, r.tree.Saved); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		entry.Error = strings.Join(errs, "; ")
		return entry
	}
	entry.OK = true
	return entry
}

// Review is what nia-hostd shows of a plan: Changes is the exact text whose
// SHA-256 makes the plan id; Files hold the texts small enough to show.
type Review struct {
	Plan    string       `json:"plan"`
	Changes string       `json:"changes"`
	Files   []ReviewFile `json:"files"`
}

// ReviewFile is one file's text before and after, each when it is UTF-8 text
// of at most 64 KiB.
type ReviewFile struct {
	Path   string  `json:"path"`
	Before *string `json:"before,omitempty"`
	After  *string `json:"after,omitempty"`
}

const (
	reviewFileLimit  = 64 << 10
	reviewTotalLimit = 512 << 10
)

func showable(data []byte) *string {
	if len(data) > reviewFileLimit || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	text := string(data)
	return &text
}

// planReview answers the review of a kept plan. Called with s.mu held.
func (s *Server) planReview(id string) Response {
	s.expirePlans()
	p, ok := s.plans[id]
	if !ok {
		return Response{Error: "no plan " + id + " is kept"}
	}
	changes, err := json.Marshal(p.report.Changes)
	if err != nil {
		return Response{Error: err.Error()}
	}
	review := Review{Plan: id, Changes: string(changes), Files: []ReviewFile{}}
	trees, err := s.openTrees(p.trees, p.report.Changes)
	if err != nil {
		return Response{Error: err.Error()}
	}
	defer func() {
		for _, o := range trees {
			o.root.Close()
		}
	}()
	total := len(changes)
	for _, o := range trees {
		for _, c := range o.changes {
			if c.Type != "file" || c.Kind == "metadata" || c.Kind == "deleted" {
				continue
			}
			name := relIn(o.tree.Mount, c.Path)
			file := ReviewFile{Path: c.Path}
			if data, err := os.ReadFile(filepath.Join(o.tree.Upper, name)); err == nil {
				file.After = showable(data)
			}
			if strings.HasPrefix(c.Base, "sha256:") {
				if data, err := o.root.ReadFile(name); err == nil {
					file.Before = showable(data)
				}
			}
			size := 0
			for _, text := range []*string{file.Before, file.After} {
				if text != nil {
					size += len(*text)
				}
			}
			if total+size > reviewTotalLimit {
				continue
			}
			total += size
			if file.Before != nil || file.After != nil {
				review.Files = append(review.Files, file)
			}
		}
	}
	text, err := json.Marshal(review)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Output: string(text)}
}
