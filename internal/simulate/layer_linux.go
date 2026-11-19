package simulate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// layer is what a simulation left: an upper directory per root, and the
// state of the machine each change depends on, to apply it only where the
// machine still holds what the simulation saw.
type layer struct {
	scratch string
	roots   []root
	changes []change
}

type changeKind int

const (
	deleted  changeKind = iota // a whiteout: the path and all it held are gone
	replaced                   // an opaque directory: what it held is gone, the layer's is kept
	written                    // a file or a symbolic link of the layer
	created                    // a directory the machine did not have
)

type change struct {
	root  int
	rel   string
	kind  changeKind
	prior string // fingerprint of the machine's path when the simulation ended
}

// fingerprint describes a path of the machine: its absence, a file's or a
// link's identity, or a directory's whole tree.
func fingerprint(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return entryPrint(info), nil
	}
	sum := sha256.New()
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(path, p)
		fmt.Fprintf(sum, "%q %s\n", rel, entryPrint(info))
		return nil
	})
	if err != nil {
		return "", err
	}
	return "tree:" + hex.EncodeToString(sum.Sum(nil)), nil
}

func entryPrint(info fs.FileInfo) string {
	st, _ := info.Sys().(*syscall.Stat_t)
	if st == nil {
		return fmt.Sprintf("%v %d %d", info.Mode(), info.Size(), info.ModTime().UnixNano())
	}
	if info.IsDir() {
		return fmt.Sprintf("%v %d", info.Mode(), st.Ino)
	}
	return fmt.Sprintf("%v %d %d %d %d", info.Mode(), info.Size(), info.ModTime().UnixNano(), st.Ino, st.Ctim.Nano())
}

// files counts what a path of the machine holds that is not a directory;
// at least one.
func files(path string) int64 {
	if n := count(path); n > 0 {
		return n
	}
	return 1
}

func count(path string) int64 {
	var n int64
	filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func whiteout(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0
}

func opaque(path string) bool {
	value := make([]byte, 4)
	n, err := syscall.Getxattr(path, "user.overlay.opaque", value)
	return err == nil && n == 1 && value[0] == 'y'
}

// read turns the layer into the effect Nia judges, and keeps the changes.
func (l *layer) read() (Effect, error) {
	effect := Effect{Paths: []string{}}
	for index, r := range l.roots {
		err := filepath.WalkDir(r.Upper, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(r.Upper, p)
			if rel == "." {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			machine := filepath.Join(r.Path, rel)
			add := func(kind changeKind, listed bool) error {
				prior, err := fingerprint(machine)
				if err != nil {
					return err
				}
				l.changes = append(l.changes, change{root: index, rel: rel, kind: kind, prior: prior})
				if listed {
					effect.Paths = append(effect.Paths, machine)
				}
				return nil
			}
			mode := info.Mode()
			switch {
			case whiteout(info):
				effect.Deleted += files(machine)
				return add(deleted, true)
			case mode.IsDir():
				lower, err := os.Lstat(machine)
				switch {
				case opaque(p):
					if err == nil && lower.IsDir() {
						effect.Deleted += count(machine)
					}
					return add(replaced, true)
				case err != nil || !lower.IsDir():
					// New: listed once, what it holds is applied with it.
					if err := add(created, true); err != nil {
						return err
					}
					if err := l.within(index, r, p, rel); err != nil {
						return err
					}
					return filepath.SkipDir
				}
				return nil
			case mode.IsRegular() || mode&fs.ModeSymlink != 0:
				if mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
					return fmt.Errorf("the command made %s setuid or setgid", machine)
				}
				return add(written, true)
			default:
				return fmt.Errorf("the command made %s, which is not a file, a link or a directory", machine)
			}
		})
		if err != nil {
			return Effect{}, err
		}
	}
	if len(effect.Paths) > MaxPaths {
		return Effect{}, fmt.Errorf("the command changed more than %d paths: too many to judge", MaxPaths)
	}
	return effect, nil
}

// within keeps what a new directory of the layer holds, unlisted.
func (l *layer) within(index int, r root, dir, dirRel string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, _ := filepath.Rel(r.Upper, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		switch {
		case mode.IsDir():
			l.changes = append(l.changes, change{root: index, rel: rel, kind: created, prior: "absent"})
		case mode.IsRegular() || mode&fs.ModeSymlink != 0:
			if mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
				return fmt.Errorf("the command made %s setuid or setgid", filepath.Join(r.Path, rel))
			}
			l.changes = append(l.changes, change{root: index, rel: rel, kind: written, prior: "absent"})
		default:
			return fmt.Errorf("the command made %s, which is not a file, a link or a directory", filepath.Join(r.Path, rel))
		}
		return nil
	})
}

// Apply writes the effect to the machine, exactly as the layer holds it,
// and only where the machine still holds what the simulation saw. Nothing
// leaves the user's roots: no symbolic link is followed out of them.
func (r *Result) Apply() error {
	l := r.layer
	if l == nil {
		return errors.New("nothing to apply")
	}
	for _, c := range l.changes {
		now, err := fingerprint(filepath.Join(l.roots[c.root].Path, c.rel))
		if err != nil {
			return err
		}
		if now != c.prior && !(c.kind == created && now == "absent") {
			return ErrChanged
		}
	}
	opened := make([]*os.Root, len(l.roots))
	for index, rt := range l.roots {
		root, err := os.OpenRoot(rt.Path)
		if err != nil {
			return err
		}
		defer root.Close()
		opened[index] = root
	}
	// Deletions first, then directories from the top, then files.
	ordered := append([]change(nil), l.changes...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].kind != ordered[j].kind {
			return ordered[i].kind < ordered[j].kind
		}
		return len(ordered[i].rel) < len(ordered[j].rel)
	})
	for _, c := range ordered {
		root, upper := opened[c.root], filepath.Join(l.roots[c.root].Upper, c.rel)
		switch c.kind {
		case deleted:
			if err := root.RemoveAll(c.rel); err != nil {
				return err
			}
		case replaced, created:
			info, err := os.Lstat(upper)
			if err != nil {
				return err
			}
			if c.kind == replaced {
				if err := root.RemoveAll(c.rel); err != nil {
					return err
				}
			} else if existing, err := root.Lstat(c.rel); err == nil && !existing.IsDir() {
				if err := root.Remove(c.rel); err != nil {
					return err
				}
			}
			if err := root.MkdirAll(c.rel, info.Mode().Perm()); err != nil {
				return err
			}
			if err := root.Chmod(c.rel, info.Mode().Perm()); err != nil {
				return err
			}
		}
	}
	for _, c := range ordered {
		if c.kind != written {
			continue
		}
		if err := writeOne(opened[c.root], filepath.Join(l.roots[c.root].Upper, c.rel), c.rel); err != nil {
			return err
		}
	}
	return nil
}

func writeOne(root *os.Root, upper, rel string) error {
	info, err := os.Lstat(upper)
	if err != nil {
		return err
	}
	if existing, err := root.Lstat(rel); err == nil && existing.IsDir() {
		if err := root.RemoveAll(rel); err != nil {
			return err
		}
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(upper)
		if err != nil {
			return err
		}
		if err := root.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return root.Symlink(target, rel)
	}
	source, err := os.Open(upper)
	if err != nil {
		return err
	}
	defer source.Close()
	temporary := filepath.Join(filepath.Dir(rel), fmt.Sprintf(".%s.nia-%d", filepath.Base(rel), os.Getpid()))
	out, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, source); err != nil {
		out.Close()
		root.Remove(temporary)
		return err
	}
	if err := out.Chmod(info.Mode().Perm()); err != nil {
		out.Close()
		root.Remove(temporary)
		return err
	}
	if err := out.Close(); err != nil {
		root.Remove(temporary)
		return err
	}
	if err := root.Rename(temporary, rel); err != nil {
		root.Remove(temporary)
		return err
	}
	return root.Chtimes(rel, info.ModTime(), info.ModTime())
}
