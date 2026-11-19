package simulate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// childEnv carries the child's configuration; it never reaches the command.
const childEnv = "NIA_SIMULATE_CHILD"

type root struct {
	Path  string `json:"path"`
	Upper string `json:"upper"`
	Work  string `json:"work"`
}

type childConfig struct {
	Command string   `json:"command"`
	Dir     string   `json:"dir"`
	Home    string   `json:"home"`
	Scratch string   `json:"scratch"`
	Roots   []root   `json:"roots"`
	UID     int      `json:"uid"`
	GID     int      `json:"gid"`
	Env     []string `json:"env"`
}

// bounded keeps the first MaxOutput bytes it is given.
type bounded struct {
	bytes.Buffer
	truncated bool
}

func (b *bounded) Write(p []byte) (int, error) {
	if room := MaxOutput - b.Len(); room < len(p) {
		b.truncated = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// overlayPath refuses what overlayfs options cannot hold.
func overlayPath(path string) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, ",:\\\n") {
		return fmt.Errorf("%q cannot be a layer's path", path)
	}
	return nil
}

func within(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// Run simulates the command. It fails, and nothing may run, when the
// sandbox cannot be made or the command outlives its time.
func Run(ctx context.Context, options Options) (*Result, error) {
	home, err := filepath.EvalSymlinks(options.Home)
	if err != nil {
		return nil, fmt.Errorf("the home %q: %w", options.Home, err)
	}
	dir, err := filepath.EvalSymlinks(options.Dir)
	if err != nil {
		return nil, fmt.Errorf("the working directory: %w", err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	paths := []string{home}
	// The working directory is a layer too when it is the user's and
	// outside their home; anywhere else it is read only.
	if !within(dir, home) && dir != "/" {
		var st syscall.Stat_t
		if syscall.Stat(dir, &st) == nil && int(st.Uid) == uid {
			paths = append(paths, dir)
		}
	}
	scratch, err := os.MkdirTemp(scratchBase(home), "nia-simulate-")
	if err != nil {
		return nil, err
	}
	result := &Result{layer: &layer{scratch: scratch}}
	defer func() {
		if result.layer != nil && result.Effect.Paths == nil && result.layer.roots == nil {
			os.RemoveAll(scratch)
		}
	}()
	config := childConfig{Command: options.Command, Dir: dir, Home: home, Scratch: scratch, UID: uid, GID: gid, Env: options.Env}
	for index, path := range paths {
		if err := overlayPath(path); err != nil {
			os.RemoveAll(scratch)
			return nil, err
		}
		r := root{Path: path, Upper: filepath.Join(scratch, fmt.Sprintf("upper%d", index)), Work: filepath.Join(scratch, fmt.Sprintf("work%d", index))}
		for _, d := range []string{r.Upper, r.Work} {
			if err := os.Mkdir(d, 0o700); err != nil {
				os.RemoveAll(scratch)
				return nil, err
			}
		}
		config.Roots = append(config.Roots, r)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		os.RemoveAll(scratch)
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		os.RemoveAll(scratch)
		return nil, err
	}
	status, statusWriter, err := os.Pipe()
	if err != nil {
		os.RemoveAll(scratch)
		return nil, err
	}
	timed, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	cmd := exec.CommandContext(timed, self, ChildCommand)
	cmd.Env = []string{childEnv + "=" + string(encoded)}
	cmd.Stdin = nil
	var stdout, stderr bounded
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.ExtraFiles = []*os.File{statusWriter}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		statusWriter.Close()
		status.Close()
		os.RemoveAll(scratch)
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	statusWriter.Close()
	reported, _ := io.ReadAll(io.LimitReader(status, 4096))
	status.Close()
	waited := cmd.Wait()
	if timed.Err() != nil && ctx.Err() == nil {
		os.RemoveAll(scratch)
		return nil, fmt.Errorf("the command ran longer than %s: nothing it did is kept", options.Timeout)
	}
	if ctx.Err() != nil {
		os.RemoveAll(scratch)
		return nil, ctx.Err()
	}
	var report struct {
		Ready  bool   `json:"ready"`
		Error  string `json:"error"`
		Denied bool   `json:"denied"`
		Exit   *int   `json:"exit"`
	}
	for _, line := range bytes.Split(bytes.TrimSpace(reported), []byte("\n")) {
		var step struct {
			Ready  bool   `json:"ready"`
			Error  string `json:"error"`
			Denied bool   `json:"denied"`
			Exit   *int   `json:"exit"`
		}
		if json.Unmarshal(line, &step) != nil {
			continue
		}
		report.Ready = report.Ready || step.Ready
		if step.Error != "" {
			report.Error, report.Denied = step.Error, step.Denied
		}
		if step.Exit != nil {
			report.Exit = step.Exit
		}
	}
	if !report.Ready || report.Exit == nil {
		os.RemoveAll(scratch)
		why := report.Error
		if why == "" {
			why = fmt.Sprint(waited)
		}
		if report.Denied {
			return nil, fmt.Errorf("%w: %s", ErrUnsupported, why)
		}
		return nil, fmt.Errorf("the sandbox could not be made: %s", why)
	}
	result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
	result.Truncated = stdout.truncated || stderr.truncated
	result.ExitCode = *report.Exit
	result.layer.roots = config.Roots
	effect, err := result.layer.read()
	if err != nil {
		os.RemoveAll(scratch)
		result.layer.roots = nil
		return nil, err
	}
	result.Effect = effect
	return result, nil
}

// overlayfsMagic is overlayfs' f_type: a layer cannot be made on it.
const overlayfsMagic = 0x794c7630

// scratchBase is where layers are made: /var/tmp, apart from the home and
// not on overlayfs (a container's own root), else /dev/shm.
func scratchBase(home string) string {
	for _, base := range []string{"/var/tmp", "/dev/shm", os.TempDir()} {
		var fs syscall.Statfs_t
		if info, err := os.Stat(base); err != nil || !info.IsDir() || within(base, home) {
			continue
		}
		if syscall.Statfs(base, &fs) == nil && uint32(fs.Type) == overlayfsMagic {
			continue
		}
		return base
	}
	return os.TempDir()
}

// Close forgets the layer.
func (r *Result) Close() error {
	if r.layer == nil {
		return nil
	}
	return removeLayer(r.layer.scratch)
}

// removeLayer removes a scratch directory, whose work directories the
// kernel leaves without permissions.
func removeLayer(scratch string) error {
	filepath.WalkDir(scratch, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(path, 0o700)
		}
		return nil
	})
	return os.RemoveAll(scratch)
}

// ------------------------------------------------------------ the child

const (
	mountAttrRdonly = 0x1
	atRecursive     = 0x8000
	atFdcwd         = -100
	sysMountSetattr = 442 // the same on amd64 and arm64
)

type mountAttr struct {
	set, clear, propagation, userns uint64
}

// readOnly makes a mount and every mount below it read only.
func readOnly(path string) error {
	name, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	attr := mountAttr{set: mountAttrRdonly}
	fd := atFdcwd
	_, _, errno := syscall.Syscall6(sysMountSetattr, uintptr(fd), uintptr(unsafe.Pointer(name)), atRecursive, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return &os.PathError{Op: "mount_setattr", Path: path, Err: errno}
	}
	return nil
}

// hidden are the entries of / the command does not see from the machine.
var hidden = map[string]bool{"proc": true, "sys": true, "dev": true, "tmp": true, "run": true}

// Child makes the sandbox and runs the command in it, as the user. It is
// PID 1 of its namespace: when it returns, everything the command started
// is killed. Its status goes to file descriptor 3.
func Child() int {
	status := os.NewFile(3, "status")
	say := func(v any) {
		line, _ := json.Marshal(v)
		status.Write(append(line, '\n'))
	}
	fail := func(err error) int {
		say(map[string]any{"error": err.Error(), "denied": errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)})
		return 125
	}
	var config childConfig
	if err := json.Unmarshal([]byte(os.Getenv(childEnv)), &config); err != nil {
		return fail(err)
	}
	os.Unsetenv(childEnv)
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		// A user namespace without its capabilities (an AppArmor policy
		// that restricts them): no sandbox can be made here.
		return fail(fmt.Errorf("private mounts: %w", err))
	}
	if err := sandbox(config); err != nil {
		say(map[string]string{"error": err.Error()})
		return 125
	}
	cmd := exec.Command("/bin/sh", "-c", config.Command)
	cmd.Dir = config.Dir
	if _, err := os.Stat(config.Dir); err != nil {
		cmd.Dir = config.Home
	}
	cmd.Env = config.Env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// The command runs as the user, in a user namespace of its own with no
	// capability over the sandbox's mounts.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: config.UID, HostID: 0, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: config.GID, HostID: 0, Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	say(map[string]bool{"ready": true})
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return fail(err)
		}
		code = exit.ExitCode()
		if code < 0 {
			code = 128 + int(exit.Sys().(syscall.WaitStatus).Signal())
		}
	}
	say(map[string]int{"exit": code})
	return 0
}

func sandbox(config childConfig) error {
	newRoot := filepath.Join(config.Scratch, "root")
	if err := os.Mkdir(newRoot, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=1m,mode=0755"); err != nil {
		return fmt.Errorf("the root: %w", err)
	}
	entries, err := os.ReadDir("/")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if hidden[name] {
			continue
		}
		source, target := "/"+name, filepath.Join(newRoot, name)
		info, err := os.Lstat(source)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(source)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		case info.IsDir():
			if err := bindReadOnly(source, target, true); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := bindReadOnly(source, target, false); err != nil {
				return err
			}
		}
	}
	// /sys read only; /proc of this PID namespace; a /dev of its own.
	if err := bindReadOnly("/sys", filepath.Join(newRoot, "sys"), true); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(newRoot, "proc"), 0o555); err != nil {
		return err
	}
	if err := syscall.Mount("proc", filepath.Join(newRoot, "proc"), "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	if err := makeDev(filepath.Join(newRoot, "dev")); err != nil {
		return err
	}
	// Empty and private: the machine's sockets (a container engine's,
	// D-Bus) are not reachable, even read only.
	for _, private := range []struct{ path, options string }{
		{"tmp", "size=512m,mode=1777"},
		{"run", "size=1m,mode=0755"},
		{"var/tmp", "size=512m,mode=1777"},
	} {
		target := filepath.Join(newRoot, private.path)
		if _, err := os.Stat(target); err != nil {
			if private.path == "var/tmp" {
				continue
			}
			if err := os.Mkdir(target, 0o755); err != nil {
				return err
			}
		}
		if err := syscall.Mount("tmpfs", target, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, private.options); err != nil {
			return fmt.Errorf("/%s: %w", private.path, err)
		}
	}
	// The user's files: an overlay each, the only places writes are kept.
	for _, r := range config.Roots {
		target := filepath.Join(newRoot, r.Path)
		// Under a directory the sandbox empties (/tmp): its place is made.
		if _, err := os.Stat(target); err != nil {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("the place of %s: %w", r.Path, err)
			}
		}
		options := "lowerdir=" + r.Path + ",upperdir=" + r.Upper + ",workdir=" + r.Work + ",userxattr"
		if err := syscall.Mount("overlay", target, "overlay", syscall.MS_NOSUID|syscall.MS_NODEV, options); err != nil {
			return fmt.Errorf("the layer over %s: %w", r.Path, err)
		}
	}
	old := filepath.Join(newRoot, ".old")
	if err := os.Mkdir(old, 0o700); err != nil {
		return err
	}
	if err := syscall.PivotRoot(newRoot, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if err := syscall.Unmount("/.old", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("the former root: %w", err)
	}
	if err := os.Remove("/.old"); err != nil {
		return err
	}
	// The sandbox's own root is read only too.
	return syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
}

func bindReadOnly(source, target string, dir bool) error {
	if dir {
		if err := os.Mkdir(target, 0o755); err != nil {
			return err
		}
	} else if err := os.WriteFile(target, nil, 0o644); err != nil {
		return err
	}
	if err := syscall.Mount(source, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	return readOnly(target)
}

func makeDev(dev string) error {
	if err := os.Mkdir(dev, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", dev, "tmpfs", syscall.MS_NOSUID|syscall.MS_NOEXEC, "size=64k,mode=0755"); err != nil {
		return fmt.Errorf("/dev: %w", err)
	}
	for _, name := range []string{"null", "zero", "full", "random", "urandom"} {
		target := filepath.Join(dev, name)
		if err := os.WriteFile(target, nil, 0o666); err != nil {
			return err
		}
		if err := syscall.Mount("/dev/"+name, target, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("/dev/%s: %w", name, err)
		}
	}
	for name, link := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(link, filepath.Join(dev, name)); err != nil {
			return err
		}
	}
	shm := filepath.Join(dev, "shm")
	if err := os.Mkdir(shm, 0o1777); err != nil {
		return err
	}
	return syscall.Mount("tmpfs", shm, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=64m,mode=1777")
}
