package hostd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Podman runs dry runs in a rootful podman container: the machine's root
// read only and without its other mounts, /etc an overlay whose upper layer
// is in the scratch tmpfs, no network, no capability, no new privilege.
type Podman struct {
	// Binary is podman's path; empty looks in the usual places.
	Binary string
	// Root and RunRoot are podman's storage for nia-hostd alone.
	Root, RunRoot string
	// Limits refuses a dry run on a machine where podman cannot bound its
	// processes and memory: cgroup v2 with the pids and memory controllers.
	// Controllers is the file that lists them; empty is the system's.
	Limits      bool
	Controllers string
}

// bounded reports why a dry run's processes and memory cannot be bounded
// here, or "".
func (p Podman) bounded() string {
	if !p.Limits {
		return ""
	}
	file := p.Controllers
	if file == "" {
		file = "/sys/fs/cgroup/cgroup.controllers"
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "this machine has no cgroup v2, so a dry run's processes and memory cannot be bounded"
	}
	have := strings.Fields(string(data))
	for _, want := range []string{"pids", "memory"} {
		if !slices.Contains(have, want) {
			return "cgroup v2 has no " + want + " controller here, so a dry run cannot be bounded"
		}
	}
	return ""
}

func (p Podman) binary() (string, error) {
	if p.Binary != "" {
		return p.Binary, nil
	}
	for _, candidate := range []string{"/usr/bin/podman", "/usr/local/bin/podman", "/bin/podman"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("podman is not installed: dry runs need it")
}

// Prepare mounts a bounded tmpfs on scratch, whose atimes are always
// updated (a read decoy is seen), and in it the container's root: an overlay
// whose lower layer is the machine's root, bound read only, and whose upper
// layer is in the tmpfs. podman prepares the container there (an /etc/mtab it
// creates when the machine has none, its mount points), never on the
// machine; inside, the container's root is read only (--read-only).
func (Podman) Prepare(scratch string) (func(), error) {
	if err := syscall.Mount("tmpfs", scratch, "tmpfs", syscall.MS_NOSUID|syscall.MS_STRICTATIME, "size="+strconv.Itoa(layerBytes)+",nr_inodes="+strconv.Itoa(layerInodes)+",mode=0700"); err != nil {
		return nil, fmt.Errorf("tmpfs: %w", err)
	}
	lower, root := filepath.Join(scratch, "lower"), filepath.Join(scratch, "root")
	undo := func() {
		_ = syscall.Unmount(root, syscall.MNT_DETACH)
		_ = syscall.Unmount(lower, syscall.MNT_DETACH)
		_ = syscall.Unmount(scratch, syscall.MNT_DETACH)
	}
	for _, dir := range []string{lower, root, filepath.Join(scratch, "rootup"), filepath.Join(scratch, "rootwork")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			undo()
			return nil, err
		}
	}
	if err := syscall.Mount("/", lower, "", syscall.MS_BIND, ""); err != nil {
		undo()
		return nil, fmt.Errorf("bind /: %w", err)
	}
	if err := syscall.Mount("", lower, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err != nil {
		undo()
		return nil, fmt.Errorf("read-only /: %w", err)
	}
	options := "lowerdir=" + lower + ",upperdir=" + filepath.Join(scratch, "rootup") + ",workdir=" + filepath.Join(scratch, "rootwork")
	if err := syscall.Mount("overlay", root, "overlay", syscall.MS_NOSUID|syscall.MS_NODEV, options); err != nil {
		undo()
		return nil, fmt.Errorf("the container's root: %w", err)
	}
	return undo, nil
}

// Args is the podman command line of a dry run, without the binary.
func (p Podman) Args(spec SandboxSpec) []string {
	args := []string{
		"--root", p.Root, "--runroot", p.RunRoot, "--storage-driver", "vfs", "--log-level", "error",
		"run", "--rm", "--network", "none", "--cap-drop", "all",
		"--security-opt", "no-new-privileges", "--read-only", "--read-only-tmpfs=false",
		"--pids-limit", "256", "--memory", "512m",
		"--timeout", strconv.Itoa(int(spec.Timeout.Seconds())),
		"--no-hosts", "--hostname", "dry-run", "--workdir", "/",
		"--env", spec.PathVariable, "--env", "HOME=/root", "--env", "LANG=C.UTF-8",
		"--volume", spec.Etc + ":/etc:O,upperdir=" + spec.Upper + ",workdir=" + spec.Work,
	}
	for _, dir := range spec.Masked {
		args = append(args, "--tmpfs", dir+":rw,nosuid,nodev,noexec,notmpcopyup,size=16m,mode=0755")
	}
	for _, file := range spec.MaskedFiles {
		args = append(args, "--volume", "/dev/null:"+file+":ro")
	}
	return append(args, "--rootfs", spec.Root, "/bin/sh", "-c", spec.Script)
}

func (p Podman) Run(ctx context.Context, spec SandboxSpec) (string, error) {
	if why := p.bounded(); why != "" {
		return "", errors.New(why)
	}
	binary, err := p.binary()
	if err != nil {
		return "", err
	}
	// podman's own storage configuration, whatever the machine's says.
	conf := p.RunRoot + ".storage.conf"
	text := fmt.Sprintf("[storage]\ndriver = \"vfs\"\nrunroot = %q\ngraphroot = %q\n", p.RunRoot, p.Root)
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, binary, p.Args(spec)...)
	cmd.Env = append(append([]string{}, baseEnv...), "CONTAINERS_STORAGE_CONF="+conf)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if len(out) > outputLimit {
		out = append([]byte("…"), out[len(out)-outputLimit:]...)
	}
	return string(out), err
}

// DefaultSandbox is nia-hostd's: podman, with its storage in nia-hostd's
// own directories.
func DefaultSandbox() Sandbox {
	return Podman{Root: "/var/lib/nia-hostd/podman", RunRoot: "/run/nia-hostd/podman", Limits: true}
}
