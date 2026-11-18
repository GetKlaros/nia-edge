package mcpd

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// In the container: nia-edge's binary, which runs the server on its
// stream and relays its connections, and the directory of the two sockets
// nia-mcp listens on: the server's stream and its way out.
const (
	relayPath = "/nia/nia-edge"
	runDir    = "/nia/run"
	proxyAddr = "127.0.0.1:3128"
	// Names of the sockets in the run directory.
	egressName = "egress.sock"
	streamName = "stream.sock"
)

// Podman starts containers with rootless podman, as nia-mcp.
type Podman struct {
	// Binary is podman's path; empty looks in the usual places.
	Binary string
	// Relay is nia-edge's binary on this machine, mounted read only in each
	// container: static, it runs in any image.
	Relay string
	// Home and Runtime are nia-mcp's home (podman's storage) and runtime
	// directory.
	Home, Runtime string
	// Memory and Processes bound each container's memory (bytes) and its
	// user's processes; zero takes the defaults.
	Memory    int64
	Processes int
}

func (p Podman) binary() string {
	if p.Binary != "" {
		return p.Binary
	}
	for _, candidate := range []string{"/usr/bin/podman", "/usr/local/bin/podman", "/bin/podman"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return "podman"
}

// Args are podman's arguments for one server, in a container called
// container, whose sockets are in the directory run on this machine. The
// container is detached: podman ends once it started, and the server's
// stream goes through a socket. The image is run by its ID and never
// pulled; nothing of the machine is mounted but the relay and those two
// sockets; no network, no capability, no new privilege, a read-only root.
// Variables are named here and valued in podman's environment: a value is
// never on a command line.
func (p Podman) Args(l Launch, container, run string) []string {
	processes := p.Processes
	if processes <= 0 {
		processes = 256
	}
	args := []string{
		// No systemd session for nia-mcp: podman's own cgroups and events.
		"--cgroup-manager=cgroupfs", "--events-backend=file",
		"run", "--rm", "--detach",
		"--name", container,
		"--pull", "never",
		"--network", "none",
		"--cap-drop", "all",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--read-only-tmpfs=false",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
		"--ulimit", "nproc=" + strconv.Itoa(processes) + ":" + strconv.Itoa(processes),
		"--ulimit", "nofile=4096:4096",
		"--log-driver", "k8s-file", "--log-opt", "max-size=1mb",
		"--stop-timeout", "5",
		"--mount", "type=bind,src=" + p.Relay + ",dst=" + relayPath + ",ro=true",
		// The two sockets, each mounted alone: the container cannot create
		// anything in the directory that holds them.
		"--mount", "type=bind,src=" + run + "/" + streamName + ",dst=" + runDir + "/" + streamName,
		"--mount", "type=bind,src=" + run + "/" + egressName + ",dst=" + runDir + "/" + egressName,
	}
	if p.Memory > 0 {
		args = append(args, "--memory", strconv.FormatInt(p.Memory, 10))
	} else {
		// No cgroup of its own: the container stays in nia-mcp's, bounded
		// by the service's limits (MemoryMax, TasksMax).
		args = append(args, "--cgroups", "disabled")
	}
	names := make([]string, 0, len(l.Env))
	for name := range l.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args = append(args, "--env", name)
	}
	args = append(args, "--entrypoint", relayPath, strings.TrimPrefix(l.Image, "sha256:"), "mcp", "relay", "--")
	return append(args, l.Command...)
}

// Environ is podman's environment for one server: nia-mcp's own and the
// server's variables, nothing inherited.
func (p Podman) Environ(l Launch) []string {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + p.Home, "XDG_RUNTIME_DIR=" + p.Runtime, "LANG=C.UTF-8"}
	for name, value := range l.Env {
		env = append(env, name+"="+value)
	}
	sort.Strings(env[4:])
	return env
}
