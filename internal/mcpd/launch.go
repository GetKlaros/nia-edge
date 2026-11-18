// Package mcpd is nia-mcp: it runs the agent's MCP servers, each in its own
// rootless container, as a user that holds no secret and no privilege. Only
// nia-edge asks it, over a Unix socket (the kernel names the peer), and only
// to start one server from an image that is already here, named by its ID.
//
// A container has no network: its only way out is a socket to nia-edge's
// egress proxy, which knows the server by that socket and decides each
// connection with Nia. It sees none of the machine's files, holds only the
// variables nia-edge gives it (its own token), and its standard input and
// output are the MCP stream nia-edge reads.
package mcpd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Launch asks for one MCP server. Its first line on the socket is this
// object in JSON; the rest of the connection is the server's standard input
// and output.
type Launch struct {
	// Name is the server's name, as the agent's tools are named after it
	// (mcp__<name>__<tool>).
	Name string `json:"name"`
	// Image is the ID of the image, sha256:<64 hex>: its content, layers
	// included, is fixed by it. It must already be here: nothing is pulled.
	Image string `json:"image"`
	// Command is what runs in the container, with its arguments.
	Command []string `json:"command"`
	// Env is the server's own variables (its token): given to podman in its
	// environment, never on a command line.
	Env map[string]string `json:"env,omitempty"`
}

// Ack is mcpd's answer, on one line, before the stream starts.
type Ack struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

const (
	maxCommand   = 64
	maxArgument  = 4096
	maxEnv       = 64
	maxEnvValue  = 16 << 10
	maxEnvTotal  = 64 << 10
	maxLaunchLen = 128 << 10
)

var (
	serverName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	imageID    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	envName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// reserved are the variables nia-mcp sets itself: the way out and the
// server's identity are not the caller's to choose.
var reserved = map[string]bool{
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,
	"NODE_USE_ENV_PROXY": true, "PATH": true, "HOME": true, "XDG_RUNTIME_DIR": true,
	"CONTAINERS_CONF": true, "CONTAINERS_STORAGE_CONF": true, "CONTAINERS_REGISTRIES_CONF": true,
}

// ValidName reports whether name can name a server: a lower-case letter,
// then up to 31 lower-case letters, digits or underscores. Not "host", which
// is nia-edge's own server of host actions.
func ValidName(name string) bool {
	return serverName.MatchString(name) && name != "host" && !strings.Contains(name, "__")
}

// ValidImage reports whether image is an image ID, sha256:<64 hex>.
func ValidImage(image string) bool {
	return imageID.MatchString(image)
}

// ValidEnvName reports whether name can be one of a server's variables.
func ValidEnvName(name string) bool {
	return envName.MatchString(name) && !reserved[name] && !strings.HasPrefix(name, "NIA_")
}

// Validate refuses a launch that is not plainly what it says.
func (l Launch) Validate() error {
	if !ValidName(l.Name) {
		return errors.New("the server's name is a lower-case letter, then up to 31 lower-case letters, digits or single underscores (not host)")
	}
	if !ValidImage(l.Image) {
		return errors.New("the image is named by its ID, sha256:<64 hex>")
	}
	if len(l.Command) == 0 || len(l.Command) > maxCommand {
		return fmt.Errorf("the command has 1 to %d words", maxCommand)
	}
	for _, word := range l.Command {
		if word == "" || len(word) > maxArgument || !utf8.ValidString(word) || strings.ContainsRune(word, 0) {
			return fmt.Errorf("each word of the command is 1 to %d bytes of UTF-8, without NUL", maxArgument)
		}
	}
	if len(l.Env) > maxEnv {
		return fmt.Errorf("at most %d variables", maxEnv)
	}
	total := 0
	for name, value := range l.Env {
		if !ValidEnvName(name) {
			return fmt.Errorf("variable %q is not one a server may be given", name)
		}
		if len(value) > maxEnvValue || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return fmt.Errorf("variable %s: at most %d bytes of UTF-8, without NUL", name, maxEnvValue)
		}
		total += len(name) + len(value)
	}
	if total > maxEnvTotal {
		return fmt.Errorf("the variables hold more than %d bytes", maxEnvTotal)
	}
	return nil
}
