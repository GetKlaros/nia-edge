package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/GetKlaros/nia-edge/internal/mcpd"
	"github.com/GetKlaros/nia-edge/internal/state"
)

const (
	defaultMCPSocket  = "/run/nia-mcp/mcpd.sock"
	defaultMCPSockets = "/run/nia-mcp/egress"
	defaultMCPEgress  = "/run/nia-edge/mcp-egress.sock"
)

// mcpCommand manages the agent's MCP servers that run on this machine:
//
//	nia-edge mcp add -name mail -image sha256:<id> [-ref ...] [-env-file f|-] -- command...
//	nia-edge mcp remove -name mail
//	nia-edge mcp list
//	nia-edge mcp serve      nia-mcp: start the servers' containers, for nia-edge alone
//	nia-edge mcp relay -- command...   in a container: its way out, then the server
func mcpCommand(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: nia-edge mcp add|remove|list|serve|relay")
	}
	switch args[0] {
	case "add", "remove", "list":
		return mcpConfigure(args[0], args[1:], getenv, stdin, stdout, stderr)
	case "serve":
		return mcpServe(ctx, args[1:], getenv, stdout, stderr)
	case "relay":
		command := args[1:]
		if len(command) > 0 && command[0] == "--" {
			command = command[1:]
		}
		listen, socket := mcpd.RelayDefaults()
		os.Exit(mcpd.Relay(ctx, listen, socket, command, stderr))
	}
	return fmt.Errorf("unknown mcp command %q (add, remove, list, serve, relay)", args[0])
}

func mcpConfigure(action string, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nia-edge mcp "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateFile := flags.String("state", "", "state file (or EDGE_STATE; default "+defaultState+")")
	name := flags.String("name", "", "the server's name: the agent's tools are mcp__<name>__<tool>")
	image := flags.String("image", "", "the image's ID, sha256:<64 hex> (podman image inspect --format '{{.Id}}' as nia-mcp)")
	ref := flags.String("ref", "", "where the image came from, shown to people")
	envFile := flags.String("env-file", "", "the server's variables, NAME=value per line (its token): a file, or - for standard input")
	if err := flags.Parse(args); err != nil {
		return err
	}
	path := statePath(*stateFile, getenv)
	saved, err := state.Load(path)
	if errors.Is(err, state.ErrNotEnrolled) {
		return errors.New("this machine is not enrolled: run nia-edge enroll first")
	}
	if err != nil {
		return err
	}
	switch action {
	case "list":
		if flags.NArg() != 0 {
			return errors.New("unexpected argument")
		}
		names := make([]string, 0, len(saved.MCP))
		for server := range saved.MCP {
			names = append(names, server)
		}
		sort.Strings(names)
		if len(names) == 0 {
			fmt.Fprintln(stdout, "no MCP server runs on this machine through nia-edge")
		}
		for _, server := range names {
			entry := saved.MCP[server]
			variables := make([]string, 0, len(entry.Env))
			for variable := range entry.Env {
				variables = append(variables, variable)
			}
			sort.Strings(variables)
			// The values are tokens: only their names are shown.
			fmt.Fprintf(stdout, "%s: image %s%s, command %q, variables %s, at http://127.0.0.1:8787/local/%s/mcp\n",
				server, entry.Image, map[bool]string{true: " (" + entry.Ref + ")", false: ""}[entry.Ref != ""], entry.Command, strings.Join(variables, ","), server)
		}
		return nil
	case "remove":
		if flags.NArg() != 0 || *name == "" {
			return errors.New("usage: nia-edge mcp remove -name <server>")
		}
		if saved.MCP[*name] == nil {
			return fmt.Errorf("no MCP server %q", *name)
		}
		delete(saved.MCP, *name)
		if err := state.Save(path, saved); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "MCP server %s removed (restart nia-edge)\n", *name)
		return nil
	}
	command := flags.Args()
	launch := mcpd.Launch{Name: *name, Image: *image, Command: command, Env: map[string]string{}}
	if *envFile != "" {
		var source io.Reader = stdin
		if *envFile != "-" {
			file, err := os.Open(*envFile)
			if err != nil {
				return err
			}
			defer file.Close()
			source = file
		}
		scanner := bufio.NewScanner(io.LimitReader(source, 128<<10))
		scanner.Buffer(make([]byte, 64<<10), 64<<10)
		for line := 1; scanner.Scan(); line++ {
			text := strings.TrimRight(scanner.Text(), "\r")
			if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
				continue
			}
			variable, value, ok := strings.Cut(text, "=")
			if !ok {
				// Not echoed: it may be a token.
				return fmt.Errorf("line %d of the variables is not NAME=value", line)
			}
			launch.Env[variable] = value
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}
	if err := launch.Validate(); err != nil {
		return err
	}
	if saved.MCP == nil {
		saved.MCP = map[string]*state.MCPServer{}
	}
	saved.MCP[launch.Name] = &state.MCPServer{Image: launch.Image, Ref: *ref, Command: launch.Command, Env: launch.Env}
	if err := state.Save(path, saved); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "MCP server %s kept in %s, its image %s (restart nia-edge). The agent reaches it at http://127.0.0.1:8787/local/%s/mcp; its tools are mcp__%s__<tool>.\n",
		launch.Name, path, launch.Image, launch.Name, launch.Name)
	return nil
}

// lookupUID is a user's uid.
func lookupUID(name string) (uint32, error) {
	found, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(found.Uid, 10, 32)
	if err != nil {
		return 0, errors.New("no numeric uid")
	}
	return uint32(uid), nil
}

func mcpServe(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nia-edge mcp serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", defaultMCPSocket, "the socket nia-edge asks on")
	sockets := flags.String("sockets", defaultMCPSockets, "the directory of the containers' egress sockets")
	upstream := flags.String("upstream", defaultMCPEgress, "nia-edge's socket for the servers' connections")
	served := flags.String("user", "nia-edge", "the only user served on the socket")
	memory := flags.Int64("memory", 0, "each container's memory, in bytes (0: not bounded per container; the service's own bound holds)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if os.Geteuid() == 0 {
		return errors.New("nia-mcp does not run as root: run it as its own user")
	}
	uid, err := lookupUID(*served)
	if err != nil {
		return fmt.Errorf("the user nia-mcp serves: %w", err)
	}
	relay, err := os.Executable()
	if err != nil {
		return err
	}
	if relay, err = filepath.EvalSymlinks(relay); err != nil {
		return err
	}
	home := getenv("HOME")
	runtimeDir := getenv("XDG_RUNTIME_DIR")
	if home == "" || runtimeDir == "" {
		return errors.New("HOME and XDG_RUNTIME_DIR must be set: podman keeps its storage and state there")
	}
	if err := os.MkdirAll(*sockets, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(*sockets, 0o700); err != nil {
		return err
	}
	_ = os.Remove(*socket)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: *socket, Net: "unix"})
	if err != nil {
		return err
	}
	// Anyone may connect; only nia-edge's user is served (the kernel names
	// the peer).
	if err := os.Chmod(*socket, 0o666); err != nil {
		listener.Close()
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	server := &mcpd.Server{
		Podman:   mcpd.Podman{Relay: relay, Home: home, Runtime: runtimeDir, Memory: *memory},
		Sockets:  *sockets,
		Upstream: *upstream,
		Logger:   logger,
	}
	fmt.Fprintf(stdout, "nia-mcp %s: serving %s on %s; the servers' way out is %s\n", version, *served, *socket, *upstream)
	return server.Serve(ctx, listener, func(peer uint32) bool { return peer == uid })
}
