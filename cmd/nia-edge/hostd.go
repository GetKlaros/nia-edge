package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/GetKlaros/nia-edge/internal/hostd"
)

const (
	defaultHostdSocket  = "/run/nia-hostd/hostd.sock"
	defaultHostdJournal = "/var/lib/nia-hostd/journal.jsonl"
)

// hostdCommand is nia-hostd: `run` serves the host actions as root, `undo`
// undoes a journal entry, `journal` prints the journal.
func hostdCommand(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: nia-edge hostd run|undo <id>|journal")
	}
	flags := flag.NewFlagSet("nia-edge hostd "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateFile := flags.String("state", "", "nia-edge's state file (or EDGE_STATE; default "+defaultState+")")
	policyFile := flags.String("policy", "", "nia-edge's signed policy (default policy.json next to the state file)")
	journal := flags.String("journal", defaultHostdJournal, "the journal of the actions")
	socket := flags.String("socket", defaultHostdSocket, "the socket nia-edge asks on")
	allowedUser := flags.String("user", "nia-edge", "the only user served on the socket")
	verify := flags.Bool("verify", false, "journal: check the hash chain and print its head")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	statePathValue := statePath(*stateFile, getenv)
	if *policyFile == "" {
		*policyFile = filepath.Join(filepath.Dir(statePathValue), "policy.json")
	}
	// NIA_HOSTD_DRY_RUN=yes runs nothing and says what it would run: for tests.
	var runner hostd.Runner = hostd.Exec{}
	dry := getenv("NIA_HOSTD_DRY_RUN") == "yes"
	if dry {
		runner = &hostd.DryRun{}
	} else if os.Geteuid() != 0 {
		return errors.New("nia-hostd runs as root")
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	server := &hostd.Server{StatePath: statePathValue, PolicyPath: *policyFile, JournalPath: *journal, Run: runner, Logger: logger}
	if !dry {
		// Dry runs: the agent's script in a container over a copy of /etc.
		server.Sandbox = hostd.DefaultSandbox()
	}
	switch args[0] {
	case "journal":
		if *verify {
			head, err := server.VerifyJournal()
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "the journal's chain holds: %d entries, head %s\n", head.Seq, head.Hash)
			return nil
		}
		entries, err := server.Journal()
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		for _, entry := range entries {
			if err := encoder.Encode(entry); err != nil {
				return err
			}
		}
		return nil
	case "undo":
		if flags.NArg() != 1 {
			return errors.New("usage: nia-edge hostd undo <journal id>")
		}
		resp := server.Undo(ctx, flags.Arg(0))
		if !resp.OK {
			return errors.New(resp.Error)
		}
		fmt.Fprintf(stdout, "undone (journal %s)\n%s\n", resp.Journal, resp.Output)
		return nil
	case "run":
	default:
		return fmt.Errorf("unknown hostd command %q (run, undo, journal)", args[0])
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	allowed, err := user.Lookup(*allowedUser)
	if err != nil {
		return fmt.Errorf("the user nia-hostd serves: %w", err)
	}
	uid, err1 := strconv.ParseUint(allowed.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(allowed.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return errors.New("the user nia-hostd serves has no numeric uid or gid")
	}
	if err := os.MkdirAll(filepath.Dir(*journal), 0o700); err != nil {
		return err
	}
	// The socket's directory: reached by the group of the user served.
	if err := os.MkdirAll(filepath.Dir(*socket), 0o750); err != nil {
		return err
	}
	if !dry {
		if err := os.Chown(filepath.Dir(*socket), 0, int(gid)); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Dir(*socket), 0o750); err != nil {
			return err
		}
	}
	_ = os.Remove(*socket)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: *socket, Net: "unix"})
	if err != nil {
		return err
	}
	// Reached by the socket's group, and served to that user only.
	if err := os.Chmod(*socket, 0o660); err != nil {
		listener.Close()
		return err
	}
	if !dry {
		if err := os.Chown(*socket, 0, int(gid)); err != nil {
			listener.Close()
			return err
		}
	}
	fmt.Fprintf(stdout, "nia-hostd %s: serving %s on %s%s\n", version, *allowedUser, *socket, map[bool]string{true: " (dry run: nothing is run)", false: ""}[dry])
	return server.Serve(ctx, listener, func(peer uint32) bool { return uint64(peer) == uid })
}
