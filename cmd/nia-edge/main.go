// Command nia-edge runs next to an agent, on the machine that runs it. It is
// the agent's only way to its model and its tools: every call goes to Nia
// with this machine's key, and Nia decides.
//
//	nia-edge enroll -url https://nia.example   exchange a one-time token for this machine's key
//	nia-edge run                               relay the agent's calls and report to Nia
//	nia-edge version
//
// The enrollment token is read from NIA_ENROLL_TOKEN, from -token-file, or
// from standard input: never from the command line, which other users of the
// machine can read.
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
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/GetKlaros/nia-edge/internal/egress"
	"github.com/GetKlaros/nia-edge/internal/niaclient"
	"github.com/GetKlaros/nia-edge/internal/relay"
	"github.com/GetKlaros/nia-edge/internal/state"
)

// version is set at build time: go build -ldflags "-X main.version=0.3.0".
var version = "dev"

const defaultState = "/var/lib/nia-edge/state.json"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nia-edge enroll|run|version")
		return 2
	}
	var err error
	switch args[0] {
	case "enroll":
		err = enroll(ctx, args[1:], getenv, stdin, stdout, stderr)
	case "run":
		err = serve(ctx, args[1:], getenv, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		fmt.Fprintf(stderr, "nia-edge: unknown command %q (enroll, run, version)\n", args[0])
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "nia-edge: %v\n", err)
		return 1
	}
	return 0
}

var unsafeInName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// hostname is this machine's name in the form Nia accepts: letters, digits,
// dot, underscore and hyphen, starting with a letter or a digit.
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		name = ""
	}
	name = strings.TrimLeft(unsafeInName.ReplaceAllString(name, "-"), "._-")
	if len(name) > 128 {
		name = name[:128]
	}
	if name == "" {
		return "unknown"
	}
	return name
}

func report() niaclient.Report {
	return niaclient.Report{Hostname: hostname(), OS: runtime.GOOS, Arch: runtime.GOARCH, Version: version}
}

func statePath(flagValue string, getenv func(string) string) string {
	if flagValue != "" {
		return flagValue
	}
	if fromEnv := getenv("EDGE_STATE"); fromEnv != "" {
		return fromEnv
	}
	return defaultState
}

func readToken(tokenFile string, getenv func(string) string, stdin io.Reader) (string, error) {
	token := getenv("NIA_ENROLL_TOKEN")
	switch {
	case token != "":
	case tokenFile != "":
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		token = string(raw)
	default:
		line, err := bufio.NewReader(io.LimitReader(stdin, 1024)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		token = line
	}
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "nen_") {
		return "", errors.New("no enrollment token: set NIA_ENROLL_TOKEN, pass -token-file, or write the token on standard input (it starts with nen_)")
	}
	return token, nil
}

func enroll(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nia-edge enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	niaURL := flags.String("url", getenv("NIA_URL"), "URL of the Nia instance (or NIA_URL)")
	stateFile := flags.String("state", "", "state file (or EDGE_STATE; default "+defaultState+")")
	tokenFile := flags.String("token-file", "", "file holding the enrollment token")
	force := flags.Bool("force", false, "enroll again and replace the key this machine already has")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q: the token is never given on the command line", flags.Arg(0))
	}
	base, err := niaclient.ParseBaseURL(*niaURL)
	if err != nil {
		return err
	}
	path := statePath(*stateFile, getenv)
	if _, err := state.Load(path); err == nil && !*force {
		return fmt.Errorf("this machine is already enrolled (%s): use -force to replace its key", path)
	} else if err != nil && !errors.Is(err, state.ErrNotEnrolled) && !*force {
		return err
	}
	token, err := readToken(*tokenFile, getenv, stdin)
	if err != nil {
		return err
	}
	// A token is used once: it must not be spent if its key cannot be kept.
	if err := state.CheckWritable(path); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	client := &niaclient.Client{Base: base, HTTP: niaclient.NewHTTPClient(30 * time.Second)}
	enrolled, err := client.Enroll(ctx, token, report())
	if err != nil {
		return err
	}
	saved := &state.State{
		NiaURL:       base.String(),
		MachineID:    enrolled.MachineID,
		Key:          enrolled.Key,
		Role:         enrolled.Role,
		Upstream:     enrolled.Upstream,
		KeyExpiresAt: enrolled.KeyExpiresAt,
		EnrolledAt:   time.Now().UTC(),
	}
	if err := state.Save(path, saved); err != nil {
		return fmt.Errorf("enrolled as machine %s, but the key could not be written to %s (%w): revoke this machine in the console and enroll again", enrolled.MachineID, path, err)
	}
	fmt.Fprintf(stdout, "enrolled as machine %s, role %s, upstream %s; key kept in %s\n", enrolled.MachineID, enrolled.Role, enrolled.Upstream, path)
	return nil
}

// machineStatus is what the last heartbeat learned, for the health route.
type machineStatus struct {
	mu    sync.Mutex
	value string
}

func (s *machineStatus) set(value string) {
	s.mu.Lock()
	s.value = value
	s.mu.Unlock()
}

func (s *machineStatus) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value
}

func serve(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nia-edge run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateFile := flags.String("state", "", "state file (or EDGE_STATE; default "+defaultState+")")
	listen := flags.String("listen", getenv("EDGE_LISTEN"), "address of the relay (or EDGE_LISTEN; default 127.0.0.1:8787)")
	proxyListen := flags.String("proxy-listen", getenv("EDGE_PROXY_LISTEN"), "address of the egress proxy (or EDGE_PROXY_LISTEN; default 127.0.0.1:3128; \"off\" to disable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *listen == "" {
		*listen = "127.0.0.1:8787"
	}
	if *proxyListen == "" {
		*proxyListen = "127.0.0.1:3128"
	}
	saved, err := state.Load(statePath(*stateFile, getenv))
	if errors.Is(err, state.ErrNotEnrolled) {
		return errors.New("this machine is not enrolled: run nia-edge enroll first")
	}
	if err != nil {
		return err
	}
	base, err := niaclient.ParseBaseURL(saved.NiaURL)
	if err != nil {
		return err
	}
	// The run links this machine's conversations: what one read hardens the
	// others. NIA_RUN=none unlinks them.
	// The egress proxy is one session of this machine. By default it shares
	// its run with the conversations: what a conversation read hardens the
	// network, and what came back from the network hardens the conversations.
	session := getenv("NIA_SESSION")
	if session == "" {
		session = "edge-" + hostname()
		if len(session) > 128 {
			session = session[:128]
		}
	}
	if !relay.ValidRun(session) {
		return errors.New("NIA_SESSION: 1 to 128 characters of A-Z a-z 0-9 . _ : -")
	}
	run := getenv("NIA_RUN")
	switch run {
	case "":
		run = session
	case "none":
		run = ""
	}
	if run != "" && !relay.ValidRun(run) {
		return errors.New("NIA_RUN: 1 to 128 characters of A-Z a-z 0-9 . _ : -")
	}
	wait := 0
	if raw := getenv("EDGE_APPROVAL_WAIT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 900 {
			return errors.New("EDGE_APPROVAL_WAIT: seconds a held connection waits for a reviewer, 0 to 900")
		}
		wait = parsed
	}
	var allowPrivate []string
	for _, host := range strings.Split(getenv("EDGE_ALLOW_PRIVATE"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			allowPrivate = append(allowPrivate, host)
		}
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	status := &machineStatus{value: "unknown"}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: relay.New(relay.Options{Nia: base, Key: saved.Key, Run: run, Status: status.get, Logger: logger}),
		// Headers must arrive promptly. Bodies and answers have no time
		// limit: a model answer streams, and a held call waits for a reviewer.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	fmt.Fprintf(stdout, "nia-edge %s: listening on %s, Nia at %s, machine %s, role %s\n", version, listener.Addr(), base, saved.MachineID, saved.Role)

	var proxy *http.Server
	served := make(chan error, 2)
	if *proxyListen != "off" {
		proxyListener, err := net.Listen("tcp", *proxyListen)
		if err != nil {
			listener.Close()
			return err
		}
		proxy = &http.Server{
			Handler: egress.New(egress.Options{
				Authority: &egress.Remote{
					Base: base,
					Key:  saved.Key,
					// No time limit on the client: each call sets its own, which
					// covers the wait for a reviewer.
					HTTP:   niaclient.NewHTTPClient(0),
					Wait:   wait,
					Logger: logger,
				},
				Session:      session,
				Run:          run,
				AllowPrivate: allowPrivate,
				Logger:       logger,
			}),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		}
		fmt.Fprintf(stdout, "nia-edge %s: egress proxy on %s, session %s\n", version, proxyListener.Addr(), session)
		go func() { served <- proxy.Serve(proxyListener) }()
	}

	beats := make(chan struct{})
	go func() {
		defer close(beats)
		heartbeat(ctx, &niaclient.Client{Base: base, HTTP: niaclient.NewHTTPClient(15 * time.Second)}, saved.Key, status, logger)
	}()
	go func() { served <- server.Serve(listener) }()

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		server.Close()
	}
	if proxy != nil {
		// Tunnels are taken over from the server: Close ends its listener,
		// and the tunnels end with the process.
		proxy.Close()
	}
	<-beats
	return nil
}

// heartbeat reports to Nia until ctx ends. A failure is logged and tried
// again at the next beat: the relay keeps running, and Nia refuses the calls
// of a key it no longer accepts.
func heartbeat(ctx context.Context, client *niaclient.Client, key string, status *machineStatus, logger *slog.Logger) {
	interval := 30 * time.Second
	last := ""
	for {
		beat, err := client.Heartbeat(ctx, key, report(), "")
		now := "active"
		var refused *niaclient.Refused
		switch {
		case ctx.Err() != nil:
			return
		case errors.As(err, &refused):
			now = fmt.Sprintf("refused (%d %s)", refused.Status, refused.Code)
		case err != nil:
			now = "unreachable"
		case !beat.RoleInPolicy:
			now = "role missing from the policy"
		}
		if err == nil && beat.HeartbeatSeconds >= 5 && beat.HeartbeatSeconds <= 3600 {
			interval = time.Duration(beat.HeartbeatSeconds) * time.Second
		}
		if now != last {
			if now == "active" {
				logger.Info("heartbeat accepted", "machine", beat.MachineID, "role", beat.Role)
			} else if err != nil {
				logger.Error("heartbeat failed", "status", now, "error", err.Error())
			} else {
				logger.Error("heartbeat accepted, but this machine's calls will be refused", "status", now)
			}
			last = now
		}
		status.set(now)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
