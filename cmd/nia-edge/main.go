// Command nia-edge runs next to an agent, on the machine that runs it. It is
// the agent's only way to its model and its tools: every call goes to Nia
// with this machine's key, and Nia decides.
//
//	nia-edge enroll -url https://nia.example   exchange a one-time token for this machine's key
//	nia-edge run                               relay the agent's calls and report to Nia
//	nia-edge doctor                            from the agent's user: is nia-edge its only way out?
//	nia-edge health                            is nia-edge running, and does it reach Nia?
//	nia-edge mcp add|remove|list|serve|relay   the agent's MCP servers, each in a container
//	nia-edge version
//
// The enrollment token is read from NIA_ENROLL_TOKEN, from -token-file, or
// from standard input: never from the command line, which other users of the
// machine can read.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/GetKlaros/nia-edge/internal/doctor"
	"github.com/GetKlaros/nia-edge/internal/egress"
	"github.com/GetKlaros/nia-edge/internal/engine"
	"github.com/GetKlaros/nia-edge/internal/hooks"
	"github.com/GetKlaros/nia-edge/internal/hostd"
	"github.com/GetKlaros/nia-edge/internal/hostmcp"
	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/localmcp"
	"github.com/GetKlaros/nia-edge/internal/mcpd"
	"github.com/GetKlaros/nia-edge/internal/niaclient"
	"github.com/GetKlaros/nia-edge/internal/policy"
	"github.com/GetKlaros/nia-edge/internal/relay"
	"github.com/GetKlaros/nia-edge/internal/remotemcp"
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
		fmt.Fprintln(stderr, "usage: nia-edge enroll|provider|run|hostd|mcp|agents|hook|doctor|health|version")
		return 2
	}
	var err error
	switch args[0] {
	case "enroll":
		err = enroll(ctx, args[1:], getenv, stdin, stdout, stderr)
	case "run":
		err = serve(ctx, args[1:], getenv, stdout, stderr)
	case "provider":
		err = provider(args[1:], getenv, stdin, stdout, stderr)
	case "hostd":
		err = hostdCommand(ctx, args[1:], getenv, stdout, stderr)
	case "mcp":
		err = mcpCommand(ctx, args[1:], getenv, stdin, stdout, stderr)
	case "agents":
		err = agentsCommand(args[1:], getenv, stdout, stderr)
	case "hook":
		err = hookCommand(args[1:], getenv, stdin, stdout, stderr)
	case "doctor":
		return check(ctx, args[1:], getenv, stdout, stderr)
	case "health":
		return health(ctx, args[1:], getenv, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		fmt.Fprintf(stderr, "nia-edge: unknown command %q (enroll, provider, run, hostd, mcp, agents, doctor, health, version)\n", args[0])
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

func edgeFlag(flags *flag.FlagSet, getenv func(string) string) *string {
	edge := getenv("NIA_EDGE")
	if edge == "" {
		edge = "http://127.0.0.1:8787"
	}
	return flags.String("edge", edge, "relay of nia-edge, as the agent reaches it (or NIA_EDGE)")
}

// health asks the relay's health route: 0 when nia-edge runs and reaches
// Nia, 1 otherwise. It records nothing.
func health(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("nia-edge health", flag.ContinueOnError)
	flags.SetOutput(stderr)
	relayURL := edgeFlag(flags, getenv)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(*relayURL, "/")+"/edge/health", nil)
	if err != nil {
		fmt.Fprintf(stderr, "nia-edge: %v\n", err)
		return 2
	}
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintf(stdout, "nia-edge is not reachable at %s\n", *relayURL)
		return 1
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	fmt.Fprintln(stdout, strings.TrimSpace(string(body)))
	if response.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// check runs the doctor: 0 isolated, 1 breached, 2 could not check.
func check(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("nia-edge doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	relayURL := edgeFlag(flags, getenv)
	timeout := flags.Duration("timeout", 4*time.Second, "time given to each attempt to get out")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *timeout <= 0 {
		return doctor.CouldNotCheck
	}
	return doctor.Run(ctx, doctor.Options{Edge: *relayURL, Timeout: *timeout, Out: stdout})
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
		PolicyKey:    enrolled.PolicyKey,
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
	policies := &keeper{path: filepath.Join(filepath.Dir(statePath(*stateFile, getenv)), "policy.json"), key: saved.PolicyKey, machineID: saved.MachineID}
	policies.load(logger)
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	// Tools of MCP servers that run here (host actions, and the agent's
	// servers in containers): calls released by the model path.
	releases := &local.Releases{Prefix: "mcp__"}
	hostSocket := getenv("NIA_HOSTD_SOCKET")
	if hostSocket == "" {
		hostSocket = defaultHostdSocket
	}
	host := &hostmcp.Handler{
		Catalogue: func() (*hostd.Catalogue, error) {
			rules := policies.rules()
			if rules == nil {
				return nil, errors.New("no policy in force")
			}
			return hostd.ParseCatalogue(rules.Role.Host)
		},
		Releases: releases,
		Prefix:   "mcp__host__",
		Host:     &hostd.Client{Socket: hostSocket},
		Version:  version,
	}
	// The MCP servers hosted by their vendor: nia-edge holds their token.
	remotes := &remotemcp.Handler{
		Clients:  map[string]*remotemcp.Client{},
		Nia:      pinner{client: &niaclient.Client{Base: base, HTTP: niaclient.NewHTTPClient(30 * time.Second)}, key: saved.Key},
		Releases: releases,
		Version:  version,
	}
	runAuthority := &local.Remote{Base: base, Key: saved.Key, Run: run, HTTP: niaclient.NewHTTPClient(30 * time.Second)}
	remotes.Taint = func(ctx context.Context, session, source string) error {
		return runAuthority.Ingested(ctx, session, source)
	}
	vendors := remotemcp.NewHTTPClient(2 * time.Minute)
	var renewed sync.Mutex
	for name, remote := range saved.Remote {
		endpoint, err := remotemcp.ValidURL(remote.URL)
		if err != nil || !mcpd.ValidName(name) || remote.Header == "" || remote.Value == "" {
			logger.Error("an MCP server hosted by its vendor is left out: its entry cannot be used", "server", name)
			continue
		}
		client := &remotemcp.Client{Endpoint: remotemcp.Endpoint{Name: name, URL: endpoint, Header: remote.Header, Value: remote.Value}, HTTP: vendors, Version: version}
		if remote.OAuth != nil {
			// A server nia-edge signed in with: its token renewed, and kept.
			name := name
			client.Renewer = &remotemcp.Renewer{HTTP: vendors, OAuth: *remote.OAuth, Save: func(access string, oauth remotemcp.OAuth) error {
				renewed.Lock()
				defer renewed.Unlock()
				current, err := state.Load(statePath(*stateFile, getenv))
				if err != nil {
					return err
				}
				entry := current.Remote[name]
				if entry == nil {
					return errors.New("the server is no longer in the state file")
				}
				entry.Value = "Bearer " + access
				entry.OAuth = &oauth
				return state.Save(statePath(*stateFile, getenv), current)
			}}
		}
		remotes.Clients[name] = client
	}
	if len(remotes.Clients) > 0 {
		fmt.Fprintf(stdout, "nia-edge %s: %d MCP servers hosted by their vendor, their tokens held here\n", version, len(remotes.Clients))
	}
	// The agent's MCP servers that run here, each in a container of nia-mcp.
	servers := &localmcp.Handler{Servers: map[string]*localmcp.Server{}, Releases: releases, Version: version}
	if len(saved.MCP) > 0 {
		mcpSocket := getenv("NIA_MCPD_SOCKET")
		if mcpSocket == "" {
			mcpSocket = defaultMCPSocket
		}
		cache := filepath.Join(filepath.Dir(statePath(*stateFile, getenv)), "mcp-tools")
		if err := os.MkdirAll(cache, 0o700); err != nil {
			return err
		}
		for name, entry := range saved.MCP {
			servers.Servers[name] = &localmcp.Server{
				Launch:   mcpd.Launch{Name: name, Image: entry.Image, Command: entry.Command, Env: entry.Env},
				Launcher: &mcpd.Client{Socket: mcpSocket},
				Cache:    cache,
			}
		}
		defer func() {
			for _, server := range servers.Servers {
				server.Close()
			}
		}()
	}
	modelPath := "provider"
	if saved.Provider == nil {
		modelPath = "none"
		if getenv("NIA_RELAY_MODEL_CALLS") == "yes" {
			modelPath = "relay"
		}
	}
	var handler http.Handler = relay.New(relay.Options{Nia: base, Key: saved.Key, Run: run, Status: status.get, Policy: policies.status, Logger: logger})
	if saved.Provider == nil && getenv("NIA_RELAY_MODEL_CALLS") != "yes" {
		// No provider on this machine: its prompts do not leave for Nia.
		// NIA_RELAY_MODEL_CALLS=yes sends them, for a Nia that relays them.
		relayed := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if format, ok := local.Format(strings.TrimSuffix(r.URL.Path, "/")); ok {
				local.Refuse(w, format, http.StatusServiceUnavailable, "local_mode_required",
					"This machine has no model provider: set one with `nia-edge provider`")
				return
			}
			relayed.ServeHTTP(w, r)
		})
		fmt.Fprintf(stdout, "nia-edge %s: no model provider on this machine; model calls are refused until one is set\n", version)
	}
	if saved.Provider != nil {
		// Model calls go from this machine to the provider; Nia decides the
		// tool calls and sees neither the prompts nor the answers.
		providerURL, err := providerBaseURL(saved.Provider.BaseURL)
		if err != nil {
			return err
		}
		remote := &local.Remote{Base: base, Key: saved.Key, Run: run, HTTP: niaclient.NewHTTPClient(time.Duration(30+wait) * time.Second), Wait: wait}
		model := &local.Handler{
			Provider:      providerURL,
			Key:           saved.Provider.Key,
			Anthropic:     saved.Provider.Format == "anthropic",
			SessionHeader: providerSessionHeader(saved.Provider, providerURL),
			HTTP:          local.NewProviderClient(15 * time.Minute),
			Nia:           remote,
			Budgets:       remote,
			Rules:         policies.rules,
			Releases:      releases,
			Review:        planReview(&hostd.Client{Socket: hostSocket}),
			Logger:        logger,
		}
		relayed := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := local.Format(r.URL.Path); ok && r.URL.RawPath == "" && r.Method == http.MethodPost {
				model.ServeHTTP(w, r)
				return
			}
			relayed.ServeHTTP(w, r)
		})
		fmt.Fprintf(stdout, "nia-edge %s: model calls go from this machine to %s; Nia decides the tool calls\n", version, providerURL.Host)
	}
	// The tool hooks of the agents that run their own tools (Claude Code,
	// Codex): decided here as the model path decides, with or without a
	// provider on this machine.
	toolHooks := &hooks.Handler{
		Nia:      &local.Remote{Base: base, Key: saved.Key, Run: run, HTTP: niaclient.NewHTTPClient(time.Duration(30+wait) * time.Second), Wait: wait},
		Rules:    policies.rules,
		Releases: releases,
		Logger:   logger,
	}
	// The agent's MCP server of host actions, on nia-edge's own address.
	agentRoutes := handler
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hooks.Route(r.URL.Path) != "" && r.URL.RawPath == "" {
			toolHooks.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/host/mcp" && r.URL.RawPath == "" {
			host.ServeHTTP(w, r)
			return
		}
		if localmcp.Route(r.URL.Path) != "" {
			servers.ServeHTTP(w, r)
			return
		}
		if remotemcp.Route(r.URL.Path) != "" {
			remotes.ServeHTTP(w, r)
			return
		}
		agentRoutes.ServeHTTP(w, r)
	})
	server := &http.Server{
		Handler: handler,
		// Headers must arrive promptly. Bodies and answers have no time
		// limit: a model answer streams, and a held call waits for a reviewer.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	fmt.Fprintf(stdout, "nia-edge %s: listening on %s, Nia at %s, machine %s, role %s\n", version, listener.Addr(), base, saved.MachineID, saved.Role)

	var proxy *http.Server
	served := make(chan error, 3)
	authority := &egress.Remote{
		Base: base,
		Key:  saved.Key,
		// No time limit on the client: each call sets its own, which
		// covers the wait for a reviewer.
		HTTP:   niaclient.NewHTTPClient(0),
		Wait:   wait,
		Logger: logger,
	}
	if len(saved.MCP) > 0 {
		// The MCP servers' only way out: nia-mcp hands each of their
		// connections over this socket, under the server's name.
		mcpUser := getenv("NIA_MCP_USER")
		if mcpUser == "" {
			mcpUser = "nia-mcp"
		}
		egressSocket := getenv("EDGE_MCP_EGRESS_SOCKET")
		if egressSocket == "" {
			egressSocket = defaultMCPEgress
		}
		if uid, err := lookupUID(mcpUser); err != nil {
			logger.Error("the MCP servers have no way out: their user is unknown", "user", mcpUser, "error", err.Error())
		} else if listener, err := listenServers(egressSocket); err != nil {
			logger.Error("the MCP servers have no way out", "socket", egressSocket, "error", err.Error())
		} else {
			proxies := map[string]http.Handler{}
			for name := range saved.MCP {
				proxies[name] = egress.New(egress.Options{Authority: authority, Session: session, Run: run, Server: name, AllowPrivate: allowPrivate, Logger: logger})
			}
			fmt.Fprintf(stdout, "nia-edge %s: %d MCP servers in containers, their way out on %s\n", version, len(proxies), egressSocket)
			go func() {
				served <- egress.ServeServers(ctx, listener, func(peer uint32) bool { return peer == uid }, func(name string) http.Handler { return proxies[name] }, logger)
			}()
		}
	}
	if *proxyListen != "off" {
		proxyListener, err := net.Listen("tcp", *proxyListen)
		if err != nil {
			listener.Close()
			return err
		}
		proxy = &http.Server{
			Handler: egress.New(egress.Options{
				Authority:    authority,
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
		agentsReport := getenv("EDGE_AGENTS_REPORT")
		if agentsReport == "" {
			agentsReport = defaultReport
		}
		heartbeat(ctx, &niaclient.Client{Base: base, HTTP: niaclient.NewHTTPClient(15 * time.Second)}, saved.Key, modelPath, status, policies, journalAnchor(&hostd.Client{Socket: hostSocket}), agentsReport, logger)
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

// listenServers opens the socket of the MCP servers' way out: anyone may
// connect, only nia-mcp's user is served.
func listenServers(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o711); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// keeper holds the signed policy of this machine: read from disk at start,
// refreshed from the server, and gone once it has expired.
type keeper struct {
	mu        sync.Mutex
	current   *policy.Policy
	note      string
	path      string
	key       *policy.Key
	machineID string
	// ready is the policy in force read by the engine, for its digest.
	ready *local.Rules
}

// rules returns the policy in force, ready to decide, or nil when there is
// none or this nia-edge cannot read its role: then Nia decides from the
// arguments.
func (k *keeper) rules() *local.Rules {
	current := k.valid(time.Now())
	if current == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ready != nil && k.ready.Digest == current.Digest {
		return k.ready
	}
	role, err := engine.ParseRole(current.Role)
	if err != nil {
		return nil
	}
	dispatchers, err := engine.ParseDispatchers(current.Dispatchers)
	if err != nil {
		return nil
	}
	k.ready = &local.Rules{Role: role, Dispatchers: dispatchers, Digest: current.Digest}
	return k.ready
}

// valid returns the policy in force at now, or nil.
func (k *keeper) valid(now time.Time) *policy.Policy {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.current != nil && !now.Before(k.current.NotAfter) {
		k.current = nil
		k.note = "expired"
	}
	return k.current
}

// status is what the health route says about the policy.
func (k *keeper) status() string {
	current := k.valid(time.Now())
	k.mu.Lock()
	defer k.mu.Unlock()
	if current == nil {
		return "none (" + k.note + ")"
	}
	described := fmt.Sprintf("version %s, digest %s, valid until %s", current.Version, current.Digest, current.NotAfter.UTC().Format(time.RFC3339))
	if k.note != "" {
		described += " (not refreshed: " + k.note + ")"
	}
	return described
}

func (k *keeper) set(current *policy.Policy, note string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if current != nil {
		k.current = current
	}
	k.note = note
}

// fail notes why there is no newer policy, and logs it once per reason.
func (k *keeper) fail(logger *slog.Logger, note string) {
	k.mu.Lock()
	again := k.note == note
	k.note = note
	k.mu.Unlock()
	if !again {
		logger.Error("no new policy", "reason", note)
	}
}

// load reads the policy kept on disk. It is verified like one from the
// server: a file that was changed, or has expired, is no policy.
func (k *keeper) load(logger *slog.Logger) {
	if k.key == nil {
		k.set(nil, "the server signs none")
		return
	}
	signed, err := policy.Load(k.path)
	if errors.Is(err, policy.ErrNone) {
		k.set(nil, "not fetched yet")
		return
	}
	if err == nil {
		var opened *policy.Policy
		if opened, err = policy.Open(signed, *k.key, k.machineID, time.Now()); err == nil {
			k.set(opened, "")
			logger.Info("policy read from disk", "version", opened.Version, "digest", opened.Digest, "valid_until", opened.NotAfter.UTC().Format(time.RFC3339))
			return
		}
	}
	k.set(nil, "the one on disk was refused")
	logger.Warn("the policy on disk was refused", "error", err.Error())
}

// refresh fetches a new policy when the server has another one, or when the
// one in force is past half of its life. It reports whether the policy in
// force changed. A failure keeps the policy in force until it expires.
func (k *keeper) refresh(ctx context.Context, client *niaclient.Client, machineKey string, beat *niaclient.Beat, logger *slog.Logger) bool {
	if k.key == nil || beat.PolicyKeyID == "" {
		return false
	}
	if beat.PolicyKeyID != k.key.ID {
		k.fail(logger, "the server signs with another key ("+beat.PolicyKeyID+") than the one learned at enrollment ("+k.key.ID+"): enroll again")
		return false
	}
	now := time.Now()
	current := k.valid(now)
	if current != nil && beat.Policy != nil && current.Digest == beat.Policy.Digest && now.Before(current.IssuedAt.Add(current.NotAfter.Sub(current.IssuedAt)/2)) {
		return false
	}
	signed, err := client.SignedPolicy(ctx, machineKey)
	if err != nil {
		k.fail(logger, "the server gave none: "+err.Error())
		return false
	}
	opened, err := policy.Open(signed, *k.key, k.machineID, now)
	if err != nil {
		k.fail(logger, "the one from the server was refused: "+err.Error())
		return false
	}
	if err := policy.Save(k.path, signed); err != nil {
		logger.Warn("the policy could not be kept on disk", "error", err.Error())
	}
	changed := current == nil || current.Digest != opened.Digest
	k.set(opened, "")
	if changed {
		logger.Info("policy in force", "version", opened.Version, "digest", opened.Digest, "valid_until", opened.NotAfter.UTC().Format(time.RFC3339))
	}
	return changed
}

// providerBaseURL reads the base URL of a model provider: https, or http on
// this machine for a model that runs here.
func providerBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("the provider URL must look like https://api.example.com/v1")
	}
	host := parsed.Hostname()
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local) {
		return nil, errors.New("the provider URL must be https (http only for a model on this machine)")
	}
	return parsed, nil
}

// provider sets, shows or removes the model provider this machine calls
// itself. The key comes from NIA_PROVIDER_KEY, a file or standard input:
// never from the command line.
func provider(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nia-edge provider", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateFile := flags.String("state", "", "state file (or EDGE_STATE; default "+defaultState+")")
	base := flags.String("url", "", "base URL of the provider, as its clients use it (https://api.example.com/v1)")
	format := flags.String("format", "openai", "how the key is sent: openai (Authorization: Bearer) or anthropic (x-api-key)")
	keyFile := flags.String("key-file", "", "file holding the provider key")
	sessionHeader := flags.String("session-header", "", "header that carries an id of the conversation, for a provider that routes by it (default x-opencode-session for opencode.ai, none otherwise)")
	remove := flags.Bool("remove", false, "forget the provider: model calls go through Nia again")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		// Not echoed: it may be the key.
		return errors.New("unexpected argument: the key is never given on the command line")
	}
	path := statePath(*stateFile, getenv)
	saved, err := state.Load(path)
	if errors.Is(err, state.ErrNotEnrolled) {
		return errors.New("this machine is not enrolled: run nia-edge enroll first")
	}
	if err != nil {
		return err
	}
	switch {
	case *remove:
		saved.Provider = nil
		if err := state.Save(path, saved); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "provider removed: model calls go through Nia again (restart nia-edge)")
		return nil
	case *base == "":
		if saved.Provider == nil {
			fmt.Fprintln(stdout, "no provider: model calls go through Nia")
		} else {
			fmt.Fprintf(stdout, "provider %s (%s): model calls go from this machine\n", saved.Provider.BaseURL, saved.Provider.Format)
		}
		return nil
	}
	parsed, err := providerBaseURL(*base)
	if err != nil {
		return err
	}
	if *format != "openai" && *format != "anthropic" {
		return errors.New("-format is openai or anthropic")
	}
	key := getenv("NIA_PROVIDER_KEY")
	switch {
	case key != "":
	case *keyFile != "":
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		key = string(raw)
	default:
		line, err := bufio.NewReader(io.LimitReader(stdin, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		key = line
	}
	key = strings.TrimSpace(key)
	if key == "" || strings.ContainsAny(key, " \t\r\n") {
		return errors.New("no provider key: set NIA_PROVIDER_KEY, pass -key-file, or write the key on standard input")
	}
	if *sessionHeader != "" && !validSessionHeader(*sessionHeader) {
		return errors.New("-session-header is a lower-case header name that carries no credential")
	}
	saved.Provider = &state.Provider{BaseURL: parsed.String(), Key: key, Format: *format, SessionHeader: *sessionHeader}
	if err := state.Save(path, saved); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "provider %s (%s) kept in %s: model calls go from this machine (restart nia-edge)\n", parsed, *format, path)
	return nil
}

// validSessionHeader accepts a lower-case header name that is not one nia-edge
// sets itself or one that carries a credential.
func validSessionHeader(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	switch name {
	case "authorization", "x-api-key", "host", "content-type", "content-length", "cookie", "proxy-authorization", "transfer-encoding", "connection":
		return false
	}
	return true
}

// providerSessionHeader is the session header the provider gets: the one
// kept, else x-opencode-session for OpenCode, which refuses requests without
// it.
func providerSessionHeader(provider *state.Provider, base *url.URL) string {
	if provider.SessionHeader != "" {
		if validSessionHeader(provider.SessionHeader) {
			return provider.SessionHeader
		}
		return ""
	}
	host := strings.ToLower(base.Hostname())
	if host == "opencode.ai" || strings.HasSuffix(host, ".opencode.ai") {
		return "x-opencode-session"
	}
	return ""
}

// planReview asks nia-hostd what a reviewer must see of a plan; nil when it
// does not answer: Nia then tells the reviewer it could not check the plan.
func planReview(host *hostd.Client) func(context.Context, string) json.RawMessage {
	return func(ctx context.Context, plan string) json.RawMessage {
		askCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		resp, err := host.Do(askCtx, hostd.Request{Action: hostd.PlanReviewAction, Name: plan})
		if err != nil || !resp.OK || !json.Valid([]byte(resp.Output)) {
			return nil
		}
		return json.RawMessage(resp.Output)
	}
}

// journalAnchor asks nia-hostd for the head of its journal and the hash of
// entry at; nil when nia-hostd does not answer (it may not be installed).
func journalAnchor(host *hostd.Client) func(context.Context, int64) *niaclient.Journal {
	return func(ctx context.Context, at int64) *niaclient.Journal {
		askCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		resp, err := host.Do(askCtx, hostd.Request{Action: hostd.HeadAction, At: at})
		if err != nil || !resp.OK {
			return nil
		}
		var anchor niaclient.Journal
		if json.Unmarshal([]byte(resp.Output), &anchor) != nil {
			return nil
		}
		return &anchor
	}
}

// heartbeat reports to Nia until ctx ends, and keeps the signed policy
// fresh. A failure is logged and tried again at the next beat: the relay
// keeps running, and Nia refuses the calls of a key it no longer accepts.
func heartbeat(ctx context.Context, client *niaclient.Client, key, modelPath string, status *machineStatus, policies *keeper, journal func(context.Context, int64) *niaclient.Journal, agentsReport string, logger *slog.Logger) {
	interval := 30 * time.Second
	last := ""
	var anchorAt int64
	// The agents found on the machine go to a Nia that said it takes them:
	// an older Nia refuses a heartbeat with a field it does not know.
	acceptsAgents := false
	for {
		digest := ""
		if current := policies.valid(time.Now()); current != nil {
			digest = current.Digest
		}
		reported := report()
		reported.ModelPath = modelPath
		if journal != nil {
			reported.Journal = journal(ctx, anchorAt)
		}
		if acceptsAgents {
			if found := readReport(agentsReport); found != nil {
				reported.Agents, _ = json.Marshal(found)
			}
		}
		beat, err := client.Heartbeat(ctx, key, reported, digest)
		if err == nil {
			anchorAt = beat.JournalSeq
			acceptsAgents = slices.Contains(beat.Accepts, "agents")
		}
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
		wait := interval
		if err == nil && policies.refresh(ctx, client, key, beat, logger) {
			// Tell the server at once which policy is now in force.
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// pinner asks Nia which tools of a vendor's MCP server the agent may see.
type pinner struct {
	client *niaclient.Client
	key    string
}

func (p pinner) Pin(ctx context.Context, server string, tools []json.RawMessage) ([]string, error) {
	return p.client.PinTools(ctx, p.key, server, tools)
}
