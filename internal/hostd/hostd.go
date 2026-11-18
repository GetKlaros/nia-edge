package hostd

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/engine"
	"github.com/GetKlaros/nia-edge/internal/policy"
	"github.com/GetKlaros/nia-edge/internal/state"
)

// Request is one action asked of nia-hostd.
type Request struct {
	Action string `json:"action"`
	// Name is the action's one parameter: a service, a package or a sync pair.
	Name string `json:"name"`
	// Call is the hash of the tool call the model path released, for the
	// journal.
	Call string `json:"call,omitempty"`
	// Script is a dry run's.
	Script string `json:"script,omitempty"`
	// At is the entry whose hash a journal_head request asks for.
	At int64 `json:"at,omitempty"`
}

// Response is what nia-hostd answers.
type Response struct {
	OK bool `json:"ok"`
	// Output is the end of what the program printed.
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
	// Journal is the id of the journal entry, for an undo.
	Journal string `json:"journal,omitempty"`
}

// The actions, each with the kind of name it takes.
const (
	ServiceStatus  = "service_status"
	ServiceRestart = "service_restart"
	ServiceReload  = "service_reload"
	PackageInstall = "package_install"
	Sync           = "sync"
)

// Actions lists the actions nia-hostd knows.
var Actions = []string{ServiceStatus, ServiceRestart, ServiceReload, PackageInstall, Sync, DryRunAction, ApplyAction}

// Runner runs a program. Exec runs it; tests use another.
type Runner interface {
	Run(ctx context.Context, env []string, argv ...string) (output string, err error)
}

// Exec runs programs with execve, no shell, and the environment it is given.
type Exec struct{}

const outputLimit = 16 << 10

func (Exec) Run(ctx context.Context, env []string, argv ...string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if len(out) > outputLimit {
		out = append([]byte("…"), out[len(out)-outputLimit:]...)
	}
	return string(out), err
}

// DryRun records what it would run and runs nothing.
type DryRun struct {
	mu    sync.Mutex
	Calls [][]string
	// Answers maps a program to what it prints; others print nothing.
	Answers map[string]string
}

func (d *DryRun) Run(_ context.Context, _ []string, argv ...string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Calls = append(d.Calls, argv)
	return d.Answers[strings.Join(argv, " ")], nil
}

// The environment of what nia-hostd runs: nothing inherited.
var baseEnv = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=/root"}

// Server is nia-hostd.
type Server struct {
	// StatePath and PolicyPath are nia-edge's state file and signed policy:
	// the pinned key, the machine id and the role come from them.
	StatePath, PolicyPath string
	// JournalPath is where every action is written, one JSON line each.
	JournalPath string
	Run         Runner
	// Sandbox runs dry runs; nil runs none.
	Sandbox Sandbox
	// EtcRoot, ScratchRoot and BackupRoot are /etc, where dry runs keep their
	// layers and where applies save what they replace; tests set others.
	EtcRoot, ScratchRoot, BackupRoot string
	// Installed reports whether a check's program is installed; nil looks.
	Installed func(program string) bool
	Now       func() time.Time
	Logger    *slog.Logger

	mu    sync.Mutex
	plans map[string]*plan
}

// Entry is one line of the journal.
type Entry struct {
	// Seq numbers the entry from 1; Prev is the SHA-256 of the line before
	// it (see chain.go).
	Seq    int64     `json:"seq,omitempty"`
	Prev   string    `json:"prev,omitempty"`
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Name   string    `json:"name"`
	Call   string    `json:"call,omitempty"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	// Undo is how to undo the action, when it can be: a package that was not
	// installed before is removed.
	Undo *Request `json:"undo,omitempty"`
	// Of names the entry an undo undid.
	Of string `json:"of,omitempty"`
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Catalogue is the catalogue of the role in force, from the signed policy,
// verified here.
func (s *Server) Catalogue() (*Catalogue, error) {
	saved, err := state.Load(s.StatePath)
	if err != nil {
		return nil, err
	}
	if saved.PolicyKey == nil {
		return nil, errors.New("hostd: this machine pinned no policy key at enrollment: there is no catalogue")
	}
	signed, err := policy.Load(s.PolicyPath)
	if err != nil {
		return nil, err
	}
	opened, err := policy.Open(signed, *saved.PolicyKey, saved.MachineID, s.now())
	if err != nil {
		return nil, err
	}
	role, err := engine.ParseRole(opened.Role)
	if err != nil {
		return nil, err
	}
	return ParseCatalogue(role.Host)
}

// Do runs one request, if the catalogue in force allows it, and writes it to
// the journal.
func (s *Server) Do(ctx context.Context, req Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Action == HeadAction {
		text, _ := json.Marshal(s.anchor(req.At))
		return Response{OK: true, Output: string(text)}
	}
	// Nothing runs that could not be written after the last entry.
	if _, _, err := s.chain(); err != nil {
		return Response{Error: err.Error()}
	}
	catalogue, err := s.Catalogue()
	if err != nil {
		return Response{Error: "no catalogue in force: " + err.Error()}
	}
	if req.Action == DryRunAction {
		return s.dryRun(ctx, catalogue, req)
	}
	if req.Action == ApplyAction {
		if catalogue.Etc == nil {
			return Response{Error: "this role's catalogue allows no dry run, so no apply (no etc)"}
		}
		return s.apply(ctx, req)
	}
	argvs, undo, refusal := s.plan(ctx, catalogue, req)
	if refusal != "" {
		s.log("action refused", "action", req.Action, "name", req.Name, "reason", refusal)
		return Response{Error: refusal}
	}
	entry := Entry{ID: newID(), At: s.now().UTC(), Action: req.Action, Name: req.Name, Call: req.Call, Undo: undo}
	var output strings.Builder
	for _, run := range argvs {
		timeout := 2 * time.Minute
		if req.Action == PackageInstall || req.Action == Sync {
			timeout = 30 * time.Minute
		}
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		out, err := s.Run.Run(runCtx, run.env, run.argv...)
		cancel()
		output.WriteString(out)
		// systemctl status answers 3 for a unit that is not running: still an answer.
		var exitErr *exec.ExitError
		if err != nil && !(req.Action == ServiceStatus && errors.As(err, &exitErr) && exitErr.ExitCode() == 3) {
			entry.Error = err.Error()
			entry.Undo = nil
			break
		}
	}
	entry.OK = entry.Error == ""
	if err := s.write(entry); err != nil {
		// An action that cannot be recorded is reported as failed.
		return Response{Error: "the action ran but could not be written to the journal: " + err.Error(), Output: tail(output.String())}
	}
	s.log("action", "action", req.Action, "name", req.Name, "ok", entry.OK, "journal", entry.ID)
	return Response{OK: entry.OK, Output: tail(output.String()), Error: entry.Error, Journal: entry.ID}
}

type run struct {
	env  []string
	argv []string
}

// plan turns a request into the programs to run, or says why it may not run.
func (s *Server) plan(ctx context.Context, c *Catalogue, req Request) ([]run, *Request, string) {
	plain := func(argv ...string) run { return run{env: baseEnv, argv: argv} }
	switch req.Action {
	case ServiceStatus, ServiceRestart, ServiceReload:
		if !c.HasService(req.Name) {
			return nil, nil, fmt.Sprintf("%q is not a service of this role's catalogue", req.Name)
		}
		verb := map[string]string{ServiceStatus: "status", ServiceRestart: "restart", ServiceReload: "reload"}[req.Action]
		if verb == "status" {
			return []run{plain("systemctl", "status", "--no-pager", "--lines=20", "--", unit(req.Name))}, nil, ""
		}
		return []run{plain("systemctl", verb, "--", unit(req.Name))}, nil, ""
	case PackageInstall:
		if !c.HasPackage(req.Name) {
			return nil, nil, fmt.Sprintf("%q is not a package of this role's catalogue", req.Name)
		}
		apt := append(append([]string{}, baseEnv...), "DEBIAN_FRONTEND=noninteractive")
		var undo *Request
		status, _ := s.Run.Run(ctx, baseEnv, "dpkg-query", "-W", "-f=${Status}", "--", req.Name)
		if !strings.Contains(status, "install ok installed") {
			undo = &Request{Action: "package_remove", Name: req.Name}
		}
		return []run{
			{env: apt, argv: []string{"apt-get", "update", "-qq"}},
			{env: apt, argv: []string{"apt-get", "install", "-y", "-q", "--no-install-recommends", "--", req.Name}},
		}, undo, ""
	case Sync:
		pair := c.SyncPair(req.Name)
		if pair == nil {
			return nil, nil, fmt.Sprintf("%q is not a sync pair of this role's catalogue", req.Name)
		}
		argv := []string{"rsync", "-a"}
		if pair.Delete {
			argv = append(argv, "--delete")
		}
		argv = append(argv, "--", pair.Source+"/", pair.Destination+"/")
		return []run{plain(argv...)}, nil, ""
	}
	return nil, nil, fmt.Sprintf("%q is not an action of nia-hostd", req.Action)
}

// Undo undoes the journal entry id when it can be undone and was not.
func (s *Server) Undo(ctx context.Context, id string) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.Journal()
	if err != nil {
		return Response{Error: err.Error()}
	}
	var target *Entry
	for i := range entries {
		if entries[i].Of == id {
			return Response{Error: "already undone by " + entries[i].ID}
		}
		if entries[i].ID == id {
			target = &entries[i]
		}
	}
	if target == nil {
		return Response{Error: "no journal entry " + id}
	}
	if target.Undo != nil && target.Undo.Action == RestoreAction {
		entry := s.restoreEntry(*target)
		if err := s.write(entry); err != nil {
			return Response{Error: "restore not written to the journal: " + err.Error()}
		}
		return Response{OK: entry.OK, Error: entry.Error, Journal: entry.ID}
	}
	if target.Undo == nil || target.Undo.Action != "package_remove" || !packageName.MatchString(target.Undo.Name) {
		return Response{Error: "this action cannot be undone"}
	}
	apt := append(append([]string{}, baseEnv...), "DEBIAN_FRONTEND=noninteractive")
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	out, runErr := s.Run.Run(runCtx, apt, "apt-get", "remove", "-y", "-q", "--", target.Undo.Name)
	entry := Entry{ID: newID(), At: s.now().UTC(), Action: target.Undo.Action, Name: target.Undo.Name, OK: runErr == nil, Of: id}
	if runErr != nil {
		entry.Error = runErr.Error()
	}
	if err := s.write(entry); err != nil {
		return Response{Error: "undone but not written to the journal: " + err.Error()}
	}
	return Response{OK: entry.OK, Output: tail(out), Error: entry.Error, Journal: entry.ID}
}

// Journal reads every entry, oldest first.
func (s *Server) Journal() ([]Entry, error) {
	file, err := os.Open(s.JournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var entries []Entry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("hostd: the journal cannot be read: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

func (s *Server) write(entry Entry) error {
	_, head, err := s.chain()
	if err != nil {
		return err
	}
	entry.Seq, entry.Prev = head.Seq+1, head.Hash
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.JournalPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func (s *Server) log(message string, args ...any) {
	if s.Logger != nil {
		s.Logger.Info(message, args...)
	}
}

func tail(text string) string {
	if len(text) > outputLimit {
		return "…" + text[len(text)-outputLimit:]
	}
	return text
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b)
}

// Serve answers requests on listener until ctx ends. Each connection carries
// one request from a process whose user is allowed (allowed reports it from
// the peer's uid), and gets one answer.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener, allowed func(uid uint32) bool) error {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveConn(ctx, conn, allowed)
	}
}

func (s *Server) serveConn(ctx context.Context, conn *net.UnixConn, allowed func(uid uint32) bool) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil || !allowed(uid) {
		s.log("connection refused", "uid", uid, "error", fmt.Sprint(err))
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, 128<<10)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: "not a request"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = json.NewEncoder(conn).Encode(s.Do(ctx, req))
}

// Client asks nia-hostd, over its socket.
type Client struct {
	Socket string
}

// Do sends one request and reads the answer. An error means no answer:
// nothing is known to have run.
func (c *Client) Do(ctx context.Context, req Request) (Response, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return Response{}, fmt.Errorf("nia-hostd cannot be reached: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("nia-hostd gave no answer: %w", err)
	}
	return resp, nil
}
