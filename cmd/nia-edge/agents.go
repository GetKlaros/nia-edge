package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/GetKlaros/nia-edge/internal/agents"
	"github.com/GetKlaros/nia-edge/internal/inventory"
)

// defaultReport is where a scan run as root leaves its report, for the
// heartbeat to carry to Nia: a report, shown to admins, that decides nothing.
const defaultReport = "/var/lib/nia-edge/agents.json"

// defaultInventory is where the same scan leaves the machine's inventory
// (internal/inventory): readable by root and nia-edge only, which sends it to
// Nia, since some names under /etc are not for every user of the machine.
const defaultInventory = "/var/lib/nia-edge/inventory.json"

// agentsCommand lists the agents of every account of this machine, or
// onboards one that runs its own tools (Claude Code, Codex) so that Nia
// decides each of its tool calls, or puts it back as it was.
//
//	nia-edge agents [-json]
//	nia-edge agents onboard <agent> [-dry-run] [-model]
//	nia-edge agents status <agent>
//	nia-edge agents restore <agent>      (offboard is the same)
func agentsCommand(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "list":
			args = args[1:]
		case "onboard", "status", "restore", "offboard":
			return onboardCommand(args[0], args[1:], getenv, stdout, stderr)
		}
	}
	flags := flag.NewFlagSet("nia-edge agents", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print JSON")
	root := flags.String("root", "", "read the machine's files under this directory (tests)")
	report := flags.String("report", "", "write the report Nia receives with the heartbeat here (default "+defaultReport+" when run as root)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("agents takes no argument")
	}
	found, err := agents.Find(agents.Options{Root: *root})
	if err != nil {
		return err
	}
	if found == nil {
		found = []agents.Agent{}
	}
	if err := writeReport(*report, *root, found); err != nil {
		fmt.Fprintln(stderr, "nia-edge agents: the report for Nia was not written:", err)
	}
	if *report == "" && *root == "" {
		if err := writeInventory(context.Background(), defaultInventory); err != nil {
			fmt.Fprintln(stderr, "nia-edge agents: the machine's inventory for Nia was not written:", err)
		}
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(found)
	}
	if len(found) == 0 {
		fmt.Fprintln(stdout, "no agent found (Hermes, OpenClaw, Codex, OpenCode, Claude Code)")
		return nil
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "USER\tAGENT\tRUNNING\tMCP\tMODEL\tPROTECTION\tNEXT")
	for _, a := range found {
		servers := fmt.Sprint(a.Settings.MCPServers)
		if a.Settings.MCPServers < 0 {
			servers = "?"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.User, a.Kind, yes(a.Running), servers, a.Settings.Model, protection(a), a.Next)
	}
	return table.Flush()
}

// protection is how Nia stands between the agent and the machine.
func protection(a agents.Agent) string {
	switch {
	case a.Confined:
		return "confined"
	case a.Governed == "machine", a.Governed == "user":
		return "governed"
	}
	return "none"
}

// Report is what the heartbeat carries: names and counts, never a secret or a
// path of the agent's files.
type Report struct {
	ScannedAt time.Time      `json:"scanned_at"`
	Agents    []ReportedItem `json:"agents"`
}

// ReportedItem is one agent, as Nia shows it.
type ReportedItem struct {
	Kind       string   `json:"kind"`
	User       string   `json:"user"`
	Running    bool     `json:"running"`
	MCPServers int      `json:"mcp_servers"`
	Model      string   `json:"model"`
	Protection string   `json:"protection"`
	Groups     []string `json:"privileged_groups"`
	Next       string   `json:"next"`
}

// MaxReported bounds the report.
const MaxReported = 64

func writeReport(path, root string, found []agents.Agent) error {
	if path == "" {
		if os.Geteuid() != 0 || root != "" {
			return nil
		}
		if _, err := os.Stat(filepath.Dir(defaultReport)); err != nil {
			return nil
		}
		path = defaultReport
	}
	report := Report{ScannedAt: time.Now().UTC().Truncate(time.Second), Agents: []ReportedItem{}}
	for _, a := range found {
		if len(report.Agents) == MaxReported {
			break
		}
		groups := a.Groups
		if groups == nil {
			groups = []string{}
		}
		report.Agents = append(report.Agents, ReportedItem{
			Kind: a.Kind, User: a.User, Running: a.Running, MCPServers: a.Settings.MCPServers,
			Model: a.Settings.Model, Protection: protection(a), Groups: groups, Next: a.Next,
		})
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".agents.*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	// Readable by nia-edge, which sends it: it holds no secret.
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// readReport reads the last report for the heartbeat; nil when there is none
// or it cannot be read as one.
func readReport(path string) *Report {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64<<10 {
		return nil
	}
	var report Report
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || len(report.Agents) > MaxReported || report.ScannedAt.IsZero() {
		return nil
	}
	return &report
}

func onboardCommand(action string, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nia-edge agents "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	dryRun := flags.Bool("dry-run", false, "print what would change, change nothing")
	model := flags.Bool("model", false, "also send the agent's model calls to nia-edge (claude-code: an anthropic provider on nia-edge; codex: an openai one)")
	root := flags.String("root", "", "the machine's files under this directory (tests)")
	only := flags.String("user", "", "pi, omp: only this user (default: every user it is found under)")
	if len(args) == 0 {
		return fmt.Errorf("usage: nia-edge agents %s <%s>", action, strings.Join(append(agents.Governable(), agents.PerUser()...), "|"))
	}
	kind := args[0]
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("agents %s takes one agent", action)
	}
	if slices.Contains(agents.PerUser(), kind) {
		return perUserCommand(action, kind, *root, *only, *dryRun, *model, getenv, stdout)
	}
	onboarding, err := agents.For(kind, *root, *model)
	if err != nil {
		return err
	}
	switch action {
	case "status":
		state := onboarding.Status()
		switch state {
		case "machine":
			fmt.Fprintf(stdout, "%s: governed, nia-edge's hooks are in %s\n", kind, onboarding.File)
		case "changed":
			fmt.Fprintf(stdout, "%s: nia-edge's hooks are in %s, but the file changed since onboarding\n", kind, onboarding.File)
		default:
			fmt.Fprintf(stdout, "%s: not onboarded (sudo nia-edge agents onboard %s)\n", kind, kind)
		}
		if state != "" && !edgeHealthy(getenv) {
			fmt.Fprintln(stdout, "  nia-edge does not answer on "+agents.Edge+": every tool call of "+kind+" is refused")
		}
		return nil
	case "restore", "offboard":
		if *dryRun {
			fmt.Fprintf(stdout, "would put %s back as it was before onboarding\n", onboarding.File)
			return nil
		}
		if err := needRoot(*root); err != nil {
			return err
		}
		if err := onboarding.Restore(); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: %s is back as it was; Nia no longer decides its tool calls\n", kind, onboarding.File)
		rescan()
		return nil
	}
	before, after, err := onboarding.Plan()
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(stdout, "would write %s (saved first to %s.nia-edge.json):\n", onboarding.File, onboarding.File)
		if len(before) == 0 {
			fmt.Fprintln(stdout, "--- (no file)")
		} else {
			fmt.Fprintf(stdout, "--- before\n%s", before)
			if !bytes.HasSuffix(before, []byte("\n")) {
				fmt.Fprintln(stdout)
			}
		}
		fmt.Fprintf(stdout, "+++ after\n%s", after)
		return nil
	}
	if err := needRoot(*root); err != nil {
		return err
	}
	if err := onboarding.Apply(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: onboarded for every user of this machine (%s)\n", kind, onboarding.File)
	fmt.Fprintln(stdout, "  Nia decides each tool call before it runs; a call it does not allow, or cannot decide, is refused.")
	if kind == "codex" {
		fmt.Fprintln(stdout, "  Codex runs "+agents.HookCommand+" for each call: keep nia-edge there.")
	}
	if *model {
		format := "anthropic"
		if kind == "codex" {
			format = "openai"
		}
		fmt.Fprintln(stdout, "  Its model calls go to nia-edge, which calls the provider with its own key (nia-edge provider -format "+format+").")
	}
	fmt.Fprintln(stdout, "  This governs "+kind+", it does not confine it: its user's other programs reach the network as before.")
	if !edgeHealthy(getenv) {
		fmt.Fprintln(stdout, "  nia-edge does not answer on "+agents.Edge+" yet: until it does, every tool call is refused.")
	}
	rescan()
	return nil
}

// perUserCommand onboards, shows or restores nia-edge's extension of an
// agent governed user by user, for every user it is found under.
func perUserCommand(action, kind, root, only string, dryRun, model bool, getenv func(string) string, stdout io.Writer) error {
	if model {
		return fmt.Errorf("-model is for claude-code only for now: %s's model calls go to its provider", kind)
	}
	found, err := agents.Find(agents.Options{Root: root})
	if err != nil {
		return err
	}
	var targets []agents.Onboarding
	for _, agent := range found {
		if agent.Kind != kind || (only != "" && agent.User != only) {
			continue
		}
		onboarding, err := agents.ForUser(kind, root, agents.Owner{Name: agent.User, UID: agent.UID, GID: agent.GID}, agent.Home)
		if err != nil {
			return err
		}
		targets = append(targets, onboarding)
	}
	if len(targets) == 0 {
		return fmt.Errorf("%s is not found under any user of this machine (nia-edge agents lists what is)", kind)
	}
	if !dryRun && action != "status" {
		if err := needRoot(root); err != nil {
			return err
		}
	}
	for _, onboarding := range targets {
		user := onboarding.User.Name
		switch action {
		case "status":
			switch onboarding.Status() {
			case "machine":
				fmt.Fprintf(stdout, "%s (%s): governed, nia-edge's extension is %s\n", kind, user, onboarding.File)
			case "changed":
				fmt.Fprintf(stdout, "%s (%s): nia-edge's extension changed since onboarding (%s)\n", kind, user, onboarding.File)
			default:
				fmt.Fprintf(stdout, "%s (%s): not onboarded (sudo nia-edge agents onboard %s)\n", kind, user, kind)
			}
		case "restore", "offboard":
			if dryRun {
				fmt.Fprintf(stdout, "would remove %s\n", onboarding.File)
				continue
			}
			if err := onboarding.Restore(); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "%s (%s): nia-edge's extension removed; Nia no longer decides its tool calls\n", kind, user)
		default:
			if dryRun {
				_, after, err := onboarding.Plan()
				if err != nil {
					return err
				}
				fmt.Fprintf(stdout, "would write %s:\n%s", onboarding.File, after)
				continue
			}
			if err := onboarding.Apply(); err != nil {
				return fmt.Errorf("%s (%s): %w", kind, user, err)
			}
			fmt.Fprintf(stdout, "%s (%s): onboarded with nia-edge's extension (%s)\n", kind, user, onboarding.File)
		}
	}
	if action == "onboard" && !dryRun {
		fmt.Fprintln(stdout, "  Nia decides each tool call before it runs; a call it does not allow, or cannot decide, is refused.")
		fmt.Fprintln(stdout, "  The extension is in the user's own directory: they can remove it. This governs "+kind+", it does not confine it.")
		if !edgeHealthy(getenv) {
			fmt.Fprintln(stdout, "  nia-edge does not answer on "+agents.Edge+" yet: until it does, every tool call is refused.")
		}
	}
	if action != "status" && !dryRun {
		rescan()
	}
	return nil
}

func needRoot(root string) error {
	if root != "" || os.Geteuid() == 0 {
		return nil
	}
	return errors.New("run as root: the agent's managed configuration applies to every user of the machine")
}

// rescan refreshes the report Nia receives.
func rescan() {
	if os.Geteuid() != 0 {
		return
	}
	if found, err := agents.Find(agents.Options{}); err == nil {
		_ = writeReport("", "", found)
	}
	_ = writeInventory(context.Background(), defaultInventory)
}

// writeInventory lists the machine's services and the names under /etc, as
// root, for the heartbeat to carry to Nia. Without the nia-edge group there is
// no one to give it to: nothing is written.
func writeInventory(ctx context.Context, path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return nil
	}
	group, err := user.LookupGroup("nia-edge")
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(inventory.Collect(ctx, ""))
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".inventory.*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chown(0, gid); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// readInventory reads the last inventory for the heartbeat, as it is; nil
// when there is none or it is not one.
func readInventory(path string) json.RawMessage {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1<<20 {
		return nil
	}
	var found inventory.Inventory
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&found) != nil || found.ScannedAt.IsZero() || len(found.Services) > inventory.MaxServices || len(found.Etc) > inventory.MaxEtc {
		return nil
	}
	return raw
}

func edgeHealthy(getenv func(string) string) bool {
	base := getenv("NIA_EDGE_URL")
	if base == "" {
		base = agents.Edge
	}
	return healthOK(base)
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// healthOK reports whether nia-edge answers its health route with 200.
func healthOK(base string) bool {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(strings.TrimRight(base, "/") + "/edge/health")
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusOK
}
