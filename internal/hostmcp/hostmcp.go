// Package hostmcp is the agent's way to the host actions: a small MCP server
// on nia-edge's own address. Its tools are the host actions, always: an agent
// that listed them once keeps them when a new catalogue is published. Each
// call is checked against the role's catalogue in force, runs only when the
// model path released that exact call (same tool, same canonical arguments,
// once), and only through nia-hostd, which checks the catalogue again itself.
package hostmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/GetKlaros/nia-edge/internal/hostd"
	"github.com/GetKlaros/nia-edge/internal/inspect"
	"github.com/GetKlaros/nia-edge/internal/local"
)

// Host runs an action: nia-hostd's client.
type Host interface {
	Do(ctx context.Context, req hostd.Request) (hostd.Response, error)
}

// Handler serves the MCP endpoint.
type Handler struct {
	// Catalogue is the catalogue of the role in force; an error means none.
	Catalogue func() (*hostd.Catalogue, error)
	Releases  *local.Releases
	// Prefix is how the agent names this server's tools; empty is
	// mcp__host__ (Hermes: mcp__<server>__<tool>).
	Prefix string
	Host   Host
	// Server is the agent's name for this MCP server: tools reach the model
	// as Releases.Prefix + tool.
	Version string
	Now     func() time.Time
	// Tasks sends a task to Nia; without it, propose_task refuses.
	Tasks Tasks
	// Review returns the review of a dry run's plan, for a task's apply.
	Review func(ctx context.Context, plan string) json.RawMessage
	// Simulate says what installing a package would install, for a task's
	// reviewer; shown, never decided on. Nil simulates nothing.
	Simulate func(ctx context.Context, pkg string) []string
}

// Tasks is Nia's task endpoint: its decision and its message for the model.
type Tasks interface {
	ProposeTask(ctx context.Context, session string, body map[string]any) (decision, message string, err error)
}

// TaskTool is the tool that proposes several host actions for one decision.
const TaskTool = "propose_task"

// maxSteps bounds a task, as Nia does.
const maxSteps = 20

// Protocol versions with the initialize handshake that this server answers.
var versions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

type tool struct {
	action string
	// param is the one argument, and kind what it names in the catalogue.
	param, kind, description string
	// readOnly and destructive are the MCP tool annotations.
	readOnly, destructive bool
}

var order = []string{"service_status", "service_logs", "disk_usage", "service_restart", "service_reload", "package_install", "sync", "dry_run", "apply"}

var tools = map[string]tool{
	"service_status":  {hostd.ServiceStatus, "service", "services", "Show the state of a service of the machine and its last log lines.", true, false},
	"service_logs":    {hostd.ServiceLogs, "service", "services", "Read the last 200 lines of a service's log. Secrets in them are redacted.", true, false},
	"disk_usage":      {hostd.DiskUsage, "", "none", "Show the size, use and free space of the machine's file systems.", true, false},
	"service_restart": {hostd.ServiceRestart, "service", "services", "Restart a service of the machine.", false, true},
	"service_reload":  {hostd.ServiceReload, "service", "services", "Reload the configuration of a service of the machine.", false, false},
	"package_install": {hostd.PackageInstall, "package", "packages", "Install a package from the machine's package sources.", false, false},
	"sync":            {hostd.Sync, "pair", "sync", "Copy a source directory into its destination, as the pair defines them.", false, true},
	"dry_run": {hostd.DryRunAction, "script", "etc", "Run a shell script against a copy of the machine's /etc and of the directories the role lists (a site in /srv/www, an app in /opt/app), " +
		"in a container without network or privilege, and get the list of the files it would create, change or delete. The machine is not changed. " +
		"Files the agent may not read are decoys there. Everything else is read only, and /root, /home, /tmp and the rest of /var are empty. " +
		"A file of a listed directory may not be made executable.", true, false},
	"apply": {hostd.ApplyAction, "plan", "etc", "Write a dry run's plan to the machine, exactly as the dry run left it, without running the script again. " +
		"Refused when the machine changed since the dry run. The configurations it touches are checked (nginx -t, visudo -c, sshd -t...) " +
		"and the former files are put back when a check fails.", false, true},
}

func names(c *hostd.Catalogue, kind string) []string {
	switch kind {
	case "etc":
		return nil
	case "services":
		return c.Services
	case "packages":
		return c.Packages
	}
	var pairs []string
	for _, pair := range c.Sync {
		pairs = append(pairs, pair.Name)
	}
	return pairs
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// localOrigin reports whether an Origin is this machine's: a page elsewhere
// must not drive the host actions through the agent's browser.
func localOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !localOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "this MCP server answers POST only", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var msg message
	if err != nil || json.Unmarshal(raw, &msg) != nil || msg.JSONRPC != "2.0" || msg.Method == "" {
		reply(w, nil, nil, &rpcError{Code: -32600, Message: "not a JSON-RPC 2.0 request"})
		return
	}
	if len(msg.ID) == 0 {
		// A notification: nothing to answer.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch msg.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &params)
		version := versions[0]
		if slices.Contains(versions, params.ProtocolVersion) {
			version = params.ProtocolVersion
		}
		reply(w, msg.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "nia-host", "version": h.Version},
			"instructions":    "Actions on this machine, from the role's catalogue. Each call runs only once Nia allowed it.",
		}, nil)
	case "ping":
		reply(w, msg.ID, map[string]any{}, nil)
	case "tools/list":
		reply(w, msg.ID, map[string]any{"tools": list()}, nil)
	case "tools/call":
		result, rpcErr := h.call(r.Context(), msg.Params)
		reply(w, msg.ID, result, rpcErr)
	default:
		reply(w, msg.ID, nil, &rpcError{Code: -32601, Message: "method not found"})
	}
}

func describe(t tool) string {
	if t.kind == "none" {
		return t.description + " It takes no argument."
	}
	if t.kind == "etc" {
		return t.description + " The role's catalogue must allow dry runs."
	}
	return t.description + " Only a " + t.param + " of the role's catalogue: another one is refused with the list of those allowed."
}

// list is the same whatever the catalogue: Hermes and other agents keep the
// list they read at connection, so a list that followed the catalogue would
// hide a newly published one until the agent restarts.
func list() []map[string]any {
	list := []map[string]any{}
	for _, name := range order {
		t := tools[name]
		list = append(list, map[string]any{
			"name":        name,
			"description": describe(t),
			"inputSchema": schema(t),
			"annotations": map[string]any{
				"readOnlyHint":    t.readOnly,
				"destructiveHint": t.destructive,
				"openWorldHint":   false,
			},
		})
	}
	list = append(list, map[string]any{
		"name": TaskTool,
		"description": "Propose several host actions for one human decision, instead of one approval each: install the packages, " +
			"apply the dry runs' plans, reload the services. Do the dry runs first and list their plans. Nia decides each step as its call " +
			"would be; once the task is approved, call each step yourself, exactly as listed: each runs once. A step the role refuses " +
			"refuses the task. Steps are this server's tools, without " + TaskTool + ".",
		"inputSchema": taskSchema(),
		"annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
	})
	return list
}

func taskSchema() map[string]any {
	var names []string
	for _, name := range order {
		names = append(names, name)
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"title": map[string]any{"type": "string", "description": "What the task does, for the person who approves it.", "maxLength": 200},
			"steps": map[string]any{
				"type":     "array",
				"minItems": 1,
				"maxItems": maxSteps,
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"tool":      map[string]any{"type": "string", "enum": names},
						"arguments": map[string]any{"type": "object", "description": "The arguments the step will be called with, exactly."},
					},
					"required":             []string{"tool", "arguments"},
					"additionalProperties": false,
				},
			},
		},
		"required":             []string{"title", "steps"},
		"additionalProperties": false,
	}
}

func schema(t tool) map[string]any {
	if t.param == "" {
		return map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	}
	return map[string]any{
		"type":                 "object",
		"properties":           map[string]any{t.param: map[string]any{"type": "string"}},
		"required":             []string{t.param},
		"additionalProperties": false,
	}
}

func (h *Handler) call(ctx context.Context, params json.RawMessage) (map[string]any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(params, &p) != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}
	failed := func(text string) (map[string]any, *rpcError) {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": true}, nil
	}
	arguments := string(p.Arguments)
	if arguments == "" || arguments == "null" {
		arguments = "{}"
	}
	if p.Name == TaskTool {
		text, ok := h.task(ctx, arguments)
		if !ok {
			return failed(text)
		}
		return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": false}, nil
	}
	t, ok := tools[p.Name]
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "unknown tool " + p.Name}
	}
	var args map[string]any
	if json.Unmarshal([]byte(arguments), &args) != nil {
		return failed(fmt.Sprintf("%s takes one argument, %q", p.Name, t.param))
	}
	catalogue, err := h.Catalogue()
	if err != nil {
		return failed("[Nia agent firewall] The role in force has no host catalogue: no host action runs.")
	}
	value, refusal := check(p.Name, t, args, catalogue)
	if refusal != "" {
		return failed(refusal)
	}
	// Only a call the model path released runs, once.
	if h.Releases == nil || !h.Releases.Take(h.prefix()+p.Name, arguments, h.now()) {
		return failed("[Nia agent firewall] This action was not released by Nia: it runs only as the model proposed it and Nia allowed it, once.")
	}
	runCtx, cancel := context.WithTimeout(ctx, 35*time.Minute)
	defer cancel()
	req := hostd.Request{Action: t.action, Name: value}
	if t.action == hostd.DryRunAction {
		req = hostd.Request{Action: t.action, Script: value}
	}
	resp, err := h.Host.Do(runCtx, req)
	if err != nil {
		return failed("nia-hostd could not be reached, so nothing ran")
	}
	if t.action == hostd.DryRunAction && resp.OK {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": DescribeReport(resp.Output)}}, "isError": false}, nil
	}
	// What the machine printed goes to the model provider: no secret in it.
	text := strings.TrimSpace(inspect.RedactSecrets(resp.Output))
	if resp.Error != "" {
		text = strings.TrimSpace(text + "\n" + resp.Error)
	}
	if resp.Journal != "" {
		text = strings.TrimSpace(text + "\n(journal " + resp.Journal + ")")
	}
	if text == "" {
		text = "done"
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": !resp.OK}, nil
}

func (h *Handler) prefix() string {
	if h.Prefix == "" {
		return "mcp__host__"
	}
	return h.Prefix
}

// check reads a call's one argument and checks it against the catalogue: the
// refusal, for the model, when it is not one of the role's.
func check(name string, t tool, args map[string]any, catalogue *hostd.Catalogue) (string, string) {
	var value string
	var ok bool
	if t.param == "" {
		if len(args) != 0 {
			return "", name + " takes no argument"
		}
	} else if value, ok = args[t.param].(string); !ok || len(args) != 1 {
		return "", fmt.Sprintf("%s takes one argument, %q", name, t.param)
	}
	if t.kind == "etc" {
		if catalogue.Etc == nil && len(catalogue.Dirs) == 0 {
			return "", "[Nia agent firewall] The role's catalogue allows no dry run."
		}
	} else if t.kind == "none" {
		// Nothing to check against the catalogue: nia-hostd reads the machine.
	} else if allowed := names(catalogue, t.kind); !slices.Contains(allowed, value) {
		if len(allowed) == 0 {
			return "", fmt.Sprintf("[Nia agent firewall] The role's catalogue allows no %s for %s.", t.param, name)
		}
		return "", fmt.Sprintf("[Nia agent firewall] %q is not in the role's catalogue. %s accepts: %s.", value, name, strings.Join(allowed, ", "))
	}
	return value, ""
}

// task sends a task to Nia, as the model proposed it and the model path
// released it, in the session it was released in. Each step is checked
// against the catalogue first; an apply carries its plan's review, and a
// package install what the package manager says it would install. The text
// is for the model; false when nothing was sent or Nia refused.
func (h *Handler) task(ctx context.Context, arguments string) (string, bool) {
	var p struct {
		Title string `json:"title"`
		Steps []struct {
			Tool      string          `json:"tool"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"steps"`
	}
	decoder := json.NewDecoder(strings.NewReader(arguments))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || strings.TrimSpace(p.Title) == "" || len(p.Title) > 200 || len(p.Steps) == 0 || len(p.Steps) > maxSteps {
		return fmt.Sprintf("%s takes a title (200 characters at most) and 1 to %d steps, each {\"tool\", \"arguments\"}.", TaskTool, maxSteps), false
	}
	catalogue, err := h.Catalogue()
	if err != nil {
		return "[Nia agent firewall] The role in force has no host catalogue: no host action runs.", false
	}
	type step struct {
		name, value, arguments string
		t                      tool
	}
	var steps []step
	for index, item := range p.Steps {
		t, ok := tools[item.Tool]
		if !ok {
			return fmt.Sprintf("Step %d: %q is not a tool of this server.", index+1, item.Tool), false
		}
		var args map[string]any
		if json.Unmarshal(item.Arguments, &args) != nil || args == nil {
			return fmt.Sprintf("Step %d: its arguments must be an object.", index+1), false
		}
		value, refusal := check(item.Tool, t, args, catalogue)
		if refusal != "" {
			return fmt.Sprintf("Step %d: %s", index+1, refusal), false
		}
		steps = append(steps, step{name: item.Tool, value: value, arguments: string(item.Arguments), t: t})
	}
	// Only a task the model path released is sent, once, in its session.
	session, released := "", false
	if h.Releases != nil {
		session, released = h.Releases.TakeSession(h.prefix()+TaskTool, arguments, h.now())
	}
	if !released {
		return "[Nia agent firewall] This task was not released by Nia: it is sent only as the model proposed it and Nia allowed it, once.", false
	}
	if session == "" || h.Tasks == nil {
		return "[Nia agent firewall] Tasks are not available on this machine: call each step on its own.", false
	}
	var body []map[string]any
	for _, s := range steps {
		item := map[string]any{"tool": h.prefix() + s.name, "arguments": json.RawMessage(s.arguments)}
		if s.t.action == hostd.ApplyAction && h.Review != nil {
			if review := h.Review(ctx, s.value); review != nil {
				item["review"] = review
			}
		}
		if s.t.action == hostd.PackageInstall && h.Simulate != nil {
			if installs := h.Simulate(ctx, s.value); len(installs) > 0 {
				item["installs"] = installs
			}
		}
		body = append(body, item)
	}
	decision, message, err := h.Tasks.ProposeTask(ctx, session, map[string]any{"title": strings.TrimSpace(p.Title), "steps": body})
	if err != nil {
		return "[Nia agent firewall] Nia could not be reached, so the task was not sent.", false
	}
	if message == "" {
		message = "Nia decided: " + decision + "."
	}
	return "[Nia agent firewall] " + message, decision != "deny"
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func reply(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *rpcError) {
	body := map[string]any{"jsonrpc": "2.0", "id": id}
	if id == nil {
		body["id"] = nil
	}
	if rpcErr != nil {
		body["error"] = rpcErr
	} else {
		body["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// DescribeReport writes a dry run's report for the model.
func DescribeReport(raw string) string {
	var r hostd.Report
	if json.Unmarshal([]byte(raw), &r) != nil {
		return "The dry run's report cannot be read."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Dry run, plan %s. The machine was not changed.\n", r.Plan)
	if len(r.Changes) == 0 {
		b.WriteString("No change.\n")
	}
	for _, c := range r.Changes {
		switch c.Kind {
		case "deleted":
			fmt.Fprintf(&b, "- deleted %s\n", c.Path)
		case "metadata":
			fmt.Fprintf(&b, "- mode or owner of %s: %04o %d:%d\n", c.Path, c.Mode, c.UID, c.GID)
		default:
			what := c.Type
			if c.Type == "file" {
				what = fmt.Sprintf("file, %d bytes", c.Size)
			} else if c.Type == "symlink" {
				what = "symlink to " + c.Target
			}
			replaced := ""
			if c.Replaced {
				replaced = ", its former entries removed"
			}
			fmt.Fprintf(&b, "- %s %s (%s, %04o %d:%d%s)\n", c.Kind, c.Path, what, c.Mode, c.UID, c.GID, replaced)
		}
	}
	list := func(title string, paths []string) {
		if len(paths) > 0 {
			fmt.Fprintf(&b, "%s: %s\n", title, strings.Join(paths, ", "))
		}
	}
	for _, f := range r.Guards {
		fmt.Fprintf(&b, "Refused by the %s guard: %s\n", f.Guard, f.Detail)
	}
	list("Protected paths changed", r.Protected)
	list("Secrets read (the run saw decoys, not the secrets)", r.SecretsRead)
	list("Secrets changed", r.SecretsChanged)
	list("Secrets' decoys that came out of the run", r.SecretsCopied)
	if r.Failed != "" {
		fmt.Fprintf(&b, "The script failed: %s\n", r.Failed)
	}
	if ok, why := r.Applicable(); !ok {
		fmt.Fprintf(&b, "This plan cannot be applied: %s.\n", why)
	} else {
		fmt.Fprintf(&b, "To write it to the machine, call apply with plan %q.\n", r.Plan)
	}
	if r.Output != "" {
		fmt.Fprintf(&b, "Output:\n%s", r.Output)
	}
	return strings.TrimSpace(b.String())
}
