// Package agents finds the AI agents installed on this machine, under every
// account, and says for each whether it runs behind nia-edge.
//
// It reads files and /proc only, changes nothing and decides nothing: what
// the machine says about itself is a report. Whether an agent's user has a
// way out is proven by nia-edge doctor run as that user, and judged by Nia.
// It never prints a secret: of a configuration it reports its path, how many
// MCP servers it declares and whether its model is nia-edge.
package agents

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind is an agent nia-edge knows how to find.
type Kind struct {
	Name string
	// Files, relative to the home, any of which says the agent is there.
	Files []string
	// Installer is the script that moves it under a user of its own, behind
	// nia-edge; empty when there is none yet.
	Installer string
	// Process reports whether a command line is this agent's.
	Process func(args []string) bool
	// Read reports what its configuration says: MCP servers and model.
	Read func(data []byte) Config
}

// Config is what a configuration says, as far as it can be read.
type Config struct {
	// MCPServers is the number of MCP servers it declares, -1 when the file
	// cannot be read as its format.
	MCPServers int `json:"mcp_servers"`
	// Model is "nia-edge" when its model is nia-edge's relay, "other" when it
	// is something else, "unknown" when that cannot be read.
	Model string `json:"model"`
}

// Agent is one agent found under one account.
type Agent struct {
	Kind     string `json:"kind"`
	User     string `json:"user"`
	UID      int    `json:"uid"`
	Home     string `json:"home"`
	Config   string `json:"config"`
	Settings Config `json:"configuration"`
	// Running is true when a process of that user runs it.
	Running bool `json:"running"`
	// Groups are the user's groups that are root in disguise or go around
	// the network rule.
	Groups []string `json:"privileged_groups"`
	// Confined is true when nia-edge's firewall unit names this user: its
	// network is nia-edge's. nia-edge doctor, as that user, proves it.
	Confined bool `json:"confined"`
	// Next is what to do about it, for a person to read.
	Next string `json:"next"`
}

// Privileged lists the groups install/linux.sh refuses for an agent's user.
var Privileged = []string{"root", "docker", "sudo", "wheel", "admin", "adm", "lxd", "incus-admin", "libvirt", "disk", "nia-edge"}

const relay = "http://127.0.0.1:8787"

func base(args []string, names ...string) bool {
	for i, arg := range args {
		if i > 2 {
			break
		}
		name := filepath.Base(arg)
		for _, want := range names {
			if name == want {
				return true
			}
		}
	}
	return false
}

// Kinds are the agents nia-edge looks for.
var Kinds = []Kind{
	{
		Name: "hermes", Files: []string{".hermes/config.yaml"}, Installer: "hermes-linux.sh",
		Process: func(args []string) bool { return base(args, "hermes") },
		Read:    readHermes,
	},
	{
		Name: "openclaw", Files: []string{".openclaw/openclaw.json"}, Installer: "openclaw-linux.sh",
		Process: func(args []string) bool {
			if base(args, "openclaw", "openclaw.mjs", "openclaw-gateway") {
				return true
			}
			return len(args) > 1 && strings.Contains(args[1], "/node_modules/openclaw/")
		},
		Read: readOpenClaw,
	},
	{
		Name: "codex", Files: []string{".codex/config.toml"},
		Process: func(args []string) bool { return base(args, "codex") },
		Read:    readCodex,
	},
	{
		Name: "opencode", Files: []string{".config/opencode/opencode.json", ".config/opencode/opencode.jsonc"},
		Process: func(args []string) bool { return base(args, "opencode") },
		Read:    readOpenCode,
	},
	{
		Name: "claude-code", Files: []string{".claude.json", ".claude/settings.json"},
		Process: func(args []string) bool { return base(args, "claude") },
		Read:    readClaude,
	},
}

// Options says where the machine's files are: Root prefixes every path
// (tests), and FirewallUnit is the unit install/linux.sh writes.
type Options struct {
	Root         string
	FirewallUnit string
}

func (o Options) path(p string) string { return filepath.Join(o.Root, p) }

// Find returns every agent of Kinds under every account of /etc/passwd,
// sorted by user then kind.
func Find(o Options) ([]Agent, error) {
	if o.FirewallUnit == "" {
		o.FirewallUnit = "/etc/systemd/system/nia-agent-firewall.service"
	}
	users, err := passwd(o.path("/etc/passwd"))
	if err != nil {
		return nil, err
	}
	groups := memberships(o.path("/etc/group"), users)
	confined := firewalled(o.path(o.FirewallUnit))
	processes := running(o.path("/proc"))
	var found []Agent
	for _, u := range users {
		if u.home == "" || u.home == "/" || u.home == "/nonexistent" {
			continue
		}
		for _, kind := range Kinds {
			for _, file := range kind.Files {
				full := filepath.Join(u.home, file)
				// A link is not followed: the user chose where it points.
				if info, err := os.Lstat(o.path(full)); err != nil || !info.Mode().IsRegular() {
					continue
				}
				data, err := readLimited(o.path(full))
				if err != nil {
					continue
				}
				agent := Agent{
					Kind: kind.Name, User: u.name, UID: u.uid, Home: u.home, Config: full,
					Settings: kind.Read(data), Confined: confined[u.name],
				}
				for _, args := range processes[u.uid] {
					if kind.Process(args) {
						agent.Running = true
						break
					}
				}
				for _, g := range Privileged {
					if groups[u.name][g] || (g == "root" && u.uid == 0) {
						agent.Groups = append(agent.Groups, g)
					}
				}
				agent.Next = next(kind, agent)
				found = append(found, agent)
				break
			}
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].User != found[j].User {
			return found[i].User < found[j].User
		}
		return found[i].Kind < found[j].Kind
	})
	return found, nil
}

func next(kind Kind, a Agent) string {
	switch {
	case a.Confined && len(a.Groups) == 0 && a.Settings.Model != "other":
		return "behind nia-edge: prove it with sudo -u " + a.User + " nia-edge doctor"
	case a.Confined && len(a.Groups) > 0:
		return "remove " + a.User + " from " + strings.Join(a.Groups, ", ") + ": those groups go around nia-edge"
	case a.Confined:
		return "its model is not nia-edge's: point it at " + relay + "/v1"
	case kind.Installer == "":
		return "no installer for " + kind.Name + " yet: it runs with " + a.User + "'s files and network"
	default:
		return "sudo sh " + kind.Installer + " --from " + a.User + ": a user of its own, behind nia-edge"
	}
}

type user struct {
	name string
	uid  int
	gid  string
	home string
}

func passwd(path string) ([]user, error) {
	data, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	var users []user
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		users = append(users, user{name: fields[0], uid: uid, gid: fields[3], home: filepath.Clean(fields[5])})
	}
	return users, nil
}

func memberships(path string, users []user) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	gids := map[string]string{}
	data, _ := readLimited(path)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		gids[fields[2]] = fields[0]
		for _, member := range strings.Split(fields[3], ",") {
			if member == "" {
				continue
			}
			if out[member] == nil {
				out[member] = map[string]bool{}
			}
			out[member][fields[0]] = true
		}
	}
	// The primary group, from /etc/passwd.
	for _, u := range users {
		if name, ok := gids[u.gid]; ok {
			if out[u.name] == nil {
				out[u.name] = map[string]bool{}
			}
			out[u.name][name] = true
		}
	}
	return out
}

var applyLine = regexp.MustCompile(`(?m)^ExecStart=\S+ \S*firewall-linux\.sh apply (\S+)`)

func firewalled(path string) map[string]bool {
	out := map[string]bool{}
	data, err := readLimited(path)
	if err != nil {
		return out
	}
	for _, m := range applyLine.FindAllSubmatch(data, -1) {
		out[string(m[1])] = true
	}
	return out
}

// running maps each uid to the command lines of its processes.
func running(proc string) map[int][][]string {
	out := map[int][][]string{}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		status, err := readLimited(filepath.Join(proc, entry.Name(), "status"))
		if err != nil {
			continue
		}
		uid := -1
		scanner := bufio.NewScanner(bytes.NewReader(status))
		for scanner.Scan() {
			if fields := strings.Fields(scanner.Text()); len(fields) >= 2 && fields[0] == "Uid:" {
				uid, _ = strconv.Atoi(fields[1])
				break
			}
		}
		cmdline, err := readLimited(filepath.Join(proc, entry.Name(), "cmdline"))
		if err != nil || uid < 0 || len(cmdline) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		out[uid] = append(out[uid], args)
	}
	return out
}

// A configuration is read up to 4 MiB: past that it is not read at all.
const limit = 4 << 20

func readLimited(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Mode()&(fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeCharDevice) != 0 {
		return nil, fs.ErrInvalid
	}
	data := make([]byte, 0, 4096)
	buffer := make([]byte, 32<<10)
	for {
		n, err := file.Read(buffer)
		data = append(data, buffer[:n]...)
		if len(data) > limit {
			return nil, errors.New("too large")
		}
		if err != nil {
			break
		}
	}
	return data, nil
}

// jsonc reads JSON with comments and trailing commas (OpenClaw's JSON5 as it
// writes it, OpenCode's JSONC). Anything else is not read.
func jsonc(data []byte) (map[string]any, bool) {
	var out bytes.Buffer
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return nil, false
			}
			i += end + 3
			out.WriteByte(' ')
		case c == ',':
			// A comma before a closing bracket is dropped.
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	var value map[string]any
	if err := json.Unmarshal(out.Bytes(), &value); err != nil {
		return nil, false
	}
	return value, true
}

func object(value any) map[string]any {
	m, _ := value.(map[string]any)
	return m
}

func atRelay(value any) bool {
	text, _ := value.(string)
	return text == relay || strings.HasPrefix(text, relay+"/")
}

func readOpenClaw(data []byte) Config {
	config, ok := jsonc(data)
	if !ok {
		return Config{MCPServers: -1, Model: "unknown"}
	}
	c := Config{MCPServers: len(object(object(config["mcp"])["servers"])), Model: "other"}
	agents := object(object(config["agents"])["defaults"])
	primary, _ := object(agents["model"])["primary"].(string)
	if primary == "" {
		primary, _ = agents["model"].(string)
	}
	if id, _, found := strings.Cut(primary, "/"); found {
		if atRelay(object(object(object(config["models"])["providers"])[id])["baseUrl"]) {
			c.Model = "nia-edge"
		}
	}
	return c
}

func readOpenCode(data []byte) Config {
	config, ok := jsonc(data)
	if !ok {
		return Config{MCPServers: -1, Model: "unknown"}
	}
	mcp := object(config["mcp"])
	// OpenCode 2 names its servers under mcp.servers.
	if servers := object(mcp["servers"]); servers != nil && object(servers)["type"] == nil {
		mcp = servers
	}
	c := Config{MCPServers: len(mcp), Model: "other"}
	model, _ := config["model"].(string)
	if id, _, found := strings.Cut(model, "/"); found {
		options := object(object(object(config["provider"])[id])["options"])
		if atRelay(options["baseURL"]) {
			c.Model = "nia-edge"
		}
	}
	return c
}

func readClaude(data []byte) Config {
	config, ok := jsonc(data)
	if !ok {
		return Config{MCPServers: -1, Model: "unknown"}
	}
	c := Config{MCPServers: len(object(config["mcpServers"])), Model: "other"}
	for _, project := range object(config["projects"]) {
		c.MCPServers += len(object(object(project)["mcpServers"]))
	}
	if atRelay(object(config["env"])["ANTHROPIC_BASE_URL"]) {
		c.Model = "nia-edge"
	}
	return c
}

var codexServer = regexp.MustCompile(`(?m)^\s*\[mcp_servers\.("[^"\n]+"|[A-Za-z0-9_-]+)\]\s*(#.*)?$`)

// readCodex counts the [mcp_servers.<name>] tables; the model is unknown:
// TOML is not read whole.
func readCodex(data []byte) Config {
	return Config{MCPServers: len(codexServer.FindAll(data, -1)), Model: "unknown"}
}

// readHermes counts the keys under mcp_servers: at the top of the YAML; the
// model is unknown: YAML is not read whole.
func readHermes(data []byte) Config {
	count, in, indent := 0, false, -1
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		depth := len(line) - len(trimmed)
		if depth == 0 {
			in = strings.HasPrefix(line, "mcp_servers:")
			indent = -1
			if in && strings.TrimSpace(strings.TrimPrefix(line, "mcp_servers:")) == "{}" {
				in = false
			}
			continue
		}
		if !in {
			continue
		}
		if indent < 0 {
			indent = depth
		}
		if depth == indent && strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "-") {
			count++
		}
	}
	return Config{MCPServers: count, Model: "unknown"}
}
