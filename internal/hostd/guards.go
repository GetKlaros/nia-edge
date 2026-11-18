package hostd

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Guards judge a dry run by the state it leaves, not by its script: what
// /etc would hold once the plan is applied is compared with what it holds
// now. Every guard is on unless the catalogue's etc.permit names it, and any
// finding makes the plan not applicable. Since each plan is judged against
// the machine as it is, a series of plans cannot weaken it a step at a time.

// Finding is what a guard refuses in a plan.
type Finding struct {
	Guard  string `json:"guard"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail"`
}

// rootHooks are the places where a file makes root run something, or decides
// who is root: no plan changes them unless the guard is permitted.
var rootHooks = []struct {
	guard, why string
	paths      []string
}{
	{"sudoers", "decides who runs commands as root", []string{"/etc/sudoers", "/etc/sudoers.d"}},
	{"pam", "decides how anyone logs in", []string{"/etc/pam.d", "/etc/pam.conf", "/etc/security"}},
	{"cron", "runs commands on a schedule, as root for the system's", []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/anacrontab", "/etc/cron.allow", "/etc/cron.deny"}},
	{"systemd", "runs services, as root by default", []string{"/etc/systemd", "/etc/init.d", "/etc/rc.local", "/etc/init"}},
	{"preload", "loads code into every program", []string{"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d"}},
	{"shell_startup", "runs in every login shell, root's included", []string{"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/environment", "/etc/zsh", "/etc/csh.cshrc", "/etc/csh.login"}},
	{"package_sources", "decides where packages come from and runs APT hooks as root", []string{"/etc/apt", "/etc/dpkg", "/etc/yum.repos.d", "/etc/dnf"}},
	{"kernel_modules", "loads kernel modules and runs modprobe commands", []string{"/etc/modules", "/etc/modprobe.d", "/etc/modules-load.d", "/etc/sysctl.conf", "/etc/sysctl.d"}},
	{"udev", "runs commands as root on device events", []string{"/etc/udev"}},
	{"logrotate", "runs scripts as root after rotations", []string{"/etc/logrotate.conf", "/etc/logrotate.d"}},
	{"polkit", "grants privileged actions", []string{"/etc/polkit-1", "/etc/dbus-1"}},
	{"network_hooks", "runs scripts as root on network events", []string{"/etc/NetworkManager/dispatcher.d", "/etc/network/if-up.d", "/etc/network/if-down.d", "/etc/network/if-pre-up.d", "/etc/network/if-post-down.d", "/etc/dhcp/dhclient-enter-hooks.d", "/etc/dhcp/dhclient-exit-hooks.d", "/etc/ppp"}},
}

// Guards names every guard, for the catalogue.
var Guards = func() []string {
	names := []string{"ssh", "accounts"}
	for _, hook := range rootHooks {
		names = append(names, hook.guard)
	}
	return names
}()

// view reads /etc as it is now, or as it would be after the plan.
type view interface {
	read(p string) ([]byte, bool)
	list(dir string) []string
}

// judge runs the guards the catalogue does not permit over the plan's
// changes, comparing the state before (the machine) and after.
func judge(permit []string, changes []Change, before, after view) []Finding {
	findings := []Finding{}
	on := func(guard string) bool { return !slices.Contains(permit, guard) }
	for _, hook := range rootHooks {
		if !on(hook.guard) {
			continue
		}
		for _, c := range changes {
			for _, p := range hook.paths {
				if c.Path == p || strings.HasPrefix(c.Path, p+"/") || strings.HasPrefix(p, c.Path+"/") && (c.Kind == "deleted" || c.Replaced) {
					findings = append(findings, Finding{Guard: hook.guard, Path: c.Path, Detail: fmt.Sprintf("%s %s: this %s", c.Kind, c.Path, hook.why)})
					break
				}
			}
		}
	}
	if on("ssh") && touches(changes, "/etc/ssh") {
		findings = append(findings, sshWeakened(before, after)...)
	}
	if on("accounts") && (touches(changes, "/etc/passwd") || touches(changes, "/etc/group")) {
		findings = append(findings, accountsWidened(before, after)...)
	}
	return findings
}

func touches(changes []Change, p string) bool {
	for _, c := range changes {
		if c.Path == p || strings.HasPrefix(c.Path, p+"/") || strings.HasPrefix(p, c.Path+"/") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- sshd

// sshRanks orders values from the strictest; a setting may not move up.
var sshRanks = map[string]map[string]int{
	"permitrootlogin":        {"no": 0, "forced-commands-only": 1, "prohibit-password": 2, "without-password": 2, "yes": 3},
	"passwordauthentication": {"no": 0, "yes": 1},
	"permitemptypasswords":   {"no": 0, "yes": 1},
	"pubkeyauthentication":   {"yes": 0, "no": 0},
}

// The defaults of OpenSSH (sshd_config(5)) for the ranked settings.
var sshDefaults = map[string]string{"permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "permitemptypasswords": "no"}

// sshState is sshd's configuration as far as the guard reads it: the value
// of each setting outside Match blocks (the first obtained, sshd_config(5)),
// the strictest-to-weakest highest value set in any Match block, and the
// authorized keys files.
type sshState struct {
	global   map[string]string
	matched  map[string]int
	keyFiles string
	unread   string
}

func readSSH(v view) sshState {
	st := sshState{global: map[string]string{}, matched: map[string]int{}}
	inMatch := false
	depth := 0
	var read func(file string)
	read = func(file string) {
		depth++
		defer func() { depth-- }()
		if depth > 16 {
			st.unread = "Include nests too deep"
			return
		}
		data, ok := v.read(file)
		if !ok {
			return
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			keyword, value, _ := strings.Cut(strings.Replace(line, "=", " ", 1), " ")
			keyword = strings.ToLower(strings.TrimSpace(keyword))
			value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))
			switch keyword {
			case "match":
				inMatch = true
				continue
			case "include":
				for _, pattern := range strings.Fields(value) {
					if !path.IsAbs(pattern) {
						pattern = path.Join("/etc/ssh", pattern)
					}
					for _, p := range glob(v, pattern) {
						read(p)
					}
				}
				continue
			case "authorizedkeysfile":
				if !inMatch && st.keyFiles == "" {
					st.keyFiles = value
				} else if inMatch {
					st.keyFiles += " | match: " + value
				}
				continue
			}
			ranks, ranked := sshRanks[keyword]
			if !ranked {
				continue
			}
			if inMatch {
				if r, ok := ranks[value]; ok && r > st.matched[keyword] {
					st.matched[keyword] = r
				} else if !ok {
					st.matched[keyword] = 99
				}
				continue
			}
			if _, set := st.global[keyword]; !set {
				st.global[keyword] = value
			}
		}
	}
	read("/etc/ssh/sshd_config")
	return st
}

func (st sshState) rank(keyword string) int {
	value, ok := st.global[keyword]
	if !ok {
		value = sshDefaults[keyword]
	}
	r, known := sshRanks[keyword][value]
	if !known {
		return 99
	}
	return r
}

func sshWeakened(before, after view) []Finding {
	b, a := readSSH(before), readSSH(after)
	var findings []Finding
	if a.unread != "" {
		findings = append(findings, Finding{Guard: "ssh", Path: "/etc/ssh/sshd_config", Detail: a.unread})
	}
	keywords := []string{}
	for keyword := range sshRanks {
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	for _, keyword := range keywords {
		if keyword == "pubkeyauthentication" {
			continue
		}
		was := max(b.rank(keyword), b.matched[keyword])
		if now := max(a.rank(keyword), a.matched[keyword]); now > was {
			findings = append(findings, Finding{Guard: "ssh", Path: "/etc/ssh/sshd_config", Detail: fmt.Sprintf("sshd's %s would be weaker than it is (%s)", keyword, sshValue(a, keyword))})
		}
	}
	if a.keyFiles != b.keyFiles {
		findings = append(findings, Finding{Guard: "ssh", Path: "/etc/ssh/sshd_config", Detail: fmt.Sprintf("sshd's AuthorizedKeysFile would change from %q to %q", b.keyFiles, a.keyFiles)})
	}
	return findings
}

func sshValue(st sshState, keyword string) string {
	if value, ok := st.global[keyword]; ok {
		if st.matched[keyword] > 0 {
			return value + ", and weaker in a Match block"
		}
		return value
	}
	if st.matched[keyword] > 0 {
		return "set in a Match block"
	}
	return sshDefaults[keyword] + ", by default"
}

// glob matches a pattern of path.Match against the view, one directory level
// at a time.
func glob(v view, pattern string) []string {
	parts := strings.Split(strings.TrimPrefix(path.Clean(pattern), "/"), "/")
	matches := []string{"/"}
	for _, part := range parts {
		var next []string
		for _, dir := range matches {
			if !strings.ContainsAny(part, "*?[") {
				next = append(next, path.Join(dir, part))
				continue
			}
			for _, name := range v.list(dir) {
				if ok, _ := path.Match(part, name); ok {
					next = append(next, path.Join(dir, name))
				}
			}
		}
		matches = next
	}
	sort.Strings(matches)
	return matches
}

// ---------------------------------------------------------------- accounts

// Groups whose members are root, or can become it.
var privilegedGroups = []string{"root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "incus-admin", "libvirt", "disk", "shadow", "kmem", "systemd-journal"}

func readAccounts(v view) (rootUsers map[string]bool, members map[string]map[string]bool) {
	rootUsers = map[string]bool{}
	members = map[string]map[string]bool{}
	if data, ok := v.read("/etc/passwd"); ok {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 4 || strings.HasPrefix(line, "#") {
				continue
			}
			uid, err1 := strconv.Atoi(fields[2])
			gid, err2 := strconv.Atoi(fields[3])
			if err1 != nil || err2 != nil || uid == 0 || gid == 0 {
				rootUsers[fields[0]] = true
			}
		}
	}
	gids := map[string]string{}
	if data, ok := v.read("/etc/group"); ok {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 4 || strings.HasPrefix(line, "#") {
				continue
			}
			name := fields[0]
			if fields[2] == "0" {
				name = "root"
			}
			gids[fields[0]] = fields[2]
			if !slices.Contains(privilegedGroups, name) {
				continue
			}
			if members[name] == nil {
				members[name] = map[string]bool{}
			}
			for _, member := range strings.Split(fields[3], ",") {
				if member = strings.TrimSpace(member); member != "" {
					members[name][member] = true
				}
			}
		}
	}
	return rootUsers, members
}

func accountsWidened(before, after view) []Finding {
	rootBefore, groupsBefore := readAccounts(before)
	rootAfter, groupsAfter := readAccounts(after)
	var findings []Finding
	for _, user := range sortedKeys(rootAfter) {
		if !rootBefore[user] {
			findings = append(findings, Finding{Guard: "accounts", Path: "/etc/passwd", Detail: fmt.Sprintf("user %s would have uid or gid 0", user)})
		}
	}
	for _, group := range sortedKeys(groupsAfter) {
		for _, member := range sortedKeys(groupsAfter[group]) {
			if !groupsBefore[group][member] {
				findings = append(findings, Finding{Guard: "accounts", Path: "/etc/group", Detail: fmt.Sprintf("%s would join the group %s", member, group)})
			}
		}
	}
	return findings
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
