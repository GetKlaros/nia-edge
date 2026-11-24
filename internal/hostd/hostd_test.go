package hostd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/policy"
	"github.com/GetKlaros/nia-edge/internal/state"
)

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

const role = `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],` +
	`"host":{"services":["nginx","postgresql@16-main"],"packages":["fail2ban"],"sync":[{"name":"site","source":"/srv/www","destination":"/backup/www","delete":true}]}}`

// machine writes a state file and a signed policy as nia-edge keeps them, for
// a role, and returns a server reading them.
func machine(t *testing.T, roleJSON string) (*Server, *DryRun, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", ed25519.SeedSize)))
	key := &policy.Key{ID: "k1", Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}
	if err := state.Save(filepath.Join(dir, "state.json"), &state.State{NiaURL: "https://nia.test", MachineID: "m1", Key: "nia_x", Role: "vps", PolicyKey: key}); err != nil {
		t.Fatal(err)
	}
	writePolicy(t, filepath.Join(dir, "policy.json"), private, roleJSON)
	run := &DryRun{}
	return &Server{StatePath: filepath.Join(dir, "state.json"), PolicyPath: filepath.Join(dir, "policy.json"), JournalPath: filepath.Join(dir, "journal.jsonl"), Run: run, Now: func() time.Time { return now }}, run, private
}

func writePolicy(t *testing.T, path string, private ed25519.PrivateKey, roleJSON string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"v": 1, "key_id": "k1", "tenant_id": "t1", "machine_id": "m1", "role": json.RawMessage(roleJSON), "dispatchers": []any{},
		"policy": map[string]any{"version": 1, "digest": "abcdef0123456789"}, "issued_at": now.Add(-time.Hour), "not_after": now.Add(time.Hour),
	})
	signed := policy.Signed{Payload: string(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload)), KeyID: "k1", Alg: "ed25519"}
	if err := policy.Save(path, signed); err != nil {
		t.Fatal(err)
	}
}

func TestRunsOnlyWhatTheCatalogueNamesWithFixedPrograms(t *testing.T) {
	s, run, _ := machine(t, role)
	ctx := context.Background()
	for _, c := range []struct {
		req  Request
		argv string
	}{
		{Request{Action: ServiceRestart, Name: "nginx"}, "systemctl restart -- nginx.service"},
		{Request{Action: ServiceReload, Name: "postgresql@16-main"}, "systemctl reload -- postgresql@16-main.service"},
		{Request{Action: ServiceStatus, Name: "nginx"}, "systemctl status --no-pager --lines=20 -- nginx.service"},
		{Request{Action: ServiceLogs, Name: "postgresql@16-main"}, "journalctl --no-pager --quiet --output=short-iso --lines=200 --unit=postgresql@16-main.service"},
		{Request{Action: DiskUsage}, "df --human-readable --output=target,size,used,avail,pcent --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=overlay --exclude-type=squashfs"},
		{Request{Action: Sync, Name: "site"}, "rsync -a --delete -- /srv/www/ /backup/www/"},
	} {
		run.Calls = nil
		resp := s.Do(ctx, c.req)
		if !resp.OK || resp.Journal == "" || len(run.Calls) != 1 || strings.Join(run.Calls[0], " ") != c.argv {
			t.Errorf("%+v: %+v ran %q", c.req, resp, run.Calls)
		}
	}
	for _, req := range []Request{
		{Action: ServiceRestart, Name: "sshd"},
		{Action: ServiceRestart, Name: "nginx; rm -rf /"},
		{Action: ServiceLogs, Name: "sshd"},
		{Action: DiskUsage, Name: "/etc"},
		{Action: PackageInstall, Name: "netcat-traditional"},
		{Action: Sync, Name: "/srv/www"},
		{Action: "shell", Name: "id"},
	} {
		run.Calls = nil
		if resp := s.Do(ctx, req); resp.OK || resp.Error == "" || len(run.Calls) != 0 {
			t.Errorf("%+v: %+v ran %q", req, resp, run.Calls)
		}
	}
}

func TestAPackageItInstalledCanBeUndoneOnce(t *testing.T) {
	s, run, _ := machine(t, role)
	ctx := context.Background()
	resp := s.Do(ctx, Request{Action: PackageInstall, Name: "fail2ban", Call: "abc"})
	if !resp.OK || len(run.Calls) != 3 || strings.Join(run.Calls[2], " ") != "apt-get install -y -q --no-install-recommends -- fail2ban" {
		t.Fatalf("%+v %q", resp, run.Calls)
	}
	undone := s.Undo(ctx, resp.Journal)
	if !undone.OK || strings.Join(run.Calls[3], " ") != "apt-get remove -y -q -- fail2ban" {
		t.Fatalf("%+v %q", undone, run.Calls)
	}
	if again := s.Undo(ctx, resp.Journal); again.OK || !strings.Contains(again.Error, "already undone") {
		t.Errorf("undone twice: %+v", again)
	}
	entries, err := s.Journal()
	if err != nil || len(entries) != 2 || entries[0].Call != "abc" || entries[1].Of != resp.Journal {
		t.Errorf("journal %+v %v", entries, err)
	}
	info, _ := os.Stat(s.JournalPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("journal mode %v", info.Mode())
	}

	// A package that was there before stays: nothing to undo.
	run.Answers = map[string]string{"dpkg-query -W -f=${Status} -- fail2ban": "install ok installed"}
	again := s.Do(ctx, Request{Action: PackageInstall, Name: "fail2ban"})
	if undo := s.Undo(ctx, again.Journal); undo.OK || !strings.Contains(undo.Error, "cannot be undone") {
		t.Errorf("%+v", undo)
	}
	restart := s.Do(ctx, Request{Action: ServiceRestart, Name: "nginx"})
	if undo := s.Undo(ctx, restart.Journal); undo.OK {
		t.Errorf("a restart undone: %+v", undo)
	}
}

func TestNoTrustedCatalogueNoAction(t *testing.T) {
	ctx := context.Background()
	// Signed by another key.
	s, run, _ := machine(t, role)
	other := ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", ed25519.SeedSize)))
	writePolicy(t, s.PolicyPath, other, strings.Replace(role, `"fail2ban"`, `"fail2ban","netcat-traditional"`, 1))
	if resp := s.Do(ctx, Request{Action: ServiceRestart, Name: "nginx"}); resp.OK || len(run.Calls) != 0 {
		t.Errorf("a policy signed by another key: %+v", resp)
	}
	// Expired.
	s, run, private := machine(t, role)
	s.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if resp := s.Do(ctx, Request{Action: ServiceRestart, Name: "nginx"}); resp.OK || len(run.Calls) != 0 {
		t.Errorf("an expired policy: %+v", resp)
	}
	// A catalogue with a field this nia-edge does not know.
	s.Now = func() time.Time { return now }
	writePolicy(t, s.PolicyPath, private, strings.Replace(role, `"sync":`, `"shell":["id"],"sync":`, 1))
	if resp := s.Do(ctx, Request{Action: ServiceRestart, Name: "nginx"}); resp.OK || len(run.Calls) != 0 {
		t.Errorf("an unknown catalogue field: %+v", resp)
	}
	// No catalogue: nothing.
	s, run, _ = machine(t, `{"name":"vps","mode":"enforce","rule_of_two":"deny","destructive":"deny","tools":[]}`)
	if resp := s.Do(ctx, Request{Action: ServiceRestart, Name: "nginx"}); resp.OK || len(run.Calls) != 0 {
		t.Errorf("no catalogue: %+v", resp)
	}
}

func TestTheCatalogueRefusesWhatItCannotName(t *testing.T) {
	for name, raw := range map[string]string{
		"a service with a space":    `{"services":["ng inx"]}`,
		"a service with an option":  `{"services":["--now"]}`,
		"a package with a capital":  `{"packages":["Fail2ban"]}`,
		"a relative directory":      `{"sync":[{"name":"a","source":"srv","destination":"/b"}]}`,
		"a directory with ..":       `{"sync":[{"name":"a","source":"/srv/../etc","destination":"/b"}]}`,
		"the root":                  `{"sync":[{"name":"a","source":"/","destination":"/b"}]}`,
		"a pair into itself":        `{"sync":[{"name":"a","source":"/b","destination":"/b"}]}`,
		"two pairs of one name":     `{"sync":[{"name":"a","source":"/a","destination":"/b"},{"name":"a","source":"/c","destination":"/d"}]}`,
		"an unknown field":          `{"commands":["id"]}`,
		"an unknown field of pairs": `{"sync":[{"name":"a","source":"/a","destination":"/b","exclude":["x"]}]}`,
	} {
		if _, err := ParseCatalogue(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func TestTheSocketServesOnlyTheAllowedUser(t *testing.T) {
	s, run, _ := machine(t, role)
	path := filepath.Join(t.TempDir(), "hostd.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	me := uint32(os.Getuid())
	var allow atomic.Bool
	allow.Store(true)
	go func() { _ = s.Serve(ctx, listener, func(uid uint32) bool { return allow.Load() && uid == me }) }()
	client := &Client{Socket: path}
	call, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	resp, err := client.Do(call, Request{Action: ServiceRestart, Name: "nginx"})
	if err != nil || !resp.OK || run.count() != 1 {
		t.Fatalf("%+v %v", resp, err)
	}
	allow.Store(false)
	if _, err := client.Do(call, Request{Action: ServiceRestart, Name: "nginx"}); err == nil || run.count() != 1 {
		t.Errorf("another user was served: %v", err)
	}
}

func (d *DryRun) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.Calls)
}

// The server writes the catalogue in the role it signs: this reads it.
func TestItReadsTheCatalogueAsTheServerWritesIt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "decisions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Roles []struct {
			Name string          `json:"name"`
			Host json.RawMessage `json:"host"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, role := range file.Roles {
		c, err := ParseCatalogue(role.Host)
		if err != nil {
			t.Fatalf("%s: %v", role.Name, err)
		}
		if len(role.Host) == 0 {
			continue
		}
		found++
		if !c.HasService("postgresql@16-main") || !c.HasPackage("fail2ban") || c.SyncPair("site") == nil || !c.SyncPair("site").Delete ||
			c.Etc == nil || len(c.Etc.Protected) != 2 || c.Etc.Secrets[0] != "/etc/app/token.conf" || len(c.Etc.Permit) != 2 || len(c.Etc.Writable) != 2 {
			t.Errorf("%s: %+v", role.Name, c)
		}
	}
	if found == 0 {
		t.Error("no role of the cases has a catalogue")
	}
}
