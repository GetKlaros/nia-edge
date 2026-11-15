package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GetKlaros/nia-edge/internal/state"
)

// fakeNia answers the machine routes and one agent route.
type fakeNia struct {
	*httptest.Server
	mu          sync.Mutex
	enrollments int
	heartbeats  int
	lastToken   string
	lastAgent   http.Header
	enrollCode  int
}

func newFakeNia(t *testing.T) *fakeNia {
	t.Helper()
	nia := &fakeNia{enrollCode: http.StatusCreated}
	nia.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nia.mu.Lock()
		defer nia.mu.Unlock()
		switch r.URL.Path {
		case "/edge/v1/enroll":
			nia.enrollments++
			nia.lastToken = r.Header.Get("Authorization")
			if nia.enrollCode != http.StatusCreated {
				w.WriteHeader(nia.enrollCode)
				fmt.Fprint(w, `{"error":{"code":"invalid_enrollment_token","message":"This enrollment token cannot be used"}}`)
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(body["hostname"]) {
				t.Errorf("host name %q is not in the form Nia accepts", body["hostname"])
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"machine_id":"m%d","key":"nia_key%d","key_expires_at":"2027-02-13T10:00:00.000Z","role":"research","upstream":"openai","heartbeat_seconds":30}`, nia.enrollments, nia.enrollments)
		case "/edge/v1/heartbeat":
			nia.heartbeats++
			fmt.Fprint(w, `{"machine_id":"m1","role":"research","role_in_policy":true,"policy":{"version":3,"digest":"abcdef0123456789"},"heartbeat_seconds":30,"server_time":"2026-11-15T10:00:00.000Z"}`)
		case "/health/ready":
		case "/v1/tools/decide":
			nia.lastAgent = r.Header.Clone()
			fmt.Fprint(w, `{"decision":"allow"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(nia.Close)
	return nia
}

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func command(t *testing.T, ctx context.Context, values map[string]string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(ctx, args, env(values), strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestEnrollKeepsTheKeyInAFileOnlyItsOwnerReads(t *testing.T) {
	nia := newFakeNia(t)
	path := filepath.Join(t.TempDir(), "state.json")
	code, stdout, stderr := command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_token"}, "", "enroll", "-url", nia.URL, "-state", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if nia.lastToken != "Bearer nen_token" {
		t.Errorf("token sent as %q", nia.lastToken)
	}
	// Neither secret is printed.
	if strings.Contains(stdout+stderr, "nen_token") || strings.Contains(stdout+stderr, "nia_key1") {
		t.Errorf("a secret was printed: %s %s", stdout, stderr)
	}
	saved, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Key != "nia_key1" || saved.MachineID != "m1" || saved.Role != "research" || saved.NiaURL != nia.URL {
		t.Errorf("state %+v", saved)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %04o", info.Mode().Perm())
	}

	// A second enrollment would throw away a working key: it needs -force.
	code, _, stderr = command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_other"}, "", "enroll", "-url", nia.URL, "-state", path)
	if code == 0 || !strings.Contains(stderr, "already enrolled") || nia.enrollments != 1 {
		t.Errorf("second enrollment: exit %d, %d enrollments, %s", code, nia.enrollments, stderr)
	}
	code, _, stderr = command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_other"}, "", "enroll", "-url", nia.URL, "-state", path, "-force")
	if saved, _ := state.Load(path); code != 0 || saved == nil || saved.Key != "nia_key2" {
		t.Errorf("forced enrollment: exit %d, state %+v, %s", code, saved, stderr)
	}
}

func TestTheTokenComesFromStdinOrAFileNeverFromTheCommandLine(t *testing.T) {
	nia := newFakeNia(t)
	dir := t.TempDir()
	if code, _, stderr := command(t, context.Background(), nil, "  nen_from-stdin\n", "enroll", "-url", nia.URL, "-state", filepath.Join(dir, "a.json")); code != 0 || nia.lastToken != "Bearer nen_from-stdin" {
		t.Errorf("stdin: exit %d, token %q, %s", code, nia.lastToken, stderr)
	}
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte("nen_from-file\n"), 0o600)
	if code, _, stderr := command(t, context.Background(), nil, "", "enroll", "-url", nia.URL, "-state", filepath.Join(dir, "b.json"), "-token-file", tokenFile); code != 0 || nia.lastToken != "Bearer nen_from-file" {
		t.Errorf("file: exit %d, token %q, %s", code, nia.lastToken, stderr)
	}
	before := nia.enrollments
	for _, args := range [][]string{
		{"enroll", "-url", nia.URL, "-state", filepath.Join(dir, "c.json"), "nen_on-the-command-line"},
		{"enroll", "-url", nia.URL, "-state", filepath.Join(dir, "c.json")},
	} {
		if code, _, _ := command(t, context.Background(), nil, "", args...); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
	if code, _, _ := command(t, context.Background(), nil, "nia_an-agent-key\n", "enroll", "-url", nia.URL, "-state", filepath.Join(dir, "c.json")); code == 0 {
		t.Error("a text that is not an enrollment token was sent")
	}
	if nia.enrollments != before {
		t.Error("Nia was called without a token")
	}
}

func TestEnrollSpendsNoTokenItCannotKeepTheKeyOf(t *testing.T) {
	nia := newFakeNia(t)
	// The state directory cannot be created: its parent is a file.
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	code, _, stderr := command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_token"}, "", "enroll", "-url", nia.URL, "-state", filepath.Join(blocker, "state.json"))
	if code == 0 || nia.enrollments != 0 {
		t.Errorf("exit %d, %d enrollments: %s", code, nia.enrollments, stderr)
	}
	// Over plain http to another machine, the token is not sent either.
	code, _, stderr = command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_token"}, "", "enroll", "-url", "http://nia.example", "-state", filepath.Join(t.TempDir(), "s.json"))
	if code == 0 || !strings.Contains(stderr, "https") {
		t.Errorf("plain http: exit %d, %s", code, stderr)
	}
}

func TestARefusedEnrollmentLeavesNoState(t *testing.T) {
	nia := newFakeNia(t)
	nia.enrollCode = http.StatusUnauthorized
	path := filepath.Join(t.TempDir(), "state.json")
	code, _, stderr := command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_spent"}, "", "enroll", "-url", nia.URL, "-state", path)
	if code == 0 || !strings.Contains(stderr, "invalid_enrollment_token") || strings.Contains(stderr, "nen_spent") {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a state file was left behind")
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 0 {
		t.Errorf("%d files left behind", len(entries))
	}
}

func TestRunNeedsAnEnrolledMachine(t *testing.T) {
	code, _, stderr := command(t, context.Background(), nil, "", "run", "-state", filepath.Join(t.TempDir(), "state.json"))
	if code == 0 || !strings.Contains(stderr, "not enrolled") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

// syncBuffer lets the test read what a running command has written so far.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunRelaysWithTheMachineKeyAndReportsToNia(t *testing.T) {
	nia := newFakeNia(t)
	path := filepath.Join(t.TempDir(), "state.json")
	if code, _, stderr := command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_token"}, "", "enroll", "-url", nia.URL, "-state", path); code != 0 {
		t.Fatal(stderr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"run", "-state", path, "-listen", "127.0.0.1:0"}, env(map[string]string{"NIA_RUN": "run-7"}), strings.NewReader(""), &stdout, &stderr)
	}()
	address := ""
	for deadline := time.Now().Add(5 * time.Second); address == "" && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if match := regexp.MustCompile(`listening on (\S+),`).FindStringSubmatch(stdout.String()); match != nil {
			address = match[1]
		}
	}
	if address == "" {
		cancel()
		t.Fatalf("nia-edge did not start: %s %s", stdout.String(), stderr.String())
	}
	request, _ := http.NewRequest(http.MethodPost, "http://"+address+"/v1/tools/decide", strings.NewReader(`{"tool":"terminal"}`))
	request.Header.Set("Authorization", "Bearer nia_agent-chosen")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	nia.mu.Lock()
	agent := nia.lastAgent
	nia.mu.Unlock()
	if string(body) != `{"decision":"allow"}` || agent.Get("Authorization") != "Bearer nia_key1" || agent.Get("X-Nia-Run-Id") != "run-7" {
		t.Errorf("relayed call: body %q, headers %v", body, agent)
	}
	// The heartbeat goes out at start, and the health route says so.
	health := ""
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(health, `"machine":"active"`) && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if answer, err := http.Get("http://" + address + "/edge/health"); err == nil {
			raw, _ := io.ReadAll(answer.Body)
			answer.Body.Close()
			health = string(raw)
		}
	}
	if !strings.Contains(health, `"machine":"active"`) || !strings.Contains(health, `"nia":"ready"`) {
		t.Errorf("health %q", health)
	}
	// The key is never logged.
	if strings.Contains(stdout.String()+stderr.String(), "nia_key1") {
		t.Errorf("the machine key was logged: %s %s", stdout.String(), stderr.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d on shutdown: %s", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("nia-edge did not stop")
	}
}

func TestRunRefusesABadRun(t *testing.T) {
	nia := newFakeNia(t)
	path := filepath.Join(t.TempDir(), "state.json")
	command(t, context.Background(), map[string]string{"NIA_ENROLL_TOKEN": "nen_token"}, "", "enroll", "-url", nia.URL, "-state", path)
	code, _, stderr := command(t, context.Background(), map[string]string{"NIA_RUN": "bad run!"}, "", "run", "-state", path, "-listen", "127.0.0.1:0")
	if code == 0 || !strings.Contains(stderr, "NIA_RUN") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestUsage(t *testing.T) {
	if code, _, _ := command(t, context.Background(), nil, ""); code != 2 {
		t.Errorf("no command: exit %d", code)
	}
	if code, _, _ := command(t, context.Background(), nil, "", "delete-everything"); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
	if code, stdout, _ := command(t, context.Background(), nil, "", "version"); code != 0 || strings.TrimSpace(stdout) != version {
		t.Errorf("version: exit %d %q", code, stdout)
	}
}
