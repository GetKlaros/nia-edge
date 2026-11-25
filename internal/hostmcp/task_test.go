package hostmcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/GetKlaros/nia-edge/internal/hostd"
)

type fakeTasks struct {
	session  string
	body     map[string]any
	decision string
}

func (f *fakeTasks) ProposeTask(_ context.Context, session string, body map[string]any) (string, string, error) {
	f.session, f.body = session, body
	return f.decision, "sent for review", nil
}

func taskCall(arguments string) string {
	return `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"propose_task","arguments":` + arguments + `}}`
}

func resultText(t *testing.T, answer map[string]any) (string, bool) {
	t.Helper()
	result := answer["result"].(map[string]any)
	return result["content"].([]any)[0].(map[string]any)["text"].(string), result["isError"].(bool)
}

func TestATaskIsSentInTheSessionItWasReleasedIn(t *testing.T) {
	h, host, releases := setup()
	h.Catalogue = func() (*hostd.Catalogue, error) {
		return &hostd.Catalogue{Services: []string{"nginx"}, Packages: []string{"nginx"}}, nil
	}
	tasks := &fakeTasks{decision: "require_approval"}
	h.Tasks = tasks
	h.Simulate = func(context.Context, string) []string { return []string{"nginx", "nginx-common"} }
	arguments := `{"title":"Serve the site","steps":[{"tool":"package_install","arguments":{"package":"nginx"}},{"tool":"service_reload","arguments":{"service":"nginx"}}]}`

	// Not released: nothing is sent.
	if text, failed := resultText(t, mustRPC(t, h, taskCall(arguments))); !failed || !strings.Contains(text, "not released") {
		t.Fatalf("%v %s", failed, text)
	}
	releases.ReleaseIn("conv-1", "mcp__host__propose_task", arguments, now)
	text, failed := resultText(t, mustRPC(t, h, taskCall(arguments)))
	if failed || !strings.Contains(text, "sent for review") {
		t.Fatalf("%v %s", failed, text)
	}
	if tasks.session != "conv-1" || tasks.body["title"] != "Serve the site" {
		t.Fatalf("sent %q %v", tasks.session, tasks.body)
	}
	sent, _ := json.Marshal(tasks.body["steps"])
	for _, want := range []string{`"tool":"mcp__host__package_install"`, `"installs":["nginx","nginx-common"]`, `"tool":"mcp__host__service_reload"`} {
		if !strings.Contains(string(sent), want) {
			t.Errorf("steps lack %s: %s", want, sent)
		}
	}
	// Proposing runs nothing on the machine.
	if len(host.asked) != 0 {
		t.Errorf("ran %v", host.asked)
	}
	// Once.
	if _, failed := resultText(t, mustRPC(t, h, taskCall(arguments))); !failed {
		t.Error("a release was spent twice")
	}
}

func TestATaskStepOutsideTheCatalogueSendsNothing(t *testing.T) {
	h, _, releases := setup()
	tasks := &fakeTasks{decision: "require_approval"}
	h.Tasks = tasks
	for _, arguments := range []string{
		`{"title":"x","steps":[{"tool":"package_install","arguments":{"package":"telnetd"}}]}`,
		`{"title":"x","steps":[{"tool":"propose_task","arguments":{}}]}`,
		`{"title":"x","steps":[]}`,
		`{"title":"","steps":[{"tool":"disk_usage","arguments":{}}]}`,
		`{"title":"x","steps":[{"tool":"disk_usage","arguments":{}}],"extra":1}`,
	} {
		releases.ReleaseIn("conv-1", "mcp__host__propose_task", arguments, now)
		if text, failed := resultText(t, mustRPC(t, h, taskCall(arguments))); !failed {
			t.Errorf("%s was sent: %s", arguments, text)
		}
	}
	if tasks.body != nil {
		t.Errorf("sent %v", tasks.body)
	}
}

func TestARefusedTaskIsAnError(t *testing.T) {
	h, _, releases := setup()
	h.Tasks = &fakeTasks{decision: "deny"}
	arguments := `{"title":"x","steps":[{"tool":"service_restart","arguments":{"service":"nginx"}}]}`
	releases.ReleaseIn("conv-1", "mcp__host__propose_task", arguments, now)
	if _, failed := resultText(t, mustRPC(t, h, taskCall(arguments))); !failed {
		t.Error("a refused task reads as a success")
	}
}

func TestSimulatedReadsWhatAptWouldInstall(t *testing.T) {
	out := []byte("NOTE: This is only a simulation!\nInst libnginx (1.24 Debian:12/stable [amd64])\nInst nginx (1.24 Debian:12/stable [amd64])\nConf nginx (1.24 Debian:12/stable [amd64])\n")
	if got := simulated(out); strings.Join(got, ",") != "libnginx,nginx" {
		t.Errorf("%v", got)
	}
	if AptSimulate(context.Background(), "-o=evil") != nil {
		t.Error("an option passed for a package name")
	}
}

func mustRPC(t *testing.T, h *Handler, body string) map[string]any {
	t.Helper()
	code, answer := rpc(t, h, body)
	if code != 200 {
		t.Fatalf("%d %v", code, answer)
	}
	return answer
}
