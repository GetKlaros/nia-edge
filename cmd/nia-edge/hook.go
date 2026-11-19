package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/GetKlaros/nia-edge/internal/hooks"
)

// hookCommand is the command hook of an agent whose hooks are programs
// (Codex): it hands the hook to nia-edge, on this machine, and prints its
// answer. Whatever fails, the answer refuses: a call is not run, an output
// does not reach the model.
func hookCommand(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) != 1 || hooks.Route("/v1/hooks/"+args[0]) == "" {
		return fmt.Errorf("usage: nia-edge hook claude-code|codex|gemini-cli (the hook on standard input)")
	}
	agent := hooks.Route("/v1/hooks/" + args[0])
	raw, err := io.ReadAll(io.LimitReader(stdin, hooks.MaxPayload+1))
	var event struct {
		Event string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(raw, &event)
	refuse := func(why string) error {
		fmt.Fprintln(stderr, "nia-edge hook: "+why)
		if event.Event == "PostToolUse" || event.Event == "AfterTool" {
			return json.NewEncoder(stdout).Encode(hooks.Refusal(agent, "after", why))
		}
		return json.NewEncoder(stdout).Encode(hooks.Refusal(agent, "before", why+", so this call was not run"))
	}
	if err != nil || len(raw) > hooks.MaxPayload {
		return refuse("the hook could not be read")
	}
	base := getenv("NIA_EDGE_URL")
	if base == "" {
		base = "http://127.0.0.1:8787"
	}
	client := &http.Client{
		// Within the agent's hook timeout (330 s): an agent that kills its
		// hook may let the call through, so the hook answers first.
		Timeout:   300 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Post(base+"/v1/hooks/"+args[0], "application/json", bytes.NewReader(raw))
	if err != nil {
		return refuse("nia-edge cannot be reached")
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
	if err != nil || response.StatusCode != http.StatusOK || len(answer) > 4<<20 {
		return refuse("nia-edge did not answer")
	}
	if len(bytes.TrimSpace(answer)) == 0 {
		// Nothing to say: Gemini CLI reads JSON on standard output, always.
		if agent == hooks.GeminiCLI {
			_, err = io.WriteString(stdout, "{}\n")
			return err
		}
		return nil
	}
	if !json.Valid(answer) {
		return refuse("nia-edge's answer cannot be read")
	}
	_, err = stdout.Write(answer)
	return err
}
