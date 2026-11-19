package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/GetKlaros/nia-edge/internal/simulate"
)

// simulateCommand runs what an agent's hook handed over under a ticket: in
// a sandbox over the user's files, then, when Nia allows what it did,
// applies it and gives back its output. Whatever fails, nothing is applied
// and the agent is told why.
func simulateCommand(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	refuse := func(why string) int {
		fmt.Fprintln(stderr, "[Nia agent firewall] "+why)
		return 126
	}
	if len(args) != 1 {
		return refuse("nia-edge simulate takes the ticket its hook gave")
	}
	edge := strings.TrimRight(getenv("NIA_EDGE"), "/")
	if edge == "" {
		edge = "http://127.0.0.1:8787"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 16 * time.Minute}
	base := edge + "/v1/simulate/" + args[0]

	response, err := client.Get(base)
	if err != nil {
		return refuse("nia-edge could not be reached, so the command was not run")
	}
	var handed struct {
		Command string `json:"command"`
		Timeout int    `json:"timeout_seconds"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&handed)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || handed.Command == "" || handed.Timeout < 1 {
		return refuse("this command is not one nia-edge handed over, so it was not run")
	}
	home, err := homeOfUser()
	if err != nil {
		return refuse("the command was not run: " + err.Error())
	}
	dir, err := os.Getwd()
	if err != nil {
		return refuse("the command was not run: " + err.Error())
	}
	result, err := simulate.Run(ctx, simulate.Options{Command: handed.Command, Dir: dir, Home: home, Timeout: time.Duration(handed.Timeout) * time.Second, Env: os.Environ()})
	if err != nil {
		return refuse("the command was simulated and not run: " + err.Error())
	}
	defer result.Close()

	var body bytes.Buffer
	json.NewEncoder(&body).Encode(result.Effect)
	response, err = client.Post(base+"/effect", "application/json", &body)
	if err != nil {
		return refuse("nia-edge could not be reached, so the command's effect was not applied")
	}
	var judged struct {
		Allowed bool   `json:"allowed"`
		Message string `json:"message"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&judged)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		return refuse("nia-edge's answer could not be read, so the command's effect was not applied")
	}
	if !judged.Allowed {
		return refuse(strings.TrimPrefix(judged.Message, "[Nia agent firewall] ") + "\n" + describe(result.Effect))
	}
	if err := result.Apply(); err != nil {
		if errors.Is(err, simulate.ErrChanged) {
			return refuse(err.Error() + "; run the command again")
		}
		return refuse("the command's effect could not be applied: " + err.Error())
	}
	stdout.Write(result.Stdout)
	stderr.Write(result.Stderr)
	if result.Truncated {
		fmt.Fprintf(stderr, "[Nia agent firewall] the output was cut at %d bytes\n", simulate.MaxOutput)
	}
	return result.ExitCode
}

// describe says what a simulated command would have done, for the agent.
func describe(effect simulate.Effect) string {
	shown := effect.Paths
	more := ""
	if len(shown) > 10 {
		more = fmt.Sprintf(" and %d more", len(shown)-10)
		shown = shown[:10]
	}
	return fmt.Sprintf("Its simulation deleted %d files and changed %s%s. Nothing was applied.", effect.Deleted, strings.Join(shown, ", "), more)
}

// homeOfUser is the home the system gives the user, not $HOME.
func homeOfUser() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", err
	}
	if current.HomeDir == "" {
		return "", errors.New("the user has no home")
	}
	return current.HomeDir, nil
}
