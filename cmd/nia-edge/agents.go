package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/GetKlaros/nia-edge/internal/agents"
)

// agentsCommand lists the agents of every account of this machine and what
// to do about each: a report, read from files and /proc, that changes and
// decides nothing. Run as root to see every account.
func agentsCommand(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nia-edge agents", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print JSON")
	root := flags.String("root", "", "read the machine's files under this directory (tests)")
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
	if *asJSON {
		if found == nil {
			found = []agents.Agent{}
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(found)
	}
	if len(found) == 0 {
		fmt.Fprintln(stdout, "no agent found (Hermes, OpenClaw, Codex, OpenCode, Claude Code)")
		return nil
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "USER\tAGENT\tRUNNING\tMCP\tMODEL\tCONFINED\tNEXT")
	for _, a := range found {
		servers := fmt.Sprint(a.Settings.MCPServers)
		if a.Settings.MCPServers < 0 {
			servers = "?"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.User, a.Kind, yes(a.Running), servers, a.Settings.Model, yes(a.Confined), a.Next)
	}
	return table.Flush()
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
