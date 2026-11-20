# nia-edge contributor guide

nia-edge is the client of Nia, a firewall for AI agents. It runs next to an
agent and is its way to its model and its tools. The Nia server is a separate,
private code base; this repository is public.

## Invariants

- Fail closed: an unreachable server, an answer that cannot be read or an
  internal error never lets a call through.
- The machine's key and run replace whatever the agent sends. Nothing the
  agent puts in a request can select another key, another run or another
  route than `/v1/` and `/mcp/`.
- The enrollment token and the machine key are never printed, logged, put in
  an error or accepted on the command line. The state file is mode 0600,
  replaced atomically, and refused when another user can read it.
- A token is used once: nothing asks the server to spend it before the key
  can be kept.
- The server is the reference engine. `conformance/*.json` is what it
  answers; this code replays the cases and must answer the same, byte for
  byte. The files are never edited by hand.
- Arguments that are not valid UTF-8, or that cannot be canonicalised where a
  canonical form is needed, are refused, never guessed.
- A policy is the server's only when its Ed25519 signature matches the key
  pinned at enrollment, it names this machine and it has not expired. That is
  checked on what comes from the server and again on what is read from disk.
  A key the server changed is never adopted without a new enrollment.
- The decision engine answers as the server or not at all: what it cannot be
  sure of is `ErrUndecidable`, never a guess, and a role with a field it does
  not know is refused whole.
- An enrolled machine's prompts stay on it: without a provider, model calls
  are refused; they never go to Nia, which does not carry them. A call
  the signed policy in force can decide goes to Nia as its hash and the
  decision for each state of the session; its arguments go only when Nia asks
  for them (a reviewer must see them), for a dispatcher, or when the engine
  cannot be sure. An apply's arguments then carry the plan's review: its
  changes as hashed into the plan id and the texts of the `/etc` files it
  writes, which Nia checks against those hashes before showing them. Nia picks the decision; the machine never picks it alone.
- With a provider set on the machine, the model path is local: a turn is read
  whole before anything is released; a request or a response that cannot be
  read as the server reads it, a secret in the model's answer, or Nia out of
  reach refuse it. A provider-run tool is decided before the request leaves
  and removed from it unless Nia allows it. Prompts, tool results and model text
  are never sent to Nia or logged. Before each call nia-edge asks Nia
  whether the key's budget allows it, and after it reports the tokens the
  provider counted; with a budget, a call it cannot count or report is not
  released. The provider key is in the state file
  only, never shown, never accepted on the command line, never sent anywhere
  but to the provider.
- The firewall lets the agent's user reach nia-edge and its own services on
  the loopback, never another user's, and nothing else. The Hermes and
  OpenClaw installers never leave the agent under a person's account without
  saying so, and run its terminal (OpenClaw: every sandboxed tool, exec never
  on the host, no tool that changes its configuration) in a rootless
  container without network or host directory. `nia-edge agents` only
  reports; what it reports decides nothing.
- An agent governed by its hooks (Claude Code, Codex, Gemini CLI, and
  OpenCode through nia-edge's plugin) gets them in the machine's own
  configuration; Pi and Oh My Pi, which have none, get
  nia-edge's extension in each user's agent directory, and are said to be
  governed for that user only. Before a
  tool runs nia-edge decides it as the model path does (hash and decisions,
  arguments only when Nia asks), and "allow" answers nothing, so the agent's
  own permissions still apply; a hold is a deny. nia-edge out of reach, a
  hook it cannot read or a decision it cannot obtain refuse the call, and
  `nia-edge hook` answers deny whatever fails. Onboarding saves each file
  before it changes it, and restore puts it back byte for byte.
- A role with `simulate` has each shell command of a hook-governed agent
  rewritten to `nia-edge simulate <ticket>`, which runs it in new user,
  mount, PID, network, IPC and UTS namespaces, the user's files as an
  overlay and everything else read only or empty, then has Nia judge the
  layer (`nia:effect`) and writes it as it is, once, only where the machine
  still holds what it saw and never out of the user's files. A command that
  cannot be simulated, or an agent that cannot be rewritten, is refused.
- nia-hostd is the only part that runs as root. It serves the nia-edge user
  alone (peer credentials), verifies the signed policy itself, and runs only
  the actions of the role's catalogue, by name, with fixed programs and
  arguments: no shell, no inherited environment, nothing the agent wrote. A
  host action runs only against an unused release of the model path for the
  same tool and canonical arguments. Every action is journaled, in a hash
  chain that must verify before anything runs; its head goes to Nia with
  each heartbeat, as a report that decides nothing.
- The one script an agent writes, a dry run, runs only in a container: the
  machine's `/etc` and the catalogue's directories (`dirs`, never one of
  `closedTrees`: programs, libraries, `/boot`, `/root`, `/home`, the package
  manager's and systemd's state, nia-edge's own, nor a directory holding
  one; reached without a symbolic link) as overlays whose layers are in a
  bounded tmpfs, of the rest only `/usr`, `/bin`, `/sbin` and `/lib*`, read only, no network, no
  capability, and bounded processes and memory (no cgroup v2, no dry run). Every file of
  `/etc` and of a catalogue directory its other users cannot read, and each
  secret of the catalogue, is a decoy there. What leaves the container is the list of its changes, and a
  plan that changes a protected path or a secret, lets a decoy out, makes a
  setuid file, makes a file of a catalogue directory executable or links it
  out of that directory, changes `/etc` for a role without `etc`, or failed
  is never applicable. Guards judge the state a plan
  leaves against the machine as it is (sshd not weaker, no new root or
  privileged member, no change where root runs something); only the
  catalogue's `etc.permit` lifts one, by name, and `etc.writable` narrows
  what any plan may change. A plan never makes a file writable by all or a
  link out of the system's trees, and stays under 1,000 changes and 8 MiB.
- An apply writes a plan exactly as its layer holds it, once, and only where
  the machine still holds what the dry run saw. It never leaves `/etc` and
  the catalogue's directories (no symbolic link out is followed), saves what it replaces first, checks the
  configurations it touched with fixed programs, and puts the former files
  back when a write or a check fails.
- The agent's MCP servers that run on the machine run in nia-mcp's rootless
  containers: one per server, from an image named by its ID and never
  pulled, without network, capability or new privilege, a read-only root,
  nothing of the machine but nia-edge's binary and its two sockets. nia-mcp
  serves the nia-edge user alone and has no secret, privilege or network.
  The server's token is in nia-edge's state file, never with the agent. Its
  only way out is nia-edge's egress proxy, under the name nia-mcp writes,
  never the server. A tool call runs only against an unused release of the
  model path for the same tool and canonical arguments.
- An MCP server hosted by its vendor is reached through nia-edge, which holds
  its token in the state file only: never with the agent, never shown or
  logged, sent only to the server's own URL over HTTPS, no redirect
  followed. The agent sees only the tools Nia pinned for the tenant, and a
  call runs only against an unused release of the model path or of the
  agent's hooks for the same tool and canonical arguments. A secret in a
  result is redacted before the agent sees it. A resource or prompt read
  from it taints the run. Signed in with OAuth, it requires PKCE S256, the
  `state` it sent and the server's URL as resource; the access and refresh
  tokens are in the state file only, like the token.
- What the machine reports about itself decides nothing. nia-edge's log of
  decisions (`decisions.jsonl`, 0600, beside the state file) holds tools,
  hosts, verdicts and Nia's reasons, redacted: never a prompt, an argument
  or an output; it decides nothing, and failing to write it stops no call.
- The egress proxy refuses an internal IP literal before any decision,
  resolves a name only after the connection is allowed, once, and connects to
  the address it checked. Only an explicit `allow` opens a connection; a
  connection Nia could not record is refused. Credentials from the agent are
  ignored and never forwarded.
- The installer never puts the token or the key on a command line or in a
  file other than the state file, enrolls only after everything else that can
  fail, and ends by proving isolation with `nia-edge doctor`: it fails when
  the agent's user still has a way out. Isolation is Nia's verdict, never the
  machine's own.
- This repository is public: no secret, no customer name, no internal host
  name, and none of the server's source code. What the client must compute
  as the server does is written here from the conformance cases.

## Stack

Go 1.27 (the exact version is in `go.mod`), standard library only: a
dependency needs a reason written in the commit that adds it. Write from the
official documentation (`go doc`, go.dev), and use the latest stable release.

## Commands

- `scripts/verify.sh`: gofmt, go vet, tests with the race detector, build,
  shell syntax. The installer itself is run by the server's `npm run e2e:native`.
  `git config core.hooksPath .githooks` runs it before every push.
- `go test ./canon -run '^$' -fuzz FuzzCanonical -fuzztime 60s`: the JSON
  grammar against `encoding/json`.
- `scripts/sync-conformance.sh <dir>`: refresh the cases from the server's.
- `scripts/release.sh <tag>`: the release binaries and their checksums, from
  a clean tagged commit. Reproducible: same tag, same Go, same bytes.
