# nia-edge

nia-edge runs next to an AI agent, on the machine that runs it. It is the
agent's way to its model and its tools: every call goes to a
[Nia](https://getklaros.com) server with this machine's key, and Nia
authorizes it against the agent's role.

This repository is the client. It is open so that you can read what runs on
your machine. It is one binary, written in Go with the standard library only.

## Status

nia-edge relays today; Nia decides every call.

| Part | State |
| --- | --- |
| Enrollment with a one-time token, key kept in a private file | done |
| Relay of the agent's model and MCP calls (`/v1/`, `/mcp/`) | done |
| Heartbeat and health route | done |
| Hash of a call's arguments, identical to the server's (`canon`) | done |
| Egress proxy: every outbound connection decided by the role | done |
| Linux installer: systemd service, firewall rule, proof of isolation | done |
| macOS installer | not yet |
| Local MCP servers | not yet |
| Signed policy: fetched, verified against the key learned at enrollment, kept, reported | done |
| Decision engine: roles, argument rules, dispatchers, answering as the server on its cases | done, not used yet |
| Reading a request and a model's response (Chat Completions, Responses, Anthropic Messages; documents and streams) as the server does | done, not used yet |
| Secret detection and redaction (keys, tokens, labelled credentials) as the server does | done, not used yet |
| Model calls sent from the machine to the provider; Nia decides the tool calls and sees no prompt | done |
| Decisions made on the machine, from that policy | not yet |

The egress proxy governs the connections that go through it. It closes the
agent's network only when the agent has no other route out. On Linux the
installer sets that up and proves it; elsewhere it is yours to set (a firewall
rule by user, or a container whose only network is nia-edge).

## Get the binary

Releases are on the [releases page](https://github.com/GetKlaros/nia-edge/releases):
one static binary per system, the Linux installer with its firewall script
(keep the two in one directory), and `SHA256SUMS`.

```bash
sha256sum -c --ignore-missing SHA256SUMS      # before running anything
chmod +x nia-edge_*_linux_amd64 && mv nia-edge_*_linux_amd64 nia-edge
```

The builds are reproducible: `scripts/release.sh <tag>` on the tagged commit,
with the Go version `go.mod` names, gives the same checksums.

## Build

Go 1.27.4 ([go.dev/dl](https://go.dev/dl/)).

```bash
CGO_ENABLED=0 go build -ldflags "-X main.version=0.1.0" -o nia-edge ./cmd/nia-edge
```

`CGO_ENABLED=0` gives a static binary that runs on any Linux of the same
architecture.

## Install on Linux

An admin creates a one-time enrollment token in the Nia console (Machines).
Then, on the machine, as root:

```bash
sudo NIA_URL=https://nia.example NIA_ENROLL_TOKEN=nen_… install/linux.sh <agent-user>
```

It needs systemd and nftables. It:

1. creates the agent's user if needed, and refuses one that is in a group
   which goes around the rule (`sudo`, `docker`, `lxd`, …);
2. installs the binary and runs it as a service under its own user,
   `nia-edge`, whose state directory (mode 0700) holds the key;
3. enrolls the machine, the token passed on standard input;
4. loads an nftables rule, at every boot, that lets the agent's user reach
   `127.0.0.1:8787` and `127.0.0.1:3128` and nothing else, DNS included;
5. writes the proxy variables to the agent's profile;
6. runs `nia-edge doctor` as the agent's user, and fails if that user still
   has a way out.

Running it again keeps the key: no token is needed then. Root is not locked.
To undo the rule: `/usr/local/lib/nia-edge/firewall-linux.sh remove`.

`nia-edge doctor`, run as the agent's user at any time, tries every way out
(the server directly, raw TCP, the resolver, DNS over UDP) and reports to
Nia, which shows the machine as isolated or breached. Nia also sees the
attempt itself, so the result does not rest on what the machine says.

## Use without the installer

The token carries the role of this machine; the machine chooses nothing.

```bash
# The token comes from the environment, a file (-token-file) or standard
# input: never from the command line, which other users can read.
NIA_ENROLL_TOKEN=nen_… ./nia-edge enroll -url https://nia.example
./nia-edge run
```

Then point the agent's model at `http://127.0.0.1:8787/v1`. Any API key works
there: nia-edge replaces it with the machine's. For the network, give the
agent the proxy and no other route:

```bash
export HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128
```

Every connection is then a call to the `egress` tool of the machine's role:
list it in the role (`when_untrusted: require_approval`, for instance) or the
network is denied.

| Setting | Meaning |
| --- | --- |
| `-url` / `NIA_URL` | The Nia server. `https`, or `http` for a server on this machine. |
| `-state` / `EDGE_STATE` | State file, default `/var/lib/nia-edge/state.json`. It holds the key: mode 0600, replaced atomically, refused when another user can read it. |
| `-listen` / `EDGE_LISTEN` | Address of the relay, default `127.0.0.1:8787`. |
| `-proxy-listen` / `EDGE_PROXY_LISTEN` | Address of the egress proxy, default `127.0.0.1:3128`; `off` to disable. |
| `NIA_SESSION` | Session of the egress proxy (default `edge-<hostname>`). |
| `NIA_RUN` | Run that links this machine's conversations and its egress proxy (default: the session; `none` to unlink). What a conversation read hardens the network, and the reverse. The agent's own `x-nia-run-id` is ignored. |
| `EDGE_ALLOW_PRIVATE` | Hosts allowed on internal addresses, comma-separated: names, addresses or `*.suffix`. They are still decided by the role. |
| `EDGE_APPROVAL_WAIT` | Seconds a held connection waits for a reviewer (0 to 900, default 0). |
| `-force` (enroll) | Enroll again and replace the key this machine has. |
| `-edge` / `NIA_EDGE` (doctor, health) | The relay, as the agent reaches it; default `http://127.0.0.1:8787`. |

`GET /edge/health` answers `{"edge":"ok","nia":"ready","machine":"active","policy":"…"}`:
whether Nia is reachable, what the last heartbeat learned, and the signed
policy in force.

### Calling the model provider from the machine

By default the agent's model calls are relayed to Nia, which calls the
provider. With a provider set on the machine, nia-edge calls it itself:

```bash
# The key comes from NIA_PROVIDER_KEY, -key-file or standard input, never from the command line.
sudo -u nia-edge nia-edge provider -url https://api.example.com/v1 < provider.key
sudo systemctl restart nia-edge
nia-edge provider            # shows it;  nia-edge provider -remove  goes back to the relay
```

`-format anthropic` sends the key as `x-api-key`. The agent's configuration
does not change: it still talks to `http://127.0.0.1:8787/v1`, and the key it
sends is ignored.

What then goes to Nia, for each turn: the names of the tools whose results the
conversation holds (that is what taints a session), and each call the model
proposes, with its arguments, to be decided. What does not: the prompts, the
tool results and the model's text. Nia still decides, holds approvals and
keeps the log.

Every turn is read whole before anything is released:

- a secret in what is new in the request is replaced before it leaves the
  machine; a model response that holds one is not released;
- a response the provider did not finish, or that cannot be read as Nia reads
  it, is not released;
- one call Nia does not allow replaces the whole turn by what Nia says, in the
  agent's own API, streamed or not;
- a request that declares a provider-run tool (web search, code interpreter,
  remote MCP) is refused: the provider would run it before any decision;
- Nia out of reach refuses the turn.

Limits of this mode today: no detection of personal data or prompt attacks
(Nia's detectors do not see the text), the inspection settings of the policy
are not read (secrets are always replaced on the way in and block on the way
out), and when one call of a turn is refused, an approval another call of
the same turn used is spent.

### Signed policy

When the server signs policies, the machine learns the server's public key
(Ed25519) once, at enrollment, and keeps it in the state file. It then fetches
its policy, verifies it and keeps it in `policy.json` next to the state file.
A policy is refused when its signature does not match the pinned key, when it
names another machine, when it has expired or claims to live longer than eight
days, or when it is dated more than five minutes ahead of this machine's
clock. The file on disk is verified again at every start: editing it leaves
the machine with no policy.

The policy is renewed at half its life or as soon as the server names another
one. A server that starts signing with another key is not followed: enroll
the machine again (`nia-edge enroll -force`) if the change is yours.

Today the policy is verified and reported, not yet used: Nia decides every
call.

### Decision engine

`internal/engine` decides a call from a role as the server does: tool rules
and globs, argument rules (`match`, `hosts`, `shell_safe`), the role-wide
rules, observed roles, dispatchers. It replays the server's answers
(`conformance/decisions.json`, `dispatch.json`, `regex.json`).

The server is written in JavaScript and a role's `match` patterns are
JavaScript regular expressions. Where this engine cannot be sure to answer as
the server would, it does not answer, and the call is left to the server:

- a pattern outside the syntax both languages read alike (look-around,
  back-references, named groups, `\p`, legacy escapes);
- a pattern that can match any character (`.`, a negated class, `\S`, `\W`,
  `\D`, `\B`) on text outside the Basic Multilingual Plane, which JavaScript
  reads as two units;
- a URL with a punycode label (`xn--`), or an allowed host outside ASCII;
- arguments nested deeper than 9000 levels;
- a role with a field or a value this version does not know: refused whole.

Nothing uses the engine yet.

Run nia-edge under its own user, one the agent is not: the key in the state
file is protected by file permissions.

## What it guarantees

- The machine's key replaces any credential the agent sends, including a
  header the agent names in `Connection` to have it dropped.
- The run sent to Nia is nia-edge's, never the agent's.
- Only `/v1/` and `/mcp/` leave the edge, written plainly: a path with a dot
  segment, an empty segment or an escaped separator is refused.
- When Nia cannot be reached, the call is refused (`502 nia_unreachable`).
  A redirect is handed back, never followed with the key.
- An enrollment that could not keep its key does not use the token.

The egress proxy:

- An internal IP literal (this machine, the local network, cloud metadata,
  and every IPv6 form that carries such an IPv4 address) is refused before
  Nia is asked.
- A name is resolved only after the connection is allowed, once, and the
  connection goes to the address that was checked. A name that resolves to
  any internal address is refused.
- A name some resolvers read as an address (`127.1`, `0x7f.0.0.1`,
  `2130706433`) is refused.
- Only an explicit `allow` from Nia opens a connection. An error, an answer
  that cannot be read, or a connection Nia could not record refuses it.
- HTTPS is tunnelled without interception: Nia sees the host and the port.
  Plain HTTP also shows the method and the URL. Credentials the agent puts in
  the proxy URL are ignored and never reach the target.
- Neither the token nor the key is printed or logged.

## The contract with the server

The server is the reference engine. `conformance/` holds what it answers for
a fixed set of inputs; this code replays those cases and must answer the
same, byte for byte. See [conformance/README.md](conformance/README.md).

nia-edge calls three kinds of routes on the server:

| Route | Credential | Purpose |
| --- | --- | --- |
| `POST /edge/v1/enroll` | enrollment token | Get this machine's key, once |
| `POST /edge/v1/heartbeat` | machine key | Report, and learn the policy version to apply |
| `GET /edge/v1/policy` | machine key | This machine's policy, signed |
| `/v1/*`, `/mcp/*` | machine key | The agent's calls |

## Development

The installer is tested from the server's repository, in a machine with
systemd and nftables, against a real server: install, enrollment, services,
isolation, a breach when the rule is removed, a reboot, a second run.

```bash
scripts/verify.sh          # gofmt, go vet, tests with the race detector, shell syntax
git config core.hooksPath .githooks   # run it before every push
go test ./canon -run '^$' -fuzz FuzzCanonical -fuzztime 60s
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
