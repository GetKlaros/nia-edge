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
| Egress proxy, so that the agent has no other way out | not yet |
| Local MCP servers | not yet |
| Decisions made on the machine, from a signed policy | not yet |

Until the egress proxy is here, nia-edge alone does not close a sandbox's
network: an agent with another route out is not held by it.

## Build

Go 1.27.4 or later of the 1.27 line ([go.dev/dl](https://go.dev/dl/)).

```bash
go build -ldflags "-X main.version=0.3.0" -o nia-edge ./cmd/nia-edge
```

## Use

An admin creates a one-time enrollment token in the Nia console (Machines).
It carries the role of this machine; the machine chooses nothing.

```bash
# The token comes from the environment, a file (-token-file) or standard
# input: never from the command line, which other users can read.
NIA_ENROLL_TOKEN=nen_… ./nia-edge enroll -url https://nia.example
./nia-edge run
```

Then point the agent's model at `http://127.0.0.1:8787/v1`. Any API key works
there: nia-edge replaces it with the machine's.

| Setting | Meaning |
| --- | --- |
| `-url` / `NIA_URL` | The Nia server. `https`, or `http` for a server on this machine. |
| `-state` / `EDGE_STATE` | State file, default `/var/lib/nia-edge/state.json`. It holds the key: mode 0600, replaced atomically, refused when another user can read it. |
| `-listen` / `EDGE_LISTEN` | Listening address, default `127.0.0.1:8787`. |
| `NIA_RUN` | Run that links this machine's conversations (default `edge-<hostname>`; `none` to unlink). The agent's own `x-nia-run-id` is ignored. |
| `-force` (enroll) | Enroll again and replace the key this machine has. |

`GET /edge/health` answers `{"edge":"ok","nia":"ready","machine":"active"}`:
whether Nia is reachable, and what the last heartbeat learned.

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
| `/v1/*`, `/mcp/*` | machine key | The agent's calls |

## Development

```bash
scripts/verify.sh          # gofmt, go vet, tests with the race detector
git config core.hooksPath .githooks   # run it before every push
go test ./canon -run '^$' -fuzz FuzzCanonical -fuzztime 60s
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
