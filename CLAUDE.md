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
- What the machine reports about itself decides nothing.
- The egress proxy refuses an internal IP literal before any decision,
  resolves a name only after the connection is allowed, once, and connects to
  the address it checked. Only an explicit `allow` opens a connection; a
  connection Nia could not record is refused. Credentials from the agent are
  ignored and never forwarded.
- This repository is public: no secret, no customer name, no internal host
  name, and nothing copied from the server's code.

## Stack

Go 1.27 (the exact version is in `go.mod`), standard library only: a
dependency needs a reason written in the commit that adds it. Write from the
official documentation (`go doc`, go.dev), and use the latest stable release.

## Commands

- `scripts/verify.sh`: gofmt, go vet, tests with the race detector, build.
  `git config core.hooksPath .githooks` runs it before every push.
- `go test ./canon -run '^$' -fuzz FuzzCanonical -fuzztime 60s`: the JSON
  grammar against `encoding/json`.
- `scripts/sync-conformance.sh <dir>`: refresh the cases from the server's.
