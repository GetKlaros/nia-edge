# nia-edge

nia-edge runs next to an AI agent, on the machine that runs it. It is the
agent's way to its model and its tools: every call goes to a
[Nia](https://getklaros.com) server with this machine's key, and Nia
authorizes it against the agent's role.

This repository is the client. It is open so that you can read what runs on
your machine. It is one binary, written in Go with the standard library only.

## Status

nia-edge calls the model provider from the machine and decides the calls with the signed policy; Nia holds the session state, the approvals and the log.

| Part | State |
| --- | --- |
| Enrollment with a one-time token, key kept in a private file | done |
| Relay of the agent's MCP calls (`/mcp/`); model calls only with `NIA_RELAY_MODEL_CALLS=yes` | done |
| Heartbeat and health route | done |
| Hash of a call's arguments, identical to the server's (`canon`) | done |
| Egress proxy: every outbound connection decided by the role | done |
| Linux installer: systemd service, firewall rule, proof of isolation | done |
| Hermes installer: its own user, its terminal in a rootless container without network, migration of an existing Hermes | done |
| Host actions: nia-hostd runs the role's catalogue as root (services, packages, sync), each call released by the model path once | done (Linux) |
| macOS installer | not yet |
| The agent's MCP servers, each in its own rootless container (nia-mcp): token kept by nia-edge, way out per server, each call released by the model path once | done (Linux) |
| Signed policy: fetched, verified against the key learned at enrollment, kept, reported | done |
| Decision engine: roles, argument rules, site categories, dispatchers, answering as the server on its cases | done: decides the model path's calls |
| Reading a request and a model's response (Chat Completions, Responses, Anthropic Messages; documents and streams) as the server does | done |
| Secret detection and redaction (keys, tokens, labelled credentials) as the server does | done |
| Model calls sent from the machine to the provider; Nia decides the tool calls and sees no prompt | done |
| Decisions made on the machine, from that policy: Nia gets a hash of the arguments | done |

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

To update a machine later: `sudo sh update-linux.sh <version>` (from a
release) checks the new binary against `SHA256SUMS`, replaces it and
restarts the services; the key, the provider and the policy stay.

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

## Install a Hermes agent on Linux

`install/hermes-linux.sh` installs Hermes so that it cannot go around Nia,
whatever command or script it runs:

```bash
# Take over a Hermes already installed under <user>, with the provider it uses:
sudo NIA_URL=https://nia.example NIA_ENROLL_TOKEN=nen_… install/hermes-linux.sh --from <user>
# Or a new one, with the provider named:
sudo NIA_URL=https://nia.example NIA_ENROLL_TOKEN=nen_… \
     NIA_PROVIDER_URL=https://api.example.com/v1 NIA_PROVIDER_KEY_FILE=/root/provider.key \
     install/hermes-linux.sh --fresh
```

It needs systemd, nftables and rootless Podman (Debian, Ubuntu:
`apt install podman uidmap catatonit`). It:

1. looks for Hermes under every account. Hermes installs itself under the
   account that runs its installer, with that account's files and network;
   nia-edge cannot close that account without closing its owner's own
   network. So the script stops and says so, unless told `--from <user>`
   (copy that Hermes' configuration, `.env`, memories, skills, sessions and
   scheduled jobs; the original is left as it is) or `--fresh`;
2. with `--from` and no `NIA_PROVIDER_URL`, takes over the provider that
   Hermes uses: Hermes' own code says which endpoint and which key it would
   send (`install/hermes-config.py`), the key moves from the agent's `.env`
   and `config.yaml` to nia-edge's state file, and is never printed. A
   provider Hermes signs in to by itself (OAuth: Nous Portal, Codex…), or
   one that does not speak chat completions, cannot be taken over: the script
   stops and asks for `NIA_PROVIDER_URL`;
3. creates the user `hermes`, with subordinate ids and a user manager that
   runs without a login, and installs Hermes there with its official
   installer;
4. points Hermes' model at nia-edge, and runs its terminal and file tools in
   a container (`terminal.backend docker` through rootless Podman, no
   network, no host directory mounted); Podman runs as `hermes`, so the
   container is never root on the machine and the user is in no `docker`
   group;
5. runs `install/linux.sh hermes`: nia-edge, the firewall rule, enrollment,
   and the proof with `nia-edge doctor`;
6. gives nia-edge the provider, so prompts do not go through Nia, and gives
   every MCP server Hermes starts the proxy of nia-edge in its own `env`
   (Hermes passes a server only a few variables), with `NODE_USE_ENV_PROXY=1`
   for Node; it names the servers whose command `hermes` may not reach (one
   under another person's home, say);
7. checks that a container of `hermes` has no network interface but loopback
   and sees nothing of its home.

What holds then, for a script the agent wrote and ran (tested by the
server's `npm run e2e:hermes`, with real Hermes and real calls the role
allows): it reads, deletes and sends nothing outside its container. Without
the container (`terminal.backend local`), the same script deletes the agent's
own files, but still nobody else's and still sends nothing.

The messaging gateway (Telegram…) is not installed by this script: its host
needs an `egress` rule in the role first.

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

### Host actions: nia-hostd

An agent that runs in a container has no shell on the machine. To manage it,
its role names a catalogue, signed with the rest of the policy:

```yaml
host:
  services: [nginx, postgresql@16-main]     # status, restart, reload
  packages: [fail2ban]                       # install from the machine's sources
  sync:
    - { name: site, source: /srv/www, destination: /backup/www, delete: true }
```

nia-edge serves these as MCP tools on its own address,
`http://127.0.0.1:8787/host/mcp` (`service_status`, `service_restart`,
`service_reload`, `package_install`, `sync`), whose one argument must be an
entry of that catalogue: another one is refused with the entries allowed. The
list is the same whatever the catalogue, so an agent that connected before a
new catalogue was published still has every action. The Hermes installer adds
this server as `host`, so the model sees `mcp__host__<action>`, and the role
decides each tool like any other.

- A tool call runs only against a release of the model path: the same tool
  and canonical arguments that Nia allowed in a turn, once, within ten
  minutes. Asked directly, it runs nothing.
- nia-edge passes it to `nia-edge hostd run`, a systemd service as root whose
  socket serves the `nia-edge` user only (the kernel's peer credentials).
- nia-hostd verifies the signed policy itself, against the key pinned at
  enrollment, and runs the action with a fixed program and fixed arguments,
  without a shell or an inherited environment: `systemctl restart -- nginx.service`,
  `apt-get install -y --no-install-recommends -- fail2ban`,
  `rsync -a --delete -- /srv/www/ /backup/www/`. A name outside the catalogue
  runs nothing.
- Every action is written to `/var/lib/nia-hostd/journal.jsonl` (mode 0600).
  `nia-edge hostd journal` prints it; `nia-edge hostd undo <id>` removes a
  package the action installed. Restarts and copies cannot be undone.
- The journal is a hash chain: each entry carries its number (`seq`) and the
  SHA-256 of the line before it (`prev`). `nia-edge hostd journal -verify`
  checks it; nia-hostd runs nothing while it does not verify. At each
  heartbeat nia-edge sends Nia the head of the chain and the hash of the entry
  Nia last saw as its head: Nia keeps that head, and shows the journal as
  rewritten when the chain no longer holds it, or broken when it does not
  verify. Root on the machine can still rewrite the file; it cannot make Nia
  forget a head it saw.

#### Dry runs against /etc

A role whose catalogue has `etc` lets its agent try a shell script against
the machine's configuration without changing it:

```yaml
host:
  etc:
    protected: [/etc/ssh/sshd_config, /etc/sudoers.d]   # must come out unchanged
    secrets: [/etc/app/token.conf]                       # seen only as decoys
```

`dry_run` takes the script. nia-hostd runs it with podman, as root inside a
container that has:

- the machine's `/etc` as an overlay: what the script writes goes to a layer
  in memory, bounded to 64 MiB, and the machine's `/etc` is not changed;
- of the rest of the machine's root file system, only `/usr`, `/bin`,
  `/sbin` and `/lib*`, read only and without their other mounts (podman
  prepares the container in a throwaway layer over it, so a machine without
  `/etc/mtab` works too): every other top-level directory (`/root`, `/home`,
  `/var`, `/srv`, `/opt`, `/data`, whatever an admin made) is an empty tmpfs
  and every other top-level file (a swap file) is `/dev/null`, and `/root`, `/home`, `/var`, `/srv`, `/opt`, `/mnt`, `/media`,
  `/boot` and `/tmp` empty;
- no network (only its own loopback), no capability, no new privilege,
  podman's masked `/proc` and read-only `/proc/sys`, a minimal `/dev`, at most
  256 processes, 512 MiB of memory and two minutes; nia-hostd refuses a dry
  run on a machine without cgroup v2 and its `pids` and `memory` controllers,
  where podman could not hold those bounds;
- a layer of at most 64 MiB and 32,768 files;
- a decoy in place of every file of `/etc` that the machine's other users
  cannot read, by its own mode or a directory above it they cannot cross (`/etc/shadow`, private keys, `sudoers`...) and of each secret
  of the catalogue. A decoy holds a random token: the run cannot read a
  secret, and nia-hostd sees which decoys it opened (their access time, on a
  tmpfs mounted `strictatime`) and where a token came out.

Guards then judge the state the plan would leave, against `/etc` as it is
now: each plan is compared with the machine, so a series of plans cannot
weaken it a step at a time. All are on unless the catalogue names them in
`etc.permit`:

- `ssh`: sshd's `PermitRootLogin`, `PasswordAuthentication` and
  `PermitEmptyPasswords` may not get weaker, read as sshd reads them (the first
  value obtained, `Include`s where they stand, `Match` blocks counted at their
  weakest, OpenSSH's defaults), and `AuthorizedKeysFile` may not change;
- `accounts`: no new user with uid or gid 0, no new member of `root`, `sudo`,
  `wheel`, `admin`, `adm`, `docker`, `lxd`, `incus-admin`, `libvirt`, `disk`,
  `shadow`, `kmem` or `systemd-journal`;
- `ssh` also refuses any change to the settings that decide who logs in, as
  whom and what runs (`AuthorizedKeysCommand`, `AuthorizedPrincipals*`,
  `TrustedUserCAKeys`, `PermitUserEnvironment`, `ForceCommand`, `AllowUsers`,
  `Port`, `ListenAddress`...), and an `Include` outside `/etc`;
- `accounts` also counts a user whose primary group is privileged, and a
  group that shares a privileged group's gid, and refuses any change to
  `subuid`, `subgid` and the defaults of new users;
- places where a file makes root run something, decides who is root or what
  root trusts: no change at all to `sudoers` (and `sudo.conf`, `doas.conf`),
  `pam` (and `login.defs`, `securetty`, `shells`), `cron` (and `at`),
  `systemd` (and `init.d`, `rc?.d`, `rc.local`, `/etc/default`,
  `/etc/sysconfig`), `preload` (`ld.so`), `shell_startup` (`profile`,
  `bash.bashrc`, `environment`, `zsh`), `login_scripts` (`update-motd.d`,
  `ssh/sshrc`, Xsession, autostart), `ssh_client` (root's `ssh_config`),
  `package_sources` (`/etc/apt`, `/etc/dpkg`, yum, dnf, zypp, pacman, apk,
  pip, npm, gem), `kernel_modules` (`modprobe.d`, `sysctl`, `binfmt.d`),
  `boot` (`grub.d`, `kernel`, `initramfs-tools`, dracut, `fstab`,
  `crypttab`), `udev`, `logrotate` (and rsyslog), `polkit` (and `dbus-1`),
  `mac` (AppArmor, SELinux), `trust_store` (`/etc/ssl`, `ca-certificates`,
  `pki`, `gnupg`), `name_resolution` (`hosts`, `resolv.conf`, `nsswitch.conf`,
  `gai.conf`), `interpreters` (`/etc/python*`, `perl`, `php*`, `ruby*`,
  `node*`, `java*`: sitecustomize, auto_prepend_file) and `network_hooks`.

Guards are a list of what is known to be dangerous: a file of another
program can still make root run something. `etc.writable` is the list of the
only paths a role's plans may change (for example `[/etc/nginx]`); set it.

A plan is not applicable either when it makes more than 1,000 changes or
writes more than 8 MiB, when a file or a directory would be writable by every
user, or when a symbolic link would point outside `/etc`, `/usr`, `/bin`,
`/sbin`, `/lib*`, `/dev/null`, `/run/systemd` and `/proc/self/mounts`: whoever
writes there would write the configuration after the review.

The answer is the run's plan: the files it created, changed or deleted, those
whose owner or mode alone changed, the protected paths it changed, and the
secrets it read, changed or copied, and what the guards refuse. A plan cannot
be applied when the script failed, a guard refuses it, a protected path or a
secret changed, a decoy came out, or a file would be setuid or setgid. nia-hostd keeps the last three applicable plans
for half an hour, in their layers. Every dry run is journaled with its plan.
Dry runs need podman on the machine; nia-hostd's mounts stay in its own
namespace (`PrivateMounts=yes`).

`apply` takes a plan and writes it to the machine's `/etc` as the run left
its layer, without running the script again:

- it refuses a plan whose paths changed on the machine since the dry run (each
  path's SHA-256, link target or absence is checked), and a layer that no
  longer holds what the report says;
- it saves every path it changes, a deleted directory with what it holds,
  under `/var/lib/nia-hostd/backups` (64 MiB at most);
- it writes through a handle on `/etc` that never leaves it (Go's `os.Root`: a
  symbolic link out of `/etc` is not followed); a file is written beside its
  name, given its owner and mode through its own descriptor, synced and
  renamed over it;
- it checks what it touched with the program of that configuration, when it
  is installed: `visudo -c`, `sshd -t`, `nginx -t`, `apache2ctl configtest`,
  `haproxy -c`, `findmnt --verify`, `pwck -r`, `grpck -r`. A failed check, or
  a failed write, puts the former files back;
- a plan is applied once; `nia-edge hostd undo <id>` puts back what an apply
  changed, if the machine still holds what it wrote.

When Nia holds an apply for a reviewer, nia-edge sends the plan with it:
nia-hostd's `plan_review` gives the plan's changes exactly as their SHA-256
makes the plan id, and the text before and after of each file it writes
(UTF-8 text of at most 64 KiB each, 512 KiB in all). Nia checks the changes
against the plan id and each text against its hash in the changes, then shows
the reviewer every change and the diff of each file. What the reviewer reads
is what that apply writes; a plan that did not come or does not match is
shown as not checked. These texts are `/etc` files the dry run could read:
secrets are decoys there, and a plan that changes one is never applicable.

### The agent's MCP servers: nia-mcp

An MCP server the agent starts itself (`npx some-mcp`) runs as the agent's
user, on the machine: it reads what the agent reads (its `.env`, its tokens),
it reaches what the agent reaches, and a new version of its package changes
it silently. nia-mcp runs each one in its own rootless container instead:

```sh
# The image, built where its registry is reachable, its dependencies inside.
docker save acme/mail-mcp:1.4.2 -o mail.tar
# Its token on standard input, never on a command line.
printf 'MAIL_TOKEN=...\n' | sudo install/mcp-linux.sh add mail mail.tar -- node /app/index.js
```

- The agent keeps a URL, `http://127.0.0.1:8787/local/<name>/mcp` (the Hermes
  installer's helper points the agent's configuration at it); the command and
  the token are in nia-edge's state file only.
- nia-mcp, under its own user without secret, privilege or network, starts
  the server from the image named by its ID: it is never pulled, so its code
  changes only when you load another image. The container is detached:
  without network, capability or new privilege, a read-only root, only its
  own variables, and nothing of the machine but nia-edge's binary and the
  directory of its two sockets.
- Its stream and its way out are those two sockets. Its only way out is
  nia-edge's egress proxy, which knows the server by its socket and sends
  `server: <name>` with each decision: a role gives each server its hosts.
- A call runs only when the model path released that exact call (same tool,
  same canonical arguments, once), as for the host actions. The server gets
  nothing it asks for itself (sampling, roots).
- A server starts at its first call and stops after ten minutes without
  one; its list of tools is kept by image, so listing it starts nothing.
  Each running server costs nia-mcp's monitor and relay, about 5 MB, on top
  of the server itself.

The role's egress rules for MCP servers, first in the list:

```yaml
- name: egress
  when_untrusted: allow
  arguments:
    - { applies: always, decision: allow, match: { server: '^mail$' }, hosts: { path: url, allow: [api.postmarkapp.com] } }
    - { applies: always, decision: deny, match: { server: '.' } }
    # ...then the agent's own hosts
```

What it does not stop: a server that sends its own token, or the data it is
given, through its own host (a blind copy added to every mail goes to the
mail API like the mail). Only the image you loaded runs: read what a new
version changes before you load it.

### Calling the model provider from the machine

An enrolled machine calls its model provider itself: its prompts never go to
Nia, and until a provider is set nia-edge refuses the agent's model calls
(`NIA_RELAY_MODEL_CALLS=yes` relays them instead, for a Nia whose policy lets
machines do so). Set the provider:

```bash
# The key comes from NIA_PROVIDER_KEY, -key-file or standard input, never from the command line.
sudo -u nia-edge nia-edge provider -url https://api.example.com/v1 < provider.key
sudo systemctl restart nia-edge
nia-edge provider            # shows it;  nia-edge provider -remove  removes it
```

`-format anthropic` sends the key as `x-api-key`. `-session-header <name>`
sends an opaque, stable id of each conversation in that header, for a
provider that routes or caches by it; for `opencode.ai` it is
`x-opencode-session` by default, which OpenCode Go requires. The agent's configuration
does not change: it still talks to `http://127.0.0.1:8787/v1`, and the key it
sends is ignored.

What then goes to Nia, for each turn: the names of the tools whose results the
conversation holds (that is what taints a session), the names of the
provider-run tools the request declares, and for each call the model
proposes, its name, the hash of its arguments and what the signed policy in
force decides for each state of the session (clean, tainted, exposed, both).
Nia picks the decision its session state calls for, applies the approvals and
keeps the log. The arguments go to Nia only when a reviewer must see them
(a held call nobody has been asked about yet), for a call through a
dispatcher, when the machine applies another policy than the active one, or
when the engine cannot be sure of the server's answer. What never goes: the
prompts, the tool results and the model's text.

Every turn is read whole before anything is released:

- a secret in what is new in the request is replaced before it leaves the
  machine; a model response that holds one is not released;
- a response the provider did not finish, or that cannot be read as Nia reads
  it, is not released;
- one call Nia does not allow replaces the whole turn by what Nia says, in the
  agent's own API, streamed or not;
- a tool the provider would run itself during the call (web search, code
  interpreter, remote MCP) is decided before the request leaves: Nia says
  which the role allows in this session, and the others are removed from the
  request, so they never run;
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

nia-mcp:

- Only nia-edge's user is served on its socket (the kernel names the peer);
  a launch names an image by its ID, a command and its variables, nothing
  else: a proxy variable, `PATH` or `HOME` is refused.
- A container has no network: going around the proxy reaches nothing. Its
  user and the range of ids of its containers reach no network either.
- nia-edge serves the servers' way out to nia-mcp's user alone, and reads the
  server's name from the line nia-mcp writes first, never from the server.

The firewall rule (`install/firewall-linux.sh`), for the agent's user:

- TCP to nia-edge (`127.0.0.1:8787`, `127.0.0.1:3128`) only, and to its own
  services on `127.0.0.1` (Hermes' command talks to its gateway on a port the
  kernel picks): a connection the agent opens on the loopback is marked, and
  its answers must come from a socket of the agent. A local proxy, database
  or API of another user answers nothing it can use.
- Nothing else, UDP and DNS included.

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
