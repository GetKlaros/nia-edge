#!/bin/sh
# Installs an OpenClaw agent that cannot go around Nia, on Linux:
#
#   - OpenClaw runs under its own user (openclaw), not under a person's
#     account: it reaches that user's files only, never a person's keys or
#     documents;
#   - every tool it runs (exec, files) runs in a rootless Podman container
#     with no network and no host directory, and exec never runs on the host
#     (no elevated mode);
#   - its model is nia-edge, its runtime's network goes through nia-edge's
#     proxy, and that user's only way out is nia-edge (install/linux.sh:
#     firewall rule, enrollment, proof with nia-edge doctor).
#
#   sudo NIA_URL=https://nia.example NIA_ENROLL_TOKEN=nen_... \
#     NIA_PROVIDER_URL=https://api.example/v1 NIA_PROVIDER_KEY_FILE=key \
#     install/openclaw-linux.sh [--from <user> | --fresh]
#
# OpenClaw installs itself under the account that runs its installer. When
# this script finds it under another account, it stops and says so. --from
# <user> copies that OpenClaw's configuration, agents, workspaces and state
# to the dedicated user (the original is left as it is: stop its gateway
# first); --fresh starts the dedicated agent from nothing.
#
# Settings, from the environment:
#   NIA_URL, NIA_ENROLL_TOKEN (or NIA_ENROLL_TOKEN_FILE)  as for install/linux.sh
#   NIA_EDGE_BINARY            the nia-edge binary (default ./nia-edge)
#   NIA_PROVIDER_URL           the model provider nia-edge calls itself, so
#                              prompts do not go through Nia (https://…/v1)
#   NIA_PROVIDER_KEY_FILE      the file holding its key (or NIA_PROVIDER_KEY)
#   NIA_PROVIDER_FORMAT        openai (default) or anthropic
#   OPENCLAW_MODEL             the model OpenClaw asks for (required with
#                              --fresh; with --from, that of its primary)
#   OPENCLAW_SANDBOX_IMAGE     the image of its tools (default
#                              docker.io/library/python:3.14-slim-trixie:
#                              OpenClaw's file tools need a Python in it)
#   OPENCLAW_INSTALLER         a local copy of OpenClaw's installer (default:
#                              https://openclaw.ai/install-cli.sh)
#   OPENCLAW_INSTALL_ARGS      extra arguments for that installer (--version …)
#   OPENCLAW_USER              the dedicated user (default openclaw)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
AGENT=${OPENCLAW_USER:-openclaw}
IMAGE=${OPENCLAW_SANDBOX_IMAGE:-docker.io/library/python:3.14-slim-trixie}
FROM=
FRESH=0

fail() { echo "install: $1" >&2; exit "${2:-2}"; }
say() { echo "install: $1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM=${2:?--from needs a user}; shift 2 ;;
    --fresh) FRESH=1; shift ;;
    *) fail "unknown argument $1 (--from <user> or --fresh)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -f "$HERE/linux.sh" ] || fail "linux.sh must be next to this script"
[ -f "$HERE/openclaw-config.mjs" ] || fail "openclaw-config.mjs must be next to this script"
for tool in podman newuidmap newgidmap loginctl runuser; do
  command -v "$tool" >/dev/null || fail "$tool is required (Debian, Ubuntu: apt install podman uidmap catatonit)"
done
# OpenClaw starts its sandboxes with --init: the engine's own init.
command -v catatonit >/dev/null || [ -x /usr/libexec/podman/catatonit ] ||
  fail "catatonit is required: OpenClaw starts its Podman sandboxes with --init (Debian, Ubuntu: apt install catatonit)"
# The docker group is root on the machine: an agent in it has a way out.
if id -nG "$AGENT" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
  fail "$AGENT is in the docker group, which is root on this machine: gpasswd -d $AGENT docker"
fi
[ "$AGENT" != root ] || fail "the agent cannot run as root"
[ -z "$FROM" ] || [ "$FROM" != "$AGENT" ] || fail "--from names the dedicated user itself"
[ -z "$FROM" ] || [ "$FRESH" -eq 0 ] || fail "--from and --fresh exclude each other"
case "$IMAGE" in *[!A-Za-z0-9._:/@-]* | "") fail "OPENCLAW_SANDBOX_IMAGE is not an image name" ;; esac
case "${OPENCLAW_MODEL:-}" in *[!A-Za-z0-9._:/@-]*) fail "OPENCLAW_MODEL is not a model name" ;; esac
# The provider before anything is changed: without it the agent has no model.
case "${NIA_PROVIDER_URL:-}" in
  https://?* | http://127.0.0.1[:/]* | http://localhost[:/]*) ;;
  "") fail "NIA_PROVIDER_URL is required: nia-edge calls the model provider itself" ;;
  *) fail "NIA_PROVIDER_URL must be https" ;;
esac
if [ -n "${NIA_PROVIDER_KEY_FILE:-}" ]; then
  [ -r "$NIA_PROVIDER_KEY_FILE" ] || fail "NIA_PROVIDER_KEY_FILE cannot be read"
  NIA_PROVIDER_KEY=$(cat "$NIA_PROVIDER_KEY_FILE")
fi
[ -n "${NIA_PROVIDER_KEY:-}" ] || fail "NIA_PROVIDER_KEY (or NIA_PROVIDER_KEY_FILE) is required"
umask 077

home_of() { getent passwd "$1" | cut -d: -f6; }

# 1. Where OpenClaw already is. It installs itself under whoever ran its
# installer, with that account's files and network.
found=
while IFS=: read -r name _ _ _ _ home _; do
  [ "$name" != "$AGENT" ] || continue
  [ -f "$home/.openclaw/openclaw.json" ] && found="$found $name"
done <<USERS
$(getent passwd)
USERS
found=${found# }
if [ -n "$found" ] && [ -z "$FROM" ] && [ "$FRESH" -eq 0 ]; then
  cat >&2 <<MESSAGE
install: OpenClaw is installed under: $found
  There it runs with that account's files and network: it can read its keys
  and documents, and reach anything that account reaches. nia-edge cannot
  close that account without closing its owner's own network.

  This installer gives OpenClaw a user of its own, $AGENT, whose only way out
  is nia-edge and whose tools run in a container. Run it again with:
    --from <user>  to copy that OpenClaw's configuration, agents, workspaces
                   and state to $AGENT (the original is left as it is: stop
                   its gateway first, openclaw gateway stop);
    --fresh        to start $AGENT's OpenClaw from nothing.
MESSAGE
  exit 4
fi
if [ -n "$FROM" ]; then
  FROM_HOME=$(home_of "$FROM")
  [ -n "$FROM_HOME" ] && [ -f "$FROM_HOME/.openclaw/openclaw.json" ] || fail "no OpenClaw under $FROM ($FROM_HOME/.openclaw/openclaw.json)"
fi
# A new OpenClaw has no primary model to keep.
[ -n "$FROM" ] || [ -n "${OPENCLAW_MODEL:-}" ] || [ -f "$(home_of "$AGENT")/.openclaw/openclaw.json" ] ||
  fail "OPENCLAW_MODEL is required for a new OpenClaw"

# 2. The dedicated user: subordinate ids for rootless containers, and a user
# manager that runs without a login (Podman and the gateway service need it).
id "$AGENT" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$AGENT"
AGENT_HOME=$(home_of "$AGENT")
AGENT_UID=$(id -u "$AGENT")
for file in /etc/subuid /etc/subgid; do
  if ! grep -q "^$AGENT:" "$file" 2>/dev/null; then
    start=$(awk -F: '{ end = $2 + $3; if (end > max) max = end } END { print (max > 100000 ? max : 100000) }' "$file" 2>/dev/null || echo 100000)
    if [ "$file" = /etc/subuid ]; then
      usermod --add-subuids "$start-$((start + 65535))" "$AGENT"
    else
      usermod --add-subgids "$start-$((start + 65535))" "$AGENT"
    fi
  fi
done
loginctl enable-linger "$AGENT"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -d "/run/user/$AGENT_UID" ] && break
  sleep 1
done
[ -d "/run/user/$AGENT_UID" ] || fail "no runtime directory for $AGENT (/run/user/$AGENT_UID): is systemd-logind running?"

OPENCLAW=$AGENT_HOME/.openclaw/bin/openclaw
# As the agent, with its own home and runtime directory. The proxy settings of
# this shell, if any, are kept: OpenClaw's installer and the image pull need
# the network, and the agent's own is closed only at the end.
as_agent() {
  runuser -u "$AGENT" -- env HOME="$AGENT_HOME" USER="$AGENT" LOGNAME="$AGENT" \
    XDG_RUNTIME_DIR="/run/user/$AGENT_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$AGENT_UID/bus" \
    OPENCLAW="$OPENCLAW" PATH="$AGENT_HOME/.openclaw/bin:/usr/local/bin:/usr/bin:/bin" sh -c "umask 077; cd; $1"
}

# 3. OpenClaw under the dedicated user, with its official installer: its own
# Node and its CLI under ~/.openclaw (bin, tools).
if [ -x "$OPENCLAW" ]; then
  say "OpenClaw is already installed for $AGENT"
else
  installer=${OPENCLAW_INSTALLER:-}
  if [ -z "$installer" ]; then
    command -v curl >/dev/null || fail "curl is required to download OpenClaw's installer"
    installer=$(mktemp)
    curl -fsSL --proto '=https' --tlsv1.2 https://openclaw.ai/install-cli.sh -o "$installer" || fail "cannot download OpenClaw's installer"
  fi
  chmod 0644 "$installer"
  say "installing OpenClaw for $AGENT (its official installer, a few minutes)"
  as_agent "bash '$installer' --no-onboard ${OPENCLAW_INSTALL_ARGS:-}" || fail "OpenClaw's installer failed"
fi
[ -x "$OPENCLAW" ] || fail "OpenClaw's installer left no openclaw command in $AGENT_HOME/.openclaw/bin"
# The Node that runs OpenClaw runs the helper too.
NODE=$(sed -n 's/^exec \(\/[^ ]*\/node\) .*/\1/p' "$OPENCLAW" | head -n 1)
[ -n "$NODE" ] && [ -x "$NODE" ] || NODE=$(find "$AGENT_HOME/.openclaw/tools" -maxdepth 4 -path '*/bin/node' -type f 2>/dev/null | head -n 1)
[ -n "$NODE" ] && [ -x "$NODE" ] || fail "cannot find the Node of $AGENT's OpenClaw"

# 4. What made the other OpenClaw this agent: never its code (bin, tools),
# logs or sandboxes.
if [ -n "$FROM" ]; then
  for item in "$FROM_HOME"/.openclaw/* "$FROM_HOME"/.openclaw/.[!.]*; do
    [ -e "$item" ] || continue
    case "${item##*/}" in bin | tools | logs | sandboxes) continue ;; esac
    rm -rf "$AGENT_HOME/.openclaw/${item##*/}"
    cp -a "$item" "$AGENT_HOME/.openclaw/${item##*/}"
  done
  say "copied $FROM's OpenClaw configuration, agents, workspaces and state to $AGENT"
  keys=$(grep -E '^[A-Z0-9_]*(API_KEY|_TOKEN|_SECRET)=' "$AGENT_HOME/.openclaw/.env" 2>/dev/null | cut -d= -f1 | tr '\n' ' ' || true)
  [ -z "$keys" ] || say "$AGENT's .openclaw/.env holds: $keys- the agent can read these; a model key is not needed there: nia-edge holds the provider's"
fi
find "$AGENT_HOME/.openclaw" ! -user "$AGENT" -exec chown -h "$AGENT:$AGENT" {} + 2>/dev/null || true
find "$AGENT_HOME/.openclaw" ! -type l -perm /go=w -exec chmod go-w {} + 2>/dev/null || true
left=$(find "$AGENT_HOME/.openclaw" \( ! -user "$AGENT" -o \( ! -type l -perm /go=w \) \) -print -quit 2>/dev/null || true)
[ -z "$left" ] || fail "$left is not $AGENT's alone"

helper_dir=$(mktemp -d)
chmod 0755 "$helper_dir"
cp "$HERE/openclaw-config.mjs" "$helper_dir/"
chmod 0644 "$helper_dir/openclaw-config.mjs"
openclaw_config() {
  as_agent "'$NODE' '$helper_dir/openclaw-config.mjs' $1"
}

# 5. The model through nia-edge.
if [ -n "$FROM" ] || [ -f "$AGENT_HOME/.openclaw/openclaw.json" ]; then
  [ -z "$FROM" ] || openclaw_config "paths '$FROM_HOME'" >"$helper_dir/left" || fail "cannot point $AGENT's OpenClaw at its own home"
  if [ -s "$helper_dir/left" ]; then
    say "these settings still name $FROM's home; change them by hand:"
    sed 's/^/install:   /' "$helper_dir/left"
  fi
  model=$(openclaw_config "model '${OPENCLAW_MODEL:-}'") || fail "cannot point $AGENT's OpenClaw at nia-edge (set OPENCLAW_MODEL)"
  # The agent keeps no provider key: a fooled agent cannot leak what it
  # cannot read.
  scrubbed=$(openclaw_config scrub) || fail "cannot remove the provider keys from $AGENT's OpenClaw configuration"
  [ -z "$scrubbed" ] || say "removed the key of these providers from $AGENT's configuration: $(echo $scrubbed)"
else
  model=$OPENCLAW_MODEL
  openclaw_config "fresh '$model'" >/dev/null || fail "OpenClaw's onboarding failed"
fi
say "$AGENT's OpenClaw asks nia-edge for $model"

# 6. Its tools in a container without network or host directory, no exec on
# the host, the runtime's network through nia-edge's proxy.
PODMAN=$(command -v podman)
case "$PODMAN" in /*) ;; *) fail "podman is not a file on the PATH: $PODMAN" ;; esac
openclaw_config "harden '$IMAGE'" || fail "OpenClaw does not report its tools confined (see above)"
# The MCP servers it starts get only a few variables and their own env.
elsewhere=$(openclaw_config mcp) || fail "cannot give $AGENT's MCP servers the proxy of nia-edge"
openclaw_config host || fail "$AGENT's OpenClaw already has an MCP server named mcp__host: rename it, the host actions take that name"
if [ -n "$elsewhere" ]; then
  say "these MCP servers of $AGENT run a command $AGENT may not reach; copy it under $AGENT_HOME or /opt and point the server at it:"
  printf '%s\n' "$elsewhere" | sed 's/^/install:   /'
fi
as_agent "openclaw config validate >/dev/null" || fail "OpenClaw does not validate $AGENT's configuration"

# 7. The image, while the agent can still download it, and a first container.
if ! as_agent "podman image exists '$IMAGE'"; then
  say "pulling $IMAGE for $AGENT"
  as_agent "podman pull -q '$IMAGE' >/dev/null" || fail "cannot pull $IMAGE"
fi
as_agent "podman run --rm --init --network=none '$IMAGE' true" ||
  fail "rootless containers do not run for $AGENT: check podman info as that user"
PROFILE=$AGENT_HOME/.profile
grep -q 'XDG_RUNTIME_DIR' "$PROFILE" 2>/dev/null || {
  printf '%s\n' '# Rootless containers of the OpenClaw sandbox' 'export XDG_RUNTIME_DIR=/run/user/$(id -u)' >> "$PROFILE"
  chown "$AGENT:$AGENT" "$PROFILE"
}

# 8. nia-edge, the firewall rule and the proof that the agent has no way out.
# The openclaw command talks to its own gateway on the loopback: the rule
# lets the agent reach its own services there, never another user's.
sh "$HERE/linux.sh" "$AGENT"

# 9. The provider: prompts do not go through Nia. Its key on standard input,
# as the nia-edge user: never on a command line.
printf '%s\n' "$NIA_PROVIDER_KEY" |
  runuser -u nia-edge -- env -i PATH=/usr/bin:/bin /usr/local/bin/nia-edge provider \
    -state /var/lib/nia-edge/state.json -url "$NIA_PROVIDER_URL" -format "${NIA_PROVIDER_FORMAT:-openai}"
unset NIA_PROVIDER_KEY
systemctl restart nia-edge.service
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  /usr/local/bin/nia-edge health >/dev/null 2>&1 && break
  sleep 1
done

# 10. The container, once the agent's network is closed: no interface but
# loopback, and nothing of the agent's home.
nets=$(as_agent "podman run --rm --network=none '$IMAGE' ls /sys/class/net" 2>&1 | tr '\n' ' ' || true)
[ "$nets" = "lo " ] || fail "a container of $AGENT has network interfaces: $nets" 5
homes=$(as_agent "podman run --rm --network=none '$IMAGE' ls -A /home /root" 2>&1 || true)
case "$homes" in
  *"$AGENT"* | *.openclaw*) fail "a container of $AGENT sees its home: $homes" 5 ;;
esac

# 11. The gateway as the agent's own service, on the loopback.
if as_agent "openclaw gateway install --force >/dev/null 2>&1"; then
  say "OpenClaw's gateway runs as $AGENT's service (systemctl --user)"
else
  say "OpenClaw's gateway service could not be installed: start it with sudo -iu $AGENT openclaw gateway run"
fi
rm -rf "$helper_dir"

echo
echo "Done. $AGENT runs OpenClaw: sudo -iu $AGENT openclaw"
echo "  - its tools run in $IMAGE, without network or host directory, never on the host;"
echo "  - its model and every connection go through nia-edge, decided by Nia."
echo "  Channels (Telegram...) need an egress rule for their host in the role first."
