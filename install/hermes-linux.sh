#!/bin/sh
# Installs a Hermes agent that cannot go around Nia, on Linux:
#
#   - Hermes runs under its own user (hermes), not under a person's account:
#     it reaches that user's files only, never a person's keys or documents;
#   - its terminal and file tools run in a rootless Podman container with no
#     network and no host directory mounted: a command, or a script the agent
#     wrote, sees only that container;
#   - that user's only way out is nia-edge (install/linux.sh: firewall rule,
#     enrollment, proof with nia-edge doctor), so every connection, the
#     container's included, goes through Nia.
#
#   sudo NIA_URL=https://nia.example NIA_ENROLL_TOKEN=nen_... install/hermes-linux.sh [--from <user> | --fresh]
#
# Hermes installs itself under the account that runs its installer. When this
# script finds it under another account, it stops and says so: that account
# cannot be closed without closing its owner's own network. --from <user>
# copies that Hermes' configuration, memories, skills, sessions and scheduled
# jobs to the dedicated user (the original is left as it is); --fresh starts
# the dedicated agent from nothing.
#
# Settings, from the environment:
#   NIA_URL, NIA_ENROLL_TOKEN (or NIA_ENROLL_TOKEN_FILE)  as for install/linux.sh
#   NIA_EDGE_BINARY            the nia-edge binary (default ./nia-edge)
#   NIA_PROVIDER_URL           the model provider nia-edge calls itself, so
#                              prompts do not go through Nia (https://…/v1).
#                              With --from and no NIA_PROVIDER_URL, the
#                              provider that Hermes uses is taken over: its
#                              key leaves the agent's files for nia-edge's
#   NIA_PROVIDER_KEY_FILE      the file holding its key (or NIA_PROVIDER_KEY)
#   NIA_PROVIDER_FORMAT        openai (default) or anthropic
#   HERMES_MODEL               the model Hermes asks for
#   HERMES_SANDBOX_IMAGE       the image of the terminal (default: Hermes' own)
#   HERMES_INSTALLER           a local copy of Hermes' installer (default:
#                              https://hermes-agent.nousresearch.com/install.sh)
#   HERMES_INSTALL_ARGS        extra arguments for Hermes' installer
#   HERMES_USER                the dedicated user (default hermes)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
AGENT=${HERMES_USER:-hermes}
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
for tool in podman newuidmap newgidmap loginctl runuser; do
  command -v "$tool" >/dev/null || fail "$tool is required (Debian, Ubuntu: apt install podman uidmap catatonit)"
done
command -v catatonit >/dev/null || [ -x /usr/libexec/podman/catatonit ] || command -v tini >/dev/null ||
  fail "an init for containers is required (Debian, Ubuntu: apt install catatonit)"
[ "$AGENT" != root ] || fail "the agent cannot run as root"
[ -z "$FROM" ] || [ "$FROM" != "$AGENT" ] || fail "--from names the dedicated user itself"
[ -z "$FROM" ] || [ "$FRESH" -eq 0 ] || fail "--from and --fresh exclude each other"
# The provider before anything is changed: without it the agent has no model.
# With --from, the one the existing Hermes uses can be taken over (step 4).
provider_url_ok() {
  case "$1" in https://?*|http://127.0.0.1[:/]*|http://localhost[:/]*) return 0 ;; esac
  return 1
}
TAKE_OVER=0
if [ -n "${NIA_PROVIDER_URL:-}" ]; then
  provider_url_ok "$NIA_PROVIDER_URL" || fail "NIA_PROVIDER_URL must be https"
  if [ -n "${NIA_PROVIDER_KEY_FILE:-}" ]; then
    [ -r "$NIA_PROVIDER_KEY_FILE" ] || fail "NIA_PROVIDER_KEY_FILE cannot be read"
    NIA_PROVIDER_KEY=$(cat "$NIA_PROVIDER_KEY_FILE")
  fi
  [ -n "${NIA_PROVIDER_KEY:-}" ] || fail "NIA_PROVIDER_KEY (or NIA_PROVIDER_KEY_FILE) is required"
elif [ -n "$FROM" ]; then
  TAKE_OVER=1
  [ -f "$HERE/hermes-provider.py" ] || fail "hermes-provider.py must be next to this script"
else
  fail "NIA_PROVIDER_URL is required with --fresh: nia-edge calls the model provider itself (with --from, the provider of that Hermes is taken over)"
fi
umask 077

home_of() { getent passwd "$1" | cut -d: -f6; }

# 1. Where Hermes already is. It installs itself under whoever ran its
# installer, with that account's files and network.
found=
while IFS=: read -r name _ _ _ _ home _; do
  [ "$name" != "$AGENT" ] || continue
  [ -f "$home/.hermes/config.yaml" ] && found="$found $name"
done <<USERS
$(getent passwd)
USERS
found=${found# }
if [ -n "$found" ] && [ -z "$FROM" ] && [ "$FRESH" -eq 0 ]; then
  cat >&2 <<MESSAGE
install: Hermes is installed under: $found
  There it runs with that account's files and network: it can read its keys
  and documents, and reach anything that account reaches. nia-edge cannot
  close that account without closing its owner's own network.

  This installer gives Hermes a user of its own, $AGENT, whose only way out
  is nia-edge and whose commands run in a container. Run it again with:
    --from <user>  to copy that Hermes' configuration, memories, skills,
                   sessions and scheduled jobs to $AGENT (the original is
                   left as it is: stop its gateway yourself);
    --fresh        to start $AGENT's Hermes from nothing.
MESSAGE
  exit 4
fi
if [ -n "$FROM" ]; then
  FROM_HOME=$(home_of "$FROM")
  [ -n "$FROM_HOME" ] && [ -f "$FROM_HOME/.hermes/config.yaml" ] || fail "no Hermes under $FROM ($FROM_HOME/.hermes/config.yaml)"
fi

# 2. The dedicated user: subordinate ids for rootless containers, and a user
# manager that runs without a login (Podman needs its runtime directory).
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

# As the agent, with its own home and runtime directory. The proxy settings of
# this shell, if any, are kept: Hermes' installer and the image pull need the
# network, and the agent's own is closed only at the end.
as_agent() {
  runuser -u "$AGENT" -- env HOME="$AGENT_HOME" USER="$AGENT" LOGNAME="$AGENT" XDG_RUNTIME_DIR="/run/user/$AGENT_UID" \
    PATH="$AGENT_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin" sh -c "umask 077; cd; $1"
}

# 3. Hermes under the dedicated user, with its official installer.
if [ -x "$AGENT_HOME/.local/bin/hermes" ]; then
  say "Hermes is already installed for $AGENT"
else
  installer=${HERMES_INSTALLER:-}
  if [ -z "$installer" ]; then
    command -v curl >/dev/null || fail "curl is required to download Hermes' installer"
    installer=$(mktemp)
    curl -fsSL https://hermes-agent.nousresearch.com/install.sh -o "$installer" || fail "cannot download Hermes' installer"
  fi
  chmod 0644 "$installer"
  say "installing Hermes for $AGENT (its official installer, a few minutes)"
  as_agent "bash '$installer' --skip-setup --skip-browser --skip-computer-use ${HERMES_INSTALL_ARGS:-}" || fail "Hermes' installer failed"
fi
[ -x "$AGENT_HOME/.local/bin/hermes" ] || fail "Hermes' installer left no hermes command in $AGENT_HOME/.local/bin"

# 4. What made the other Hermes this agent: never its code, caches or logs.
if [ -n "$FROM" ]; then
  for item in config.yaml .env SOUL.md memories skills cron sessions pairing hooks; do
    if [ -e "$FROM_HOME/.hermes/$item" ]; then
      rm -rf "$AGENT_HOME/.hermes/$item"
      cp -a "$FROM_HOME/.hermes/$item" "$AGENT_HOME/.hermes/$item"
    fi
  done
  chown -R "$AGENT:$AGENT" "$AGENT_HOME/.hermes"
  say "copied $FROM's Hermes configuration, memories and skills to $AGENT"
fi
# Hermes refuses a home others can write to.
chmod -R go-w "$AGENT_HOME/.hermes"

# The provider that Hermes used, read by Hermes' own code, before this script
# points it at nia-edge. Its key goes from the agent's files to this shell,
# and from here to nia-edge only (step 8); it is never printed.
if [ "$TAKE_OVER" -eq 1 ]; then
  helper_dir=$(mktemp -d)
  chmod 0755 "$helper_dir"
  cp "$HERE/hermes-provider.py" "$helper_dir/"
  chmod 0644 "$helper_dir/hermes-provider.py"
  HERMES_PY=
  for candidate in $(find "$AGENT_HOME/.hermes" "$AGENT_HOME/.local" -maxdepth 8 \( -name python -o -name python3 \) -path '*/bin/*' 2>/dev/null); do
    if as_agent "'$candidate' -I -c 'import hermes_cli.runtime_provider'" >/dev/null 2>&1; then
      HERMES_PY=$candidate
      break
    fi
  done
  [ -n "$HERMES_PY" ] || fail "cannot find Hermes' Python for $AGENT to read the provider of $FROM's Hermes: set NIA_PROVIDER_URL"
  hermes_provider() {
    as_agent "HERMES_HOME=\"\$HOME/.hermes\" '$HERMES_PY' -I '$helper_dir/hermes-provider.py' $1"
  }
  described=$(hermes_provider describe 2>/dev/null) || fail "Hermes cannot say which provider $FROM's Hermes uses: set NIA_PROVIDER_URL"
  field() { printf '%s\n' "$described" | sed -n "s/^$1=//p"; }
  provider_name=$(field provider)
  provider_mode=$(field api_mode)
  NIA_PROVIDER_URL=$(field base_url)
  [ "$(field has_key)" = 1 ] ||
    fail "$FROM's Hermes has no key it would send to its provider ($provider_name, $NIA_PROVIDER_URL): set NIA_PROVIDER_URL and NIA_PROVIDER_KEY_FILE" 6
  [ "$(field static)" = 1 ] ||
    fail "the provider of $FROM's Hermes ($provider_name) signs in by itself (OAuth): it cannot be handed to nia-edge; set NIA_PROVIDER_URL and NIA_PROVIDER_KEY_FILE" 6
  [ "$provider_mode" = chat_completions ] ||
    fail "the provider of $FROM's Hermes ($provider_name) speaks $provider_mode, not chat completions: set NIA_PROVIDER_URL and NIA_PROVIDER_FORMAT" 6
  provider_url_ok "$NIA_PROVIDER_URL" || fail "the provider of $FROM's Hermes is at $NIA_PROVIDER_URL, not https: set NIA_PROVIDER_URL" 6
  NIA_PROVIDER_KEY=$(hermes_provider key 2>/dev/null) || fail "cannot read the key of $FROM's Hermes provider"
  [ -n "$NIA_PROVIDER_KEY" ] || fail "the key of $FROM's Hermes provider is empty"
  # The agent keeps no copy: a fooled agent cannot leak what it cannot read.
  hermes_provider scrub >/dev/null 2>&1 || fail "cannot remove the provider key from $AGENT's Hermes files"
  rm -rf "$helper_dir"
  say "took over the provider of $FROM's Hermes ($provider_name, $NIA_PROVIDER_URL): its key is nia-edge's now, $AGENT's files no longer hold it ($FROM's own copy is left as it is)"
fi
if [ -n "$FROM" ]; then
  keys=$(grep -E '^[A-Z0-9_]*(API_KEY|_TOKEN|_SECRET)=' "$AGENT_HOME/.hermes/.env" 2>/dev/null | cut -d= -f1 | tr '\n' ' ' || true)
  [ -z "$keys" ] || say "$AGENT's .env holds: $keys- the agent can read these; a model key is not needed there: nia-edge holds the provider's"
fi

# 5. The model through nia-edge; the terminal and the file tools in a
# container without network, without any host directory.
set_hermes() {
  as_agent "hermes config set $1 '$2' >/dev/null" || fail "hermes config set $1 failed"
}
set_hermes model.provider custom
set_hermes model.base_url http://127.0.0.1:8787/v1
set_hermes model.api_key provided-by-nia-edge
set_hermes model.api_mode chat_completions
[ -z "${HERMES_MODEL:-}" ] || set_hermes model.default "$HERMES_MODEL"
set_hermes terminal.backend docker
set_hermes terminal.docker_network false
set_hermes terminal.docker_mount_cwd_to_workspace false
set_hermes HERMES_DOCKER_BINARY podman
[ -z "${HERMES_SANDBOX_IMAGE:-}" ] || set_hermes terminal.docker_image "$HERMES_SANDBOX_IMAGE"
get_hermes() { as_agent "hermes config get $1" 2>/dev/null | tail -n 1; }
[ "$(get_hermes terminal.backend)" = docker ] || fail "Hermes does not report terminal.backend docker"
case "$(get_hermes terminal.docker_network)" in
  false | False) ;;
  *) fail "Hermes does not report terminal.docker_network false" ;;
esac
IMAGE=$(get_hermes terminal.docker_image)
[ -n "$IMAGE" ] || fail "Hermes names no image for its terminal"
# Podman resolves a short name only through the registries the machine lists
# (registries.conf), and asks or fails otherwise. Hermes names its image as
# Docker does: say where it is, for Podman and for Hermes alike.
case "$IMAGE" in
  */*)
    case "${IMAGE%%/*}" in
      *.* | *:* | localhost) ;;
      *) IMAGE="docker.io/$IMAGE" ;;
    esac ;;
  *) IMAGE="docker.io/library/$IMAGE" ;;
esac
[ "$IMAGE" = "$(get_hermes terminal.docker_image)" ] || set_hermes terminal.docker_image "$IMAGE"

# 6. The image, while the agent can still download it, and a first container.
if ! as_agent "podman image exists '$IMAGE'"; then
  say "pulling $IMAGE for $AGENT"
  as_agent "podman pull -q '$IMAGE' >/dev/null" || fail "cannot pull $IMAGE"
fi
as_agent "podman run --rm --network=none '$IMAGE' true" ||
  fail "rootless containers do not run for $AGENT: check podman info as that user"

# The profile: the runtime directory Podman needs in any shell of the agent.
PROFILE=$AGENT_HOME/.profile
grep -q 'XDG_RUNTIME_DIR' "$PROFILE" 2>/dev/null || {
  printf '%s\n' '# Rootless containers of the Hermes terminal' 'export XDG_RUNTIME_DIR=/run/user/$(id -u)' >> "$PROFILE"
  chown "$AGENT:$AGENT" "$PROFILE"
}

# 7. nia-edge, the firewall rule and the proof that the agent has no way out.
# The hermes command talks to its own gateway on the loopback: the rule
# lets the agent reach its own services there, never another user's.
sh "$HERE/linux.sh" "$AGENT"

# 8. The provider: prompts do not go through Nia. Its key on standard input,
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

# 9. The container, once the agent's network is closed: no interface but
# loopback, and nothing of the agent's home.
nets=$(as_agent "podman run --rm --network=none '$IMAGE' ls /sys/class/net" 2>&1 | tr '\n' ' ' || true)
[ "$nets" = "lo " ] || fail "a container of $AGENT has network interfaces: $nets" 5
homes=$(as_agent "podman run --rm --network=none '$IMAGE' ls -A /home /root" 2>&1 || true)
case "$homes" in
  *"$AGENT"* | *.hermes*) fail "a container of $AGENT sees its home: $homes" 5 ;;
esac

echo
echo "Done. $AGENT runs Hermes: sudo -iu $AGENT hermes"
echo "  - its terminal and file tools run in $IMAGE, without network or host directory;"
echo "  - its model and every connection go through nia-edge, decided by Nia."
echo "  The messaging gateway (Telegram...) is not installed by this script: it needs"
echo "  an egress rule for its host in the role first."
