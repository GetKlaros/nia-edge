#!/bin/sh
# Euthyna on this machine, in one command:
#
#   curl -fsSL https://get.euthyna.io | sudo sh
#
# It downloads the latest nia-edge release, checks every file against the
# release's SHA256SUMS, then:
#   - on a new machine, finds the agent it runs (Hermes, OpenClaw, Claude
#     Code, Codex, Gemini CLI, OpenCode), asks for the connection code shown
#     in the console, and installs it behind nia-edge;
#   - on a machine already connected, updates nia-edge and its services and
#     keeps its key; a new code connects it again (a revoked machine, say).
#
# The code is read from the terminal, never from the command line or a file
# other than a 0600 one this script deletes. Settings, from the environment:
#   EUTHYNA_URL       the console (default https://app.euthyna.io)
#   NIA_EDGE_VERSION  a release tag instead of the latest (v0.15.0)
#   EUTHYNA_AGENT     hermes | openclaw | claude-code | codex | gemini-cli | opencode
#   EUTHYNA_FROM      the account whose agent is taken over (default: the one found)
#   NIA_ENROLL_TOKEN_FILE  a 0600 file holding the code, for a machine set up
#                     without a terminal (it is not deleted)
set -eu

URL=${EUTHYNA_URL:-https://app.euthyna.io}
# Releases as GitHub serves them (releases/download/<tag>/<file>), mirrored at get.euthyna.io.
REPO=${NIA_EDGE_REPO:-https://get.euthyna.io}
STATE=/var/lib/nia-edge/state.json

say() { printf '%s\n' "$*"; }
fail() { printf 'euthyna: %s\n' "$1" >&2; exit "${2:-2}"; }
ask() {
  # The script is piped to sh: questions go to, and answers come from, the terminal.
  printf '%s' "$1" > /dev/tty
  IFS= read -r answer < /dev/tty || answer=
  printf '%s' "$answer"
}

[ "$(uname -s)" = Linux ] || fail "this installer is for Linux; on a Mac, see https://docs.euthyna.io"
[ "$(id -u)" -eq 0 ] || fail "run it with sudo: curl -fsSL https://get.euthyna.io | sudo sh"
command -v curl > /dev/null || fail "curl is required"
command -v sha256sum > /dev/null || fail "sha256sum is required"
command -v systemctl > /dev/null || fail "systemd is required"
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "no release for $(uname -m)" ;;
esac

# 1. The release, every file checked.
VERSION=${NIA_EDGE_VERSION:-}
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "$REPO/releases/latest" | head -n 1)
fi
case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "cannot find the latest release" ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
chmod 0755 "$work"
binary="nia-edge_${VERSION#v}_linux_$arch"
say "Euthyna: nia-edge $VERSION"
curl -fsSL -o "$work/SHA256SUMS" "$REPO/releases/download/$VERSION/SHA256SUMS" || fail "cannot download the release"
: > "$work/expected"
for file in "$binary" linux.sh firewall-linux.sh apparmor-linux.sh mcp-linux.sh hermes-linux.sh hermes-config.py openclaw-linux.sh openclaw-config.mjs update-linux.sh; do
  grep " $file\$" "$work/SHA256SUMS" >> "$work/expected" || continue
  curl -fsSL -o "$work/$file" "$REPO/releases/download/$VERSION/$file" || fail "cannot download $file"
done
grep -q " $binary\$" "$work/expected" || fail "the release has no $binary"
(cd "$work" && sha256sum -c expected > /dev/null) || fail "a file does not match its checksum: nothing changed"
chmod 0755 "$work/$binary"
chmod 0644 "$work"/*.sh "$work"/*.py "$work"/*.mjs 2> /dev/null || true
"$work/$binary" version > /dev/null || fail "nia-edge does not run on this machine: nothing changed"
export NIA_EDGE_BINARY="$work/$binary"

# The connection code, read without echo, kept in a 0600 file this script deletes.
code_file=${NIA_ENROLL_TOKEN_FILE:-}
read_code() {
  [ -z "$code_file" ] || return 0
  stty -echo < /dev/tty 2> /dev/null || true
  code=$(ask "$1")
  stty echo < /dev/tty 2> /dev/null || true
  printf '\n' > /dev/tty
  [ -n "$code" ] || return 1
  code_file="$work/code"
  (umask 077 && printf '%s\n' "$code" > "$code_file")
  return 0
}

# 2. A machine already connected: update it, keep or renew its key.
if [ -f "$STATE" ]; then
  agent_user=$(systemctl cat nia-agent-firewall.service 2> /dev/null | sed -n 's#.*firewall-linux.sh apply \([^ ]*\).*#\1#p' | head -n 1)
  before=$(/usr/local/bin/nia-edge version 2> /dev/null || echo "?")
  say "This machine is connected (nia-edge $before${agent_user:+, agent $agent_user})."
  if read_code "Connection code to connect it again (Enter to keep it as it is): "; then
    mv "$STATE" "$STATE.replaced-$(date +%Y%m%d%H%M%S)"
    say "The former key is set aside; the machine connects with the new code."
  fi
  export NIA_URL="$URL"
  [ -z "$code_file" ] || export NIA_ENROLL_TOKEN_FILE="$code_file"
  install_here() {
    # The installer restarts the services: a recent failure must not hold them back.
    systemctl reset-failed nia-edge.service nia-hostd.service nia-mcp.service 2> /dev/null || true
    { sh "$work/linux.sh" "${agent_user:---governed}"; echo "$?" > "$work/rc"; } 2>&1 | tee "$work/install.log"
    # What Nia answered the first heartbeat of the service as it runs now.
    beat=
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      run=$(systemctl show -p InvocationID --value nia-edge.service 2> /dev/null || true)
      [ -n "$run" ] && beat=$(journalctl "_SYSTEMD_INVOCATION_ID=$run" -o cat 2> /dev/null | grep -m 1 'heartbeat' || true)
      [ -z "$beat" ] || break
      sleep 1
    done
    case "$beat" in *'refused (401'*) echo 'HTTP 401' >> "$work/install.log"; return 1 ;; esac
    [ "$(cat "$work/rc")" = 0 ]
  }
  if ! install_here; then
    # Nia no longer knows this key (the machine was revoked): a new code connects it again.
    grep -q 'HTTP 401' "$work/install.log" || exit 1
    say ""
    say "Euthyna no longer accepts this machine's key: it was revoked. Copy a new code from $URL/console/connect."
    if [ -z "${NIA_ENROLL_TOKEN_FILE:-}" ] && read_code "Connection code: "; then
      mv "$STATE" "$STATE.replaced-$(date +%Y%m%d%H%M%S)"
      export NIA_ENROLL_TOKEN_FILE="$code_file"
      install_here || exit 1
    else
      fail "run this again and paste a new code when asked" 1
    fi
  fi
  say "Euthyna: nia-edge $before -> $(/usr/local/bin/nia-edge version)."
  exit 0
fi

# 3. A new machine: which agent, and whose.
found=
while IFS=: read -r name _ uid _ _ home _; do
  [ "$uid" -ge 1000 ] 2> /dev/null || [ "$name" = root ] || continue
  [ -f "$home/.hermes/config.yaml" ] && found="$found hermes:$name"
  [ -d "$home/.openclaw" ] && found="$found openclaw:$name"
  [ -d "$home/.claude" ] && found="$found claude-code:$name"
  [ -d "$home/.codex" ] && found="$found codex:$name"
  [ -d "$home/.gemini" ] && found="$found gemini-cli:$name"
  [ -d "$home/.config/opencode" ] && found="$found opencode:$name"
done << USERS
$(getent passwd)
USERS
found=${found# }
agent=${EUTHYNA_AGENT:-}
from=${EUTHYNA_FROM:-}
if [ -z "$agent" ]; then
  [ -n "$found" ] || fail "no agent found on this machine: install yours (Hermes, OpenClaw, Claude Code…), then run this again"
  # shellcheck disable=SC2086 # one word per agent found
  set -- $found
  if [ "$#" -eq 1 ]; then
    choice=1
  else
    say "Agents found:"
    n=0
    for item in "$@"; do n=$((n + 1)); say "  $n) ${item%%:*} (${item#*:})"; done
    choice=$(ask "Which one? [1-$#] ")
  fi
  case "$choice" in '' | *[!0-9]*) fail "no agent chosen" ;; esac
  [ "$choice" -ge 1 ] && [ "$choice" -le "$#" ] || fail "no agent chosen"
  eval "item=\${$choice}"
  agent=${item%%:*}
  from=${from:-${item#*:}}
fi

say "Open $URL/console/connect, choose this agent's role, and copy the connection code."
read_code "Connection code: " || fail "no code: nothing installed"
export NIA_URL="$URL" NIA_ENROLL_TOKEN_FILE="$code_file"
case "$agent" in
  hermes | openclaw)
    if [ -n "$from" ] && [ "$from" != "$agent" ] && [ "$from" != root ]; then
      sh "$work/$agent-linux.sh" --from "$from"
    else
      sh "$work/$agent-linux.sh"
    fi
    ;;
  claude-code | codex | gemini-cli | opencode)
    sh "$work/linux.sh" --governed
    /usr/local/bin/nia-edge agents onboard "$agent"
    ;;
  *) fail "unknown agent $agent" ;;
esac
say "Euthyna: $agent is connected. See it in $URL/console."
