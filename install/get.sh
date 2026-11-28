#!/bin/sh
# Euthyna on this machine, in one command, in a terminal:
#
#   curl -fsSL https://get.euthyna.io | sh
#
# It downloads the latest nia-edge release and checks every file against the
# release's SHA256SUMS. Then it looks at the machine (with sudo) and asks, as
# you, what it needs:
#   - a new machine: which agent to connect (Hermes, OpenClaw, Claude Code,
#     Codex, Gemini CLI, OpenCode), then the connection code from the console;
#   - a machine already connected: a new code to connect it again, or Enter
#     to update it and keep its key; a key Euthyna refuses (a revoked machine)
#     asks for a code;
#   - a machine installed before whose key is gone: the code.
# The questions are asked before sudo: under sudo, a script read from a pipe
# cannot read what is typed. The code is read without echo and reaches the
# root part in a 0600 file, never on a command line.
#
# Without a terminal, from the environment:
#   NIA_ENROLL_TOKEN_FILE  a file holding the code (it is not deleted)
#   EUTHYNA_AGENT          hermes | openclaw | claude-code | codex | gemini-cli | opencode
#   EUTHYNA_FROM           the account whose agent is taken over
#   EUTHYNA_URL            the console (default https://app.euthyna.io)
#   NIA_EDGE_VERSION       a release tag instead of the latest
set -eu

URL=${EUTHYNA_URL:-https://app.euthyna.io}
# Releases as GitHub serves them (releases/download/<tag>/<file>), mirrored at get.euthyna.io.
REPO=${NIA_EDGE_REPO:-https://get.euthyna.io}
STATE=/var/lib/nia-edge/state.json
STEP=${1:-}

say() { printf '%s\n' "$*"; }
fail() { printf 'euthyna: %s\n' "$1" >&2; exit "${2:-2}"; }

# --------------------------------------------------------------- as root
# "probe" says what the machine has; "apply" does what was decided. Both are
# run by the part below, with sudo, from the release it checked.

# The agent user of an earlier install: the one its firewall rule closes.
agent_user() {
  systemctl cat nia-agent-firewall.service 2> /dev/null | sed -n 's#.*firewall-linux.sh apply \([^ ]*\).*#\1#p' | head -n 1
}

if [ "$STEP" = probe ]; then
  if [ -f "$STATE" ]; then
    say "state connected"
  elif [ -f /etc/nia-edge.env ]; then
    say "state installed"
  else
    say "state new"
  fi
  say "user $(agent_user)"
  say "version $(/usr/local/bin/nia-edge version 2> /dev/null || true)"
  while IFS=: read -r name _ uid _ _ home _; do
    [ "$uid" -ge 1000 ] 2> /dev/null && [ "$uid" -lt 60000 ] || continue
    [ -f "$home/.hermes/config.yaml" ] && say "agent hermes $name"
    [ -d "$home/.openclaw" ] && say "agent openclaw $name"
    [ -d "$home/.claude" ] && say "agent claude-code $name"
    [ -d "$home/.codex" ] && say "agent codex $name"
    [ -d "$home/.gemini" ] && say "agent gemini-cli $name"
    [ -d "$home/.config/opencode" ] && say "agent opencode $name"
  done << USERS
$(getent passwd)
USERS
  exit 0
fi

if [ "$STEP" = apply ]; then
  [ "$(id -u)" -eq 0 ] || fail "apply runs as root"
  work=$(dirname "$0")
  export NIA_URL="$URL"
  [ -z "${NIA_ENROLL_TOKEN_FILE:-}" ] || export NIA_ENROLL_TOKEN_FILE
  case "${EUTHYNA_ACTION:-}" in
    update | reconnect)
      user=$(agent_user)
      if [ "$EUTHYNA_ACTION" = reconnect ] && [ -f "$STATE" ]; then
        mv "$STATE" "$STATE.replaced-$(date +%Y%m%d%H%M%S)"
        say "The former key is set aside; the machine connects with the new code."
      fi
      # The installer restarts the services: a recent failure must not hold them back.
      systemctl reset-failed nia-edge.service nia-hostd.service nia-mcp.service 2> /dev/null || true
      { sh "$work/linux.sh" "${user:---governed}"; echo "$?" > "$work/rc"; } 2>&1 | tee "$work/install.log"
      # What Euthyna answered the first heartbeat of the service as it runs now.
      beat=
      for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        run=$(systemctl show -p InvocationID --value nia-edge.service 2> /dev/null || true)
        [ -n "$run" ] && beat=$(journalctl "_SYSTEMD_INVOCATION_ID=$run" -o cat 2> /dev/null | grep -m 1 'heartbeat' || true)
        [ -z "$beat" ] || break
        sleep 1
      done
      # A key Euthyna refuses: the part that asks knows what to do with it.
      case "$beat" in *'refused (401'*) exit 10 ;; esac
      grep -q 'HTTP 401' "$work/install.log" && exit 10
      [ "$(cat "$work/rc")" = 0 ] || exit 1
      ;;
    install)
      agent=${EUTHYNA_AGENT:?no agent}
      from=${EUTHYNA_FROM:-}
      case "$agent" in
        hermes | openclaw)
          if [ -n "$from" ] && [ "$from" != "$agent" ]; then
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
      ;;
    *) fail "nothing to apply" ;;
  esac
  exit 0
fi

# ------------------------------------------------------ as the person
# In a function called on the last line: sh has read the whole script before
# anything runs, even when the download stops half way.
main() {
  [ "$(uname -s)" = Linux ] || fail "this installer is for Linux; on a Mac, see https://docs.euthyna.io"
  command -v curl > /dev/null || fail "curl is required"
  command -v sha256sum > /dev/null || fail "sha256sum is required"
  command -v systemctl > /dev/null || fail "systemd is required"
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "no release for $(uname -m)" ;;
  esac
  if [ "$(id -u)" -eq 0 ]; then
    as_root() { "$@" < /dev/null; }
  else
    command -v sudo > /dev/null || fail "sudo is required (or run this as root)"
    # Its standard input is the rest of this script: sudo must not read it.
    as_root() { sudo "$@" < /dev/null; }
  fi

  # Questions go to, and answers come from, the terminal: the script itself is
  # what sh reads on its standard input.
  tty=
  if (: < /dev/tty) 2> /dev/null; then tty=/dev/tty; fi
  ask() {
    [ -n "$tty" ] || return 1
    printf '%s' "$1" > "$tty"
    answer=
    IFS= read -r answer < "$tty" || true
  }

  # 1. The release, every file checked.
  VERSION=${NIA_EDGE_VERSION:-}
  [ -n "$VERSION" ] || VERSION=$(curl -fsSL "$REPO/releases/latest" | head -n 1)
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
  for file in "$binary" get.sh linux.sh firewall-linux.sh apparmor-linux.sh mcp-linux.sh hermes-linux.sh hermes-config.py openclaw-linux.sh openclaw-config.mjs update-linux.sh; do
    grep " $file\$" "$work/SHA256SUMS" >> "$work/expected" || continue
    curl -fsSL -o "$work/$file" "$REPO/releases/download/$VERSION/$file" || fail "cannot download $file"
  done
  grep -q " $binary\$" "$work/expected" || fail "the release has no $binary"
  grep -q ' get.sh$' "$work/expected" || fail "the release has no get.sh"
  (cd "$work" && sha256sum -c expected > /dev/null) || fail "a file does not match its checksum: nothing changed"
  chmod 0755 "$work/$binary"
  chmod 0644 "$work"/*.sh "$work"/*.py "$work"/*.mjs 2> /dev/null || true
  "$work/$binary" version > /dev/null || fail "nia-edge does not run on this machine: nothing changed"

  # The root part, from the checked release, with what was decided.
  apply() {
    as_root env EUTHYNA_ACTION="$1" EUTHYNA_URL="$URL" NIA_EDGE_BINARY="$work/$binary" \
      ${EUTHYNA_AGENT:+EUTHYNA_AGENT="$EUTHYNA_AGENT"} ${EUTHYNA_FROM:+EUTHYNA_FROM="$EUTHYNA_FROM"} \
      ${EDGE_ALLOW_PRIVATE:+EDGE_ALLOW_PRIVATE="$EDGE_ALLOW_PRIVATE"} ${code_file:+NIA_ENROLL_TOKEN_FILE="$code_file"} \
      sh "$work/get.sh" apply
  }

  # The connection code: from NIA_ENROLL_TOKEN_FILE, or typed without echo into a 0600 file.
  code_file=${NIA_ENROLL_TOKEN_FILE:-}
  read_code() {
    [ -z "$code_file" ] || return 0
    [ -n "$tty" ] || return 1
    stty -echo < "$tty" 2> /dev/null || true
    ask "$1" || true
    stty echo < "$tty" 2> /dev/null || true
    printf '\n' > "$tty"
    [ -n "$answer" ] || return 1
    code_file="$work/code"
    (umask 077 && printf '%s\n' "$answer" > "$code_file")
  }
  need_code() {
    say "Copy the connection code from $URL/console/connect (Connect an agent, choose its role)."
    read_code "Connection code: " ||
      fail "no code: run this in a terminal (curl -fsSL https://get.euthyna.io | sh) and paste it when asked"
  }

  # 2. What the machine has.
  probe=$(as_root sh "$work/get.sh" probe) || fail "cannot look at this machine"
  state=$(printf '%s\n' "$probe" | sed -n 's/^state //p')
  user=$(printf '%s\n' "$probe" | sed -n 's/^user //p')
  before=$(printf '%s\n' "$probe" | sed -n 's/^version //p')

  case "$state" in
    connected)
      say "This machine is connected (nia-edge ${before:-?}${user:+, agent $user})."
      action=update
      if [ -z "$code_file" ] && [ -n "$tty" ]; then
        read_code "New connection code to connect it again, or Enter to update it as it is: " && action=reconnect
      elif [ -n "$code_file" ]; then
        action=reconnect
      fi
      status=0
      apply "$action" || status=$?
      if [ "$status" -eq 10 ]; then
        say ""
        say "Euthyna no longer accepts this machine's key: it was revoked."
        code_file=
        need_code
        apply reconnect || fail "the machine could not connect: see above" 1
      elif [ "$status" -ne 0 ]; then
        exit "$status"
      fi
      ;;
    installed)
      say "nia-edge was installed here${user:+ for $user}, but its key is gone."
      need_code
      apply reconnect || fail "the machine could not connect: see above" 1
      ;;
    *)
      agents=$(printf '%s\n' "$probe" | sed -n 's/^agent //p')
      if [ -z "${EUTHYNA_AGENT:-}" ]; then
        [ -n "$agents" ] || fail "no agent found on this machine: install yours (Hermes, OpenClaw, Claude Code…), then run this again"
        count=$(printf '%s\n' "$agents" | wc -l)
        if [ "$count" -eq 1 ]; then
          pick=1
        else
          say "Agents on this machine:"
          printf '%s\n' "$agents" | awk '{ printf "  %d) %s (%s)\n", NR, $1, $2 }'
          ask "Which one? [1-$count] " || fail "several agents: run this in a terminal, or set EUTHYNA_AGENT and EUTHYNA_FROM"
          pick=$answer
        fi
        case "$pick" in '' | *[!0-9]*) fail "no agent chosen" ;; esac
        [ "$pick" -ge 1 ] && [ "$pick" -le "$count" ] || fail "no agent chosen"
        line=$(printf '%s\n' "$agents" | sed -n "${pick}p")
        EUTHYNA_AGENT=${line%% *}
        EUTHYNA_FROM=${EUTHYNA_FROM:-${line#* }}
      fi
      say "Connecting $EUTHYNA_AGENT${EUTHYNA_FROM:+ ($EUTHYNA_FROM)}."
      need_code
      apply install || fail "the agent could not be connected: see above" 1
      ;;
  esac
  after=$(as_root /usr/local/bin/nia-edge version 2> /dev/null || true)
  say "Euthyna: done (nia-edge ${before:-none} -> ${after:-?}). See it in $URL/console."
}

main
