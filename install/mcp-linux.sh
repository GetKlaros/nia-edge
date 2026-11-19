#!/bin/sh
# Runs one of the agent's MCP servers in its own container, through
# nia-edge: the agent keeps a URL, nia-edge keeps the server's token, and
# nia-mcp starts the server from an image named by its ID, without network,
# its only way out nia-edge's egress proxy under the server's name.
#
#   sudo install/mcp-linux.sh add <name> <image archive> -- <command...>
#   sudo install/mcp-linux.sh remove <name>
#
# An MCP server hosted by its vendor (GitHub, Notion…): nia-edge keeps its
# token, read on standard input (remote), or gets one by signing in with the
# vendor (login: open the link it prints, in any browser):
#
#   sudo install/mcp-linux.sh remote <name> <https URL>      < token
#   sudo install/mcp-linux.sh login <name> <https URL>
#   sudo install/mcp-linux.sh remote-remove <name>
#
# The server's variables (its token) are read on standard input, NAME=value
# per line: never on a command line. The image archive is what podman save
# or docker save writes; the image is built where it can reach its registry,
# with its dependencies inside it, so that it changes only when you load
# another.
#
# NIA_AGENT names the agent's user (default hermes): when it runs Hermes or
# OpenClaw, its configuration points the server <name> at nia-edge. A Hermes
# gateway reads it at its next start; OpenClaw's applies it at once.
set -eu

ACTION=${1:-}
BIN=/usr/local/bin/nia-edge
STATE=/var/lib/nia-edge/state.json
HERE=$(cd "$(dirname "$0")" && pwd)
AGENT=${NIA_AGENT:-hermes}

fail() { echo "mcp: $1" >&2; exit "${2:-2}"; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
as_mcp() {
  runuser -u nia-mcp -- env -i PATH=/usr/bin:/bin HOME=/var/lib/nia-mcp XDG_RUNTIME_DIR=/run/nia-mcp \
    podman --cgroup-manager=cgroupfs --events-backend=file "$@"
}

hermes_local() {
  home=$(getent passwd "$AGENT" | cut -d: -f6)
  [ -n "$home" ] && [ -d "$home/.hermes" ] || return 0
  [ -f "$HERE/hermes-config.py" ] || fail "hermes-config.py must be next to this script"
  helper_dir=$(mktemp -d)
  chmod 0755 "$helper_dir"
  cp "$HERE/hermes-config.py" "$helper_dir/"
  chmod 0644 "$helper_dir/hermes-config.py"
  python=
  for candidate in $(find "$home/.hermes" "$home/.local" -maxdepth 8 \( -name python -o -name python3 \) -path '*/bin/*' 2>/dev/null); do
    if runuser -u "$AGENT" -- "$candidate" -I -c 'import hermes_cli.config' >/dev/null 2>&1; then
      python=$candidate
      break
    fi
  done
  [ -n "$python" ] || fail "cannot find Hermes' Python for $AGENT"
  runuser -u "$AGENT" -- env HOME="$home" HERMES_HOME="$home/.hermes" "$python" -I "$helper_dir/hermes-config.py" "${2:-local}" "$1" >/dev/null ||
    fail "Hermes' configuration could not point $1 at nia-edge"
  rm -rf "$helper_dir"
  echo "mcp: $AGENT's Hermes reaches $1 at http://127.0.0.1:8787/${2:-local}/$1/mcp"
}

openclaw_local() {
  home=$(getent passwd "$AGENT" | cut -d: -f6)
  [ -n "$home" ] && [ -f "$home/.openclaw/openclaw.json" ] || return 0
  [ -f "$HERE/openclaw-config.mjs" ] || fail "openclaw-config.mjs must be next to this script"
  openclaw=$home/.openclaw/bin/openclaw
  node=$(sed -n 's/^exec \(\/[^ ]*\/node\) .*/\1/p' "$openclaw" 2>/dev/null | head -n 1)
  [ -n "$node" ] && [ -x "$node" ] || fail "cannot find the Node of $AGENT's OpenClaw"
  helper_dir=$(mktemp -d)
  chmod 0755 "$helper_dir"
  cp "$HERE/openclaw-config.mjs" "$helper_dir/"
  chmod 0644 "$helper_dir/openclaw-config.mjs"
  runuser -u "$AGENT" -- env -i HOME="$home" PATH=/usr/bin:/bin OPENCLAW="$openclaw" "$node" "$helper_dir/openclaw-config.mjs" "${2:-local}" "$1" >/dev/null ||
    fail "OpenClaw's configuration could not point $1 at nia-edge"
  rm -rf "$helper_dir"
  echo "mcp: $AGENT's OpenClaw reaches $1 at http://127.0.0.1:8787/${2:-local}/$1/mcp"
}

point_agent() {
  hermes_local "$1" "$2"
  openclaw_local "$1" "$2"
}

case "$ACTION" in
  remote | login)
    NAME=${2:?usage: mcp-linux.sh $ACTION <name> <https URL>}
    URL=${3:?usage: mcp-linux.sh $ACTION <name> <https URL>}
    if [ "$ACTION" = remote ]; then
      # The token goes from standard input to nia-edge's state file only.
      runuser -u nia-edge -- env -i PATH=/usr/bin:/bin "$BIN" mcp remote add "$NAME" -url "$URL" -state "$STATE" ||
        fail "nia-edge did not keep the server"
    else
      runuser -u nia-edge -- env -i PATH=/usr/bin:/bin NIA_EDGE_OAUTH_PORT="${NIA_EDGE_OAUTH_PORT:-}" "$BIN" mcp remote login "$NAME" -url "$URL" -state "$STATE" ||
        fail "the sign-in with $URL did not complete"
    fi
    point_agent "$NAME" remote
    systemctl restart nia-edge.service
    echo "mcp: $NAME's tools reach the model as mcp__${NAME}__<tool>: give them a rule in the role. Its tools are pinned in Nia (Connectors) when the agent first lists them."
    ;;
  remote-remove)
    NAME=${2:?usage: mcp-linux.sh remote-remove <name>}
    runuser -u nia-edge -- env -i PATH=/usr/bin:/bin "$BIN" mcp remote remove "$NAME" -state "$STATE"
    systemctl restart nia-edge.service
    ;;
  add)
    id nia-mcp >/dev/null 2>&1 || fail "no nia-mcp user: run install/linux.sh again on a machine with podman and uidmap"
    NAME=${2:?usage: mcp-linux.sh add <name> <image archive> -- <command...>}
    ARCHIVE=${3:?usage: mcp-linux.sh add <name> <image archive> -- <command...>}
    shift 3
    [ "${1:-}" = "--" ] && shift
    [ "$#" -gt 0 ] || fail "the server's command is missing, after --"
    [ -f "$ARCHIVE" ] || fail "no image archive at $ARCHIVE"
    systemctl is-active --quiet nia-mcp.service || fail "nia-mcp is not running: systemctl status nia-mcp"
    # nia-mcp has no network: the image comes as a file, read from a copy
    # only it can read.
    copy=$(runuser -u nia-mcp -- mktemp /var/lib/nia-mcp/image.XXXXXX)
    cat "$ARCHIVE" > "$copy"
    loaded=$(as_mcp load -q -i "$copy" 2>&1) || { rm -f "$copy"; fail "podman could not load $ARCHIVE: $loaded"; }
    rm -f "$copy"
    ref=$(printf '%s\n' "$loaded" | sed -n 's/^Loaded image[(s)]*: *//p' | head -n 1 | cut -d, -f1)
    [ -n "$ref" ] || fail "podman loaded no image from $ARCHIVE"
    id=$(as_mcp image inspect --format '{{.Id}}' "$ref") || fail "the image loaded from $ARCHIVE has no ID"
    case "$id" in
      sha256:*) ;;
      *) id="sha256:$id" ;;
    esac
    # The variables go from standard input to nia-edge's state file only.
    variables=$(mktemp)
    chmod 0600 "$variables"
    cat > "$variables"
    runuser -u nia-edge -- env -i PATH=/usr/bin:/bin "$BIN" mcp add -state "$STATE" -name "$NAME" -image "$id" -ref "$ref" -env-file - -- "$@" < "$variables" ||
      { rm -f "$variables"; fail "nia-edge did not keep the server"; }
    names=$(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$variables")
    rm -f "$variables"
    point_agent "$NAME" local
    # The token is nia-edge's now: a copy left with the agent is still the agent's.
    home=$(getent passwd "$AGENT" | cut -d: -f6)
    for variable in $names; do
      for file in "$home/.hermes/.env" "$home/.openclaw/.env"; do
        if [ -n "$home" ] && grep -qs "^$variable=" "$file"; then
          echo "mcp: $variable is still in $file: remove it, the agent no longer needs it" >&2
        fi
      done
    done
    systemctl restart nia-edge.service
    echo "mcp: $NAME runs from $ref ($id). Its tools reach the model as mcp__${NAME}__<tool>: give them a rule in the role, and its hosts an egress rule for server $NAME."
    ;;
  remove)
    NAME=${2:?usage: mcp-linux.sh remove <name>}
    runuser -u nia-edge -- env -i PATH=/usr/bin:/bin "$BIN" mcp remove -state "$STATE" -name "$NAME"
    systemctl restart nia-edge.service
    ;;
  *)
    echo "usage: $0 add <name> <image archive> -- <command...> | remove <name> | remote <name> <URL> | login <name> <URL> | remote-remove <name>" >&2
    exit 2
    ;;
esac
