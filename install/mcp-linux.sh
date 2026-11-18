#!/bin/sh
# Runs one of the agent's MCP servers in its own container, through
# nia-edge: the agent keeps a URL, nia-edge keeps the server's token, and
# nia-mcp starts the server from an image named by its ID, without network,
# its only way out nia-edge's egress proxy under the server's name.
#
#   sudo install/mcp-linux.sh add <name> <image archive> -- <command...>
#   sudo install/mcp-linux.sh remove <name>
#
# The server's variables (its token) are read on standard input, NAME=value
# per line: never on a command line. The image archive is what podman save
# or docker save writes; the image is built where it can reach its registry,
# with its dependencies inside it, so that it changes only when you load
# another.
#
# NIA_AGENT names the agent's user (default hermes): when it runs Hermes, its
# configuration points the server <name> at nia-edge. Its Hermes gateway, if
# one runs, reads it at its next start.
set -eu

ACTION=${1:-}
BIN=/usr/local/bin/nia-edge
STATE=/var/lib/nia-edge/state.json
HERE=$(cd "$(dirname "$0")" && pwd)
AGENT=${NIA_AGENT:-hermes}

fail() { echo "mcp: $1" >&2; exit "${2:-2}"; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
id nia-mcp >/dev/null 2>&1 || fail "no nia-mcp user: run install/linux.sh again on a machine with podman and uidmap"
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
  runuser -u "$AGENT" -- env HOME="$home" HERMES_HOME="$home/.hermes" "$python" -I "$helper_dir/hermes-config.py" local "$1" >/dev/null ||
    fail "Hermes' configuration could not point $1 at nia-edge"
  rm -rf "$helper_dir"
  echo "mcp: $AGENT's Hermes reaches $1 at http://127.0.0.1:8787/local/$1/mcp"
}

case "$ACTION" in
  add)
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
    hermes_local "$NAME"
    # The token is nia-edge's now: a copy left with the agent is still the agent's.
    home=$(getent passwd "$AGENT" | cut -d: -f6)
    for variable in $names; do
      if [ -n "$home" ] && grep -qs "^$variable=" "$home/.hermes/.env"; then
        echo "mcp: $variable is still in $home/.hermes/.env: remove it, the agent no longer needs it" >&2
      fi
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
    echo "usage: $0 add <name> <image archive> -- <command...> | remove <name>" >&2
    exit 2
    ;;
esac
