#!/bin/sh
# Updates nia-edge on this machine to a release: the binary of this
# machine's architecture, checked against the release's SHA256SUMS, takes
# the place of /usr/local/bin/nia-edge, and its services restart. The key,
# the provider, the MCP servers and the policy stay as they are.
#
#   sudo sh update-linux.sh v0.2.0
#
# A release that adds a service or a user (nia-mcp came with 0.2.0) needs
# its installer once: run install/linux.sh <agent user> from that release
# again; an enrolled machine keeps its key.
set -eu

VERSION=${1:?usage: update-linux.sh <version, for instance v0.2.0>}
BIN=/usr/local/bin/nia-edge
REPO=${NIA_EDGE_REPO:-https://github.com/GetKlaros/nia-edge}

fail() { echo "update: $1" >&2; exit "${2:-2}"; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "$VERSION is not a version like v0.2.0" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "no release binary for $(uname -m)" ;;
esac
command -v curl >/dev/null || fail "curl is required"
command -v sha256sum >/dev/null || fail "sha256sum is required"

name="nia-edge_${VERSION#v}_linux_$arch"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/$name" "$REPO/releases/download/$VERSION/$name" || fail "cannot download $name"
curl -fsSL -o "$work/SHA256SUMS" "$REPO/releases/download/$VERSION/SHA256SUMS" || fail "cannot download SHA256SUMS"
grep " $name\$" "$work/SHA256SUMS" > "$work/expected" || fail "SHA256SUMS does not name $name"
(cd "$work" && sha256sum -c expected >/dev/null) || fail "$name does not match its checksum: nothing changed"
chmod 0755 "$work/$name"
"$work/$name" version >/dev/null || fail "$name does not run on this machine: nothing changed"

before=$("$BIN" version 2>/dev/null || echo none)
install -o root -g root -m 0755 "$work/$name" "$BIN"
for unit in nia-hostd nia-mcp nia-edge; do
  if systemctl cat "$unit.service" >/dev/null 2>&1; then
    systemctl restart "$unit.service"
  fi
done
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  "$BIN" health >/dev/null 2>&1 && break
  sleep 1
done
"$BIN" health || fail "nia-edge does not answer after the update: journalctl -u nia-edge" 4
echo "update: nia-edge $before -> $("$BIN" version)"

# Hermes, when this machine runs it for HERMES_USER (hermes by default): the
# payment tool joins its MCP servers, through Hermes' own code, as the agent.
AGENT=${HERMES_USER:-hermes}
AGENT_HOME=$(getent passwd "$AGENT" 2>/dev/null | cut -d: -f6 || true)
if [ -n "$AGENT_HOME" ] && [ -f "$AGENT_HOME/.hermes/config.yaml" ]; then
  if curl -fsSL -o "$work/hermes-config.py" "$REPO/releases/download/$VERSION/hermes-config.py" &&
    grep ' hermes-config.py$' "$work/SHA256SUMS" > "$work/expected-helper" &&
    (cd "$work" && sha256sum -c expected-helper >/dev/null); then
    chmod 0755 "$work" && chmod 0644 "$work/hermes-config.py"
    as_agent() {
      runuser -u "$AGENT" -- env HOME="$AGENT_HOME" USER="$AGENT" LOGNAME="$AGENT" \
        PATH="$AGENT_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin" sh -c "umask 077; cd; $1"
    }
    HERMES_PY=
    for candidate in $(find "$AGENT_HOME/.hermes" "$AGENT_HOME/.local" -maxdepth 8 \( -name python -o -name python3 \) -path '*/bin/*' 2>/dev/null); do
      if as_agent "'$candidate' -I -c 'import hermes_cli.config'" </dev/null >/dev/null 2>&1; then
        HERMES_PY=$candidate
        break
      fi
    done
    if [ -n "$HERMES_PY" ] && as_agent "HERMES_HOME=\"\$HOME/.hermes\" '$HERMES_PY' -I '$work/hermes-config.py' pay" </dev/null >/dev/null 2>&1; then
      echo "update: $AGENT's Hermes has the payment tool (mcp__nia_pay__pay): restart its gateway to load it (sudo -iu $AGENT hermes gateway restart)"
    else
      echo "update: could not add the payment tool to $AGENT's Hermes: an MCP server named nia_pay may already exist"
    fi
  else
    echo "update: hermes-config.py of $VERSION could not be checked: $AGENT's Hermes is unchanged"
  fi
fi
if ! systemctl cat nia-mcp.service >/dev/null 2>&1 && command -v podman >/dev/null; then
  echo "update: this machine has no nia-mcp yet: run install/linux.sh <agent user> of $VERSION once to add it"
fi
