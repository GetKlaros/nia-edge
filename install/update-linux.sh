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
if ! systemctl cat nia-mcp.service >/dev/null 2>&1 && command -v podman >/dev/null; then
  echo "update: this machine has no nia-mcp yet: run install/linux.sh <agent user> of $VERSION once to add it"
fi
