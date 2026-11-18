#!/bin/sh
# Installs nia-edge on Linux and leaves the agent's user no other way out:
# nia-edge as a systemd service under its own user, enrolled with a one-time
# token, and an nftables rule that lets the agent's user reach nia-edge only.
#
#   sudo NIA_URL=https://nia.example NIA_ENROLL_TOKEN=nen_... install/linux.sh <agent-user>
#
# NIA_EDGE_BINARY names the binary to install (default ./nia-edge):
#   CGO_ENABLED=0 go build -ldflags "-X main.version=0.1.0" -o nia-edge ./cmd/nia-edge
# NIA_ENROLL_TOKEN_FILE can hold the token instead of NIA_ENROLL_TOKEN.
# A machine that is already enrolled keeps its key: no token is needed then.
#
# The last step runs "nia-edge doctor" as the agent's user and fails if that
# user still has a way out.
set -eu

AGENT_USER=${1:?usage: install/linux.sh <agent-user>}
BINARY=${NIA_EDGE_BINARY:-./nia-edge}
HERE=$(cd "$(dirname "$0")" && pwd)
STATE_DIR=/var/lib/nia-edge
STATE=$STATE_DIR/state.json
BIN=/usr/local/bin/nia-edge
LIB=/usr/local/lib/nia-edge

fail() { echo "install: $1" >&2; exit "${2:-2}"; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -f "$HERE/firewall-linux.sh" ] || fail "firewall-linux.sh must be next to this script"
[ -x "$BINARY" ] || fail "no nia-edge binary at $BINARY (build it, or set NIA_EDGE_BINARY)"
"$BINARY" version >/dev/null || fail "$BINARY does not run on this machine"
command -v nft >/dev/null || fail "nftables is required (for instance: apt install nftables)"
command -v systemctl >/dev/null || fail "systemd is required"
command -v runuser >/dev/null || fail "runuser (util-linux) is required"
[ "$AGENT_USER" != root ] || fail "the agent cannot run as root"
[ "$AGENT_USER" != nia-edge ] || fail "the agent cannot run as nia-edge: that user holds the key"

# 1. The agent's user, without any group that is root in disguise.
id "$AGENT_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$AGENT_USER"
for group in docker sudo wheel admin adm lxd libvirt nia-edge; do
  if id -nG "$AGENT_USER" | tr ' ' '\n' | grep -qx "$group"; then
    fail "$AGENT_USER is in group $group, which goes around the network rule or reads the key" 3
  fi
done

# 2. nia-edge under its own user. Its state directory holds the key.
id nia-edge >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin nia-edge
install -o root -g root -m 0755 "$BINARY" "$BIN"
install -d -o root -g root -m 0755 "$LIB"
install -o root -g root -m 0755 "$HERE/firewall-linux.sh" "$LIB/firewall-linux.sh"
install -d -o nia-edge -g nia-edge -m 0700 "$STATE_DIR"

# 3. Settings of the service. No secret here: the key is in the state file.
host=$(hostname | tr -c 'A-Za-z0-9._\n-' '-')
cat > /etc/nia-edge.env <<ENV
NIA_SESSION=${NIA_SESSION:-$AGENT_USER.$host}
EDGE_APPROVAL_WAIT=${EDGE_APPROVAL_WAIT:-0}
EDGE_ALLOW_PRIVATE=${EDGE_ALLOW_PRIVATE:-}
ENV
chmod 0644 /etc/nia-edge.env

cat > /etc/systemd/system/nia-edge.service <<UNIT
[Unit]
Description=nia-edge: the agent's only way out, decided by Nia
After=network-online.target
Wants=network-online.target

[Service]
User=nia-edge
Group=nia-edge
EnvironmentFile=/etc/nia-edge.env
ExecStart=$BIN run -state $STATE
Restart=always
RestartSec=2
StateDirectory=nia-edge
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

# nia-hostd: the host actions of the role's catalogue, as root, asked by
# nia-edge only (its socket is served to the nia-edge user alone), each
# checked again against the signed policy.
cat > /etc/systemd/system/nia-hostd.service <<UNIT
[Unit]
Description=nia-hostd: the host actions of the agent's role, checked against the signed policy
After=network-online.target

[Service]
ExecStart=$BIN hostd run -state $STATE
Restart=always
RestartSec=2
RuntimeDirectory=nia-hostd
RuntimeDirectoryMode=0750
StateDirectory=nia-hostd
StateDirectoryMode=0700
UMask=0077
# Its dry runs mount a layer and the machine's root read only: those mounts
# stay in its own namespace.
PrivateMounts=yes

[Install]
WantedBy=multi-user.target
UNIT

# 4. The network rule, loaded again at every boot, before the network is up.
cat > /etc/systemd/system/nia-agent-firewall.service <<UNIT
[Unit]
Description=Leave $AGENT_USER no other way out than nia-edge
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh $LIB/firewall-linux.sh apply $AGENT_USER
ExecStop=/bin/sh $LIB/firewall-linux.sh remove

[Install]
WantedBy=multi-user.target
UNIT

# 5. Enrollment, last of what can fail before the services start: a token is
# used once. As the nia-edge user, with the token on standard input: it never
# appears on a command line or in a file this script writes.
if [ -f "$STATE" ]; then
  echo "install: this machine is already enrolled, its key is kept"
else
  : "${NIA_URL:?NIA_URL is required to enroll}"
  if [ -n "${NIA_ENROLL_TOKEN_FILE:-}" ]; then
    NIA_ENROLL_TOKEN=$(cat "$NIA_ENROLL_TOKEN_FILE")
  fi
  : "${NIA_ENROLL_TOKEN:?NIA_ENROLL_TOKEN (or NIA_ENROLL_TOKEN_FILE) is required to enroll}"
  printf '%s\n' "$NIA_ENROLL_TOKEN" |
    runuser -u nia-edge -- env -i PATH=/usr/bin:/bin "$BIN" enroll -url "$NIA_URL" -state "$STATE"
fi

systemctl daemon-reload
systemctl enable nia-agent-firewall.service nia-edge.service nia-hostd.service
systemctl restart nia-agent-firewall.service nia-hostd.service nia-edge.service

# 6. The agent's environment: its model and every connection through nia-edge.
PROFILE=$(getent passwd "$AGENT_USER" | cut -d: -f6)/.profile
grep -q 'nia-edge' "$PROFILE" 2>/dev/null || cat >> "$PROFILE" <<'PROFILE'
# nia-edge: the only way out for this user
export HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128
export http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY NO_PROXY=127.0.0.1 no_proxy=127.0.0.1
export NIA_EDGE=http://127.0.0.1:8787
PROFILE

# 7. Proof, from the agent's user. nia-edge needs a moment to listen.
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if "$BIN" health >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" -eq 1 ] || fail "nia-edge did not start, or cannot reach Nia: journalctl -u nia-edge" 4
echo
if runuser -u "$AGENT_USER" -- "$BIN" doctor; then
  echo
  echo "Done. Point the agent's model at http://127.0.0.1:8787/v1 (any API key: nia-edge replaces it)."
else
  fail "the agent's user still has a way out, or the check could not run (see above)" 5
fi
