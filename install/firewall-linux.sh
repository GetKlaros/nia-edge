#!/bin/sh
# Leaves one local user, the agent's, no other way out than nia-edge, on Linux
# with nftables. Every TCP and UDP packet that user sends is refused unless it
# goes to nia-edge on 127.0.0.1 (the relay and the egress proxy). DNS
# included: the agent cannot resolve, or leak, anything by itself.
#
#   firewall-linux.sh apply <user>
#   firewall-linux.sh remove
#   firewall-linux.sh show
#
# EDGE_HTTP_PORT and EDGE_PROXY_PORT name the ports when they are not 8787
# and 3128.
#
# Unix sockets are not network traffic: the user must not be in a group that
# reaches a privileged socket (docker, lxd, libvirt) or root (sudo, wheel).
# install/linux.sh checks it.
set -eu

ACTION=${1:-show}
RELAY_PORT=${EDGE_HTTP_PORT:-8787}
PROXY_PORT=${EDGE_PROXY_PORT:-3128}
TABLE=nia_agent

command -v nft >/dev/null || { echo "nftables (nft) is required" >&2; exit 2; }

case "$ACTION" in
  apply)
    AGENT_USER=${2:?usage: firewall-linux.sh apply <user>}
    uid=$(id -u "$AGENT_USER") || { echo "no such user: $AGENT_USER" >&2; exit 2; }
    [ "$uid" -ne 0 ] || { echo "refusing to lock root" >&2; exit 2; }
    for port in "$RELAY_PORT" "$PROXY_PORT"; do
      case "$port" in
        '' | *[!0-9]*) echo "not a port: $port" >&2; exit 2 ;;
      esac
    done
    # One transaction: the table is replaced, never left half loaded.
    nft -f - <<RULES
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid $uid oifname "lo" ip daddr 127.0.0.1 tcp dport { $RELAY_PORT, $PROXY_PORT } accept
    meta skuid $uid counter reject with icmpx admin-prohibited
  }
}
RULES
    echo "nia-edge: user $AGENT_USER (uid $uid) can only reach 127.0.0.1:$RELAY_PORT and 127.0.0.1:$PROXY_PORT"
    ;;
  remove)
    nft delete table inet $TABLE 2>/dev/null || true
    echo "nia-edge: firewall rule removed"
    ;;
  show)
    nft list table inet $TABLE 2>/dev/null || echo "nia-edge: no rule loaded"
    ;;
  *)
    echo "usage: $0 apply <user> | remove | show" >&2
    exit 2
    ;;
esac
