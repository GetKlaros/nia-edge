#!/bin/sh
# Leaves one local user, the agent's, no other way out than nia-edge, on Linux
# with nftables. Every TCP and UDP packet that user sends is refused unless it
# goes to nia-edge on 127.0.0.1 (the relay and the egress proxy). DNS
# included: the agent cannot resolve, or leak, anything by itself.
#
#   firewall-linux.sh apply <user> [<mcp user>]
#   firewall-linux.sh remove
#   firewall-linux.sh show
#
# EDGE_HTTP_PORT and EDGE_PROXY_PORT name the ports when they are not 8787
# and 3128.
#
# The agent may still reach its own services on 127.0.0.1 (Hermes' command
# talks to its gateway on a port the kernel picks), never another user's: a
# TCP connection the agent opens on the loopback is marked, and its answers
# must come from a socket of the agent. A local proxy or database of another
# user answers nothing it can use.
#
# The MCP user (nia-mcp), and the range of ids of its containers, reach no
# network at all: its containers have none, and their way out is a Unix
# socket to nia-edge.
#
# Unix sockets are not network traffic: the user must not be in a group that
# reaches a privileged socket (docker, lxd, libvirt) or root (sudo, wheel).
# install/linux.sh checks it.
set -eu

ACTION=${1:-show}
RELAY_PORT=${EDGE_HTTP_PORT:-8787}
PROXY_PORT=${EDGE_PROXY_PORT:-3128}
TABLE=nia_agent
# The bit of the connection mark that names the agent's loopback connections.
AGENT_MARK=0x40000000

command -v nft >/dev/null || { echo "nftables (nft) is required" >&2; exit 2; }

case "$ACTION" in
  apply)
    AGENT_USER=${2:?usage: firewall-linux.sh apply <user> [<mcp user>]}
    uid=$(id -u "$AGENT_USER") || { echo "no such user: $AGENT_USER" >&2; exit 2; }
    [ "$uid" -ne 0 ] || { echo "refusing to lock root" >&2; exit 2; }
    MCP_RULES=
    if [ -n "${3:-}" ]; then
      mcp_uid=$(id -u "$3") || { echo "no such user: $3" >&2; exit 2; }
      [ "$mcp_uid" -ne 0 ] || { echo "refusing to lock root" >&2; exit 2; }
      MCP_RULES="meta skuid $mcp_uid counter reject with icmpx admin-prohibited"
      range=$(awk -F: -v u="$3" '$1 == u && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { print $2 "-" $2 + $3 - 1; exit }' /etc/subuid 2>/dev/null)
      if [ -n "$range" ]; then
        MCP_RULES="$MCP_RULES
    meta skuid $range counter reject with icmpx admin-prohibited"
      fi
    fi
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
    meta skuid $uid oifname "lo" ip daddr 127.0.0.1 meta l4proto tcp ct state new ct mark set ct mark or $AGENT_MARK accept
    meta skuid $uid oifname "lo" ip daddr 127.0.0.1 meta l4proto tcp ct mark and $AGENT_MARK == $AGENT_MARK accept
    ct direction reply ct mark and $AGENT_MARK == $AGENT_MARK meta skuid $uid accept
    ct direction reply ct mark and $AGENT_MARK == $AGENT_MARK counter drop
    meta skuid $uid counter reject with icmpx admin-prohibited
    $MCP_RULES
  }
}
RULES
    echo "nia-edge: user $AGENT_USER (uid $uid) can only reach 127.0.0.1:$RELAY_PORT, 127.0.0.1:$PROXY_PORT and its own services on 127.0.0.1"
    [ -z "${3:-}" ] || echo "nia-edge: user $3 and its containers reach no network"
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
