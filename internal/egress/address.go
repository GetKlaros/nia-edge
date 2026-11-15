// Package egress is the agent's only way out to the network: an HTTP proxy
// in front of every outbound connection. Each connection is a call to the
// "egress" tool of the machine's role, decided by Nia.
//
// Some rules do not depend on any decision:
//
//   - an internal IP literal is refused before a decision is asked;
//   - a name is resolved only after the connection is allowed (resolving an
//     attacker's name such as SECRET.attacker.example already leaks), once,
//     and the connection goes to the address that was checked;
//   - a name that resolves to any internal address is refused, unless the
//     operator listed it as allowed.
//
// HTTPS is tunnelled without interception: Nia sees the host and the port.
// Plain HTTP also shows the method and the URL.
package egress

import (
	"net/netip"
	"strings"
)

func prefixes(list ...string) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(list))
	for _, item := range list {
		parsed = append(parsed, netip.MustParsePrefix(item))
	}
	return parsed
}

// The networks a sandboxed agent has no business reaching: this machine, the
// local network, cloud metadata, and ranges that are not addresses of hosts.
var (
	internalV4 = prefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	)
	internalV6 = prefixes("::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8")

	// IPv6 forms that carry an IPv4 address: the IPv4 address is what counts.
	mappedOrCompatible = netip.MustParsePrefix("::/96") // with ::ffff:0:0/96 handled by Unmap
	nat64              = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour          = netip.MustParsePrefix("2002::/16")

	// IPv6 forms that reach an address which cannot be checked from here.
	localNAT64 = netip.MustParsePrefix("64:ff9b:1::/48")
	teredo     = netip.MustParsePrefix("2001::/32")
)

func within(addr netip.Addr, networks []netip.Prefix) bool {
	for _, network := range networks {
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

// IsPrivateAddr reports whether a connection to addr must be refused:
// internal, carrying an internal IPv4 address, or impossible to check.
func IsPrivateAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		// A zone names an interface of this machine: never a public host.
		return true
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return within(addr, internalV4)
	}
	if localNAT64.Contains(addr) || teredo.Contains(addr) {
		return true
	}
	bytes := addr.As16()
	switch {
	case mappedOrCompatible.Contains(addr), nat64.Contains(addr):
		return within(netip.AddrFrom4([4]byte(bytes[12:16])), internalV4)
	case sixToFour.Contains(addr):
		return within(netip.AddrFrom4([4]byte(bytes[2:6])), internalV4)
	}
	return within(addr, internalV6)
}

// IsPrivate is IsPrivateAddr for text. Text that is not an IP address is
// refused: nothing here connects to something it could not check.
func IsPrivate(address string) bool {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return true
	}
	return IsPrivateAddr(addr)
}

// HostMatches reports whether host is one of patterns: a name, compared
// without regard to case, or "*.suffix" for every name under a suffix.
func HostMatches(host string, patterns []string) bool {
	lower := strings.ToLower(host)
	for _, pattern := range patterns {
		rule := strings.ToLower(pattern)
		if strings.HasPrefix(rule, "*.") {
			if strings.HasSuffix(lower, rule[1:]) {
				return true
			}
		} else if lower == rule {
			return true
		}
	}
	return false
}
