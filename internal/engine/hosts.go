package engine

import (
	"regexp"
	"strconv"
	"strings"
)

// A `hosts` condition holds when every URL in a value points to an allowed
// host. The server finds the URLs with a regular expression and reads each
// with the WHATWG URL parser, which is what HTTP clients implement. Only a
// plain host[:port] authority is accepted, so the part of that parser that
// matters is small: lower case, the port range, and a host that ends in a
// number, which is an IPv4 address in any of its spellings.
//
// Punycode labels (xn--) are validated by that parser with tables this code
// does not carry: a URL with one is not decided here.

var plainAuthority = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$`)

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// jsWhiteSpace is what JavaScript's \s matches.
func jsWhiteSpace(r rune) bool {
	switch {
	case r >= 0x9 && r <= 0xd, r == 0x20, r == 0xa0, r == 0x1680, r >= 0x2000 && r <= 0x200a,
		r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000, r == 0xfeff:
		return true
	}
	return false
}

// schemeAt returns the length of `http://` or `https://`, in any case, at
// the start of text, or 0.
func schemeAt(text string) int {
	if len(text) < 7 || !strings.EqualFold(text[:4], "http") {
		return 0
	}
	rest := text[4:]
	if rest[0] == 's' || rest[0] == 'S' {
		rest = rest[1:]
	}
	if !strings.HasPrefix(rest, "://") {
		return 0
	}
	return len(text) - len(rest) + 3
}

// urlCandidates is value.match(/\bhttps?:\/\/[^\s'"<>]*/gi): each candidate
// without its scheme.
func urlCandidates(value string) []string {
	var found []string
	for i := 0; i < len(value); {
		scheme := 0
		if i == 0 || !isWordByte(value[i-1]) {
			scheme = schemeAt(value[i:])
		}
		if scheme == 0 {
			i++
			continue
		}
		end := len(value)
		for j, r := range value[i+scheme:] {
			if jsWhiteSpace(r) || r == '\'' || r == '"' || r == '<' || r == '>' {
				end = i + scheme + j
				break
			}
		}
		found = append(found, value[i+scheme:end])
		i = end
	}
	return found
}

// urlHosts returns the hosts of the URLs in value, as an HTTP client reads
// them. ok is false when a URL is not one every client reads alike, or there
// is none. A host this engine cannot name as the server does (a punycode
// label) is left out, and makes undecided not nil.
func urlHosts(value string) (hosts []string, ok bool, undecided error) {
	candidates := urlCandidates(value)
	// Any mention of a scheme that does not start a parsed URL fails closed.
	if len(candidates) == 0 || strings.Count(value, "://") != len(candidates) {
		return nil, false, nil
	}
	for _, candidate := range candidates {
		authority := candidate
		if cut := strings.IndexAny(candidate, "/?#"); cut >= 0 {
			authority = candidate[:cut]
		}
		if !plainAuthority.MatchString(authority) {
			return nil, false, nil
		}
		host := authority
		if colon := strings.IndexByte(authority, ':'); colon >= 0 {
			host = authority[:colon]
			if port, err := strconv.Atoi(authority[colon+1:]); err != nil || port > 65535 {
				return nil, false, nil
			}
		}
		host = strings.ToLower(host)
		labels := strings.Split(host, ".")
		punycode := false
		for _, label := range labels {
			punycode = punycode || strings.HasPrefix(label, "xn--")
		}
		if punycode {
			undecided = notDecided("a URL with a punycode label")
			continue
		}
		if endsInNumber(labels[len(labels)-1]) {
			address, parsed := parseIPv4(labels)
			if !parsed {
				return nil, false, nil
			}
			host = address
		}
		hosts = append(hosts, host)
	}
	return hosts, true, undecided
}

// hostsAllowed reports whether every URL of value points to an allowed host.
func hostsAllowed(value string, allow []string) (bool, error) {
	hosts, ok, undecided := urlHosts(value)
	if !ok {
		return false, nil
	}
	for _, host := range hosts {
		allowed, err := hostAllowed(host, allow)
		if err != nil {
			undecided = err
		} else if !allowed {
			return false, nil
		}
	}
	if undecided != nil {
		return false, undecided
	}
	return true, nil
}

// categoryHit reports whether a URL of value points to one of hosts, or value
// holds a URL that is not read alike by every client.
func categoryHit(value string, hosts []string) (bool, error) {
	found, ok, undecided := urlHosts(value)
	if !ok {
		return true, nil
	}
	for _, host := range found {
		matched, err := hostAllowed(host, hosts)
		if err == nil && matched {
			return true, nil
		}
		if err != nil {
			undecided = err
		}
	}
	return false, undecided
}

// hostAllowed compares a lower-case ASCII host with the allowed entries,
// `*.suffix` or exact. The server lower-cases an entry as JavaScript does,
// which is not Go's lower case outside ASCII: such an entry that would be
// needed to answer leaves the call undecided.
func hostAllowed(host string, allow []string) (bool, error) {
	var undecided error
	for _, entry := range allow {
		ascii := true
		for i := 0; i < len(entry); i++ {
			ascii = ascii && entry[i] < 0x80
		}
		if !ascii {
			undecided = notDecided("an allowed host outside ASCII")
			continue
		}
		rule := strings.ToLower(entry)
		if strings.HasPrefix(rule, "*.") {
			if strings.HasSuffix(host, rule[1:]) && len(host) > len(rule)-1 {
				return true, nil
			}
		} else if host == rule {
			return true, nil
		}
	}
	return false, undecided
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// endsInNumber is the WHATWG check on the last label of a host: all digits,
// or a hexadecimal number (0x alone is one).
func endsInNumber(last string) bool {
	if last == "" {
		return false
	}
	digits := true
	for i := 0; i < len(last); i++ {
		digits = digits && last[i] >= '0' && last[i] <= '9'
	}
	if digits {
		return true
	}
	if len(last) >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X') {
		for i := 2; i < len(last); i++ {
			if !isHex(last[i]) {
				return false
			}
		}
		return true
	}
	return false
}

// ipv4Number is the WHATWG IPv4 number parser. A value too large for any
// position is returned as 1<<40.
func ipv4Number(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	base := uint64(10)
	switch {
	case len(part) >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X'):
		part, base = part[2:], 16
	case len(part) >= 2 && part[0] == '0':
		part, base = part[1:], 8
	}
	var value uint64
	for i := 0; i < len(part); i++ {
		var digit uint64
		switch c := part[i]; {
		case c >= '0' && c <= '9':
			digit = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			digit = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			digit = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if digit >= base {
			return 0, false
		}
		if value = value*base + digit; value > 1<<40 {
			value = 1 << 40
		}
	}
	return value, true
}

// parseIPv4 is the WHATWG IPv4 parser, on the labels of a host. It returns
// the address in dotted decimal.
func parseIPv4(parts []string) (string, bool) {
	if len(parts) > 4 {
		return "", false
	}
	numbers := make([]uint64, len(parts))
	for i, part := range parts {
		number, ok := ipv4Number(part)
		if !ok {
			return "", false
		}
		numbers[i] = number
	}
	last := len(numbers) - 1
	for _, number := range numbers[:last] {
		if number > 255 {
			return "", false
		}
	}
	if numbers[last] >= uint64(1)<<(8*uint(5-len(numbers))) {
		return "", false
	}
	address := numbers[last]
	for i, number := range numbers[:last] {
		address += number << (8 * uint(3-i))
	}
	return strconv.FormatUint(address>>24, 10) + "." + strconv.FormatUint(address>>16&255, 10) + "." + strconv.FormatUint(address>>8&255, 10) + "." + strconv.FormatUint(address&255, 10), true
}
