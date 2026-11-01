package proxy

import (
	"errors"
	"fmt"
	"net/netip"
)

type block struct {
	prefix netip.Prefix
	name   string
}

func b(prefix, name string) block { return block{netip.MustParsePrefix(prefix), name} }

// IPv4 ranges the proxy never dials: RFC 1918, loopback, link-local,
// multicast, carrier-grade NAT, and every IANA special-purpose block that
// isn't globally reachable (docs/phase-1.md, "Address policy").
var v4Blocks = []block{
	b("0.0.0.0/8", "this-network"),
	b("10.0.0.0/8", "private"),
	b("100.64.0.0/10", "carrier-grade NAT"),
	b("127.0.0.0/8", "loopback"),
	b("169.254.0.0/16", "link-local"),
	b("172.16.0.0/12", "private"),
	b("192.0.0.0/24", "IETF protocol assignments"),
	b("192.0.2.0/24", "documentation"),
	b("192.88.99.0/24", "6to4 relay anycast"),
	b("192.168.0.0/16", "private"),
	b("198.18.0.0/15", "benchmarking"),
	b("198.51.100.0/24", "documentation"),
	b("203.0.113.0/24", "documentation"),
	b("224.0.0.0/4", "multicast"),
	b("240.0.0.0/4", "reserved"), // includes 255.255.255.255, broadcast
}

// IPv6 ranges the proxy never dials. Only global unicast 2000::/3 is
// dialable at all; the blocks outside it are listed only to name them in
// the deny reason.
var v6Blocks = []block{
	b("::/128", "unspecified"),
	b("::1/128", "loopback"),
	b("64:ff9b::/96", "NAT64"),
	b("64:ff9b:1::/48", "local-use NAT64"),
	b("100::/64", "discard-only"),
	b("2001::/23", "IETF protocol assignments, including Teredo"),
	b("2001:db8::/32", "documentation"),
	b("2002::/16", "6to4"),
	b("3fff::/20", "documentation"),
	b("fc00::/7", "unique local (private)"),
	b("fe80::/10", "link-local"),
	b("fec0::/10", "site-local"),
	b("ff00::/8", "multicast"),
}

var v6GlobalUnicast = netip.MustParsePrefix("2000::/3")

// CheckAddr returns nil if a is a public unicast address the proxy may
// dial, and otherwise says why not. IPv4-mapped IPv6 addresses are checked
// as IPv4. Anything it can't classify is refused.
func CheckAddr(a netip.Addr) error {
	if !a.IsValid() {
		return errors.New("invalid address")
	}
	if a.Zone() != "" {
		return fmt.Errorf("%s has a zone", a)
	}
	a = a.Unmap()
	switch {
	case a.Is4():
		for _, bl := range v4Blocks {
			if bl.prefix.Contains(a) {
				return fmt.Errorf("%s is %s (%s)", a, bl.name, bl.prefix)
			}
		}
		return nil
	case a.Is6():
		for _, bl := range v6Blocks {
			if bl.prefix.Contains(a) {
				return fmt.Errorf("%s is %s (%s)", a, bl.name, bl.prefix)
			}
		}
		if !v6GlobalUnicast.Contains(a) {
			return fmt.Errorf("%s is outside global unicast (%s)", a, v6GlobalUnicast)
		}
		return nil
	}
	return fmt.Errorf("%s: unclassifiable address", a)
}
