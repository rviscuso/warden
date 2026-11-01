package proxy

import (
	"net/netip"
	"strings"
	"testing"
)

// Well-known public resolver addresses, used only as test data. They are
// stable, globally routable unicast addresses, so the address policy must
// accept them. Nothing connects to them: the fake dialer records the
// address it was asked for and connects to a local listener instead.
var (
	publicV4  = netip.MustParseAddr("1.1.1.1")              // Cloudflare's public resolver
	publicV4b = netip.MustParseAddr("8.8.8.8")              // Google's public resolver
	publicV6  = netip.MustParseAddr("2606:4700:4700::1111") // Cloudflare's public resolver, IPv6
	publicV6b = netip.MustParseAddr("2001:4860:4860::8888") // Google's public resolver, IPv6
)

func TestCheckAddrRefuses(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0":         "this-network",
		"0.1.2.3":         "this-network",
		"10.0.0.1":        "private",
		"100.64.0.1":      "carrier-grade NAT",
		"100.127.255.254": "carrier-grade NAT",
		"127.0.0.1":       "loopback",
		"127.255.255.255": "loopback",
		"169.254.169.254": "link-local", // cloud metadata services
		"172.16.0.1":      "private",
		"172.31.255.255":  "private",
		"192.0.0.8":       "IETF protocol assignments",
		"192.0.2.1":       "documentation",
		"192.88.99.1":     "6to4 relay anycast",
		"192.168.1.1":     "private",
		"198.18.0.1":      "benchmarking",
		"198.19.255.255":  "benchmarking",
		"198.51.100.7":    "documentation",
		"203.0.113.7":     "documentation",
		"224.0.0.1":       "multicast",
		"239.255.255.250": "multicast",
		"240.0.0.1":       "reserved",
		"255.255.255.255": "reserved",

		"::":                        "unspecified",
		"::1":                       "loopback",
		"::ffff:127.0.0.1":          "loopback", // IPv4-mapped: checked as IPv4
		"::ffff:10.1.2.3":           "private",
		"::ffff:169.254.1.1":        "link-local",
		"64:ff9b::a00:1":            "NAT64", // embeds 10.0.0.1
		"64:ff9b:1::1":              "local-use NAT64",
		"100::1":                    "discard-only",
		"2001::1":                   "Teredo",
		"2001:2::1":                 "IETF protocol assignments",
		"2001:db8::1":               "documentation",
		"2002:7f00:1::1":            "6to4", // embeds 127.0.0.1
		"3fff::1":                   "documentation",
		"fc00::1":                   "unique local",
		"fd12:3456::1":              "unique local",
		"fe80::1":                   "link-local",
		"fec0::1":                   "site-local",
		"ff02::1":                   "multicast",
		"::1.2.3.4":                 "outside global unicast", // deprecated IPv4-compatible
		"4000::1":                   "outside global unicast",
		"8000::1":                   "outside global unicast",
		"e000::1":                   "outside global unicast",
		"fe80::1%eth0":              "zone",
		"2606:4700:4700::1111%eth0": "zone",
	}
	for s, want := range cases {
		err := CheckAddr(netip.MustParseAddr(s))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckAddr(%s) = %v, want an error containing %q", s, err, want)
		}
	}
	if err := CheckAddr(netip.Addr{}); err == nil {
		t.Error("the zero Addr was accepted")
	}
}

func TestCheckAddrAccepts(t *testing.T) {
	for _, a := range []netip.Addr{publicV4, publicV4b, publicV6, publicV6b,
		netip.MustParseAddr("::ffff:1.1.1.1"), // IPv4-mapped public: unmapped first
	} {
		if err := CheckAddr(a); err != nil {
			t.Errorf("CheckAddr(%s) = %v, want nil", a, err)
		}
	}
	// The edges just outside refused blocks.
	for _, s := range []string{"9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "172.15.255.255",
		"172.32.0.0", "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0", "223.255.255.255",
		"2000::1", "2001:200::1", "2003::1", "3ffe:ffff::1"} {
		if err := CheckAddr(netip.MustParseAddr(s)); err != nil {
			t.Errorf("CheckAddr(%s) = %v, want nil", s, err)
		}
	}
}

// TestCheckAddrAgreesWithNetip cross-checks the tables against Go's own
// classification over the edges of every block and a sweep of addresses:
// whatever netip calls non-global or private must be refused.
func TestCheckAddrAgreesWithNetip(t *testing.T) {
	var addrs []netip.Addr
	for _, bl := range append(append([]block(nil), v4Blocks...), v6Blocks...) {
		first := bl.prefix.Addr()
		addrs = append(addrs, first, first.Prev(), first.Next(), lastAddr(bl.prefix), lastAddr(bl.prefix).Next())
	}
	for i := 0; i < 256; i++ {
		for _, j := range []byte{0, 1, 127, 128, 254, 255} {
			addrs = append(addrs, netip.AddrFrom4([4]byte{byte(i), j, byte(i ^ int(j)), 1}))
			var b16 [16]byte
			b16[0], b16[1], b16[15] = byte(i), j, 1
			addrs = append(addrs, netip.AddrFrom16(b16))
		}
	}
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		u := a.Unmap()
		goNonPublic := !u.IsGlobalUnicast() || u.IsPrivate() || u.IsLoopback() || u.IsLinkLocalUnicast() ||
			u.IsMulticast() || u.IsUnspecified() || u.IsInterfaceLocalMulticast() || u.IsLinkLocalMulticast()
		if goNonPublic && CheckAddr(a) == nil {
			t.Errorf("CheckAddr(%s) accepted an address netip says is not public", a)
		}
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
