package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rviscuso/warden/internal/config"
)

// Allowlist is the set of hostnames the proxy may connect to: exact names,
// and leading-dot entries that match a domain and all its subdomains.
type Allowlist struct {
	entries []string
	exact   map[string]bool
	domains []string // leading-dot entries, without the dot
}

// NewAllowlist validates entries with the same rules as egress.allow in the
// config, duplicates included. The proxy doesn't trust its flags because
// Warden wrote them.
func NewAllowlist(entries []string) (*Allowlist, error) {
	if len(entries) == 0 {
		return nil, errors.New("the allowlist is empty: pass at least one --allow")
	}
	a := &Allowlist{exact: map[string]bool{}}
	seen := map[string]bool{}
	for _, e := range entries {
		if err := config.ValidateAllowEntry(e); err != nil {
			return nil, fmt.Errorf("--allow: %w", err)
		}
		if seen[e] {
			return nil, fmt.Errorf("--allow: duplicate entry %q", e)
		}
		seen[e] = true
		a.entries = append(a.entries, e)
		if d, ok := strings.CutPrefix(e, "."); ok {
			a.domains = append(a.domains, d)
		} else {
			a.exact[e] = true
		}
	}
	return a, nil
}

// Entries returns the entries in the order given.
func (a *Allowlist) Entries() []string { return append([]string(nil), a.entries...) }

// Match reports the entry that allows host, if any. host is normalized
// first (lowercase, one trailing dot removed); a host that isn't a valid
// hostname never matches.
func (a *Allowlist) Match(host string) (entry string, ok bool) {
	h, kind := classifyHost(host)
	if kind != hostName {
		return "", false
	}
	return a.match(h)
}

// match takes a normalized hostname.
func (a *Allowlist) match(h string) (string, bool) {
	if a.exact[h] {
		return h, true
	}
	for _, d := range a.domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return "." + d, true
		}
	}
	return "", false
}

type hostKind int

const (
	hostName hostKind = iota
	hostIPLiteral
	hostInvalid
)

// classifyHost normalizes a CONNECT target host and says what it is.
// IP literals are recognized before hostname syntax, including the numeric
// forms some resolvers accept (2130706433, 0x7f.1, 127.1).
func classifyHost(raw string) (string, hostKind) {
	for i := 0; i < len(raw); i++ {
		// ASCII only, checked before lowercasing: strings.ToLower would map
		// non-ASCII runes such as the Kelvin sign (U+212A) to 'k'.
		if raw[i] >= 0x80 {
			return "", hostInvalid
		}
	}
	h := asciiLower(raw)
	h = strings.TrimSuffix(h, ".")
	if _, err := netip.ParseAddr(h); err == nil {
		return h, hostIPLiteral
	}
	if h == "" || len(h) > 253 {
		return "", hostInvalid
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if !validLabel(l) {
			return "", hostInvalid
		}
	}
	if last := labels[len(labels)-1]; allDigits(last) || isHex0x(last) {
		return h, hostIPLiteral
	}
	return h, hostName
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func isHex0x(s string) bool {
	rest, ok := strings.CutPrefix(s, "0x")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// splitTarget parses a CONNECT request target, "host:port", with an
// explicit, canonical decimal port.
func splitTarget(target string) (host string, port int, err error) {
	host, p, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, errors.New("invalid target: want host:port")
	}
	port, err = parsePort(p)
	if err != nil {
		return "", 0, fmt.Errorf("invalid target: %w", err)
	}
	return host, port, nil
}

// parsePort accepts only canonical decimal ports 1 to 65535: no sign, no
// leading zero, no spaces.
func parsePort(s string) (int, error) {
	if !allDigits(s) || len(s) > 5 || s[0] == '0' {
		return 0, fmt.Errorf("bad port %q", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return n, nil
}

// ParsePorts parses the --ports flag: comma-separated, each 1 to 65535,
// no duplicates, at least one.
func ParsePorts(s string) ([]int, error) {
	if s == "" {
		return nil, errors.New("--ports: no ports given")
	}
	var ports []int
	seen := map[int]bool{}
	for _, f := range strings.Split(s, ",") {
		p, err := parsePort(f)
		if err != nil {
			return nil, fmt.Errorf("--ports: %w (want comma-separated ports 1 to 65535)", err)
		}
		if seen[p] {
			return nil, fmt.Errorf("--ports: duplicate port %d", p)
		}
		seen[p] = true
		ports = append(ports, p)
	}
	return ports, nil
}
