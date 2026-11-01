package proxy

import (
	"fmt"
	"strings"
	"testing"
)

func TestAllowlistMatch(t *testing.T) {
	a, err := NewAllowlist([]string{"api.anthropic.com", ".claude.com"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host, entry string
	}{
		{"api.anthropic.com", "api.anthropic.com"},
		{"API.Anthropic.COM", "api.anthropic.com"},
		{"api.anthropic.com.", "api.anthropic.com"},
		{"claude.com", ".claude.com"}, // a leading dot matches the domain itself
		{"platform.claude.com", ".claude.com"},
		{"a.b.claude.com", ".claude.com"},
		{"Platform.CLAUDE.com.", ".claude.com"},

		{"evilapi.anthropic.com", ""},
		{"api.anthropic.com.evil.org", ""},
		{"anthropic.com", ""},
		{"x.api.anthropic.com", ""}, // exact entries don't match subdomains
		{"xclaude.com", ""},
		{"claude.com.evil.org", ""},
		{"claude.co", ""},
		{"api.anthropic.com..", ""},
		{".claude.com", ""},
		{"", ""},
		{"api.anthropic.Kom", ""}, // Kelvin sign: lowercases to 'k' in Unicode, not here
		{"api.anthropic.com:443", ""},
	}
	for _, c := range cases {
		entry, ok := a.Match(c.host)
		if ok != (c.entry != "") || entry != c.entry {
			t.Errorf("Match(%q) = %q, %v; want %q", c.host, entry, ok, c.entry)
		}
	}
}

func TestNewAllowlistRejects(t *testing.T) {
	for _, entries := range [][]string{
		nil,
		{},
		{""},
		{"*.claude.com"},
		{"Api.anthropic.com"},
		{"api.anthropic.com."},
		{"https://api.anthropic.com"},
		{"api.anthropic.com:443"},
		{"localhost"},
		{".com"},
		{"1.1.1.1"},
		{"api.anthropic.com", "api.anthropic.com"},
		{".claude.com", ".claude.com"},
	} {
		if _, err := NewAllowlist(entries); err == nil {
			t.Errorf("NewAllowlist(%q) accepted", entries)
		}
	}
	a, err := NewAllowlist([]string{"api.anthropic.com", ".claude.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(a.Entries(), " "); got != "api.anthropic.com .claude.com" {
		t.Errorf("Entries() = %q", got)
	}
}

func TestParsePorts(t *testing.T) {
	good := map[string]string{"443": "[443]", "443,8443": "[443 8443]", "1,65535": "[1 65535]"}
	for in, want := range good {
		ps, err := ParsePorts(in)
		if err != nil || fmt.Sprint(ps) != want {
			t.Errorf("ParsePorts(%q) = %v, %v; want %s", in, ps, err, want)
		}
	}
	for _, in := range []string{"", "0", "65536", "443,443", "+443", "-1", "0443", " 443", "443 ", "443,", ",443", "a", "443;80", "1e3", "99999999999999999999"} {
		if ps, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) = %v, want an error", in, ps)
		}
	}
}

func TestClassifyHost(t *testing.T) {
	cases := []struct {
		in, out string
		kind    hostKind
	}{
		{"API.Anthropic.com.", "api.anthropic.com", hostName},
		{"localhost", "localhost", hostName}, // valid syntax; the allowlist refuses it
		{"xn--bcher-kva.example", "xn--bcher-kva.example", hostName},
		{"a-b.example", "a-b.example", hostName},

		{"1.1.1.1", "1.1.1.1", hostIPLiteral},
		{"::1", "::1", hostIPLiteral},
		{"fe80::1%eth0", "fe80::1%eth0", hostIPLiteral},
		{"::ffff:127.0.0.1", "::ffff:127.0.0.1", hostIPLiteral},
		{"2130706433", "2130706433", hostIPLiteral}, // 127.0.0.1 as one number
		{"0x7f000001", "0x7f000001", hostIPLiteral},
		{"0X7F000001", "0x7f000001", hostIPLiteral},
		{"0x7f.1", "0x7f.1", hostIPLiteral},
		{"127.1", "127.1", hostIPLiteral},
		{"1.1.1.01", "1.1.1.01", hostIPLiteral},
		{"127.0.0.1.", "127.0.0.1", hostIPLiteral},

		{"", "", hostInvalid},
		{".", "", hostInvalid},
		{"a..example", "", hostInvalid},
		{".example.com", "", hostInvalid},
		{"-a.example", "", hostInvalid},
		{"a-.example", "", hostInvalid},
		{"a_b.example", "", hostInvalid},
		{"*.example.com", "", hostInvalid},
		{"bücher.example", "", hostInvalid},
		{"example.com/path", "", hostInvalid},
		{"user@example.com", "", hostInvalid},
		{"example.com..", "", hostInvalid},
		{strings.Repeat("a", 64) + ".example", "", hostInvalid},
		{strings.Repeat("a.", 127) + "ab", "", hostInvalid}, // 255 characters
	}
	for _, c := range cases {
		out, kind := classifyHost(c.in)
		if kind != c.kind || out != c.out {
			t.Errorf("classifyHost(%q) = %q, %d; want %q, %d", c.in, out, kind, c.out, c.kind)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	good := []struct {
		in, host string
		port     int
	}{
		{"api.anthropic.com:443", "api.anthropic.com", 443},
		{"[::1]:443", "::1", 443},
		{"1.1.1.1:8443", "1.1.1.1", 8443},
	}
	for _, c := range good {
		h, p, err := splitTarget(c.in)
		if err != nil || h != c.host || p != c.port {
			t.Errorf("splitTarget(%q) = %q, %d, %v", c.in, h, p, err)
		}
	}
	for _, in := range []string{"", "api.anthropic.com", "api.anthropic.com:", "api.anthropic.com:0", "api.anthropic.com:0443",
		"api.anthropic.com:65536", "api.anthropic.com:https", "api.anthropic.com:+443", "/rpc", "http://api.anthropic.com/", "::1:443", "a:b:443"} {
		if h, p, err := splitTarget(in); err == nil {
			t.Errorf("splitTarget(%q) = %q, %d, want an error", in, h, p)
		}
	}
}
