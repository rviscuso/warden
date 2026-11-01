package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// noNetwork fails the test if the proxy ever resolves or dials: the cli
// tests only refuse requests.
type noNetwork struct{ t *testing.T }

func (n noNetwork) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	n.t.Error("the proxy resolved a name")
	return nil, errors.New("no network in tests")
}

func (n noNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	n.t.Error("the proxy dialed")
	return nil, errors.New("no network in tests")
}

type proxyRun struct {
	stdout, stderr *lockedBuffer
	listenedOn     chan string // the address --listen asked for
	bound          chan string // the address actually bound
	stop           context.CancelFunc
	code           chan int
}

func startProxy(t *testing.T, args ...string) *proxyRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &proxyRun{
		stdout: &lockedBuffer{}, stderr: &lockedBuffer{},
		listenedOn: make(chan string, 1), bound: make(chan string, 1),
		stop: cancel, code: make(chan int, 1),
	}
	e := &env{
		stdin:   strings.NewReader(""),
		stdout:  r.stdout,
		stderr:  r.stderr,
		getenv:  func(k string) string { return map[string]string{"WARDEN_ROLE": "proxy"}[k] },
		geteuid: func() int { return 1000 },
		now:     time.Now,
		listen: func(address string) (net.Listener, error) {
			r.listenedOn <- address
			ln, err := net.Listen("tcp", "127.0.0.1:0") // never the requested address in tests
			if err == nil {
				r.bound <- ln.Addr().String()
				t.Cleanup(func() { ln.Close() })
			}
			return ln, err
		},
		signals:  func() (context.Context, context.CancelFunc) { return ctx, cancel },
		resolver: noNetwork{t},
		dialer:   noNetwork{t},
	}
	go func() { r.code <- run(e, append([]string{"warden", "proxy"}, args...)) }()
	return r
}

func (r *proxyRun) wait(t *testing.T) int {
	t.Helper()
	select {
	case c := <-r.code:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("warden proxy did not exit")
		return -1
	}
}

func TestProxyFlagErrors(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{nil, "the allowlist is empty"},
		{[]string{"--ports", "443"}, "the allowlist is empty"},
		{[]string{"--allow", "*.claude.com"}, "--allow:"},
		{[]string{"--allow", "API.anthropic.com"}, "lowercase"},
		{[]string{"--allow", "api.anthropic.com,platform.claude.com"}, "--allow:"}, // repeated, not comma-separated
		{[]string{"--allow", "api.anthropic.com", "--allow", "api.anthropic.com"}, "duplicate entry"},
		{[]string{"--allow", "api.anthropic.com", "--ports", ""}, "--ports: no ports"},
		{[]string{"--allow", "api.anthropic.com", "--ports", "0"}, "--ports: bad port"},
		{[]string{"--allow", "api.anthropic.com", "--ports", "443,443"}, "duplicate port"},
		{[]string{"--allow", "api.anthropic.com", "--ports", "443 8443"}, "--ports: bad port"},
		{[]string{"--allow", "api.anthropic.com", "extra"}, "unexpected arguments: extra"},
		{[]string{"--bogus"}, "flag provided but not defined"},
	}
	for _, c := range cases {
		r := startProxy(t, c.args...)
		if code := r.wait(t); code != ExitUsage || !strings.Contains(r.stderr.String(), c.want) || !strings.Contains(r.stderr.String(), "Usage: warden proxy") {
			t.Errorf("%q: exit %d, stderr %q, want exit 2 and %q", c.args, code, r.stderr.String(), c.want)
		}
		if len(r.listenedOn) != 0 {
			t.Errorf("%q: listened despite bad flags", c.args)
		}
	}
}

func TestProxyRunsAndStopsOnSignal(t *testing.T) {
	for _, c := range []struct {
		args   []string
		listen string
	}{
		{[]string{"--allow", "api.anthropic.com", "--allow", ".claude.com"}, ":3128"},
		{[]string{"--listen", "127.0.0.1:0", "--allow", "api.anthropic.com", "--ports", "443,8443"}, "127.0.0.1:0"},
	} {
		r := startProxy(t, c.args...)
		if got := <-r.listenedOn; got != c.listen {
			t.Errorf("listened on %q, want %q", got, c.listen)
		}
		addr := <-r.bound
		start := waitLine(t, r.stdout, `"event":"start"`)
		var sl struct {
			Listen string
			Allow  []string
			Ports  []int
		}
		json.Unmarshal([]byte(start), &sl)
		if sl.Listen != addr {
			t.Errorf("start line %s, want listen %s", start, addr)
		}

		// It serves: a host that isn't listed is refused without resolving.
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
		if err != nil || resp.StatusCode != 403 {
			t.Fatalf("CONNECT example.com: %v %v", resp, err)
		}
		conn.Close()
		waitLine(t, r.stdout, `"reason":"host not allowed"`)

		r.stop() // SIGTERM
		if code := r.wait(t); code != ExitOK {
			t.Errorf("exit %d after SIGTERM, stderr %q", code, r.stderr.String())
		}
	}
}

func TestProxyListenFailure(t *testing.T) {
	var errb bytes.Buffer
	e := &env{
		stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &errb,
		getenv:   func(k string) string { return map[string]string{"WARDEN_ROLE": "proxy"}[k] },
		geteuid:  func() int { return 1000 },
		now:      time.Now,
		listen:   func(string) (net.Listener, error) { return nil, errors.New("address already in use") },
		signals:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
		resolver: noNetwork{t},
		dialer:   noNetwork{t},
	}
	if code := run(e, []string{"warden", "proxy", "--allow", "api.anthropic.com"}); code != ExitFail || !strings.Contains(errb.String(), "address already in use") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

func waitLine(t *testing.T, b *lockedBuffer, substr string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(b.String(), "\n") {
			if strings.Contains(l, substr) {
				return l
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no line containing %s in:\n%s", substr, b.String())
	return ""
}
