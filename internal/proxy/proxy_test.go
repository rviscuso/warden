package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	errs    map[string]error
	calls   []string
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, network+" "+host)
	if err := f.errs[host]; err != nil {
		return nil, err
	}
	return f.answers[host], nil
}

func (f *fakeResolver) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type fakeDialer struct {
	mu       sync.Mutex
	upstream string // every successful dial connects here
	dialed   []string
	refuse   map[string]bool // address -> connection refused
	hang     map[string]bool // address -> wait until the context ends
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, network+" "+address)
	refuse, hang, upstream := f.refuse[address], f.hang[address], f.upstream
	f.mu.Unlock()
	switch {
	case hang:
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
	case refuse:
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", upstream)
}

func (f *fakeDialer) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

type syncBuffer struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	fail func(n int) bool // fail the nth write (0-based)
	n    int
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.n
	s.n++
	if s.fail != nil && s.fail(n) {
		return 0, errors.New("log sink broken")
	}
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type harness struct {
	t      *testing.T
	p      *Proxy
	addr   string
	log    *syncBuffer
	res    *fakeResolver
	dialer *fakeDialer
	cancel context.CancelFunc
	served chan error
}

// newHarness runs a proxy on a local listener with a fake resolver, a fake
// dialer and an upstream server that reads until EOF, then answers
// "reply:" plus what it read and closes.
func newHarness(t *testing.T, tweak func(*Proxy)) *harness {
	t.Helper()
	up := listen(t)
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, err := io.ReadAll(c)
				if err != nil {
					return
				}
				c.Write(append([]byte("reply:"), data...))
			}()
		}
	}()
	h := &harness{
		t:   t,
		log: &syncBuffer{},
		res: &fakeResolver{answers: map[string][]netip.Addr{
			"api.anthropic.com":   {publicV4},
			"platform.claude.com": {publicV4b, publicV6},
		}, errs: map[string]error{}},
		dialer: &fakeDialer{upstream: up.Addr().String(), refuse: map[string]bool{}, hang: map[string]bool{}},
	}
	return h.start(tweak)
}

func (h *harness) start(tweak func(*Proxy)) *harness {
	t := h.t
	p, err := New(Config{
		Allow:    []string{"api.anthropic.com", ".claude.com"},
		Ports:    []int{443},
		Resolver: h.res,
		Dialer:   h.dialer,
		Log:      h.log,
		Now:      time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tweak != nil {
		tweak(p)
	}
	h.p = p
	ln := listen(t)
	h.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.served = make(chan error, 1)
	go func() { h.served <- p.Serve(ctx, ln) }()
	t.Cleanup(func() { h.stop() })
	h.waitEvent("start", 0) // Serve has its listener running
	return h
}

func (h *harness) stop() error {
	h.cancel()
	select {
	case err := <-h.served:
		h.served <- err // stop is idempotent
		return err
	case <-time.After(10 * time.Second):
		h.t.Fatal("Serve did not return after cancel")
		return nil
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// raw sends a raw request and returns the response and the open connection.
func (h *harness) raw(req string) (*http.Response, net.Conn, *bufio.Reader) {
	h.t.Helper()
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		h.t.Fatal(err)
	}
	br := bufio.NewReader(c)
	method, _, _ := strings.Cut(req, " ")
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		h.t.Fatalf("reading the response to %q: %v", firstLine(req), err)
	}
	return resp, c, br
}

func (h *harness) connect(target, extra string) (*http.Response, net.Conn, *bufio.Reader) {
	return h.raw("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n" + extra)
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\r\n"); return l }

// lines returns the log lines, each decoded twice: as a map (to check the
// fields present) and as an event.
func (h *harness) lines() ([]map[string]any, []event) {
	h.t.Helper()
	var ms []map[string]any
	var evs []event
	for _, l := range strings.Split(strings.TrimSpace(h.log.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		var ev event
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			h.t.Fatalf("log line is not JSON: %q", l)
		}
		json.Unmarshal([]byte(l), &ev)
		ms = append(ms, m)
		evs = append(evs, ev)
	}
	return ms, evs
}

// waitEvent waits for a log line with this event and id (0: any id).
func (h *harness) waitEvent(name string, id uint64) event {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, evs := h.lines()
		for _, ev := range evs {
			if ev.Event == name && (id == 0 || ev.ID == id) {
				return ev
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("no %q line for id %d in the log:\n%s", name, id, h.log.String())
	return event{}
}

var lineFields = []string{"time", "id", "event", "client", "host", "port", "decision", "reason", "bytes_up", "bytes_down", "duration_ms"}

func checkFields(t *testing.T, m map[string]any) {
	t.Helper()
	for _, f := range lineFields {
		if _, ok := m[f]; !ok {
			t.Errorf("log line %v has no %q field", m, f)
		}
	}
	if len(m) != len(lineFields) {
		t.Errorf("log line %v has extra fields", m)
	}
	if s, _ := m["time"].(string); !strings.HasSuffix(s, "Z") {
		t.Errorf("time %q is not UTC", s)
	}
}

func TestStartLine(t *testing.T) {
	h := newHarness(t, nil)
	ms, _ := h.lines()
	if len(ms) != 1 {
		t.Fatalf("want one start line, got %v", ms)
	}
	b, _ := json.Marshal(ms[0])
	var got struct {
		Event, Listen string
		Allow         []string
		Ports         []int
	}
	json.Unmarshal(b, &got)
	if got.Event != "start" || got.Listen != h.addr || strings.Join(got.Allow, " ") != "api.anthropic.com .claude.com" || len(got.Ports) != 1 || got.Ports[0] != 443 {
		t.Fatalf("start line %s", b)
	}
}

func TestDenyPaths(t *testing.T) {
	cases := []struct {
		name     string
		req      string // a raw request; or
		target   string // a CONNECT target
		setup    func(*harness)
		status   int
		decision string
		reason   string
		host     string
		port     int
		resolved bool // the resolver was asked
		dialed   bool // the dialer was asked
	}{
		{name: "GET", req: "GET http://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
			status: 405, decision: "deny", reason: "method not allowed", host: "http://api.anthropic.com/"},
		{name: "POST", req: "POST / HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 0\r\n\r\n",
			status: 405, decision: "deny", reason: "method not allowed", host: "/"},
		{name: "no port", target: "api.anthropic.com", status: 400, decision: "deny", reason: "invalid target", host: "api.anthropic.com"},
		{name: "non-canonical port", target: "api.anthropic.com:0443", status: 400, decision: "deny", reason: "bad port", host: "api.anthropic.com:0443"},
		{name: "port out of range", target: "api.anthropic.com:70000", status: 400, decision: "deny", reason: "bad port", host: "api.anthropic.com:70000"},
		{name: "path target", target: "/rpc", status: 400, decision: "deny", reason: "invalid target", host: "/rpc"},
		{name: "port not allowed", target: "api.anthropic.com:22", status: 403, decision: "deny", reason: "port not allowed", host: "api.anthropic.com", port: 22},
		// 1.1.1.1 here: a public address, so only the IP-literal rule can refuse it.
		{name: "IPv4 literal", target: "1.1.1.1:443", status: 403, decision: "deny", reason: "ip literal", host: "1.1.1.1", port: 443},
		{name: "IPv6 literal", target: "[2606:4700:4700::1111]:443", status: 403, decision: "deny", reason: "ip literal", host: "2606:4700:4700::1111", port: 443},
		{name: "numeric literal", target: "2130706433:443", status: 403, decision: "deny", reason: "ip literal", host: "2130706433", port: 443},
		{name: "hex literal", target: "0x7f.1:443", status: 403, decision: "deny", reason: "ip literal", host: "0x7f.1", port: 443},
		{name: "invalid host", target: "api_x.anthropic.com:443", status: 400, decision: "deny", reason: "invalid host", host: "api_x.anthropic.com:443", port: 443},
		{name: "near miss prefix", target: "evilapi.anthropic.com:443", status: 403, decision: "deny", reason: "host not allowed", host: "evilapi.anthropic.com", port: 443},
		{name: "near miss suffix", target: "api.anthropic.com.evil.org:443", status: 403, decision: "deny", reason: "host not allowed", host: "api.anthropic.com.evil.org", port: 443},
		{name: "resolve error", target: "api.anthropic.com:443",
			setup:  func(h *harness) { h.res.errs["api.anthropic.com"] = errors.New("no such host") },
			status: 502, decision: "error", reason: "resolve failed: no such host", host: "api.anthropic.com", port: 443, resolved: true},
		{name: "no addresses", target: "api.anthropic.com:443",
			setup:  func(h *harness) { h.res.answers["api.anthropic.com"] = nil },
			status: 502, decision: "error", reason: "resolve failed: no addresses", host: "api.anthropic.com", port: 443, resolved: true},
		{name: "loopback answer", target: "api.anthropic.com:443",
			setup:  func(h *harness) { h.res.answers["api.anthropic.com"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
			status: 403, decision: "deny", reason: "non-public address: 127.0.0.1 is loopback", host: "api.anthropic.com", port: 443, resolved: true},
		{name: "metadata answer", target: "x.claude.com:443",
			setup:  func(h *harness) { h.res.answers["x.claude.com"] = []netip.Addr{netip.MustParseAddr("169.254.169.254")} },
			status: 403, decision: "deny", reason: "non-public address: 169.254.169.254 is link-local", host: "x.claude.com", port: 443, resolved: true},
		{name: "mixed answer", target: "api.anthropic.com:443",
			setup: func(h *harness) {
				// A public address first, then a private one: the whole request is refused.
				h.res.answers["api.anthropic.com"] = []netip.Addr{publicV4, netip.MustParseAddr("10.0.0.1")}
			},
			status: 403, decision: "deny", reason: "non-public address: 10.0.0.1 is private", host: "api.anthropic.com", port: 443, resolved: true},
		{name: "mapped loopback answer", target: "api.anthropic.com:443",
			setup: func(h *harness) {
				h.res.answers["api.anthropic.com"] = []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}
			},
			status: 403, decision: "deny", reason: "non-public address: 127.0.0.1 is loopback", host: "api.anthropic.com", port: 443, resolved: true},
		{name: "dial refused", target: "api.anthropic.com:443",
			setup:  func(h *harness) { h.dialer.refuse["1.1.1.1:443"] = true },
			status: 502, decision: "error", reason: "dial failed (1 of 1 addresses tried)", host: "api.anthropic.com", port: 443, resolved: true, dialed: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, nil)
			if c.setup != nil {
				c.setup(h)
			}
			req := c.req
			if req == "" {
				req = "CONNECT " + c.target + " HTTP/1.1\r\nHost: x\r\n\r\n"
			}
			resp, conn, br := h.raw(req)
			if resp.StatusCode != c.status {
				t.Errorf("status %d, want %d", resp.StatusCode, c.status)
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), c.reason) {
				t.Errorf("body %q, want the reason %q", body, c.reason)
			}
			if c.status == 405 && resp.Header.Get("Allow") != "CONNECT" {
				t.Errorf("Allow: %q", resp.Header.Get("Allow"))
			}
			// The connection is closed after a refusal.
			if n, err := br.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Errorf("connection still open after a refusal: %d, %v", n, err)
			}
			conn.Close()

			ev := h.waitEvent("deny", 0)
			ms, evs := h.lines()
			if len(evs) != 2 {
				t.Fatalf("want start and one deny line, got:\n%s", h.log.String())
			}
			checkFields(t, ms[1])
			if ev.Decision != c.decision || !strings.Contains(ev.Reason, c.reason) || ev.Host != c.host || ev.Port != c.port || ev.ID != 1 {
				t.Errorf("deny line %+v, want decision %q, reason %q, host %q, port %d", ev, c.decision, c.reason, c.host, c.port)
			}
			if ev.BytesUp != 0 || ev.BytesDown != 0 || !strings.HasPrefix(ev.Client, "127.0.0.1:") {
				t.Errorf("deny line %+v", ev)
			}
			if got := len(h.res.called()) > 0; got != c.resolved {
				t.Errorf("resolver called: %v, want %v", h.res.called(), c.resolved)
			}
			if got := len(h.dialer.calls()) > 0; got != c.dialed {
				t.Errorf("dialer called: %v, want %v", h.dialer.calls(), c.dialed)
			}
		})
	}
}

func TestTunnel(t *testing.T) {
	h := newHarness(t, nil)
	// The secret is sent in the same write as the CONNECT request, so
	// net/http has it buffered when the handler hijacks the connection.
	const secret = "tunnel-content-must-never-be-logged"
	resp, conn, br := h.connect("Platform.Claude.com.:443", secret)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := io.WriteString(conn, "+more"); err != nil {
		t.Fatal(err)
	}
	// Half-close: the upstream reads to EOF before it answers.
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if want := "reply:" + secret + "+more"; string(got) != want {
		t.Fatalf("through the tunnel: %q, want %q", got, want)
	}

	open := h.waitEvent("open", 1)
	cl := h.waitEvent("close", 1)
	ms, _ := h.lines()
	for _, m := range ms[1:] {
		checkFields(t, m)
	}
	if open.Decision != "allow" || open.Reason != "allowlist: .claude.com" || open.Host != "platform.claude.com" || open.Port != 443 || open.BytesUp != 0 {
		t.Errorf("open line %+v", open)
	}
	up, down := int64(len(secret)+len("+more")), int64(len(got))
	if cl.Decision != "allow" || cl.Reason != "closed" || cl.BytesUp != up || cl.BytesDown != down || cl.Client != open.Client {
		t.Errorf("close line %+v, want bytes up %d down %d", cl, up, down)
	}
	if strings.Contains(h.log.String(), secret) || strings.Contains(h.log.String(), "reply:") {
		t.Errorf("the log contains tunnel content:\n%s", h.log.String())
	}
	// IPv4 first, by address: the name is never dialed.
	if d := h.dialer.calls(); len(d) != 1 || d[0] != "tcp 8.8.8.8:443" {
		t.Errorf("dialed %v, want only the IPv4 address", d)
	}
	if r := h.res.called(); len(r) != 1 || r[0] != "ip platform.claude.com" {
		t.Errorf("resolved %v", r)
	}
}

func TestDialOrderIPv4First(t *testing.T) {
	h := newHarness(t, nil)
	h.res.answers["api.anthropic.com"] = []netip.Addr{publicV6, publicV4, publicV6b, publicV4b}
	for _, a := range []string{"[2606:4700:4700::1111]:443", "1.1.1.1:443", "[2001:4860:4860::8888]:443", "8.8.8.8:443"} {
		h.dialer.refuse[a] = true
	}
	resp, _, _ := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 502 {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	want := "tcp 1.1.1.1:443,tcp 8.8.8.8:443,tcp [2606:4700:4700::1111]:443,tcp [2001:4860:4860::8888]:443"
	if got := strings.Join(h.dialer.calls(), ","); got != want {
		t.Errorf("dial order %s\nwant %s", got, want)
	}
	if ev := h.waitEvent("deny", 0); ev.Reason != "dial failed (4 of 4 addresses tried): dial tcp: connection refused" {
		t.Errorf("reason %q", ev.Reason)
	}
}

func TestDialPerAddressTimeout(t *testing.T) {
	// An unreachable IPv4 address times out on its own and the next one is
	// tried, inside the budget.
	h := newHarness(t, func(p *Proxy) { p.dialPerAddress = 50 * time.Millisecond; p.dialBudget = 5 * time.Second })
	h.res.answers["api.anthropic.com"] = []netip.Addr{publicV4, publicV4b}
	h.dialer.hang["1.1.1.1:443"] = true
	resp, _, _ := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if got := strings.Join(h.dialer.calls(), ","); got != "tcp 1.1.1.1:443,tcp 8.8.8.8:443" {
		t.Errorf("dialed %s", got)
	}
}

func TestDialAllTimeOut(t *testing.T) {
	h := newHarness(t, func(p *Proxy) { p.dialPerAddress = 30 * time.Millisecond; p.dialBudget = 5 * time.Second })
	h.res.answers["api.anthropic.com"] = []netip.Addr{publicV4, publicV6}
	h.dialer.hang["1.1.1.1:443"] = true
	h.dialer.hang["[2606:4700:4700::1111]:443"] = true
	resp, _, _ := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 504 {
		t.Fatalf("status %d, want 504", resp.StatusCode)
	}
	if ev := h.waitEvent("deny", 0); ev.Decision != "error" || ev.Reason != "dial timed out (2 of 2 addresses tried)" {
		t.Errorf("deny line %+v", ev)
	}
}

func TestDialBudgetRunsOut(t *testing.T) {
	// Each address may take 100ms, but all of them together only 150ms:
	// the third address is never tried.
	h := newHarness(t, func(p *Proxy) { p.dialPerAddress = 100 * time.Millisecond; p.dialBudget = 150 * time.Millisecond })
	h.res.answers["api.anthropic.com"] = []netip.Addr{publicV4, publicV4b, publicV6}
	for _, a := range []string{"1.1.1.1:443", "8.8.8.8:443", "[2606:4700:4700::1111]:443"} {
		h.dialer.hang[a] = true
	}
	start := time.Now()
	resp, _, _ := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 504 {
		t.Fatalf("status %d, want 504", resp.StatusCode)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v", el)
	}
	if got := strings.Join(h.dialer.calls(), ","); got != "tcp 1.1.1.1:443,tcp 8.8.8.8:443" {
		t.Errorf("dialed %s", got)
	}
	if ev := h.waitEvent("deny", 0); ev.Reason != "dial timed out (2 of 3 addresses tried)" {
		t.Errorf("reason %q", ev.Reason)
	}
}

func TestTunnelCap(t *testing.T) {
	h := newHarness(t, func(p *Proxy) { p.slots = make(chan struct{}, 1) })
	resp, conn, _ := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 200 {
		t.Fatalf("first: status %d", resp.StatusCode)
	}
	resp2, _, _ := h.connect("api.anthropic.com:443", "")
	if resp2.StatusCode != 503 {
		t.Fatalf("second: status %d, want 503", resp2.StatusCode)
	}
	if ev := h.waitEvent("deny", 0); ev.Reason != "too many tunnels" || ev.ID != 2 {
		t.Errorf("deny line %+v", ev)
	}
	if n := len(h.res.called()); n != 1 {
		t.Errorf("the refused request was resolved: %v", h.res.called())
	}
	// Closing the first tunnel frees its slot.
	conn.Close()
	h.waitEvent("close", 1)
	resp3, _, _ := h.connect("api.anthropic.com:443", "")
	if resp3.StatusCode != 200 {
		t.Fatalf("third: status %d, want 200", resp3.StatusCode)
	}
}

func TestNoIdleTimeoutAfterHijack(t *testing.T) {
	// The server's own timeouts are 50ms here. A tunnel idle for much
	// longer must still work: the deadlines are cleared after Hijack.
	h := newHarness(t, func(p *Proxy) {
		p.headerTimeout, p.resolveTimeout, p.dialBudget = 50*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond
	})
	resp, conn, br := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	conn.SetDeadline(time.Time{})
	time.Sleep(300 * time.Millisecond)
	io.WriteString(conn, "late")
	conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(br)
	if err != nil || string(got) != "reply:late" {
		t.Fatalf("after idling: %q, %v", got, err)
	}
}

func TestHeaderTimeout(t *testing.T) {
	h := newHarness(t, func(p *Proxy) { p.headerTimeout = 100 * time.Millisecond })
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "CONNECT api.anthropic.com:443 HTTP/1.1\r\n") // never finished
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("the slow client was not disconnected: %v", err)
	}
	if len(h.dialer.calls()) != 0 || len(h.res.called()) != 0 {
		t.Fatal("an unfinished request reached the resolver or dialer")
	}
}

func TestShutdownClosesTunnels(t *testing.T) {
	h := newHarness(t, nil)
	resp, _, br := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	h.waitEvent("open", 1)
	if err := h.stop(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// Serve returned, so the close line is already written.
	_, evs := h.lines()
	if last := evs[len(evs)-1]; last.Event != "close" || last.ID != 1 || last.Reason != "shutdown" {
		t.Errorf("last line %+v, want close of tunnel 1 with reason shutdown", last)
	}
	if _, err := io.ReadAll(br); err != nil {
		t.Errorf("client side after shutdown: %v", err)
	}
	if _, err := net.Dial("tcp", h.addr); err == nil {
		t.Error("still accepting after shutdown")
	}
}

func TestOpenNotLoggedMeansNotOpened(t *testing.T) {
	h := newHarness(t, nil)
	h.log.mu.Lock()
	h.log.fail = func(n int) bool { return n >= 1 } // the start line works, nothing after
	h.log.mu.Unlock()
	resp, _, br := h.connect("api.anthropic.com:443", "")
	if resp.StatusCode != 502 {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	if n, err := br.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Error("connection still open")
	}
}

func TestServeFailsWithoutStartLine(t *testing.T) {
	p, err := New(Config{Allow: []string{"api.anthropic.com"}, Ports: []int{443}, Resolver: &fakeResolver{}, Dialer: &fakeDialer{},
		Log: &syncBuffer{fail: func(int) bool { return true }}, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	if err := p.Serve(context.Background(), ln); err == nil || !strings.Contains(err.Error(), "start log line") {
		t.Fatalf("Serve = %v", err)
	}
	if _, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		t.Error("listener left open")
	}
}

func TestNewRejects(t *testing.T) {
	ok := Config{Allow: []string{"api.anthropic.com"}, Ports: []int{443}, Resolver: &fakeResolver{}, Dialer: &fakeDialer{}, Log: io.Discard, Now: time.Now}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"no allow":    func(c *Config) { c.Allow = nil },
		"bad allow":   func(c *Config) { c.Allow = []string{"*.x.com"} },
		"no ports":    func(c *Config) { c.Ports = nil },
		"port 0":      func(c *Config) { c.Ports = []int{0} },
		"port 65536":  func(c *Config) { c.Ports = []int{65536} },
		"dup port":    func(c *Config) { c.Ports = []int{443, 443} },
		"no resolver": func(c *Config) { c.Resolver = nil },
		"no dialer":   func(c *Config) { c.Dialer = nil },
		"no log":      func(c *Config) { c.Log = nil },
		"no clock":    func(c *Config) { c.Now = nil },
	} {
		c := ok
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProductionTypesSatisfyInterfaces(t *testing.T) {
	var _ Resolver = net.DefaultResolver
	var _ Dialer = &net.Dialer{}
}
