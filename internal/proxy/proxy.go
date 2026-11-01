// Package proxy is Warden's egress proxy: the only way out of the sandbox
// network. It accepts HTTP CONNECT to allowlisted hostnames on allowed
// ports, resolves the name itself, dials only public unicast addresses,
// splices bytes both ways and logs one JSON line when a tunnel opens and
// one when it closes. See docs/phase-1.md, "Egress proxy".
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Limits. Constants, not flags: fewer settings to get wrong.
const (
	HeaderTimeout  = 10 * time.Second // to read the request headers
	MaxHeaderBytes = 8 << 10          // net/http adds its own small allowance
	ResolveTimeout = 5 * time.Second
	DialBudget     = 10 * time.Second // all addresses together
	DialPerAddress = 5 * time.Second  // one address, inside the budget
	MaxTunnels     = 256              // concurrent; refused at once beyond this
)

// Resolver resolves a hostname. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer opens a TCP connection. *net.Dialer implements it. The proxy only
// ever passes it an IP:port, never a name.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Config is everything the proxy needs; it reads no config file.
type Config struct {
	Allow    []string // --allow entries
	Ports    []int    // allowed destination ports
	Resolver Resolver
	Dialer   Dialer
	Log      io.Writer // JSON lines: start, open, close, deny
	ErrorLog io.Writer // net/http's own errors
	Now      func() time.Time
}

// Proxy is one egress proxy. Create it with New, run it with Serve.
type Proxy struct {
	allow    *Allowlist
	ports    []int
	portSet  map[int]bool
	resolver Resolver
	dialer   Dialer
	log      *logger
	errorLog io.Writer
	now      func() time.Time

	// The limits above; tests shorten them.
	headerTimeout  time.Duration
	resolveTimeout time.Duration
	dialBudget     time.Duration
	dialPerAddress time.Duration
	slots          chan struct{}

	nextID atomic.Uint64

	mu       sync.Mutex
	closing  bool
	tunnels  map[*tunnel]struct{}
	handlers sync.WaitGroup
	stop     context.Context // canceled on shutdown: aborts resolves and dials
	cancel   context.CancelFunc
}

// New validates cfg and returns a proxy.
func New(cfg Config) (*Proxy, error) {
	allow, err := NewAllowlist(cfg.Allow)
	if err != nil {
		return nil, err
	}
	if len(cfg.Ports) == 0 {
		return nil, errors.New("--ports: no ports given")
	}
	portSet := map[int]bool{}
	for _, p := range cfg.Ports {
		if p < 1 || p > 65535 || portSet[p] {
			return nil, fmt.Errorf("--ports: bad or duplicate port %d", p)
		}
		portSet[p] = true
	}
	if cfg.Resolver == nil || cfg.Dialer == nil || cfg.Log == nil || cfg.Now == nil {
		return nil, errors.New("proxy: Resolver, Dialer, Log and Now are required")
	}
	errorLog := cfg.ErrorLog
	if errorLog == nil {
		errorLog = io.Discard
	}
	stop, cancel := context.WithCancel(context.Background())
	return &Proxy{
		allow:          allow,
		ports:          append([]int(nil), cfg.Ports...),
		portSet:        portSet,
		resolver:       cfg.Resolver,
		dialer:         cfg.Dialer,
		log:            &logger{w: cfg.Log},
		errorLog:       errorLog,
		now:            cfg.Now,
		headerTimeout:  HeaderTimeout,
		resolveTimeout: ResolveTimeout,
		dialBudget:     DialBudget,
		dialPerAddress: DialPerAddress,
		slots:          make(chan struct{}, MaxTunnels),
		tunnels:        map[*tunnel]struct{}{},
		stop:           stop,
		cancel:         cancel,
	}, nil
}

// Serve accepts connections on ln until ctx is canceled or ln fails. On
// cancel it stops accepting, closes every open tunnel, waits for their
// close lines and returns nil.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: p.headerTimeout,
		// Bounds writing a refusal to a slow client; must outlast the longest
		// resolve and dial. Cleared after Hijack.
		WriteTimeout:   p.headerTimeout + p.resolveTimeout + p.dialBudget,
		IdleTimeout:    p.headerTimeout,
		MaxHeaderBytes: MaxHeaderBytes,
		ErrorLog:       log.New(p.errorLog, "warden proxy: ", 0),
	}
	if err := p.log.write(startLine{
		Time:   p.timestamp(),
		Event:  "start",
		Listen: ln.Addr().String(),
		Allow:  p.allow.Entries(),
		Ports:  p.ports,
	}); err != nil {
		ln.Close()
		return fmt.Errorf("writing the start log line: %w", err)
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-served:
	}

	p.mu.Lock()
	p.closing = true
	open := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		open = append(open, t)
	}
	p.mu.Unlock()
	p.cancel()
	srv.Close() // the listener and every connection not yet hijacked
	for _, t := range open {
		t.shutdown()
	}
	p.handlers.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (p *Proxy) timestamp() string { return p.now().UTC().Format(time.RFC3339Nano) }

// ServeHTTP handles one request. The checks run in the documented order:
// method, target, port, IP literal, host syntax, allowlist, tunnel cap,
// resolve, address policy, dial.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		p.emit(&event{ID: p.nextID.Add(1), Event: "deny", Client: r.RemoteAddr, Host: cut(r.RequestURI), Decision: "deny", Reason: "shutting down"}, p.now())
		refuse(w, http.StatusServiceUnavailable, "shutting down")
		return
	}
	p.handlers.Add(1)
	p.mu.Unlock()
	defer p.handlers.Done()

	start := p.now()
	ev := &event{ID: p.nextID.Add(1), Client: r.RemoteAddr, Host: cut(r.RequestURI)}
	deny := func(status int, decision, reason string) {
		ev.Event, ev.Decision, ev.Reason = "deny", decision, reason
		p.emit(ev, start)
		refuse(w, status, reason)
	}

	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		deny(http.StatusMethodNotAllowed, "deny", "method not allowed")
		return
	}
	rawHost, port, err := splitTarget(r.RequestURI)
	if err != nil {
		deny(http.StatusBadRequest, "deny", err.Error())
		return
	}
	ev.Port = port
	host, kind := classifyHost(rawHost)
	if kind != hostInvalid {
		ev.Host = host
	}
	if !p.portSet[port] {
		deny(http.StatusForbidden, "deny", "port not allowed")
		return
	}
	switch kind {
	case hostIPLiteral:
		deny(http.StatusForbidden, "deny", "ip literal")
		return
	case hostInvalid:
		deny(http.StatusBadRequest, "deny", "invalid host")
		return
	}
	entry, ok := p.allow.match(host)
	if !ok {
		deny(http.StatusForbidden, "deny", "host not allowed")
		return
	}

	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		deny(http.StatusServiceUnavailable, "deny", "too many tunnels")
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer context.AfterFunc(p.stop, cancel)()

	addrs, err := p.resolve(ctx, host)
	if err != nil {
		deny(http.StatusBadGateway, "error", "resolve failed: "+err.Error())
		return
	}
	for _, a := range addrs {
		if err := CheckAddr(a); err != nil {
			deny(http.StatusForbidden, "deny", "non-public address: "+err.Error())
			return
		}
	}
	upstream, err := p.dial(ctx, addrs, port)
	if err != nil {
		var te timeoutError
		if errors.As(err, &te) {
			deny(http.StatusGatewayTimeout, "error", err.Error())
		} else {
			deny(http.StatusBadGateway, "error", err.Error())
		}
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		deny(http.StatusInternalServerError, "error", "connection can't be hijacked")
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		deny(http.StatusInternalServerError, "error", "hijack failed: "+err.Error())
		return
	}
	// A tunnel has no idle timeout. net/http clears its deadlines in Hijack
	// today but documents that it may not, so clear them here too.
	client.SetDeadline(time.Time{})

	ev.Event, ev.Decision, ev.Reason = "open", "allow", "allowlist: "+entry
	if err := p.emit(ev, start); err != nil {
		// Not logged, not opened.
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		client.Close()
		upstream.Close()
		return
	}

	t := &tunnel{client: client, upstream: upstream}
	if !p.register(t) {
		t.closeBoth()
		ev.Event, ev.Reason = "close", "shutdown"
		p.emit(ev, start)
		return
	}
	defer p.unregister(t)

	var up, down int64
	var reason string
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		t.closeBoth()
		reason = "writing the 200 response: " + err.Error()
	} else {
		// Bytes the client sent right after the request (a TLS ClientHello,
		// say) are already in net/http's buffer.
		pending, _ := buf.Reader.Peek(buf.Reader.Buffered())
		up, down, reason = t.splice(pending)
	}
	ev.Event, ev.Reason, ev.BytesUp, ev.BytesDown = "close", reason, up, down
	p.emit(ev, start)
}

// refuse writes an error response and closes the connection after it.
func refuse(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Connection", "close")
	http.Error(w, "warden proxy: "+reason, status)
}

func (p *Proxy) register(t *tunnel) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.tunnels[t] = struct{}{}
	return true
}

func (p *Proxy) unregister(t *tunnel) {
	p.mu.Lock()
	delete(p.tunnels, t)
	p.mu.Unlock()
}

func (p *Proxy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, p.resolveTimeout)
	defer cancel()
	addrs, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no addresses")
	}
	return addrs, nil
}

// timeoutError marks a dial that failed only by running out of time.
type timeoutError struct{ msg string }

func (e timeoutError) Error() string { return e.msg }

// dial tries IPv4 addresses before IPv6 (Docker bridge networks are
// IPv4-only by default), in resolver order within each family, each with
// its own timeout inside the total budget.
func (p *Proxy) dial(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, p.dialBudget)
	defer cancel()
	var last error
	tried, timeouts := 0, 0
	for _, a := range dialOrder(addrs) {
		if ctx.Err() != nil {
			break
		}
		actx, acancel := context.WithTimeout(ctx, p.dialPerAddress)
		c, err := p.dialer.DialContext(actx, "tcp", netip.AddrPortFrom(a.Unmap(), uint16(port)).String())
		acancel()
		if err == nil {
			return c, nil
		}
		tried++
		last = err
		if isTimeout(err) {
			timeouts++
		}
	}
	if ctx.Err() != nil || timeouts == tried {
		return nil, timeoutError{fmt.Sprintf("dial timed out (%d of %d addresses tried)", tried, len(addrs))}
	}
	return nil, fmt.Errorf("dial failed (%d of %d addresses tried): %v", tried, len(addrs), last)
}

func dialOrder(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.Unmap().Is4() {
			out = append(out, a)
		}
	}
	for _, a := range addrs {
		if !a.Unmap().Is4() {
			out = append(out, a)
		}
	}
	return out
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

// tunnel is one spliced connection pair.
type tunnel struct {
	client, upstream net.Conn
	stopped          atomic.Bool
	closeOnce        sync.Once
}

func (t *tunnel) closeBoth() {
	t.closeOnce.Do(func() {
		t.client.Close()
		t.upstream.Close()
	})
}

func (t *tunnel) shutdown() {
	t.stopped.Store(true)
	t.closeBoth()
}

// splice copies both ways until both directions are done. EOF in one
// direction half-closes the other side; an error in either closes both.
// It returns the bytes sent each way and how the tunnel ended.
func (t *tunnel) splice(pending []byte) (up, down int64, reason string) {
	type result struct {
		n   int64
		err error
	}
	upDone, downDone := make(chan result, 1), make(chan result, 1)
	go func() {
		var n int64
		var err error
		if len(pending) > 0 {
			var m int
			m, err = t.upstream.Write(pending)
			n = int64(m)
		}
		if err == nil {
			var m int64
			m, err = io.Copy(t.upstream, t.client)
			n += m
		}
		t.finish(t.upstream, err)
		upDone <- result{n, err}
	}()
	go func() {
		n, err := io.Copy(t.client, t.upstream)
		t.finish(t.client, err)
		downDone <- result{n, err}
	}()
	u, d := <-upDone, <-downDone
	t.closeBoth()

	switch {
	case t.stopped.Load():
		reason = "shutdown"
	case u.err != nil:
		reason = "client to server: " + u.err.Error()
	case d.err != nil:
		reason = "server to client: " + d.err.Error()
	default:
		reason = "closed"
	}
	return u.n, d.n, reason
}

// finish ends one direction: half-close dst after a clean EOF, or close
// everything after an error.
func (t *tunnel) finish(dst net.Conn, err error) {
	if err != nil {
		t.closeBoth()
		return
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		if cw.CloseWrite() == nil {
			return
		}
	}
	t.closeBoth()
}

// event is one open, close or deny log line. Every field is always present.
type event struct {
	Time       string `json:"time"`
	ID         uint64 `json:"id"`
	Event      string `json:"event"`
	Client     string `json:"client"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	BytesUp    int64  `json:"bytes_up"`
	BytesDown  int64  `json:"bytes_down"`
	DurationMS int64  `json:"duration_ms"`
}

type startLine struct {
	Time   string   `json:"time"`
	Event  string   `json:"event"`
	Listen string   `json:"listen"`
	Allow  []string `json:"allow"`
	Ports  []int    `json:"ports"`
}

func (p *Proxy) emit(ev *event, start time.Time) error {
	now := p.now()
	ev.Time = now.UTC().Format(time.RFC3339Nano)
	ev.DurationMS = now.Sub(start).Milliseconds()
	return p.log.write(ev)
}

// cut limits a client-supplied string in a log line.
func cut(s string) string {
	if len(s) > 255 {
		return s[:255]
	}
	return s
}

type logger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *logger) write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.w.Write(b)
	return err
}
