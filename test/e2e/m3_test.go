//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Milestone 3 live tests: the real warden proxy on the host, listening on
// 127.0.0.1. They make outbound connections and change nothing.

type logLine struct {
	Event     string `json:"event"`
	ID        uint64 `json:"id"`
	Listen    string `json:"listen"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
}

type liveProxy struct {
	cmd  *exec.Cmd
	addr string
	mu   sync.Mutex
	raw  []string
	done chan struct{} // stdout closed
}

// startLiveProxy runs warden proxy with WARDEN_ROLE=proxy and waits for its
// start line.
func startLiveProxy(t *testing.T, allow ...string) *liveProxy {
	t.Helper()
	args := []string{"proxy", "--listen", "127.0.0.1:0", "--ports", "443"}
	for _, a := range allow {
		args = append(args, "--allow", a)
	}
	cmd := exec.Command(mustEnv(t, "WARDEN_E2E_BIN"), args...)
	cmd.Env = []string{"WARDEN_ROLE=proxy", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + os.Getenv("HOME")}
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &liveProxy{cmd: cmd, done: make(chan struct{})}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	started := make(chan string, 1)
	go func() {
		defer close(p.done)
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			p.mu.Lock()
			p.raw = append(p.raw, sc.Text())
			p.mu.Unlock()
			var l logLine
			if json.Unmarshal(sc.Bytes(), &l) == nil && l.Event == "start" {
				started <- l.Listen
			}
		}
	}()
	select {
	case p.addr = <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("warden proxy wrote no start line")
	}
	return p
}

// connect sends CONNECT target and returns the response and the connection.
func (p *liveProxy) connect(t *testing.T, target string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(30 * time.Second))
	io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	return resp, c, br
}

// stop sends SIGTERM, requires exit 0 and returns the log lines.
func (p *liveProxy) stop(t *testing.T) []logLine {
	t.Helper()
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("warden proxy did not exit after SIGTERM")
	}
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("warden proxy after SIGTERM: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var lines []logLine
	for _, r := range p.raw {
		t.Logf("proxy log: %s", r)
		var l logLine
		if err := json.Unmarshal([]byte(r), &l); err != nil {
			t.Fatalf("log line is not JSON: %q", r)
		}
		lines = append(lines, l)
	}
	return lines
}

func TestProxyTunnelLive(t *testing.T) {
	const host = "api.anthropic.com"
	tlsConfig := &tls.Config{ServerName: host}

	// No network on this host is a SKIP; a failure through the proxy when
	// the direct connection works is a FAIL.
	direct, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host+":443", tlsConfig)
	if err != nil {
		t.Skipf("SKIP: no network: direct TLS to %s:443 failed: %v", host, err)
	}
	direct.Close()

	p := startLiveProxy(t, host)

	resp, conn, br := p.connect(t, host+":443")
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT %s: status %d", host, resp.StatusCode)
	}
	if br.Buffered() != 0 {
		t.Fatalf("bytes after the 200 before the TLS handshake")
	}
	tc := tls.Client(conn, tlsConfig)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS through the proxy: %v", err)
	}
	t.Logf("TLS through the proxy: %s, %s", tls.VersionName(tc.ConnectionState().Version), tc.ConnectionState().PeerCertificates[0].Subject)
	tc.Close()

	// A host that isn't listed.
	resp2, _, _ := p.connect(t, "example.com:443")
	if resp2.StatusCode != 403 {
		t.Fatalf("CONNECT example.com: status %d, want 403", resp2.StatusCode)
	}

	time.Sleep(200 * time.Millisecond) // let the close line be written before SIGTERM
	lines := p.stop(t)
	var open, closed, deny *logLine
	for i := range lines {
		l := &lines[i]
		switch {
		case l.Event == "open" && l.Host == host:
			open = l
		case l.Event == "close" && l.Host == host:
			closed = l
		case l.Event == "deny" && l.Host == "example.com":
			deny = l
		}
	}
	if open == nil || open.Decision != "allow" || open.Port != 443 {
		t.Fatalf("no open line for %s", host)
	}
	if closed == nil || closed.ID != open.ID || closed.BytesUp == 0 || closed.BytesDown == 0 {
		t.Fatalf("close line %+v for open %+v", closed, open)
	}
	if deny == nil || deny.Decision != "deny" || deny.Reason != "host not allowed" {
		t.Fatalf("deny line %+v", deny)
	}
}

func TestProxyRefusesPrivateAddressLive(t *testing.T) {
	// localtest.me is a public name that resolves to 127.0.0.1. If it
	// doesn't, right now, on this host, the test can't prove anything.
	const host = "localtest.me"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		t.Skipf("SKIP: %s doesn't resolve here: %v", host, err)
	}
	for _, a := range addrs {
		if !a.Unmap().IsLoopback() {
			t.Skipf("SKIP: %s resolves to %v, not only loopback addresses", host, addrs)
		}
	}
	t.Logf("%s resolves to %v", host, addrs)

	p := startLiveProxy(t, host)
	resp, _, _ := p.connect(t, host+":443")
	if resp.StatusCode != 403 {
		t.Fatalf("CONNECT %s: status %d, want 403", host, resp.StatusCode)
	}
	lines := p.stop(t)
	var deny *logLine
	for i := range lines {
		if lines[i].Event == "deny" && lines[i].Host == host {
			deny = &lines[i]
		}
	}
	if deny == nil || deny.Decision != "deny" || !strings.HasPrefix(deny.Reason, "non-public address: ") || !strings.Contains(deny.Reason, "loopback") {
		t.Fatalf("deny line %+v, want a non-public-address refusal naming loopback", deny)
	}
	for _, l := range lines {
		if l.Event == "open" {
			t.Fatalf("a tunnel was opened to %s", host)
		}
	}
}
