// Package canary proves the sandbox holds by observing it from inside a
// container. The probe (warden probe, running in the canary container)
// only reports what it observes, as key=value lines; Evaluate decides on
// the host. Project builds the canary's compose project. See
// docs/phase-1.md, "Canary".
package canary

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Timeouts (docs/phase-1.md).
const (
	ControlWait = 10 * time.Second // for the control file Warden writes
	ProxyWait   = 10 * time.Second // for the proxy to accept connections
	StepTimeout = 3 * time.Second  // each probe connection or lookup
)

// Keys are the probe's output keys, in output order. Parse requires
// exactly these.
var Keys = []string{
	"caps_eff", "caps_bnd", "nnp", "seccomp", "uid", "gid", "groups",
	"memory_max", "memory_swap_max", "pids_max", "cpu_max", "apparmor",
	"rootfs", "tmp_write", "tmp_mount", "mptcp", "mptcp_socket",
	"no_route", "no_dns", "no_host", "proxy_allow", "proxy_deny", "owner",
}

// ProbeOptions are warden probe's flags.
type ProbeOptions struct {
	Proxy     string // host:port of the proxy
	AllowHost string // CONNECT here must get 200
	DenyHost  string // CONNECT here must get 403
	DNSHost   string // must not resolve
	Route     string // IP:port that must not be reachable
	Dir       string // the bind-mounted directory: control file in, owner file out
}

// ProbeEnv is what the probe touches. Tests replace it.
type ProbeEnv struct {
	Root      string // filesystem root: "/" in a container
	WriteFile func(name string, data []byte) error
	Resolver  interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
	Dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	// MPTCPSocket opens and closes an MPTCP socket, returning the error.
	MPTCPSocket                         func() error
	ControlWait, ProxyWait, StepTimeout time.Duration
}

// DefaultProbeEnv is the probe's environment inside the canary container.
func DefaultProbeEnv() ProbeEnv {
	return ProbeEnv{
		Root:        "/",
		WriteFile:   func(name string, data []byte) error { return os.WriteFile(name, data, 0o600) },
		Resolver:    net.DefaultResolver,
		Dialer:      &net.Dialer{},
		MPTCPSocket: mptcpSocket,
		ControlWait: ControlWait, ProxyWait: ProxyWait, StepTimeout: StepTimeout,
	}
}

// Validate requires every option.
func (o ProbeOptions) Validate() error {
	for name, v := range map[string]string{
		"--proxy": o.Proxy, "--allow-host": o.AllowHost, "--deny-host": o.DenyHost,
		"--dns-host": o.DNSHost, "--route": o.Route, "--dir": o.Dir,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}

// Probe observes the container it runs in and writes one key=value line
// per key in Keys to w.
func Probe(ctx context.Context, o ProbeOptions, env ProbeEnv, w io.Writer) error {
	obs := map[string]string{}
	p := func(k string) string { return filepath.Join(env.Root, k) }

	status := readStatus(p("proc/self/status"))
	for _, k := range []struct{ key, field string }{
		{"caps_eff", "CapEff"}, {"caps_bnd", "CapBnd"}, {"nnp", "NoNewPrivs"}, {"seccomp", "Seccomp"},
		{"uid", "Uid"}, {"gid", "Gid"}, {"groups", "Groups"},
	} {
		v, ok := status[k.field]
		if !ok {
			v = "missing"
		}
		obs[k.key] = v
	}
	for key, file := range map[string]string{
		"memory_max": "sys/fs/cgroup/memory.max", "memory_swap_max": "sys/fs/cgroup/memory.swap.max",
		"pids_max": "sys/fs/cgroup/pids.max", "cpu_max": "sys/fs/cgroup/cpu.max",
		"apparmor": "proc/self/attr/current",
		"mptcp":    "proc/sys/net/mptcp/enabled",
	} {
		obs[key] = readValue(p(file))
	}

	obs["mptcp_socket"] = "error: no socket function"
	if env.MPTCPSocket != nil {
		obs["mptcp_socket"] = socketResult(env.MPTCPSocket())
	}
	obs["rootfs"] = writeResult(env, p("warden-canary-rootfs"))
	switch err := env.WriteFile(p("tmp/warden-canary-tmp"), []byte("canary")); {
	case err == nil:
		os.Remove(p("tmp/warden-canary-tmp"))
		obs["tmp_write"] = "ok"
	default:
		obs["tmp_write"] = "error: " + err.Error()
	}
	obs["tmp_mount"] = tmpMount(p("proc/self/mountinfo"))

	control, cerr := waitControl(ctx, filepath.Join(o.Dir, "control"), env.ControlWait)

	if c, err := dial(ctx, env, o.Route); err == nil {
		c.Close()
		obs["no_route"] = "connected"
	} else {
		obs["no_route"] = "failed: " + err.Error()
	}

	lctx, cancel := context.WithTimeout(ctx, env.StepTimeout)
	addrs, err := env.Resolver.LookupNetIP(lctx, "ip", o.DNSHost)
	cancel()
	if err == nil && len(addrs) > 0 {
		obs["no_dns"] = fmt.Sprintf("resolved: %v", addrs)
	} else if err == nil {
		obs["no_dns"] = "failed: no addresses"
	} else {
		obs["no_dns"] = "failed: " + err.Error()
	}

	switch {
	case cerr != nil:
		obs["no_host"] = "error: " + cerr.Error()
	case control["no_host"] == "skip":
		obs["no_host"] = "skipped"
	default:
		addr := net.JoinHostPort(control["gateway"], control["port"])
		if c, err := dial(ctx, env, addr); err == nil {
			c.Close()
			obs["no_host"] = "connected to " + addr
		} else {
			obs["no_host"] = "failed: " + err.Error()
		}
	}

	if err := waitProxy(ctx, env, o.Proxy); err != nil {
		obs["proxy_allow"] = "error: " + err.Error()
		obs["proxy_deny"] = "error: " + err.Error()
	} else {
		obs["proxy_allow"] = connect(ctx, env, o.Proxy, o.AllowHost+":443")
		obs["proxy_deny"] = connect(ctx, env, o.Proxy, o.DenyHost+":443")
	}

	if err := env.WriteFile(filepath.Join(o.Dir, "owner"), []byte("canary")); err != nil {
		obs["owner"] = "error: " + err.Error()
	} else {
		obs["owner"] = "written"
	}

	var b strings.Builder
	for _, k := range Keys {
		fmt.Fprintf(&b, "%s=%s\n", k, clean(obs[k]))
	}
	_, err = io.WriteString(w, b.String())
	return err
}

// readStatus parses /proc/<pid>/status. Multi-value fields (Uid, Gid,
// Groups) are joined with single spaces.
func readStatus(path string) map[string]string {
	m := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			m[k] = strings.Join(strings.Fields(v), " ")
		}
	}
	return m
}

// readValue reads a one-line file: "absent" if it doesn't exist (the kernel
// doesn't provide it), "error: ..." for any other failure.
func readValue(path string) string {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "absent"
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return strings.TrimSpace(string(data))
}

func writeResult(env ProbeEnv, path string) string {
	err := env.WriteFile(path, []byte("canary"))
	switch {
	case err == nil:
		os.Remove(path)
		return "writable"
	case errors.Is(err, syscall.EROFS):
		return "erofs"
	}
	return "error: " + err.Error()
}

// tmpMount reports the last /tmp mount in mountinfo (the visible one):
// "fstype=<t> mount=<per-mount options> super=<superblock options>".
func tmpMount(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "error: " + err.Error()
	}
	found := "missing"
	for _, line := range strings.Split(string(data), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 6 || len(g) < 3 || f[4] != "/tmp" {
			continue
		}
		found = fmt.Sprintf("fstype=%s mount=%s super=%s", g[0], f[5], g[2])
	}
	return found
}

// waitControl waits for the control file Warden writes into the mounted
// directory once its no-host listener is ready.
func waitControl(ctx context.Context, path string, wait time.Duration) (map[string]string, error) {
	deadline := time.Now().Add(wait)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			m := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				k, v, _ := strings.Cut(line, "=")
				m[k] = v
			}
			if m["no_host"] == "skip" || (m["gateway"] != "" && m["port"] != "") {
				return m, nil
			}
			return nil, fmt.Errorf("bad control file: %q", data)
		}
		if time.Now().After(deadline) {
			return nil, errors.New("no control file from Warden")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func dial(ctx context.Context, env ProbeEnv, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, env.StepTimeout)
	defer cancel()
	return env.Dialer.DialContext(ctx, "tcp", addr)
}

func waitProxy(ctx context.Context, env ProbeEnv, addr string) error {
	deadline := time.Now().Add(env.ProxyWait)
	for {
		c, err := dial(ctx, env, addr)
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("proxy not reachable: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// connect sends one CONNECT through the proxy: "status=<code>" or "error: …".
func connect(ctx context.Context, env ProbeEnv, proxy, target string) string {
	c, err := dial(ctx, env, proxy)
	if err != nil {
		return "error: " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(env.StepTimeout + DialSlack))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return "error: " + err.Error()
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return "error: " + err.Error()
	}
	resp.Body.Close()
	return fmt.Sprintf("status=%d", resp.StatusCode)
}

// DialSlack: the proxy resolves and dials before it answers a CONNECT.
const DialSlack = 15 * time.Second

func clean(s string) string {
	s = strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// ipprotoMPTCP is Linux's protocol number for MPTCP (IPPROTO_MPTCP in
// include/uapi/linux/in.h).
const ipprotoMPTCP = 262

// mptcpSocket tries to open an MPTCP socket: what MPTCP being off means in
// practice, whatever any setting says.
func mptcpSocket() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, ipprotoMPTCP)
	if err == nil {
		syscall.Close(fd)
	}
	return err
}

// socketResult names the outcome: ENOPROTOOPT is MPTCP turned off
// (net.mptcp.enabled=0), EPROTONOSUPPORT a kernel without MPTCP.
func socketResult(err error) string {
	switch {
	case err == nil:
		return "opened"
	case errors.Is(err, syscall.ENOPROTOOPT):
		return "enoprotoopt"
	case errors.Is(err, syscall.EPROTONOSUPPORT):
		return "eprotonosupport"
	}
	return "error: " + err.Error()
}
