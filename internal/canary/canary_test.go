package canary

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/compose"
	"github.com/rviscuso/warden/internal/hardening"
)

var res = hardening.Resources{MemoryMB: 1536, CPUs: 1.5, Pids: 512}

// hardenedRoot is a fixture filesystem root as a hardened container sees it.
func hardenedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"proc/self/status": "Name:\twarden\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\n" +
			"CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
		"sys/fs/cgroup/memory.max":      "1610612736\n",
		"sys/fs/cgroup/memory.swap.max": "0\n",
		"sys/fs/cgroup/pids.max":        "512\n",
		"sys/fs/cgroup/cpu.max":         "150000 100000\n",
		"proc/self/attr/current":        "docker-default (enforce)\n",
		"proc/sys/net/mptcp/enabled":    "0\n",
		"proc/self/mountinfo": "600 500 0:60 / / ro,relatime - overlay overlay rw,lowerdir=x\n" +
			"601 600 0:61 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=524288k,mode=1777,uid=0,gid=0\n",
	}
	for name, content := range files {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.Mkdir(filepath.Join(root, "tmp"), 0o755)
	return root
}

type fakeNet struct {
	addrs map[string]string // address -> local listener to connect to; absent: refused
	dns   map[string][]netip.Addr
}

func (f *fakeNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if to, ok := f.addrs[address]; ok {
		var d net.Dialer
		return d.DialContext(ctx, network, to)
	}
	return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("network is unreachable")}
}

func (f *fakeNet) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f.dns[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "server misbehaving", Name: host}
}

// fakeProxy answers CONNECT with 200 for allow and 403 for anything else.
func fakeProxy(t *testing.T, allow string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if r.Method == "CONNECT" && r.RequestURI == allow+":443" {
					fmt.Fprint(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				} else {
					fmt.Fprint(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
				}
			}()
		}
	}()
	return ln.Addr().String()
}

type probeRun struct {
	root, dir string
	env       ProbeEnv
	opts      ProbeOptions
	net       *fakeNet
}

func newProbe(t *testing.T, root string) *probeRun {
	t.Helper()
	dir := t.TempDir()
	n := &fakeNet{addrs: map[string]string{}, dns: map[string][]netip.Addr{}}
	n.addrs["warden-canary-proxy:3128"] = fakeProxy(t, "api.anthropic.com")
	env := ProbeEnv{
		Root: root,
		WriteFile: func(name string, data []byte) error {
			if name == filepath.Join(root, "warden-canary-rootfs") {
				return &os.PathError{Op: "open", Path: "/warden-canary-rootfs", Err: syscall.EROFS}
			}
			return os.WriteFile(name, data, 0o600)
		},
		Resolver: n, Dialer: n,
		ControlWait: 2 * time.Second, ProxyWait: 2 * time.Second, StepTimeout: time.Second,
	}
	return &probeRun{root: root, dir: dir, env: env, net: n, opts: ProbeOptions{
		Proxy: "warden-canary-proxy:3128", AllowHost: "api.anthropic.com", DenyHost: DenyHost,
		DNSHost: "api.anthropic.com", Route: RouteControl, Dir: dir,
	}}
}

func (p *probeRun) control(t *testing.T, s string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.dir, "control"), []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (p *probeRun) run(t *testing.T) map[string]string {
	t.Helper()
	var out bytes.Buffer
	if err := Probe(context.Background(), p.opts, p.env, &out); err != nil {
		t.Fatal(err)
	}
	obs, err := Parse(out.Bytes())
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	return obs
}

const proxyLog = `{"event":"start"}
{"id":1,"event":"open","host":"api.anthropic.com","decision":"allow","reason":"allowlist: api.anthropic.com"}
{"id":2,"event":"deny","host":"warden-canary.invalid","decision":"deny","reason":"host not allowed"}
`

func goodHost(dir string) Host {
	return Host{DNSHost: "api.anthropic.com", NoHostAddr: "172.30.0.1:40000", OwnerUID: 1000, OwnerGID: 1000, ProxyLog: []byte(proxyLog)}
}

var expect = Expect{UID: 1000, GID: 1000, Resources: res, DaemonAppArmor: true}

func verdicts(vs []Verdict) map[string]Verdict {
	m := map[string]Verdict{}
	for _, v := range vs {
		m[v.ID] = v
	}
	return m
}

func TestProbeHardened(t *testing.T) {
	p := newProbe(t, hardenedRoot(t))
	p.control(t, "gateway=192.0.2.1\nport=40000\n") // nothing answers there
	obs := p.run(t)
	if _, err := os.Stat(filepath.Join(p.dir, "owner")); err != nil {
		t.Errorf("owner file: %v", err)
	}
	for _, v := range Evaluate(obs, expect, goodHost(p.dir)) {
		if v.Status != Pass {
			t.Errorf("%s: %s %s", v.ID, v.Status, v.Detail)
		}
	}
	if len(ProbeChecks) != 17 {
		t.Errorf("%d probe checks", len(ProbeChecks))
	}
}

// TestProbeUnhardened: the probe in a container with none of the
// hardening must fail the checks; it can't pass vacuously.
func TestProbeUnhardened(t *testing.T) {
	root := hardenedRoot(t)
	os.WriteFile(filepath.Join(root, "proc/self/status"), []byte("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0 1 2\n"+
		"CapEff:\t00000000a80425fb\nCapBnd:\t00000000a80425fb\nNoNewPrivs:\t0\nSeccomp:\t0\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sys/fs/cgroup/memory.max"), []byte("max\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sys/fs/cgroup/memory.swap.max"), []byte("max\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sys/fs/cgroup/pids.max"), []byte("max\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sys/fs/cgroup/cpu.max"), []byte("max 100000\n"), 0o644)
	os.WriteFile(filepath.Join(root, "proc/self/attr/current"), []byte("unconfined\n"), 0o644)
	os.WriteFile(filepath.Join(root, "proc/sys/net/mptcp/enabled"), []byte("1\n"), 0o644)
	os.WriteFile(filepath.Join(root, "proc/self/mountinfo"), []byte("600 500 0:60 / / rw,relatime - overlay overlay rw\n"), 0o644)
	p := newProbe(t, root)
	p.env.WriteFile = func(name string, data []byte) error { return os.WriteFile(name, data, 0o600) } // a writable root
	p.net.addrs[RouteControl] = fakeProxy(t, "x")                                                     // a route out
	p.net.dns["api.anthropic.com"] = []netip.Addr{netip.MustParseAddr("1.1.1.1")}                     // outside DNS
	p.control(t, "no_host=skip\n")
	vs := verdicts(Evaluate(p.run(t), expect, goodHost(p.dir)))
	for _, id := range []string{"canary.caps", "canary.nnp", "canary.seccomp", "canary.uid", "canary.memory", "canary.pids",
		"canary.cpu", "canary.apparmor", "canary.rootfs", "canary.tmp", "canary.mptcp", "canary.no-route", "canary.no-dns"} {
		if vs[id].Status != Fail {
			t.Errorf("%s: %s %s, want fail", id, vs[id].Status, vs[id].Detail)
		}
	}
}

func TestProbeNoControlFile(t *testing.T) {
	p := newProbe(t, hardenedRoot(t))
	p.env.ControlWait = 50 * time.Millisecond
	obs := p.run(t)
	if obs["no_host"] != "error: no control file from Warden" {
		t.Fatalf("no_host = %q", obs["no_host"])
	}
	if v := verdicts(Evaluate(obs, expect, goodHost(p.dir)))["canary.no-host"]; v.Status != Fail {
		t.Fatalf("no-host without a control file: %+v", v)
	}
}

func TestProbeProxyUnreachable(t *testing.T) {
	p := newProbe(t, hardenedRoot(t))
	delete(p.net.addrs, "warden-canary-proxy:3128")
	p.env.ProxyWait = 100 * time.Millisecond
	p.control(t, "no_host=skip\n")
	vs := verdicts(Evaluate(p.run(t), expect, goodHost(p.dir)))
	if vs["canary.proxy-allow"].Status != Fail || vs["canary.proxy-deny"].Status != Fail {
		t.Fatalf("%+v %+v", vs["canary.proxy-allow"], vs["canary.proxy-deny"])
	}
}

func TestParseStrict(t *testing.T) {
	var good strings.Builder
	for _, k := range Keys {
		good.WriteString(k + "=v\n")
	}
	if _, err := Parse([]byte(good.String())); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"missing":   strings.Replace(good.String(), "owner=v\n", "", 1),
		"duplicate": good.String() + "owner=v\n",
		"dup empty": strings.Replace(good.String(), "owner=v\n", "owner=\nowner=\n", 1),
		"unknown":   good.String() + "extra=v\n",
		"no equals": good.String() + "garbage\n",
		"empty":     "",
	}
	for name, s := range bad {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEvaluateEachCheck(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			"caps_eff": zeroCaps, "caps_bnd": zeroCaps, "nnp": "1", "seccomp": "2",
			"uid": "1000 1000 1000 1000", "gid": "1000 1000 1000 1000", "groups": "",
			"memory_max": "1610612736", "memory_swap_max": "0", "pids_max": "512", "cpu_max": "150000 100000",
			"apparmor": "docker-default (enforce)", "rootfs": "erofs", "tmp_write": "ok", "mptcp": "0",
			"tmp_mount": "fstype=tmpfs mount=rw,nosuid,nodev,relatime super=rw,size=524288k,mode=1777",
			"no_route":  "failed: unreachable", "no_dns": "failed: no such host", "no_host": "failed: refused",
			"proxy_allow": "status=200", "proxy_deny": "status=403", "owner": "written",
		}
	}
	for _, v := range Evaluate(base(), expect, goodHost("")) {
		if v.Status != Pass {
			t.Fatalf("baseline %s: %s %s", v.ID, v.Status, v.Detail)
		}
	}
	type tc struct {
		id   string
		obs  map[string]string
		host func(*Host)
		exp  func(*Expect)
		want Status
	}
	cases := []tc{
		{id: "canary.caps", obs: map[string]string{"caps_bnd": "00000000a80425fb"}, want: Fail},
		{id: "canary.caps", obs: map[string]string{"caps_eff": "0000000000000400"}, want: Fail},
		{id: "canary.nnp", obs: map[string]string{"nnp": "0"}, want: Fail},
		{id: "canary.nnp", obs: map[string]string{"nnp": "missing"}, want: Fail},
		{id: "canary.seccomp", obs: map[string]string{"seccomp": "0"}, want: Fail},
		{id: "canary.uid", obs: map[string]string{"uid": "1000 0 1000 1000"}, want: Fail},
		{id: "canary.uid", obs: map[string]string{"gid": "1001 1001 1001 1001"}, want: Fail},
		{id: "canary.uid", obs: map[string]string{"groups": "1000 999"}, want: Fail},
		{id: "canary.uid", obs: map[string]string{"groups": "1000"}, want: Pass},
		{id: "canary.memory", obs: map[string]string{"memory_max": "max"}, want: Fail},
		{id: "canary.memory", obs: map[string]string{"memory_swap_max": "max"}, want: Fail},
		{id: "canary.pids", obs: map[string]string{"pids_max": "max"}, want: Fail},
		{id: "canary.cpu", obs: map[string]string{"cpu_max": "max 100000"}, want: Fail},
		{id: "canary.cpu", obs: map[string]string{"cpu_max": "150000 50000"}, want: Fail},
		{id: "canary.cpu", obs: map[string]string{"cpu_max": "149999 100000"}, want: Pass},
		{id: "canary.cpu", obs: map[string]string{"cpu_max": "100000 100000"}, want: Fail},
		{id: "canary.apparmor", obs: map[string]string{"apparmor": "unconfined"}, want: Fail},
		{id: "canary.apparmor", obs: map[string]string{"apparmor": "docker-default (complain)"}, want: Fail},
		{id: "canary.apparmor", obs: map[string]string{"apparmor": "error: no such file"}, exp: func(e *Expect) { e.DaemonAppArmor = false }, want: Warn},
		{id: "canary.rootfs", obs: map[string]string{"rootfs": "writable"}, want: Fail},
		{id: "canary.rootfs", obs: map[string]string{"rootfs": "error: permission denied"}, want: Fail},
		{id: "canary.tmp", obs: map[string]string{"tmp_write": "error: read-only file system"}, want: Fail},
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "fstype=tmpfs mount=rw,nosuid,nodev,noexec super=rw,size=524288k,mode=1777"}, want: Fail},
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "fstype=tmpfs mount=rw,nodev super=rw,size=524288k,mode=1777"}, want: Fail},
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "fstype=tmpfs mount=rw,nosuid,nodev super=rw,size=65536k,mode=1777"}, want: Fail},
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "fstype=tmpfs mount=rw,nosuid,nodev,relatime super=rw,size=524288k,inode64"}, want: Pass}, // mode 1777 is not shown
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "fstype=tmpfs mount=rw,nosuid,nodev super=rw,size=524288k,mode=777"}, want: Fail},
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "fstype=tmpfs mount=rw,nosuid,nodev,noexec,relatime super=rw,size=524288k,inode64"}, want: Fail}, // this dev container's /tmp
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "fstype=overlay mount=rw,nosuid,nodev super=rw"}, want: Fail},
		{id: "canary.tmp", obs: map[string]string{"tmp_mount": "missing"}, want: Fail},
		{id: "canary.mptcp", obs: map[string]string{"mptcp": "1"}, want: Fail},
		{id: "canary.mptcp", obs: map[string]string{"mptcp": "error: open /proc/sys/net/mptcp/enabled: no such file or directory"}, want: Fail},
		{id: "canary.mptcp", obs: map[string]string{"mptcp": ""}, want: Fail},
		{id: "canary.no-route", obs: map[string]string{"no_route": "connected"}, want: Fail},
		{id: "canary.no-route", host: func(h *Host) { h.RouteControl = errors.New("unreachable") }, want: Fail},
		{id: "canary.no-dns", obs: map[string]string{"no_dns": "resolved: [1.1.1.1]"}, want: Fail},
		{id: "canary.no-dns", host: func(h *Host) { h.DNSControl = errors.New("no such host") }, want: Fail},
		{id: "canary.no-host", obs: map[string]string{"no_host": "connected to 172.30.0.1:40000"}, want: Fail},
		{id: "canary.no-host", host: func(h *Host) { h.NoHostAccepts = 1 }, want: Fail},
		{id: "canary.no-host", host: func(h *Host) { h.NoHostErr = errors.New("no gateway in docker network inspect") }, want: Fail},
		{id: "canary.no-host", obs: map[string]string{"no_host": "error: no control file from Warden"}, want: Fail},
		{id: "canary.no-host", obs: map[string]string{"no_host": "skipped"}, host: func(h *Host) { h.NoHostSkipped = true }, want: Pass},
		{id: "canary.no-host", obs: map[string]string{"no_host": "skipped"}, want: Fail}, // the probe skipped but Warden didn't
		{id: "canary.proxy-allow", obs: map[string]string{"proxy_allow": "status=403"}, want: Fail},
		{id: "canary.proxy-allow", obs: map[string]string{"proxy_allow": "error: timeout"}, want: Fail},
		{id: "canary.proxy-deny", obs: map[string]string{"proxy_deny": "status=200"}, want: Fail},
		{id: "canary.proxy-deny", host: func(h *Host) { h.ProxyLog = []byte(`{"event":"start"}`) }, want: Fail},
		{id: "canary.owner", obs: map[string]string{"owner": "error: permission denied"}, want: Fail},
		{id: "canary.owner", host: func(h *Host) { h.OwnerUID = 0 }, want: Fail},
		{id: "canary.owner", host: func(h *Host) { h.OwnerGID = 0 }, want: Fail},
		{id: "canary.owner", host: func(h *Host) { h.OwnerErr = errors.New("no such file") }, want: Fail},
	}
	for _, c := range cases {
		o := base()
		for k, v := range c.obs {
			o[k] = v
		}
		h := goodHost("")
		if c.host != nil {
			c.host(&h)
		}
		e := expect
		if c.exp != nil {
			c.exp(&e)
		}
		v := verdicts(Evaluate(o, e, h))[c.id]
		if v.Status != c.want {
			t.Errorf("%s with %v: %s (%s), want %s", c.id, c.obs, v.Status, v.Detail, c.want)
		}
	}
}

func TestEvaluateCannotProveDetails(t *testing.T) {
	h := goodHost("")
	h.RouteControl = errors.New("unreachable")
	h.DNSControl = errors.New("no such host")
	vs := verdicts(Evaluate(map[string]string{"no_route": "failed: x", "no_dns": "failed: x"}, expect, h))
	if !strings.HasPrefix(vs["canary.no-route"].Detail, "cannot prove: host has no route to the control address") {
		t.Errorf("no-route detail %q", vs["canary.no-route"].Detail)
	}
	if !strings.HasPrefix(vs["canary.no-dns"].Detail, "cannot prove") {
		t.Errorf("no-dns detail %q", vs["canary.no-dns"].Detail)
	}
}

func TestProbeHost(t *testing.T) {
	for _, c := range []struct {
		allow []string
		want  string
	}{
		{[]string{"api.anthropic.com", "platform.claude.com"}, "api.anthropic.com"},
		{[]string{".claude.com", "api.anthropic.com"}, "api.anthropic.com"},
		{[]string{".claude.com", ".anthropic.com"}, "claude.com"},
	} {
		if got, err := ProbeHost(c.allow); err != nil || got != c.want {
			t.Errorf("ProbeHost(%v) = %q, %v", c.allow, got, err)
		}
	}
	if _, err := ProbeHost(nil); err == nil {
		t.Error("empty allowlist accepted")
	}
}

func TestProjectRendersAndValidates(t *testing.T) {
	f, err := Project(ProjectParams{
		UID: 1000, GID: 1000,
		RuntimeImage: "busybox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Binary:       "/home/u/.local/state/warden/bin/warden-abc",
		MountDir:     "/home/u/.local/state/warden/canary/r1/mnt",
		Allow:        []string{".claude.com", "api.anthropic.com"},
		Resources:    res,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := compose.Render(f, compose.Policy{UID: 1000, GID: 1000, Socket: "/var/run/docker.sock"})
	if err != nil {
		t.Fatal(err)
	}
	px, cn := f.Services["proxy"], f.Services["canary"]
	if strings.Join(px.Networks, ",") != "sandbox,egress" || strings.Join(cn.Networks, ",") != "sandbox" {
		t.Errorf("networks: proxy %v canary %v", px.Networks, cn.Networks)
	}
	if !f.Networks["sandbox"].Internal || f.Networks["egress"].Internal {
		t.Errorf("networks %+v", f.Networks)
	}
	if px.MemLimit != 256<<20 || px.PidsLimit != 128 || px.CPUs != 0.5 {
		t.Errorf("proxy limits %+v", px.Fields)
	}
	if cn.MemLimit != 1536<<20 || cn.PidsLimit != 512 || cn.CPUs != 1.5 {
		t.Errorf("canary limits %+v", cn.Fields)
	}
	if got := strings.Join(px.Command, " "); got != "proxy --listen :3128 --allow .claude.com --allow api.anthropic.com --ports 443" {
		t.Errorf("proxy command %q", got)
	}
	if got := strings.Join(cn.Command, " "); !strings.Contains(got, "--allow-host api.anthropic.com") || !strings.Contains(got, "--route 1.1.1.1:443") {
		t.Errorf("canary command %q", got)
	}
	if !px.Volumes[0].ReadOnly || !cn.Volumes[0].ReadOnly || cn.Volumes[1].ReadOnly || len(px.Volumes) != 1 {
		t.Errorf("volumes: proxy %+v canary %+v", px.Volumes, cn.Volumes)
	}
	if px.Environment["WARDEN_ROLE"] != "proxy" || cn.Environment["WARDEN_ROLE"] != "canary" {
		t.Error("WARDEN_ROLE")
	}
	if !strings.Contains(string(b), `"container_name": "warden-canary-proxy"`) {
		t.Errorf("rendered:\n%s", b)
	}
}
