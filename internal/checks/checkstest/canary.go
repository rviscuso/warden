// Package checkstest scripts a canary run on a dockertest.Fake, for the
// checks and cli tests. It doesn't import checks, so both can use it.
package checkstest

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rviscuso/warden/internal/canary"
	"github.com/rviscuso/warden/internal/docker/dockertest"
	"github.com/rviscuso/warden/internal/wardenbin/wardenbintest"
)

const (
	RunDirName = "0000000000000000" // hex of ZeroReader's 8 bytes
	Gateway    = "192.0.2.1"        // documentation address: the fake sandbox gateway
)

// Docker calls the canary makes.
var (
	ArgsLeftC  = []string{"inspect", "--type", "container", "--format", "{{.Name}}", canary.ProxyName, canary.CanaryName}
	ArgsLeftN  = []string{"network", "inspect", "--format", "{{.Name}}", canary.SandboxNet, canary.EgressNet}
	ArgsIDsC   = []string{"inspect", "--type", "container", "--format", "{{.Id}}", canary.ProxyName, canary.CanaryName}
	ArgsIDsN   = []string{"network", "inspect", "--format", "{{.Id}}", canary.SandboxNet, canary.EgressNet}
	ArgsIPAM   = []string{"network", "inspect", "--format", "{{json .IPAM.Config}}", canary.SandboxNet}
	ArgsCreate = ComposeArgs("create")
	ArgsStart  = ComposeArgs("start")
	ArgsDown   = ComposeArgs("down", "--timeout", "5")
	ArgsWait   = []string{"wait", canary.CanaryName}
	ArgsLogsC  = []string{"logs", canary.CanaryName}
	ArgsLogsP  = []string{"logs", canary.ProxyName}

	ContainerIDs = []string{strings.Repeat("c", 64), strings.Repeat("d", 64)}
	NetworkIDs   = []string{strings.Repeat("e", 64), strings.Repeat("f", 64)}
)

// ArgsImage is the canary.image call for image.
func ArgsImage(image string) []string {
	return []string{"image", "inspect", "--format", "{{.Id}}", image}
}

// ComposeArgs is a compose call on the canary project, file on stdin.
func ComposeArgs(cmd ...string) []string {
	return append([]string{"compose", "-p", canary.ProjectName, "-f", "-"}, cmd...)
}

// ZeroReader is a deterministic random source: the run directory is
// always RunDirName.
type ZeroReader struct{}

func (ZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// HostNet fakes the host's own network: the canary's controls and the
// no-host listener.
type HostNet struct {
	DialErr, DNSErr, ListenErr error
	mu                         sync.Mutex
	listened                   []string
}

func (n *HostNet) DialContext(context.Context, string, string) (net.Conn, error) {
	if n.DialErr != nil {
		return nil, n.DialErr
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func (n *HostNet) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if n.DNSErr != nil {
		return nil, n.DNSErr
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil // documentation address
}

// Listen records the address and listens on loopback instead.
func (n *HostNet) Listen(network, address string) (net.Listener, error) {
	n.mu.Lock()
	n.listened = append(n.listened, address)
	n.mu.Unlock()
	if n.ListenErr != nil {
		return nil, n.ListenErr
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

// Listened returns the addresses Listen was asked for.
func (n *HostNet) Listened() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.listened...)
}

// Canary is one scripted canary.
type Canary struct {
	UID, GID     int
	CanaryDir    string // <state>/canary
	Executable   string // a fake static warden binary
	Net          *HostNet
	RuntimeImage string

	mu      sync.Mutex
	control []byte
}

// RunDir is the run directory the canary uses with ZeroReader.
func (c *Canary) RunDir() string { return filepath.Join(c.CanaryDir, RunDirName) }

// Control is the control file as the probe saw it when the canary started.
func (c *Canary) Control() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.control
}

// ProbeOutput is what a hardened canary prints (memory 1536 MB, 1.5 CPUs,
// 512 PIDs), with overrides.
func (c *Canary) ProbeOutput(over map[string]string) string {
	u, g := strconv.Itoa(c.UID), strconv.Itoa(c.GID)
	obs := map[string]string{
		"caps_eff": "0000000000000000", "caps_bnd": "0000000000000000", "nnp": "1", "seccomp": "2",
		"uid": u + " " + u + " " + u + " " + u, "gid": g + " " + g + " " + g + " " + g, "groups": "",
		"memory_max": "1610612736", "memory_swap_max": "0", "pids_max": "512", "cpu_max": "150000 100000",
		"apparmor": "docker-default (enforce)", "rootfs": "erofs", "tmp_write": "ok", "mptcp": "0", "mptcp_socket": "enoprotoopt",
		"tmp_mount": "fstype=tmpfs mount=rw,nosuid,nodev,relatime super=rw,size=524288k,mode=1777",
		"no_route":  "failed: network is unreachable", "no_dns": "failed: no such host",
		"no_host": "failed: connection refused", "proxy_allow": "status=200", "proxy_deny": "status=403", "owner": "written",
	}
	for k, v := range over {
		obs[k] = v
	}
	var b strings.Builder
	for _, k := range canary.Keys {
		b.WriteString(k + "=" + obs[k] + "\n")
	}
	return b.String()
}

// ProxyLog is the canary proxy's log for a passing run.
const ProxyLog = `{"event":"start","listen":"[::]:3128"}
{"id":1,"event":"open","host":"api.anthropic.com","port":443,"decision":"allow","reason":"allowlist: api.anthropic.com"}
{"id":2,"event":"deny","host":"warden-canary.invalid","port":443,"decision":"deny","reason":"host not allowed"}
{"id":1,"event":"close","host":"api.anthropic.com","port":443,"decision":"allow","reason":"closed"}
`

// Script writes a fake static binary under dir and scripts a successful
// canary run on fake.
func Script(t testing.TB, fake *dockertest.Fake, dir, canaryDir, runtimeImage string) *Canary {
	t.Helper()
	c := &Canary{
		UID: os.Getuid(), GID: os.Getgid(), CanaryDir: canaryDir,
		Executable: filepath.Join(dir, "warden-exe"), Net: &HostNet{}, RuntimeImage: runtimeImage,
	}
	if err := os.WriteFile(c.Executable, wardenbintest.Static(), 0o755); err != nil {
		t.Fatal(err)
	}
	fake.On(ArgsImage(runtimeImage), dockertest.Response{Stdout: "sha256:" + strings.Repeat("a", 64) + "\n"})
	fake.On(ArgsLeftC, dockertest.Response{ExitCode: 1, Stderr: "Error: No such container: warden-canary-proxy\nError: No such container: warden-canary\n"})
	fake.On(ArgsLeftN, dockertest.Response{ExitCode: 1, Stderr: "Error response from daemon: network warden-canary-sandbox not found\nError response from daemon: network warden-canary-egress not found\n"})
	fake.On(ArgsCreate, dockertest.Response{})
	fake.On(ArgsIDsC, dockertest.Response{Stdout: strings.Join(ContainerIDs, "\n") + "\n"})
	fake.On(ArgsIDsN, dockertest.Response{Stdout: strings.Join(NetworkIDs, "\n") + "\n"})
	fake.On(ArgsIPAM, dockertest.Response{Stdout: `[{"Subnet":"192.0.2.0/24","Gateway":"` + Gateway + `"}]` + "\n"})
	fake.On(ArgsStart, dockertest.Response{Do: func([]byte) {
		// What the canary does in its bind mount.
		ctl, _ := os.ReadFile(filepath.Join(c.RunDir(), "mnt", "control"))
		c.mu.Lock()
		c.control = ctl
		c.mu.Unlock()
		os.WriteFile(filepath.Join(c.RunDir(), "mnt", "owner"), []byte("canary"), 0o600)
	}})
	fake.On(ArgsWait, dockertest.Response{Stdout: "0\n"})
	fake.On(ArgsLogsC, dockertest.Response{Stdout: c.ProbeOutput(nil)})
	fake.On(ArgsLogsP, dockertest.Response{Stdout: ProxyLog})
	fake.On(ArgsDown, dockertest.Response{})
	return c
}
