package controller

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rviscuso/warden/internal/compose"
	"github.com/rviscuso/warden/internal/hardening"
)

var update = flag.Bool("update", false, "rewrite testdata/warden.golden.json")

const (
	testRuntime = "busybox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testImage   = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

var testPolicy = compose.Policy{UID: 1000, GID: 1000, Socket: "/var/run/docker.sock", MPTCP: true}

func testParams() Params {
	return Params{
		UID: 1000, GID: 1000,
		RuntimeImage:      testRuntime,
		Binary:            "/srv/state/warden/bin/warden-0123",
		Allow:             []string{"api.anthropic.com", "platform.claude.com"},
		Image:             testImage,
		Workspace:         "/srv/repo",
		AgentHome:         "/srv/share/warden/agents/controller",
		RemoteControlName: "warden",
		Resources:         hardening.Resources{MemoryMB: 1536, CPUs: 1.5, Pids: 512},
		Host:              hardening.Host{MPTCP: true},
	}
}

// TestGolden: the generated compose file, byte for byte. Regenerate with
// go test ./internal/controller -update, and review the diff.
func TestGolden(t *testing.T) {
	f, err := Project(testParams())
	if err != nil {
		t.Fatal(err)
	}
	got, err := compose.Render(f, testPolicy)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "warden.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("generated compose differs from %s (run with -update and review):\n%s", golden, Diff(want, got))
	}
}

func TestProject(t *testing.T) {
	f, err := Project(testParams())
	if err != nil {
		t.Fatal(err)
	}
	c, px := f.Services["controller"], f.Services["proxy"]
	if c.ContainerName != ControllerName || px.ContainerName != ProxyName || f.Name != ProjectName {
		t.Errorf("names: %s %s %s", f.Name, c.ContainerName, px.ContainerName)
	}
	if strings.Join(c.Networks, ",") != "sandbox" || strings.Join(px.Networks, ",") != "sandbox,egress" {
		t.Errorf("networks: controller %v proxy %v", c.Networks, px.Networks)
	}
	if !f.Networks["sandbox"].Internal || f.Networks["sandbox"].Name != SandboxNet || f.Networks["egress"].Internal {
		t.Errorf("networks %+v", f.Networks)
	}
	if strings.Join(c.Entrypoint, " ") != "claude" || strings.Join(c.Command, " ") != "--remote-control warden" {
		t.Errorf("controller command %v %v", c.Entrypoint, c.Command)
	}
	if !c.TTY || !c.StdinOpen || strings.Join(c.DependsOn, ",") != "proxy" {
		t.Errorf("controller tty %v stdin %v depends %v", c.TTY, c.StdinOpen, c.DependsOn)
	}
	want := []compose.Bind{
		compose.BindMount("/srv/repo", "/workspace", false),
		compose.BindMount("/srv/share/warden/agents/controller", "/home/agent", false),
	}
	if !reflect.DeepEqual(c.Volumes, want) {
		t.Errorf("controller volumes %+v", c.Volumes)
	}
	for _, v := range c.Volumes {
		if strings.Contains(v.Source, "/bin/warden-") {
			t.Error("the warden binary is mounted into the controller")
		}
	}
	if !reflect.DeepEqual(c.Environment, Environment()) || c.Environment["HTTPS_PROXY"] != "http://warden-proxy:3128" ||
		c.Environment["https_proxy"] != c.Environment["HTTPS_PROXY"] {
		t.Errorf("controller env %v", c.Environment)
	}
	if c.MemLimit != 1536<<20 || c.PidsLimit != 512 || c.User != "1000:1000" {
		t.Errorf("controller hardening %+v", c.Fields)
	}
	if px.MemLimit != 256<<20 || px.Image != testRuntime || px.Environment["WARDEN_ROLE"] != "proxy" {
		t.Errorf("proxy %+v", px)
	}
}

func TestEnvironmentFixed(t *testing.T) {
	want := map[string]string{
		"HTTPS_PROXY": "http://warden-proxy:3128", "https_proxy": "http://warden-proxy:3128",
		"CLAUDE_CONFIG_DIR": "/home/agent/.claude", "DISABLE_AUTOUPDATER": "1",
		"ENABLE_CLAUDEAI_MCP_SERVERS": "false", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
	}
	if !reflect.DeepEqual(Environment(), want) {
		t.Fatalf("Environment() = %v", Environment())
	}
}

func TestProjectRefuses(t *testing.T) {
	cases := map[string]func(p *Params){
		"relative workspace": func(p *Params) { p.Workspace = "srv/repo" },
		"unclean workspace":  func(p *Params) { p.Workspace = "/srv/repo/../etc" },
		"relative home":      func(p *Params) { p.AgentHome = "agents/controller" },
		"no binary":          func(p *Params) { p.Binary = "" },
		"no name":            func(p *Params) { p.RemoteControlName = "" },
		"root":               func(p *Params) { p.UID = 0 },
		"no allowlist":       func(p *Params) { p.Allow = nil },
		"no resources":       func(p *Params) { p.Resources = hardening.Resources{} },
	}
	for name, fn := range cases {
		p := testParams()
		fn(&p)
		if _, err := Project(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A tag for the controller image is refused when rendered.
	p := testParams()
	p.Image = "warden-controller:latest"
	f, err := Project(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compose.Render(f, testPolicy); err == nil {
		t.Error("an image tag rendered")
	}
}

// TestProxyIsTheCanarysProxy: ProxyService depends only on its inputs, so
// up's proxy and the canary's differ only in the container name.
func TestProxyServiceDeterministic(t *testing.T) {
	pp := ProxyParams{UID: 1000, GID: 1000, ContainerName: "a", RuntimeImage: testRuntime, Binary: "/srv/b", Allow: []string{"x.example.com"}, Host: hardening.Host{MPTCP: true}}
	a, err := ProxyService(pp)
	if err != nil {
		t.Fatal(err)
	}
	pp.ContainerName = "b"
	b, _ := ProxyService(pp)
	b.ContainerName = "a"
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%+v\n%+v", a, b)
	}
}
