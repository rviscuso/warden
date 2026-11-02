package compose

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rviscuso/warden/internal/hardening"
)

const (
	testImage = "busybox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	sock      = "/var/run/docker.sock"
)

var pol = Policy{UID: 1000, GID: 1000, Socket: sock, MPTCP: hardening.MPTCPPresent}

func validFile(t *testing.T) File {
	t.Helper()
	h, err := hardening.Settings(1000, 1000, hardening.ProxyResources, hardening.Host{MPTCP: hardening.MPTCPPresent})
	if err != nil {
		t.Fatal(err)
	}
	return File{
		Name: "warden-test",
		Services: map[string]Service{
			"proxy": {
				Fields:        h,
				ContainerName: "warden-test-proxy",
				Image:         testImage,
				Entrypoint:    []string{"/warden"},
				Command:       []string{"proxy", "--listen", ":3128"},
				Environment:   map[string]string{"WARDEN_ROLE": "proxy"},
				Networks:      []string{"sandbox", "egress"},
				Volumes:       []Bind{BindMount("/opt/warden/bin/warden", "/warden", true)},
			},
			"probe": {
				Fields:        h,
				ContainerName: "warden-test-probe",
				Image:         testImage,
				Entrypoint:    []string{"/warden"},
				Command:       []string{"probe"},
				Networks:      []string{"sandbox"},
				DependsOn:     []string{"proxy"},
			},
		},
		Networks: map[string]Network{
			"sandbox": {Name: "warden-test-sandbox", Internal: true},
			"egress":  {Name: "warden-test-egress"},
		},
	}
}

func TestRenderValid(t *testing.T) {
	b, err := Render(validFile(t), pol)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"cap_drop": [`, `"ALL"`, `"no-new-privileges:true"`, `"read_only": true`, `"init": true`,
		`"ipc": "private"`, `"cgroup": "private"`, `"net.mptcp.enabled": "0"`, `"pull_policy": "never"`, `"restart": "no"`, `"user": "1000:1000"`,
		`"create_host_path": false`, `"internal": true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("rendered file lacks %s:\n%s", want, b)
		}
	}
}

// mutate renders the valid file, applies fn to the decoded JSON and
// re-encodes it: the way to express what the types can't.
func mutate(t *testing.T, fn func(top map[string]any, svc map[string]any)) []byte {
	t.Helper()
	b, err := Render(validFile(t), pol)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	fn(top, top["services"].(map[string]any)["proxy"].(map[string]any))
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func vol(src string) map[string]any {
	return map[string]any{"type": "bind", "source": src, "target": "/x", "read_only": true, "bind": map[string]any{"create_host_path": false}}
}

// TestInvariants: every setting docs/phase-1.md forbids, plus the
// hardened values, each refused by Validate on the rendered bytes.
func TestInvariants(t *testing.T) {
	cases := map[string]func(top, s map[string]any){
		// The invariants named in the spec.
		"privileged":        func(_, s map[string]any) { s["privileged"] = true },
		"privileged false":  func(_, s map[string]any) { s["privileged"] = false }, // not even false: the key is unknown
		"cap_add":           func(_, s map[string]any) { s["cap_add"] = []any{"NET_ADMIN"} },
		"user 0":            func(_, s map[string]any) { s["user"] = "0:0" },
		"user root":         func(_, s map[string]any) { s["user"] = "root" },
		"user uid only":     func(_, s map[string]any) { s["user"] = "1000" },
		"user empty":        func(_, s map[string]any) { s["user"] = "" },
		"user missing":      func(_, s map[string]any) { delete(s, "user") },
		"user other uid":    func(_, s map[string]any) { s["user"] = "1001:1000" },
		"pid host":          func(_, s map[string]any) { s["pid"] = "host" },
		"ipc host":          func(_, s map[string]any) { s["ipc"] = "host" },
		"ipc shareable":     func(_, s map[string]any) { s["ipc"] = "shareable" },
		"network_mode host": func(_, s map[string]any) { s["network_mode"] = "host" },
		"devices":           func(_, s map[string]any) { s["devices"] = []any{"/dev/kvm"} },
		"socket bind":       func(_, s map[string]any) { s["volumes"] = []any{vol(sock)} },
		"socket under /run": func(_, s map[string]any) { s["volumes"] = []any{vol("/run/docker.sock")} },
		"socket dir":        func(_, s map[string]any) { s["volumes"] = []any{vol("/var/run")} },
		"root dir":          func(_, s map[string]any) { s["volumes"] = []any{vol("/")} },
		"socket short":      func(_, s map[string]any) { s["volumes"] = []any{sock + ":" + sock} },
		"named volume":      func(_, s map[string]any) { v := vol("data"); v["type"] = "volume"; s["volumes"] = []any{v} },
		"create_host_path": func(_, s map[string]any) {
			v := vol("/opt/x")
			v["bind"] = map[string]any{"create_host_path": true}
			s["volumes"] = []any{v}
		},
		"bind propagation": func(_, s map[string]any) {
			v := vol("/opt/x")
			v["bind"] = map[string]any{"create_host_path": false, "propagation": "rshared"}
			s["volumes"] = []any{v}
		},
		"relative source":   func(_, s map[string]any) { s["volumes"] = []any{vol("opt/x")} },
		"unclean source":    func(_, s map[string]any) { s["volumes"] = []any{vol("/opt/../var/run/docker.sock")} },
		"duplicate target":  func(_, s map[string]any) { s["volumes"] = []any{vol("/opt/a"), vol("/opt/b")} },
		"volume extra key":  func(_, s map[string]any) { v := vol("/opt/x"); v["consistency"] = "cached"; s["volumes"] = []any{v} },
		"volumes_from":      func(_, s map[string]any) { s["volumes_from"] = []any{"other"} },
		"userns_mode host":  func(_, s map[string]any) { s["userns_mode"] = "host" },
		"uts host":          func(_, s map[string]any) { s["uts"] = "host" },
		"cgroup host":       func(_, s map[string]any) { s["cgroup"] = "host" },
		"cgroup_parent":     func(_, s map[string]any) { s["cgroup_parent"] = "/" },
		"ports":             func(_, s map[string]any) { s["ports"] = []any{"3128:3128"} },
		"sysctls":           func(_, s map[string]any) { s["sysctls"] = map[string]any{"net.ipv4.ip_forward": "1"} },
		"tty false":         func(_, s map[string]any) { s["tty"] = false },
		"tty string":        func(_, s map[string]any) { s["tty"] = "true" },
		"stdin_open false":  func(_, s map[string]any) { s["stdin_open"] = false },
		"stdin_open number": func(_, s map[string]any) { s["stdin_open"] = 1 },
		"sysctls missing":   func(_, s map[string]any) { delete(s, "sysctls") },
		"sysctls empty":     func(_, s map[string]any) { s["sysctls"] = map[string]any{} },
		"mptcp on":          func(_, s map[string]any) { s["sysctls"] = map[string]any{"net.mptcp.enabled": "1"} },
		"mptcp number":      func(_, s map[string]any) { s["sysctls"] = map[string]any{"net.mptcp.enabled": 0} },
		"sysctls list":      func(_, s map[string]any) { s["sysctls"] = []any{"net.mptcp.enabled=0"} },
		"sysctls extra": func(_, s map[string]any) {
			s["sysctls"] = map[string]any{"net.mptcp.enabled": "0", "net.ipv4.ip_forward": "1"}
		},
		"security_opt extra": func(_, s map[string]any) { s["security_opt"] = []any{"no-new-privileges:true", "seccomp=unconfined"} },
		"seccomp unconfined": func(_, s map[string]any) { s["security_opt"] = []any{"seccomp=unconfined"} },
		"no nnp":             func(_, s map[string]any) { s["security_opt"] = []any{} },
		"cap_drop partial":   func(_, s map[string]any) { s["cap_drop"] = []any{"NET_RAW"} },
		"cap_drop missing":   func(_, s map[string]any) { delete(s, "cap_drop") },
		"read_only false":    func(_, s map[string]any) { s["read_only"] = false },
		"init false":         func(_, s map[string]any) { s["init"] = false },
		"tmpfs noexec":       func(_, s map[string]any) { s["tmpfs"] = []any{"/tmp:size=512m"} },
		"tmpfs extra":        func(_, s map[string]any) { s["tmpfs"] = []any{hardening.Tmpfs, "/run"} },
		"swap allowed":       func(_, s map[string]any) { s["memswap_limit"] = -1 },
		"swap larger":        func(_, s map[string]any) { s["memswap_limit"] = s["mem_limit"].(float64) * 2 },
		"no mem limit":       func(_, s map[string]any) { delete(s, "mem_limit") },
		"mem limit string":   func(_, s map[string]any) { s["mem_limit"] = "1g" },
		"pids unlimited":     func(_, s map[string]any) { s["pids_limit"] = -1 },
		"cpus zero":          func(_, s map[string]any) { s["cpus"] = 0 },
		"restart always":     func(_, s map[string]any) { s["restart"] = "always" },
		"pull always":        func(_, s map[string]any) { s["pull_policy"] = "always" },
		"image tag":          func(_, s map[string]any) { s["image"] = "busybox:latest" },
		"no entrypoint":      func(_, s map[string]any) { s["entrypoint"] = []any{} },
		"shell command":      func(_, s map[string]any) { s["command"] = "proxy --listen :3128" },
		"unknown network":    func(_, s map[string]any) { s["networks"] = []any{"host"} },
		"no networks":        func(_, s map[string]any) { s["networks"] = []any{} },
		"depends unknown":    func(_, s map[string]any) { s["depends_on"] = []any{"nope"} },
		"env not string":     func(_, s map[string]any) { s["environment"] = map[string]any{"A": 1} },
		"extra_hosts":        func(_, s map[string]any) { s["extra_hosts"] = []any{"host.docker.internal:host-gateway"} },
		"network driver": func(top, _ map[string]any) {
			top["networks"].(map[string]any)["egress"].(map[string]any)["driver"] = "host"
		},
		"network external": func(top, _ map[string]any) {
			top["networks"].(map[string]any)["egress"].(map[string]any)["external"] = true
		},
		"top-level volumes": func(top, _ map[string]any) { top["volumes"] = map[string]any{"data": map[string]any{}} },
		"top-level secrets": func(top, _ map[string]any) { top["secrets"] = map[string]any{} },
		"no name":           func(top, _ map[string]any) { delete(top, "name") },
	}
	for name, fn := range cases {
		if err := Validate(mutate(t, fn), pol); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The unmutated file passes, so each failure above is the mutation's.
	if err := Validate(mutate(t, func(_, _ map[string]any) {}), pol); err != nil {
		t.Fatalf("valid file refused: %v", err)
	}
}

func TestRenderRefusesSocketMounts(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.sock")
	os.WriteFile(custom, nil, 0o600)
	link := filepath.Join(dir, "innocent")
	os.Symlink(custom, link)
	linkDir := filepath.Join(dir, "rundir")
	os.Symlink("/var/run", linkDir)

	p := Policy{UID: 1000, GID: 1000, Socket: custom, MPTCP: hardening.MPTCPPresent}
	for _, src := range []string{custom, dir, link, "/var/run/docker.sock", "/run", linkDir} {
		f := validFile(t)
		s := f.Services["proxy"]
		s.Volumes = []Bind{BindMount(src, "/x", true)}
		f.Services["proxy"] = s
		if _, err := Render(f, p); err == nil || !strings.Contains(err.Error(), "Docker socket") {
			t.Errorf("Render with a bind of %s: %v", src, err)
		}
	}
}

func TestValidateRefusesRootPolicy(t *testing.T) {
	b, err := Render(validFile(t), pol)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Policy{{0, 1000, sock, hardening.MPTCPPresent}, {1000, 0, sock, hardening.MPTCPPresent}} {
		if err := Validate(b, p); err == nil {
			t.Errorf("policy %+v accepted", p)
		}
	}
}

func TestValidateRefusesTrailingData(t *testing.T) {
	b, _ := Render(validFile(t), pol)
	if err := Validate(append(b, []byte(`{}`)...), pol); err == nil {
		t.Fatal("trailing data accepted")
	}
}

// TestNoMPTCPHost: on a kernel without MPTCP the file has no sysctls, and
// Validate requires exactly that; each policy refuses the other's form.
func TestNoMPTCPHost(t *testing.T) {
	noMPTCP := Policy{UID: 1000, GID: 1000, Socket: sock, MPTCP: hardening.MPTCPAbsent}
	f := validFile(t)
	for k, s := range f.Services {
		s.Sysctls = nil
		f.Services[k] = s
	}
	b, err := Render(f, noMPTCP)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sysctls") {
		t.Fatalf("rendered sysctls:\n%s", b)
	}
	if err := Validate(b, pol); err == nil {
		t.Error("an MPTCP host accepted a file without the sysctl")
	}
	withSysctl, err := Render(validFile(t), pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(withSysctl, noMPTCP); err == nil {
		t.Error("a host without MPTCP accepted sysctls")
	}
	for name, v := range map[string]any{
		"mptcp off":    map[string]any{"net.mptcp.enabled": "0"},
		"other sysctl": map[string]any{"net.ipv4.ip_forward": "1"},
		"empty":        map[string]any{},
	} {
		var top map[string]any
		json.Unmarshal(b, &top)
		top["services"].(map[string]any)["proxy"].(map[string]any)["sysctls"] = v
		out, _ := json.Marshal(top)
		if err := Validate(out, noMPTCP); err == nil {
			t.Errorf("%s: accepted on a host without MPTCP", name)
		}
	}
}

// TestTTY: the controller's interactive terminal renders and validates.
func TestTTY(t *testing.T) {
	f := validFile(t)
	s := f.Services["proxy"]
	s.TTY, s.StdinOpen = true, true
	f.Services["proxy"] = s
	b, err := Render(f, pol)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"tty": true`) || !strings.Contains(string(b), `"stdin_open": true`) {
		t.Fatalf("rendered:\n%s", b)
	}
}

// TestValidateRefusesUnknownMPTCP: a policy that doesn't state the host's
// MPTCP status validates nothing, whatever the file says.
func TestValidateRefusesUnknownMPTCP(t *testing.T) {
	with, err := Render(validFile(t), pol)
	if err != nil {
		t.Fatal(err)
	}
	unknown := Policy{UID: 1000, GID: 1000, Socket: sock}
	if err := Validate(with, unknown); err == nil || !strings.Contains(err.Error(), "MPTCP status is unknown") {
		t.Fatalf("with sysctls: %v", err)
	}
	if _, err := Render(validFile(t), unknown); err == nil {
		t.Fatal("Render accepted an unknown MPTCP policy")
	}
}
