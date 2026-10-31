package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	hex64   = strings.Repeat("0123456789abcdef", 4)
	digest  = "sha256:" + hex64
	validJS = `{
  "version": 1,
  "docker": { "socket": "/var/run/docker.sock" },
  "runtime_image": "busybox@` + digest + `",
  "egress": { "allow": ["api.anthropic.com", "platform.claude.com"] },
  "controller": {
    "image": "` + digest + `",
    "workspace": "/srv/work/repo",
    "remote_control_name": "warden",
    "resources": { "memory_mb": 1536, "cpus": 1.5, "pids": 512 }
  }
}`
)

// mutate decodes the valid config into generic JSON, applies f, and
// re-encodes it, so each test changes exactly one thing.
func mutate(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(validJS), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sub(m map[string]any, key string) map[string]any { return m[key].(map[string]any) }

func expectError(t *testing.T, data []byte, want string) {
	t.Helper()
	_, err := Parse(data)
	if err == nil {
		t.Fatalf("expected an error containing %q, got none", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(validJS))
	if err != nil {
		t.Fatal(err)
	}
	if c.Docker.Socket != "/var/run/docker.sock" || c.Controller.Resources.CPUs != 1.5 ||
		c.Egress.Allow[1] != "platform.claude.com" || c.Controller.RemoteControlName != "warden" {
		t.Fatalf("unexpected config %+v", c)
	}
}

func TestLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(validJS), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Fatalf("expected a read error, got %v", err)
	}
}

func TestSocketDefaults(t *testing.T) {
	for name, f := range map[string]func(map[string]any){
		"no docker object": func(m map[string]any) { delete(m, "docker") },
		"no socket":        func(m map[string]any) { m["docker"] = map[string]any{} },
		"docker null":      func(m map[string]any) { m["docker"] = nil },
	} {
		c, err := Parse(mutate(t, f))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Docker.Socket != DefaultSocket {
			t.Errorf("%s: socket %q", name, c.Docker.Socket)
		}
	}
}

func TestUnknownFields(t *testing.T) {
	expectError(t, mutate(t, func(m map[string]any) { m["privileged"] = true }), `unknown field "privileged"`)
	expectError(t, mutate(t, func(m map[string]any) { sub(m, "docker")["host"] = "tcp://x" }), `unknown field "host"`)
	expectError(t, mutate(t, func(m map[string]any) { sub(m, "egress")["deny"] = []string{} }), `unknown field "deny"`)
	expectError(t, mutate(t, func(m map[string]any) { sub(m, "controller")["cap_add"] = []string{"ALL"} }), `unknown field "cap_add"`)
	expectError(t, mutate(t, func(m map[string]any) { sub(m, "controller")["uid"] = 0 }), `unknown field "uid"`)
	expectError(t, mutate(t, func(m map[string]any) { sub(sub(m, "controller"), "resources")["swap_mb"] = 1 }), `unknown field "swap_mb"`)
}

func TestMalformed(t *testing.T) {
	expectError(t, []byte(`{`), "config:")
	expectError(t, []byte(`[]`), "config:")
	expectError(t, []byte(validJS+`{}`), "unexpected data after the JSON object")
	expectError(t, []byte(validJS+` x`), "unexpected data after the JSON object")
	expectError(t, mutate(t, func(m map[string]any) { m["version"] = "1" }), "config:")
	expectError(t, mutate(t, func(m map[string]any) { sub(sub(m, "controller"), "resources")["pids"] = 512.5 }), "config:")
}

func TestVersion(t *testing.T) {
	for _, v := range []any{0, 2, -1} {
		expectError(t, mutate(t, func(m map[string]any) { m["version"] = v }), "version: must be 1")
	}
	expectError(t, mutate(t, func(m map[string]any) { delete(m, "version") }), "version: must be 1")
}

func TestSocketMustBeAbsolute(t *testing.T) {
	for _, s := range []string{"docker.sock", "./docker.sock", "unix:///var/run/docker.sock", "tcp://127.0.0.1:2375"} {
		expectError(t, mutate(t, func(m map[string]any) { sub(m, "docker")["socket"] = s }), "docker.socket: must be an absolute path")
	}
}

func TestImages(t *testing.T) {
	good := []string{
		digest,
		"busybox@" + digest,
		"library/busybox@" + digest,
		"docker.io/library/busybox@" + digest,
		"registry.example.com:5000/team/img@" + digest,
		"localhost:5000/a_b/c.d/e-f@" + digest,
	}
	for _, ref := range good {
		if err := ValidateImage(ref); err != nil {
			t.Errorf("%q: %v", ref, err)
		}
	}
	bad := map[string]string{
		"":                             "not pinned",
		"busybox":                      "not pinned",
		"busybox:latest":               "has a tag",
		"busybox:1.36@" + digest:       "has a tag",
		"registry:5000/busybox:1.36":   "has a tag",
		"busybox@sha256:" + hex64[:63]: "not a valid image reference",
		"busybox@sha256:" + strings.ToUpper(hex64): "not a valid image reference",
		"busybox@sha512:" + hex64 + hex64:          "not a valid image reference",
		"BusyBox@" + digest:                        "not a valid image reference",
		"sha256:" + hex64 + "0":                    "not a valid image ID",
		hex64:                                      "not pinned",
		"busybox@" + digest + " ":                  "not a valid image reference",
	}
	for ref, want := range bad {
		err := ValidateImage(ref)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want error containing %q", ref, err, want)
		}
	}
	// Both image fields are validated.
	expectError(t, mutate(t, func(m map[string]any) { m["runtime_image"] = "busybox:latest" }), "runtime_image:")
	expectError(t, mutate(t, func(m map[string]any) { sub(m, "controller")["image"] = "warden-controller" }), "controller.image:")
}

func TestAllowEntries(t *testing.T) {
	good := []string{
		"api.anthropic.com",
		".anthropic.com",
		"a.b",
		"x1.example.org",
		"my-host.example.com",
		"xn--bcher-kva.example",
		"example.xn--p1ai",
		strings.Repeat("a", 63) + ".com",
		strings.Repeat(strings.Repeat("a", 62)+".", 4)[:249] + ".com", // 253 chars
	}
	for _, e := range good {
		if err := ValidateAllowEntry(e); err != nil {
			t.Errorf("%q (%d chars): %v", e, len(e), err)
		}
	}
	bad := map[string]string{
		"":                                     "empty entry",
		"localhost":                            "at least two labels",
		"com":                                  "at least two labels",
		".com":                                 "at least two labels after the dot",
		".":                                    "empty label",
		"..com":                                "empty label",
		"api.anthropic.com.":                   "trailing dot",
		".anthropic.com.":                      "trailing dot",
		"API.anthropic.com":                    "must be lowercase",
		"https://api.anthropic.com":            "invalid character",
		"api.anthropic.com/v1":                 "invalid character",
		"api.anthropic.com:443":                "invalid character",
		"*.anthropic.com":                      "invalid character",
		"api_x.anthropic.com":                  "invalid character",
		"api anthropic.com":                    "invalid character",
		"bücher.example":                       "invalid character",
		"-api.anthropic.com":                   "starts or ends with a hyphen",
		"api-.anthropic.com":                   "starts or ends with a hyphen",
		"a..b":                                 "empty label",
		"1.2.3.4":                              "IP addresses are not allowed",
		"::1":                                  "IP addresses are not allowed",
		"[::1]":                                "invalid character",
		"127.1":                                "last label is numeric",
		"10.0.0.1.2":                           "last label is numeric",
		strings.Repeat("a", 64) + ".com":       "longer than 63",
		strings.Repeat("a.", 127) + "com":      "longer than 253", // 257 chars
		"." + strings.Repeat("a.", 127) + "co": "longer than 253",
	}
	for e, want := range bad {
		err := ValidateAllowEntry(e)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want error containing %q", e, err, want)
		}
	}
}

func TestAllowList(t *testing.T) {
	expectError(t, mutate(t, func(m map[string]any) { sub(m, "egress")["allow"] = []string{} }), "egress.allow: must not be empty")
	expectError(t, mutate(t, func(m map[string]any) { delete(m, "egress") }), "egress.allow: must not be empty")
	expectError(t, mutate(t, func(m map[string]any) {
		sub(m, "egress")["allow"] = []string{"a.example.com", "b.example.com", "a.example.com"}
	}), `egress.allow[2]: duplicate entry "a.example.com"`)
	expectError(t, mutate(t, func(m map[string]any) {
		sub(m, "egress")["allow"] = []string{"ok.example.com", "localhost"}
	}), "egress.allow[1]:")
	// A domain and its leading-dot form are different entries, not duplicates.
	if _, err := Parse(mutate(t, func(m map[string]any) {
		sub(m, "egress")["allow"] = []string{"example.com", ".example.com"}
	})); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceMustBeAbsolute(t *testing.T) {
	for _, w := range []string{"", "repo", "./repo", "~/repo"} {
		expectError(t, mutate(t, func(m map[string]any) { sub(m, "controller")["workspace"] = w }), "controller.workspace: must be an absolute path")
	}
}

func TestRemoteControlName(t *testing.T) {
	for _, n := range []string{"a", "Warden-1.x_y", strings.Repeat("z", 64)} {
		if _, err := Parse(mutate(t, func(m map[string]any) { sub(m, "controller")["remote_control_name"] = n })); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{"", "a b", "a/b", "x;y", "$(id)", strings.Repeat("z", 65), "é"} {
		expectError(t, mutate(t, func(m map[string]any) { sub(m, "controller")["remote_control_name"] = n }), "controller.remote_control_name: must match")
	}
}

func TestResources(t *testing.T) {
	set := func(k string, v any) []byte {
		return mutate(t, func(m map[string]any) { sub(sub(m, "controller"), "resources")[k] = v })
	}
	for k, vals := range map[string][]any{
		"memory_mb": {256, 65536},
		"cpus":      {0.25, 0.5, 64, 3.75},
		"pids":      {64, 32768},
	} {
		for _, v := range vals {
			if _, err := Parse(set(k, v)); err != nil {
				t.Errorf("%s=%v: %v", k, v, err)
			}
		}
	}
	for k, vals := range map[string][]any{
		"memory_mb": {0, -1, 255, 65537},
		"cpus":      {0, -1, 0.24, 64.01},
		"pids":      {0, -1, 63, 32769},
	} {
		for _, v := range vals {
			expectError(t, set(k, v), "controller.resources."+k+": must be between")
		}
	}
	expectError(t, mutate(t, func(m map[string]any) { delete(sub(m, "controller"), "resources") }), "controller.resources.memory_mb")
}

func TestReportsAllErrors(t *testing.T) {
	_, err := Parse(mutate(t, func(m map[string]any) {
		m["version"] = 2
		m["runtime_image"] = "busybox"
		sub(m, "controller")["remote_control_name"] = ""
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"version:", "runtime_image:", "remote_control_name:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %q", want, err)
		}
	}
}
