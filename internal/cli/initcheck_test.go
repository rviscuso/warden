package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/docker"
	"github.com/rviscuso/warden/internal/docker/dockertest"
	"github.com/rviscuso/warden/internal/state"
)

const (
	zeroID  = "00000000-0000-0000-0000-000000000000"
	otherID = "11111111-1111-1111-1111-111111111111"
)

// host is a fake machine for end-to-end CLI tests: a temp root with home,
// workspace and XDG dirs as siblings, a real unix socket, a fake docker
// binary file and a scripted runner.
type host struct {
	t     *testing.T
	root  string
	home  string
	ws    string
	sock  string
	xdg   map[string]string
	fake  *dockertest.Fake
	stdin string
	now   time.Time
}

func newHost(t *testing.T) *host {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &host{
		t: t, root: root,
		home: filepath.Join(root, "home"),
		ws:   filepath.Join(root, "ws"),
		xdg: map[string]string{
			"XDG_CONFIG_HOME": filepath.Join(root, "config"),
			"XDG_STATE_HOME":  filepath.Join(root, "state"),
			"XDG_DATA_HOME":   filepath.Join(root, "share"),
		},
		now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
	}
	for _, d := range []string{h.home, h.ws, filepath.Join(root, "hostfs/sys/fs/cgroup"), filepath.Join(root, "bin")} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(filepath.Join(root, "hostfs/sys/fs/cgroup/cgroup.controllers"), []byte("cpu\n"), 0o644)
	os.WriteFile(filepath.Join(root, "bin/docker"), nil, 0o755)
	h.sock = filepath.Join(root, "d.sock")
	l, err := net.Listen("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	h.script(zeroID)
	return h
}

// script (re)creates the fake daemon with the given ID.
func (h *host) script(id string) {
	h.fake = dockertest.New(h.t)
	h.fake.On([]string{"compose", "version", "--format", "json"}, dockertest.Response{Stdout: `{"version":"2.40.3"}`})
	h.fake.On([]string{"info", "--format", "{{json .}}"}, dockertest.Response{Stdout: `{"ID":"` + id + `","CgroupVersion":"2","SecurityOptions":["name=apparmor","name=seccomp,profile=builtin"]}`})
	h.fake.On([]string{"version", "--format", "{{json .}}"}, dockertest.Response{Stdout: `{"Server":{"Version":"29.1.3","Components":[{"Name":"runc","Version":"1.4.0"},{"Name":"containerd","Version":"2.2.2"}]}}`})
	h.fake.On([]string{"ps", "-aq", "--no-trunc"}, dockertest.Response{})
}

func (h *host) configDir() string { return filepath.Join(h.xdg["XDG_CONFIG_HOME"], "warden") }
func (h *host) stateDir() string  { return filepath.Join(h.xdg["XDG_STATE_HOME"], "warden") }
func (h *host) shareDir() string  { return filepath.Join(h.xdg["XDG_DATA_HOME"], "warden") }
func (h *host) stateFile() string { return filepath.Join(h.stateDir(), "state.json") }

func (h *host) writeConfig() {
	h.t.Helper()
	cfg := strings.Replace(exampleConfig, `"/path/to/your/repo"`, `"`+h.ws+`"`, 1)
	cfg = strings.Replace(cfg, `"/var/run/docker.sock"`, `"`+h.sock+`"`, 1)
	os.MkdirAll(h.configDir(), 0o700)
	if err := os.WriteFile(filepath.Join(h.configDir(), "config.json"), []byte(cfg), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) run(args ...string) result {
	h.t.Helper()
	var out, errb bytes.Buffer
	e := &env{
		stdin:  strings.NewReader(h.stdin),
		stdout: &out,
		stderr: &errb,
		getenv: func(k string) string { return h.xdg[k] },
		buildInfo: func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-test"}}, true
		},
		geteuid:     func() int { return os.Geteuid() },
		getuid:      os.Getuid,
		home:        func() (string, error) { return h.home, nil },
		now:         func() time.Time { return h.now },
		root:        filepath.Join(h.root, "hostfs"),
		goos:        "linux",
		goarch:      "amd64",
		dockerPaths: []string{filepath.Join(h.root, "bin/docker")},
		newRunner:   func(docker.Options) (docker.Runner, error) { return h.fake, nil },
	}
	code := run(e, append([]string{"warden"}, args...))
	return result{code, out.String(), errb.String()}
}

func (h *host) loadState() *state.State {
	h.t.Helper()
	s, err := state.Load(h.stateFile())
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func TestInitWithoutConfigPrintsExample(t *testing.T) {
	h := newHost(t)
	r := h.run("init")
	if r.code != ExitFail {
		t.Fatalf("code %d", r.code)
	}
	for _, d := range []string{h.configDir(), h.stateDir(), h.shareDir()} {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi, err)
		}
	}
	if !strings.Contains(r.stderr, "no config at "+filepath.Join(h.configDir(), "config.json")) ||
		!strings.Contains(r.stderr, "egress.allow") || !strings.Contains(r.stderr, ".new; mv ") {
		t.Fatalf("stderr:\n%s", r.stderr)
	}
	// stdout is exactly the example, which is valid JSON and a valid config.
	if r.stdout != exampleConfig {
		t.Fatalf("stdout:\n%s", r.stdout)
	}
	if _, err := config.Parse([]byte(r.stdout)); err != nil {
		t.Fatalf("example config is invalid: %v", err)
	}
	if _, err := os.Stat(h.stateFile()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("state written without checks")
	}
	if len(h.fake.Calls) != 0 {
		t.Fatalf("docker called: %v", h.fake.Calls)
	}
}

func TestInitPins(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	r := h.run("init")
	if r.code != ExitOK {
		t.Fatalf("code %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "STATUS") || !strings.Contains(r.stdout, "All checks passed.") ||
		!strings.Contains(r.stdout, "Pinned daemon "+zeroID+" at "+h.sock) {
		t.Fatalf("stdout:\n%s", r.stdout)
	}
	s := h.loadState()
	want := state.State{
		Version: 1, WardenVersion: "v0.0.0-test",
		Daemon:        state.Daemon{ID: zeroID, Socket: h.sock, ServerVersion: "29.1.3", Runc: "1.4.0", Containerd: "2.2.2", Compose: "2.40.3"},
		InitializedAt: h.now,
	}
	if *s != want {
		t.Fatalf("state %+v\nwant  %+v", s, want)
	}
	fi, _ := os.Stat(h.stateFile())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %v", fi.Mode().Perm())
	}
}

func TestInitJSON(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	r := h.run("init", "--json")
	if r.code != ExitOK {
		t.Fatalf("code %d\n%s", r.code, r.stderr)
	}
	var out struct {
		OK     bool `json:"ok"`
		Checks []struct {
			ID, Status string
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.stdout)
	}
	if !out.OK || len(out.Checks) == 0 || out.Checks[0].ID != "config.valid" {
		t.Fatalf("got %+v", out)
	}
	if !strings.Contains(r.stderr, "Pinned daemon") {
		t.Fatalf("pin message should go to stderr with --json: %q", r.stderr)
	}
}

func TestInitFailingCheckWritesNoState(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.fake.On([]string{"info", "--format", "{{json .}}"}, dockertest.Response{Stdout: `{"ID":"x","CgroupVersion":"2","SecurityOptions":["name=seccomp","name=rootless"]}`})
	r := h.run("init")
	if r.code != ExitFail || !strings.Contains(r.stdout, "Some checks failed.") || !strings.Contains(r.stdout, "fix: use Docker's default rootful daemon") {
		t.Fatalf("got %d\n%s", r.code, r.stdout)
	}
	if _, err := os.Stat(h.stateFile()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("state written despite a failing check")
	}
}

func TestInitRepinNeedsApproval(t *testing.T) {
	for _, answer := range []string{"", "n\n", "N\n", "yes\n", "Y\n", "\n"} {
		h := newHost(t)
		h.writeConfig()
		if r := h.run("init"); r.code != ExitOK {
			t.Fatal(r.stderr)
		}
		h.script(otherID)
		h.stdin = answer
		r := h.run("init")
		if r.code != ExitFail || !strings.Contains(r.stderr, "pinned: "+zeroID) || !strings.Contains(r.stderr, "now:    "+otherID) ||
			!strings.Contains(r.stderr, "Re-pin to the new daemon? [y/N]") || !strings.Contains(r.stderr, "Kept the existing pin.") {
			t.Fatalf("answer %q: got %d\n%s", answer, r.code, r.stderr)
		}
		if got := h.loadState().Daemon.ID; got != zeroID {
			t.Fatalf("answer %q: pin changed to %s", answer, got)
		}
	}
}

func TestInitRepinApproved(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.run("init")
	h.script(otherID)
	h.stdin = "y\n"
	if r := h.run("init"); r.code != ExitOK {
		t.Fatalf("code %d\n%s", r.code, r.stderr)
	}
	if got := h.loadState().Daemon.ID; got != otherID {
		t.Fatalf("pin %s", got)
	}
}

func TestInitRepinOnlyAfterChecksPass(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.run("init")
	h.script(otherID)
	h.fake.On([]string{"compose", "version", "--format", "json"}, dockertest.Response{ExitCode: 1, Stderr: "no compose"})
	h.stdin = "y\n"
	r := h.run("init")
	if r.code != ExitFail || strings.Contains(r.stderr, "Re-pin") {
		t.Fatalf("got %d\n%s", r.code, r.stderr)
	}
	if got := h.loadState().Daemon.ID; got != zeroID {
		t.Fatalf("pin changed to %s", got)
	}
}

func TestInitSamePinNoPrompt(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.run("init")
	h.now = h.now.Add(time.Hour)
	r := h.run("init") // empty stdin: a prompt would be answered "no"
	if r.code != ExitOK || strings.Contains(r.stderr, "Re-pin") {
		t.Fatalf("got %d\n%s", r.code, r.stderr)
	}
	if !h.loadState().InitializedAt.Equal(h.now) {
		t.Fatal("state not refreshed")
	}
}

func TestInitCorruptStateFailsClosed(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.run("init")
	os.WriteFile(h.stateFile(), []byte(`{"version":1}`), 0o600)
	h.stdin = "y\n"
	r := h.run("init")
	if r.code != ExitFail || !strings.Contains(r.stderr, "daemon.id is empty") {
		t.Fatalf("got %d\n%s", r.code, r.stderr)
	}
}

func TestInitRefusesLooseDirectory(t *testing.T) {
	h := newHost(t)
	os.MkdirAll(h.stateDir(), 0o700)
	os.Chmod(h.stateDir(), 0o755)
	r := h.run("init")
	if r.code != ExitFail || !strings.Contains(r.stderr, "chmod 700 "+h.stateDir()) {
		t.Fatalf("got %d\n%s", r.code, r.stderr)
	}
	if fi, _ := os.Stat(h.stateDir()); fi.Mode().Perm() != 0o755 {
		t.Fatal("permissions were changed")
	}
}

func TestCheckBeforeInit(t *testing.T) {
	h := newHost(t)
	r := h.run("check")
	if r.code != ExitFail || !strings.Contains(r.stderr, "run warden init") {
		t.Fatalf("got %d\n%s", r.code, r.stderr)
	}
	for _, d := range []string{h.configDir(), h.stateDir(), h.shareDir()} {
		if _, err := os.Stat(d); err == nil {
			t.Errorf("check created %s", d)
		}
	}
}

func TestCheckAfterInit(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	os.MkdirAll(filepath.Join(h.stateDir(), "docker-config"), 0o700) // the real runner creates it during init
	if r := h.run("init"); r.code != ExitOK {
		t.Fatal(r.stderr)
	}
	r := h.run("check")
	if r.code != ExitOK || !strings.Contains(r.stdout, "daemon.pin") {
		t.Fatalf("got %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	r = h.run("check", "--json")
	if r.code != ExitOK || !strings.Contains(r.stdout, `"ok": true`) {
		t.Fatalf("got %d\n%s", r.code, r.stdout)
	}

	h.script(otherID)
	r = h.run("check")
	if r.code != ExitFail || !strings.Contains(r.stdout, "daemon changed; re-run init") {
		t.Fatalf("got %d\n%s", r.code, r.stdout)
	}
	if got := h.loadState().Daemon.ID; got != zeroID {
		t.Fatal("check changed the pin")
	}
}

func TestWarningsKeepExitZero(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.fake.On([]string{"info", "--format", "{{json .}}"}, dockertest.Response{Stdout: `{"ID":"` + zeroID + `","CgroupVersion":"2","SecurityOptions":["name=seccomp"]}`})
	r := h.run("init")
	if r.code != ExitOK || !strings.Contains(r.stdout, "warn") || !strings.Contains(r.stdout, "fix: enable AppArmor") {
		t.Fatalf("got %d\n%s", r.code, r.stdout)
	}
}

func TestConfirmed(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, " y \n": true, "y": true, "": false, "n\n": false, "yes\n": false, "Y\n": false} {
		if got := confirmed(strings.NewReader(in)); got != want {
			t.Errorf("confirmed(%q) = %v", in, got)
		}
	}
}
