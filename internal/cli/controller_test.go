package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rviscuso/warden/internal/controller"
	"github.com/rviscuso/warden/internal/docker/dockertest"
)

var (
	proxyID      = strings.Repeat("1", 64)
	controllerID = strings.Repeat("2", 64)
	testURL      = "https://claude.ai/code/session_test"
	testStarted  = "2026-11-02T09:00:00.123456789Z"
	logsArgs     = []string{"logs", "--since", testStarted, "warden-controller"}
)

func (h *host) composeFile() string { return filepath.Join(h.stateDir(), "compose", "warden.json") }

// proc writes a fixture process into the host's /proc.
func (h *host) proc(pid, ppid int, name string, uid, gid int, capEff string) {
	h.t.Helper()
	dir := filepath.Join(h.root, "hostfs", "proc", fmt.Sprint(pid))
	os.MkdirAll(dir, 0o755)
	status := fmt.Sprintf("Name:\t%s\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nCapEff:\t%s\nCapBnd:\t0000000000000000\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
		name, ppid, uid, uid, uid, uid, gid, gid, gid, gid, capEff)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// upHost is an initialized host with a scripted, passing up.
func upHost(t *testing.T) *host {
	t.Helper()
	h := newHost(t)
	h.writeConfig()
	if r := h.run("init"); r.code != ExitOK {
		t.Fatalf("init: %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	h.scriptUp("Welcome\n\x1b[1m" + testURL + "\x1b[0m\n")
	uid, gid := os.Getuid(), os.Getgid()
	h.proc(600, 1, "docker-init", uid, gid, "0000000000000000")
	h.proc(601, 600, "warden", uid, gid, "0000000000000000")
	h.proc(700, 1, "docker-init", uid, gid, "0000000000000000")
	h.proc(701, 700, "claude", uid, gid, "0000000000000000")
	h.stdin = "y\n"
	return h
}

func (h *host) scriptUp(log string) {
	f := h.composeFile()
	h.fake.On([]string{"compose", "-p", "warden", "-f", f, "up", "-d"}, dockertest.Response{})
	h.fake.On([]string{"compose", "-p", "warden", "-f", f, "down"}, dockertest.Response{})
	h.fake.On([]string{"compose", "-p", "warden", "down"}, dockertest.Response{})
	h.fake.On([]string{"inspect", "--type", "container", "--format", "{{.Id}}", "warden-proxy", "warden-controller"},
		dockertest.Response{Stdout: proxyID + "\n" + controllerID + "\n"})
	h.fake.On([]string{"inspect", "--type", "container", "--format", "{{.State.Running}} {{.State.Pid}}", "warden-proxy"}, dockertest.Response{Stdout: "true 600\n"})
	h.fake.On([]string{"inspect", "--type", "container", "--format", "{{.State.Running}} {{.State.Pid}}", "warden-controller"}, dockertest.Response{Stdout: "true 700\n"})
	h.fake.On([]string{"inspect", "--type", "container", "--format", "{{.State.StartedAt}}", "warden-controller"}, dockertest.Response{Stdout: testStarted + "\n"})
	h.fake.On(logsArgs, dockertest.Response{Stdout: log})
}

func (h *host) called(args ...string) bool { return h.fake.Called(args) }

func TestUpFirstApply(t *testing.T) {
	h := upHost(t)
	r := h.run("up")
	if r.code != ExitOK {
		t.Fatalf("up: %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	applied, err := os.ReadFile(h.composeFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.stdout, string(applied)) {
		t.Error("the file applied is not the file shown")
	}
	// The fixture host has MPTCP: every service turns it off.
	if strings.Count(string(applied), `"net.mptcp.enabled": "0"`) != 2 {
		t.Errorf("MPTCP not turned off in both services:\n%s", applied)
	}
	for _, want := range []string{"First apply: no previous file.", "Verified warden-proxy and warden-controller", "Remote Control: " + testURL} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
	if !h.called(logsArgs...) || h.called("logs", "warden-controller") {
		t.Error("the log must be read only since the container started")
	}
	if !strings.Contains(r.stderr, "Apply? [y/N] ") {
		t.Errorf("stderr %q", r.stderr)
	}
	if fi, _ := os.Stat(h.composeFile()); fi.Mode().Perm() != 0o600 {
		t.Errorf("compose file mode %v", fi.Mode())
	}
	home := filepath.Join(h.shareDir(), "agents", "controller")
	if fi, err := os.Stat(home); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("agent home: %v %v", fi, err)
	}
	if !strings.Contains(string(applied), `"source": "`+home+`"`) || !strings.Contains(string(applied), `"source": "`+h.ws+`"`) {
		t.Errorf("binds:\n%s", applied)
	}
	c := h.loadState().Controller
	if c == nil || c.AppliedCompose != string(applied) || c.ProxyID != proxyID || c.ControllerID != controllerID || c.RemoteControlURL != testURL {
		t.Fatalf("state %+v", c)
	}
}

func TestUpDeclined(t *testing.T) {
	for _, answer := range []string{"", "n\n", "yes\n", "Y\n"} {
		h := upHost(t)
		h.stdin = answer
		r := h.run("up")
		if r.code != ExitFail || !strings.Contains(r.stderr, "nothing applied") {
			t.Fatalf("answer %q: %d\n%s", answer, r.code, r.stderr)
		}
		if h.called("compose", "-p", "warden", "-f", h.composeFile(), "up", "-d") {
			t.Errorf("answer %q: compose up ran", answer)
		}
		if _, err := os.Stat(h.composeFile()); err == nil {
			t.Errorf("answer %q: compose file written", answer)
		}
		if h.loadState().Controller != nil {
			t.Errorf("answer %q: state changed", answer)
		}
	}
}

func TestUpDiffAndSameContainer(t *testing.T) {
	h := upHost(t)
	if r := h.run("up"); r.code != ExitOK {
		t.Fatal(r.stderr)
	}
	// Unchanged: no diff, and the same container keeps its URL without
	// reading the log again.
	logsBefore := countCalls(h, logsArgs...)
	r := h.run("up")
	if r.code != ExitOK || !strings.Contains(r.stdout, "No changes since the last apply.") ||
		!strings.Contains(r.stdout, "Remote Control: "+testURL+" (the controller wasn't recreated)") {
		t.Fatalf("second up: %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if countCalls(h, logsArgs...) != logsBefore {
		t.Error("read the log for an unchanged container")
	}
	// A config change shows exactly what changes.
	cfgFile := filepath.Join(h.configDir(), "config.json")
	cfg, _ := os.ReadFile(cfgFile)
	os.WriteFile(cfgFile, []byte(strings.Replace(string(cfg), `"platform.claude.com"]`, `"platform.claude.com", "docs.example.com"]`, 1)), 0o600)
	r = h.run("up")
	if r.code != ExitOK || !strings.Contains(r.stdout, "Changes since the last apply:\n\n--- applied\n+++ new\n") ||
		!strings.Contains(r.stdout, "+        \"docs.example.com\",\n") {
		t.Fatalf("third up: %d\n%s", r.code, r.stdout)
	}
}

func countCalls(h *host, args ...string) int {
	n := 0
	for _, c := range h.fake.Calls {
		if strings.Join(c, " ") == strings.Join(args, " ") {
			n++
		}
	}
	return n
}

func TestUpVerificationFailureStopsEverything(t *testing.T) {
	h := upHost(t)
	h.proc(701, 700, "claude", os.Getuid(), os.Getgid(), "00000000a80425fb")
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "post-start verification failed for warden-controller") ||
		!strings.Contains(r.stderr, "CapEff 00000000a80425fb") || !strings.Contains(r.stderr, "Stopping everything.") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
	if !h.called("compose", "-p", "warden", "-f", h.composeFile(), "down") {
		t.Error("compose down didn't run")
	}
	if c := h.loadState().Controller; c == nil || c.Running() {
		t.Errorf("state after a failed verification: %+v", c)
	}
	if strings.Contains(r.stdout, "Remote Control:") {
		t.Error("printed a URL after failing verification")
	}
}

func TestUpVerificationNoMainProcess(t *testing.T) {
	h := upHost(t)
	os.RemoveAll(filepath.Join(h.root, "hostfs", "proc", "601"))
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "warden-proxy") || !strings.Contains(r.stderr, "no child") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
}

func TestUpNoURL(t *testing.T) {
	h := upHost(t)
	h.scriptUp("Please log in.\nVisit https://claude.ai/login\n")
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "docker attach warden-controller` (detach with Ctrl-P Ctrl-Q), then run `warden status`") ||
		!strings.Contains(r.stderr, "or run `warden down` to stop") || !strings.Contains(r.stderr, "  Visit https://claude.ai/login") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
	if c := h.loadState().Controller; !c.Running() || c.RemoteControlURL != "" {
		t.Errorf("state %+v: containers stay up for the login, with no URL", c)
	}
}

func TestUpControllerStopped(t *testing.T) {
	h := upHost(t)
	h.scriptUp("crashed\n")
	h.fake.On([]string{"inspect", "--type", "container", "--format", "{{.State.Running}} {{.State.Pid}}", "warden-controller"},
		dockertest.Response{Stdout: "true 700\n", Do: func([]byte) {}})
	// Running for verification, then stopped while waiting for the URL.
	n := 0
	h.fake.On(logsArgs, dockertest.Response{Stdout: "crashed\n", Do: func([]byte) {
		n++
		h.fake.On([]string{"inspect", "--type", "container", "--format", "{{.State.Running}} {{.State.Pid}}", "warden-controller"},
			dockertest.Response{Stdout: "false 0\n"})
	}})
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "warden-controller stopped.") || n != 1 {
		t.Fatalf("%d (logs read %d times)\n%s", r.code, n, r.stderr)
	}
}

func TestUpChecksThePin(t *testing.T) {
	h := upHost(t)
	h.script(otherID)
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "daemon changed") || !strings.Contains(r.stderr, "fix: daemon changed; re-run init") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
	for _, c := range h.fake.Calls {
		if c[0] == "compose" && len(c) > 1 && c[1] == "-p" {
			t.Fatalf("ran %v against another daemon", c)
		}
	}
}

func TestUpRevalidatesWorkspace(t *testing.T) {
	h := upHost(t)
	cfgFile := filepath.Join(h.configDir(), "config.json")
	cfg, _ := os.ReadFile(cfgFile)
	os.WriteFile(cfgFile, []byte(strings.Replace(string(cfg), `"`+h.ws+`"`, `"`+h.home+`"`, 1)), 0o600)
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "workspace") || strings.Contains(r.stderr, "Apply?") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
}

func TestUpNeedsInitsBinary(t *testing.T) {
	h := upHost(t)
	os.RemoveAll(filepath.Join(h.stateDir(), "bin"))
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "run warden init") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
}

func TestBeforeInit(t *testing.T) {
	for _, args := range [][]string{{"up"}, {"down"}, {"status"}, {"status", "--json"}, {"logs", "proxy"}} {
		h := newHost(t)
		r := h.run(args...)
		if r.code != ExitFail || !strings.Contains(r.stderr, "fix: run warden init") {
			t.Errorf("%v: %d\n%s", args, r.code, r.stderr)
		}
		if len(h.fake.Calls) != 0 {
			t.Errorf("%v: docker called: %v", args, h.fake.Calls)
		}
	}
}

func TestDown(t *testing.T) {
	h := upHost(t)
	h.run("up")
	r := h.run("down")
	if r.code != ExitOK || !strings.Contains(r.stdout, "The agent home and the workspace are kept.") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
	if !h.called("compose", "-p", "warden", "down") {
		t.Fatal("compose down not run")
	}
	for _, c := range h.fake.Calls {
		if strings.Contains(strings.Join(c, " "), " -v") || strings.Contains(strings.Join(c, " "), "--volumes") {
			t.Errorf("down removed volumes: %v", c)
		}
	}
	c := h.loadState().Controller
	if c.Running() || c.RemoteControlURL != testURL || c.AppliedCompose == "" {
		t.Errorf("state after down %+v", c)
	}
	if _, err := os.Stat(filepath.Join(h.shareDir(), "agents", "controller")); err != nil {
		t.Error("agent home removed")
	}
}

func inspectJSON(id, status, image string) string {
	return `[{"Id":"` + id + `","Config":{"Image":"` + image + `"},"State":{"Status":"` + status + `","StartedAt":"2026-11-02T09:00:00Z"}}]`
}

func TestStatus(t *testing.T) {
	h := upHost(t)
	h.run("up")
	h.fake.On([]string{"inspect", "--type", "container", "warden-proxy"}, dockertest.Response{Stdout: inspectJSON(proxyID, "running", exampleRuntimeImage)})
	h.fake.On([]string{"inspect", "--type", "container", "warden-controller"}, dockertest.Response{Stdout: inspectJSON(strings.Repeat("3", 64), "exited", "sha256:x")})
	r := h.run("status")
	for _, want := range []string{
		"Daemon: " + zeroID, "warden-proxy: running", "(started by Warden)",
		"warden-controller: exited", "NOT started by Warden", "Last Remote Control URL: " + testURL,
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("status lacks %q:\n%s", want, r.stdout)
		}
	}
	if r.code != ExitOK {
		t.Errorf("code %d", r.code)
	}
	r = h.run("status", "--json")
	var rep controller.StatusReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || r.code != ExitOK {
		t.Fatalf("%v %d\n%s", err, r.code, r.stdout)
	}
	if len(rep.Containers) != 2 || !rep.Containers[0].Recorded || rep.Containers[1].Recorded || rep.URL != testURL {
		t.Fatalf("%+v", rep)
	}
}

func TestStatusNotFound(t *testing.T) {
	h := upHost(t)
	for _, n := range []string{"warden-proxy", "warden-controller"} {
		h.fake.On([]string{"inspect", "--type", "container", n}, dockertest.Response{ExitCode: 1, Stdout: "[]", Stderr: "Error: No such container: " + n})
	}
	r := h.run("status")
	if r.code != ExitOK || !strings.Contains(r.stdout, "warden-proxy: not found") || !strings.Contains(r.stdout, "No Remote Control URL recorded.") {
		t.Fatalf("%d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// Any other inspect failure fails status.
	h.fake.On([]string{"inspect", "--type", "container", "warden-proxy"}, dockertest.Response{ExitCode: 1, Stderr: "permission denied"})
	if r := h.run("status"); r.code != ExitFail {
		t.Fatalf("%d", r.code)
	}
}

func TestLogs(t *testing.T) {
	h := upHost(t)
	h.fake.On([]string{"logs", "--tail", "5", "warden-proxy"}, dockertest.Response{Stdout: "{\"event\":\"open\"}\n", Stderr: "warn\n"})
	r := h.run("logs", "proxy", "-n", "5")
	if r.code != ExitOK || r.stdout != "{\"event\":\"open\"}\n" || r.stderr != "warn\n" {
		t.Fatalf("%+v", r)
	}
	h.fake.On([]string{"logs", "--tail", "100", "warden-controller"}, dockertest.Response{ExitCode: 1, Stderr: "Error: No such container: warden-controller\n"})
	if r := h.run("logs", "controller"); r.code != ExitFail {
		t.Fatalf("%+v", r)
	}
}

// TestUpRefusesAnotherSocket: the configured socket must be the pinned one,
// even if the daemon behind it answers with the pinned ID.
func TestUpRefusesAnotherSocket(t *testing.T) {
	h := upHost(t)
	cfgFile := filepath.Join(h.configDir(), "config.json")
	cfg, _ := os.ReadFile(cfgFile)
	os.WriteFile(cfgFile, []byte(strings.Replace(string(cfg), `"`+h.sock+`"`, `"/run/other.sock"`, 1)), 0o600)
	for _, cmd := range [][]string{{"up"}, {"down"}, {"status"}, {"logs", "proxy"}} {
		r := h.run(cmd...)
		if r.code != ExitFail || !strings.Contains(r.stderr, "is not the pinned socket "+h.sock) {
			t.Errorf("%v: %d\n%s", cmd, r.code, r.stderr)
		}
	}
	if len(h.fake.Calls) > 0 && h.called("compose", "-p", "warden", "-f", h.composeFile(), "up", "-d") {
		t.Error("compose up ran")
	}
}

// TestUpHostWithoutMPTCP: on a kernel without MPTCP, up's project has no
// sysctls; the canary already proved the kernel has none.
func TestUpHostWithoutMPTCP(t *testing.T) {
	h := upHost(t)
	os.RemoveAll(filepath.Join(h.root, "hostfs/proc/sys/net/mptcp"))
	if r := h.run("up"); r.code != ExitOK {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
	applied, _ := os.ReadFile(h.composeFile())
	if strings.Contains(string(applied), "sysctls") {
		t.Fatalf("sysctls on a host without MPTCP:\n%s", applied)
	}
}

// TestUpMPTCPUnknownFailsClosed: up doesn't guess the host's MPTCP.
func TestUpMPTCPUnknownFailsClosed(t *testing.T) {
	h := upHost(t)
	net := filepath.Join(h.root, "hostfs/proc/sys/net")
	os.RemoveAll(net)
	os.WriteFile(net, nil, 0o644) // ENOTDIR
	r := h.run("up")
	if r.code != ExitFail || !strings.Contains(r.stderr, "cannot tell whether the kernel has MPTCP") || strings.Contains(r.stderr, "Apply?") {
		t.Fatalf("%d\n%s", r.code, r.stderr)
	}
}

// TestStatusFindsURLAfterLogin: up found no URL (not logged in yet); after
// the login, status finds it in the log since the container started and
// records it.
func TestStatusFindsURLAfterLogin(t *testing.T) {
	h := upHost(t)
	h.scriptUp("Please log in.\n")
	if r := h.run("up"); r.code != ExitFail {
		t.Fatalf("up: %d", r.code)
	}
	h.fake.On([]string{"inspect", "--type", "container", "warden-proxy"}, dockertest.Response{Stdout: inspectJSON(proxyID, "running", exampleRuntimeImage)})
	h.fake.On([]string{"inspect", "--type", "container", "warden-controller"}, dockertest.Response{Stdout: inspectJSON(controllerID, "running", "sha256:x")})
	h.fake.On(logsArgs, dockertest.Response{Stdout: "Please log in.\nLogged in.\n" + testURL + "\n"})
	r := h.run("status")
	if r.code != ExitOK || !strings.Contains(r.stdout, "Last Remote Control URL: "+testURL) {
		t.Fatalf("%d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if c := h.loadState().Controller; c.RemoteControlURL != testURL || c.URLFoundAt == nil {
		t.Fatalf("not recorded: %+v", c)
	}
}

// TestStatusLooksOnlyAtWardensRunningController: no lookup for a container
// up didn't start, or one that isn't running.
func TestStatusLooksOnlyAtWardensRunningController(t *testing.T) {
	for name, ctl := range map[string]string{
		"other ID": inspectJSON(strings.Repeat("3", 64), "running", "sha256:x"),
		"stopped":  inspectJSON(controllerID, "exited", "sha256:x"),
	} {
		h := upHost(t)
		h.scriptUp("Please log in.\n")
		h.run("up")
		before := countCalls(h, logsArgs...)
		h.fake.On([]string{"inspect", "--type", "container", "warden-proxy"}, dockertest.Response{Stdout: inspectJSON(proxyID, "running", exampleRuntimeImage)})
		h.fake.On([]string{"inspect", "--type", "container", "warden-controller"}, dockertest.Response{Stdout: ctl})
		if r := h.run("status"); r.code != ExitOK || countCalls(h, logsArgs...) != before {
			t.Errorf("%s: code %d, log read %d times", name, r.code, countCalls(h, logsArgs...)-before)
		}
	}
}
