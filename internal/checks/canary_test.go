package checks

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/checks/checkstest"
	"github.com/rviscuso/warden/internal/compose"
	"github.com/rviscuso/warden/internal/docker/dockertest"
	"github.com/rviscuso/warden/internal/hardening"
	"github.com/rviscuso/warden/internal/state"
	"github.com/rviscuso/warden/internal/wardenbin/wardenbintest"
)

const testRuntimeImage = "busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000"

var argsImage = checkstest.ArgsImage(testRuntimeImage)

// setupCanary gives the harness a canary environment and scripts a
// successful canary run. Tests override parts of the script.
func (h *harness) setupCanary() {
	h.env.GID = os.Getgid()
	h.cn = checkstest.Script(h.t, h.fake, h.root, h.env.Dirs.CanaryDir(), testRuntimeImage)
	exe := h.cn.Executable
	h.env.Canary = CanaryEnv{
		Executable: func() (string, error) { return exe, nil },
		Resolver:   h.cn.Net, Dialer: h.cn.Net, Listen: h.cn.Net.Listen,
		Rand: checkstest.ZeroReader{},
	}
}

func (h *harness) runDir() string { return h.cn.RunDir() }

func canaryResults(rep *Report) map[string]Result {
	m := map[string]Result{}
	for _, r := range rep.Results {
		if strings.HasPrefix(r.ID, "canary.") {
			m[r.ID] = r
		}
	}
	return m
}

func TestCanaryAllPass(t *testing.T) {
	h := newHarness(t)
	rep := h.run()
	cr := canaryResults(rep)
	if len(cr) != 19 {
		t.Fatalf("%d canary results: %v", len(cr), ids(rep))
	}
	for id, r := range cr {
		if r.Status != Pass {
			t.Errorf("%s: %s %q", id, r.Status, r.Detail)
		}
	}
	// The project handed to compose is the one Render produced, on stdin,
	// the same for create, start and down.
	var files [][]byte
	for i, c := range h.fake.Calls {
		if len(c) > 5 && c[0] == "compose" && c[4] == "-" {
			files = append(files, h.fake.Stdins[i])
		}
	}
	if len(files) != 3 || string(files[0]) != string(files[1]) || string(files[1]) != string(files[2]) {
		t.Fatalf("compose stdin: %d files", len(files))
	}
	if err := compose.Validate(files[0], compose.Policy{UID: h.env.UID, GID: h.env.GID, Socket: h.sock, MPTCP: hardening.MPTCPPresent}); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(h.env.Dirs.BinDir(), "warden-")
	if !strings.Contains(string(files[0]), bin) || !strings.Contains(string(files[0]), filepath.Join(h.runDir(), "mnt")) {
		t.Errorf("compose file doesn't mount the binary copy and the run directory:\n%s", files[0])
	}
	// The listener was only on the gateway; the probe was told where.
	if len(h.cn.Net.Listened()) != 1 || h.cn.Net.Listened()[0] != checkstest.Gateway+":0" {
		t.Errorf("listened on %v", h.cn.Net.Listened())
	}
	if !strings.HasPrefix(string(h.cn.Control()), "gateway="+checkstest.Gateway+"\nport=") {
		t.Errorf("control file %q", h.cn.Control())
	}
	if _, err := os.Stat(h.runDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("run directory left behind: %v", err)
	}
	for _, p := range []string{h.env.Dirs.BinDir(), h.env.Dirs.CanaryDir(), h.env.Dirs.CanaryLock()} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("init didn't create %s: %v", p, err)
		}
	}
	if !h.fake.Called(checkstest.ArgsDown) {
		t.Error("compose down not called")
	}
}

func TestCanaryNotRunAfterAFailure(t *testing.T) {
	h := newHarness(t)
	h.fake.OnFile(argsInfo, "testdata/docker-info-rootless.json")
	cr := canaryResults(h.run())
	for id, r := range cr {
		if r.Status != Fail || r.Detail != "not run: depends on daemon.mode" {
			t.Errorf("%s: %s %q", id, r.Status, r.Detail)
		}
	}
	if len(cr) != 19 || h.fake.Called(argsImage) {
		t.Fatalf("the canary ran on an unsupported daemon")
	}
}

func TestCanaryImageNotLocal(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsImage, dockertest.Response{ExitCode: 1, Stderr: "Error: No such image: " + testRuntimeImage})
	rep := h.run()
	r := expect(t, rep, "canary.image", Fail, "is not local; Warden never pulls")
	if r.Fix != "docker pull "+testRuntimeImage {
		t.Errorf("fix %q", r.Fix)
	}
	expect(t, rep, "canary.caps", Fail, "not run: depends on canary.image")
	expect(t, rep, "canary.cleanup", Fail, "not run: depends on canary.image")
	if h.fake.Called(checkstest.ArgsCreate) {
		t.Fatal("created the project without the image")
	}
}

func TestCanaryImageIDFix(t *testing.T) {
	h := newHarness(t)
	id := "sha256:" + strings.Repeat("1", 64)
	cfg, _ := os.ReadFile(filepath.Join(h.root, "config/warden/config.json"))
	os.WriteFile(filepath.Join(h.root, "config/warden/config.json"), []byte(strings.Replace(string(cfg), testRuntimeImage, id, 1)), 0o600)
	h.fake.On([]string{"image", "inspect", "--format", "{{.Id}}", id}, dockertest.Response{ExitCode: 1, Stderr: "Error: No such image"})
	r := expect(t, h.run(), "canary.image", Fail, "not local")
	if !strings.Contains(r.Fix, "load or build the image") {
		t.Errorf("fix %q", r.Fix)
	}
}

func TestCanaryLeftoversFailWithFix(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsLeftC, dockertest.Response{ExitCode: 1, Stdout: "/warden-canary\n", Stderr: "Error: No such container: warden-canary-proxy\n"})
	rep := h.run()
	r := expect(t, rep, "canary.caps", Fail, "left over from an earlier canary run")
	if r.Fix != "docker rm -f warden-canary" {
		t.Errorf("fix %q", r.Fix)
	}
	expect(t, rep, "canary.cleanup", Pass, "")
	if h.fake.Called(checkstest.ArgsCreate) || h.fake.Called(checkstest.ArgsDown) || h.fake.Called([]string{"rm", "-f", "warden-canary"}) {
		t.Fatal("touched the leftover or created the project")
	}
}

func TestCanaryLeftoverInspectErrorFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsLeftN, dockertest.Response{ExitCode: 1, Stderr: "permission denied while trying to connect"})
	expect(t, h.run(), "canary.caps", Fail, "permission denied")
}

func TestCanaryLocked(t *testing.T) {
	h := newHarness(t)
	f, err := os.OpenFile(h.env.Dirs.CanaryLock(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	r := expect(t, h.run(), "canary.caps", Fail, "another warden init or check is running its canary")
	if r.Fix == "" {
		t.Error("no fix")
	}
}

func TestCanaryCheckModeNeedsInit(t *testing.T) {
	h := newHarness(t)
	h.env.Mode = ModeCheck
	pin(t, h, zeroID, h.sock)
	r := expect(t, h.run(), "canary.caps", Fail, "")
	if !strings.Contains(r.Detail+r.Fix, "warden init") {
		t.Fatalf("%+v", r)
	}
	for _, p := range []string{h.env.Dirs.BinDir(), h.env.Dirs.CanaryDir(), h.env.Dirs.CanaryLock()} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("check created %s", p)
		}
	}
}

func TestCanaryCheckModeAfterInit(t *testing.T) {
	h := newHarness(t)
	if !h.run().OK() {
		t.Fatal("init failed")
	}
	h.env.Mode = ModeCheck
	pin(t, h, zeroID, h.sock)
	before := listTree(t, h.env.Dirs.State)
	rep := h.run()
	if !rep.OK() {
		for _, r := range rep.Results {
			t.Logf("%s %s %s", r.ID, r.Status, r.Detail)
		}
		t.Fatal("check after init failed")
	}
	if after := listTree(t, h.env.Dirs.State); after != before {
		t.Errorf("check changed the state directory:\nbefore %s\nafter  %s", before, after)
	}
}

func TestCanaryCheckModeBinaryChanged(t *testing.T) {
	h := newHarness(t)
	h.run()
	h.env.Mode = ModeCheck
	pin(t, h, zeroID, h.sock)
	exe, _ := h.env.Canary.Executable()
	os.WriteFile(exe, append(wardenbintest.Static(), 'x'), 0o755)
	r := expect(t, h.run(), "canary.caps", Fail, "no verified copy of this warden binary")
	if r.Fix != "run warden init" {
		t.Errorf("fix %q", r.Fix)
	}
}

func listTree(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && p != filepath.Join(root, "state.json") {
			b.WriteString(p + " " + fi.Mode().String() + "\n")
		}
		return nil
	})
	return b.String()
}

func TestCanaryProbeFailureFailsTheRun(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(map[string]string{"caps_bnd": "00000000a80425fb"})})
	rep := h.run()
	expect(t, rep, "canary.caps", Fail, "CapBnd 00000000a80425fb")
	if rep.OK() {
		t.Fatal("OK with capabilities")
	}
	expect(t, rep, "canary.cleanup", Pass, "")
}

func TestCanaryProbeExitNonZero(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsWait, dockertest.Response{Stdout: "2\n"})
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: "", Stderr: "warden probe: refusing to run"})
	rep := h.run()
	expect(t, rep, "canary.owner", Fail, "the probe exited 2: warden probe: refusing to run")
	expect(t, rep, "canary.cleanup", Pass, "")
}

func TestCanaryBadProbeOutput(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(nil) + "extra=1\n"})
	expect(t, h.run(), "canary.caps", Fail, `unknown key "extra"`)
}

func TestCanaryNoHostSkipped(t *testing.T) {
	h := newHarness(t)
	h.cn.Net.ListenErr = &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRNOTAVAIL)}
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(map[string]string{"no_host": "skipped"})})
	expect(t, h.run(), "canary.no-host", Pass, "host has no address on the sandbox network")
	if string(h.cn.Control()) != "no_host=skip\n" {
		t.Errorf("control %q", h.cn.Control())
	}
}

func TestCanaryNoHostOtherListenErrorCannotProve(t *testing.T) {
	h := newHarness(t)
	h.cn.Net.ListenErr = &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EACCES)}
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(map[string]string{"no_host": "skipped"})})
	expect(t, h.run(), "canary.no-host", Fail, "cannot prove")
}

func TestCanaryNoGatewayCannotProve(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsIPAM, dockertest.Response{Stdout: `[{"Subnet":"192.0.2.0/24"}]`})
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(map[string]string{"no_host": "skipped"})})
	expect(t, h.run(), "canary.no-host", Fail, "cannot prove: no IPv4 gateway")
	if len(h.cn.Net.Listened()) != 0 {
		t.Errorf("listened on %v", h.cn.Net.Listened())
	}
}

func TestCanaryControls(t *testing.T) {
	h := newHarness(t)
	h.cn.Net.DialErr = errors.New("network is unreachable")
	h.cn.Net.DNSErr = errors.New("no such host")
	rep := h.run()
	expect(t, rep, "canary.no-route", Fail, "cannot prove: host has no route to the control address")
	expect(t, rep, "canary.no-dns", Fail, "cannot prove")
}

func TestCanaryCleanupOnFailure(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsStart, dockertest.Response{ExitCode: 1, Stderr: "Error response from daemon: oci runtime error"})
	rep := h.run()
	expect(t, rep, "canary.caps", Fail, "oci runtime error")
	expect(t, rep, "canary.cleanup", Pass, "")
	if !h.fake.Called(checkstest.ArgsDown) {
		t.Error("compose down not called after a failed start")
	}
	if _, err := os.Stat(h.runDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("run directory left behind: %v", err)
	}
}

func TestCanaryCleanupFallsBackToIDs(t *testing.T) {
	h := newHarness(t)
	present := dockertest.Response{Stdout: "/warden-canary-proxy\n/warden-canary\n"}
	h.fake.On(checkstest.ArgsDown, dockertest.Response{ExitCode: 1, Stderr: "compose down failed", Do: func([]byte) {
		h.fake.On(checkstest.ArgsLeftC, present) // the containers are still there
	}})
	for _, id := range []string{checkstest.ContainerIDs[0], checkstest.ContainerIDs[1]} {
		h.fake.On([]string{"rm", "-f", id}, dockertest.Response{ExitCode: 1, Stderr: "cannot remove"})
	}
	for _, id := range []string{checkstest.NetworkIDs[0], checkstest.NetworkIDs[1]} {
		h.fake.On([]string{"network", "rm", id}, dockertest.Response{})
	}
	rep := h.run()
	r := expect(t, rep, "canary.cleanup", Fail, "container warden-canary-proxy is still there")
	if r.Fix != "docker rm -f warden-canary-proxy && docker rm -f warden-canary" {
		t.Errorf("fix %q", r.Fix)
	}
	if !h.fake.Called([]string{"rm", "-f", checkstest.ContainerIDs[0]}) {
		t.Error("no fallback to the recorded IDs")
	}
	if rep.OK() {
		t.Fatal("OK with leftovers")
	}
}

func TestCanaryIncompleteEnvFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.env.Canary.Listen = nil
	expect(t, h.run(), "canary.caps", Fail, "incomplete environment")
}

// TestCanaryNoSwapAccounting: without memory.swap.max, canary.memory
// passes only if the host's /proc/meminfo says there is no swap.
func TestCanaryNoSwapAccounting(t *testing.T) {
	for _, c := range []struct {
		meminfo string
		status  Status
		detail  string
	}{
		{"SwapTotal:             0 kB\n", Pass, "the host has no swap"},
		{"SwapTotal:       2097148 kB\n", Fail, "cannot prove no swap: the kernel has no memory.swap.max, and the host has 2097148 kB of swap"},
		{"", Fail, "cannot prove no swap"},
	} {
		h := newHarness(t)
		if c.meminfo != "" {
			h.write("hostfs/proc/meminfo", c.meminfo, 0o644)
		}
		h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(map[string]string{"memory_swap_max": "absent"})})
		expect(t, h.run(), "canary.memory", c.status, c.detail)
	}
}

// TestCanaryHostWithoutMPTCP: no /proc/sys/net/mptcp on the host means no
// sysctls in the project, and canary.mptcp needs the kernel to have no
// MPTCP inside the canary too.
func TestCanaryHostWithoutMPTCP(t *testing.T) {
	h := newHarness(t)
	os.RemoveAll(filepath.Join(h.root, "hostfs/proc/sys/net/mptcp"))
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(map[string]string{"mptcp": "absent", "mptcp_socket": "eprotonosupport"})})
	rep := h.run()
	expect(t, rep, "canary.mptcp", Pass, "the host has no MPTCP")
	var file []byte
	for i, c := range h.fake.Calls {
		if strings.Join(c, " ") == strings.Join(checkstest.ArgsCreate, " ") {
			file = h.fake.Stdins[i]
		}
	}
	if len(file) == 0 || strings.Contains(string(file), "sysctls") {
		t.Fatalf("project for a host without MPTCP:\n%s", file)
	}
	if err := compose.Validate(file, compose.Policy{UID: h.env.UID, GID: h.env.GID, Socket: h.sock, MPTCP: hardening.MPTCPAbsent}); err != nil {
		t.Fatal(err)
	}
	// The canary saying MPTCP is off-but-present on such a host fails.
	h = newHarness(t)
	os.RemoveAll(filepath.Join(h.root, "hostfs/proc/sys/net/mptcp"))
	expect(t, h.run(), "canary.mptcp", Fail, "the host has no MPTCP")
}

// TestCanaryMPTCPUnknownFailsClosed: if Warden can't tell whether the host
// has MPTCP, the canary doesn't run.
func TestCanaryMPTCPUnknownFailsClosed(t *testing.T) {
	h := newHarness(t)
	os.RemoveAll(filepath.Join(h.root, "hostfs/proc/sys/net"))
	h.write("hostfs/proc/sys/net", "", 0o644) // ENOTDIR
	rep := h.run()
	expect(t, rep, "canary.mptcp", Fail, "cannot tell whether the kernel has MPTCP")
	if h.fake.Called(checkstest.ArgsCreate) {
		t.Fatal("the canary was created")
	}
}

// TestCanaryRecord: a passing init run produces the record; ModeUp passes
// with it and fails on each kind of mismatch, without running the canary.
func TestCanaryRecord(t *testing.T) {
	h := newHarness(t)
	rep := h.run() // ModeInit: installs the binary copy, runs the canary
	if !rep.CanaryRan || rep.CanaryPass == nil {
		t.Fatalf("ran %v, pass %+v", rep.CanaryRan, rep.CanaryPass)
	}
	good := *rep.CanaryPass
	if good.DaemonID != rep.Daemon.ID || len(good.BinarySHA256) != 64 || len(good.HardeningSHA256) != 64 {
		t.Fatalf("record %+v", good)
	}
	save := func(cp *state.CanaryPass) {
		s := &state.State{Version: 1, Daemon: state.Daemon{ID: rep.Daemon.ID, Socket: h.sock}, InitializedAt: time.Now(), CanaryPass: cp}
		if err := state.Save(h.env.Dirs.StateFile(), s); err != nil {
			t.Fatal(err)
		}
	}
	up := func() *Report {
		h.env.Mode = ModeUp
		defer func() { h.env.Mode = ModeInit }()
		return h.run()
	}
	save(&good)
	creates := len(h.fake.Calls)
	r := up()
	expect(t, r, "canary.recorded", Pass, "on this daemon, with this binary and these settings")
	if r.CanaryRan {
		t.Error("ModeUp ran the canary")
	}
	for _, c := range h.fake.Calls[creates:] {
		if strings.Join(c, " ") == strings.Join(checkstest.ArgsCreate, " ") {
			t.Fatal("ModeUp created the canary")
		}
	}
	for name, c := range map[string]struct {
		edit func(*state.CanaryPass)
		want string
	}{
		"other daemon":   {func(p *state.CanaryPass) { p.DaemonID = "11111111-1111-1111-1111-111111111111" }, "daemon " + rep.Daemon.ID + ", recorded 11111111"},
		"other binary":   {func(p *state.CanaryPass) { p.BinarySHA256 = strings.Repeat("e", 64) }, "warden binary"},
		"other settings": {func(p *state.CanaryPass) { p.HardeningSHA256 = strings.Repeat("e", 64) }, "hardening settings"},
	} {
		bad := good
		c.edit(&bad)
		save(&bad)
		expect(t, up(), "canary.recorded", Fail, c.want)
		_ = name
	}
	save(nil)
	expect(t, up(), "canary.recorded", Fail, "no canary pass recorded")
}

// TestCanaryFailureHasNoRecord: a failing canary run produces no record,
// and says it ran, so the caller withdraws an older one.
func TestCanaryFailureHasNoRecord(t *testing.T) {
	h := newHarness(t)
	h.fake.On(checkstest.ArgsLogsC, dockertest.Response{Stdout: h.cn.ProbeOutput(map[string]string{"nnp": "0"})})
	rep := h.run()
	if !rep.CanaryRan || rep.CanaryPass != nil {
		t.Fatalf("ran %v, pass %+v", rep.CanaryRan, rep.CanaryPass)
	}
	// Not run at all (an earlier check failed): nothing to withdraw.
	h = newHarness(t)
	h.fake.On([]string{"compose", "version", "--format", "json"}, dockertest.Response{ExitCode: 1, Stderr: "no compose"})
	if rep := h.run(); rep.CanaryRan {
		t.Fatal("CanaryRan without running")
	}
}
