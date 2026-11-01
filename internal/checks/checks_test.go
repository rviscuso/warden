package checks

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/docker"
	"github.com/rviscuso/warden/internal/docker/dockertest"
	"github.com/rviscuso/warden/internal/paths"
	"github.com/rviscuso/warden/internal/state"
)

var (
	argsCompose = []string{"compose", "version", "--format", "json"}
	argsInfo    = []string{"info", "--format", "{{json .}}"}
	argsVersion = []string{"version", "--format", "{{json .}}"}
	argsPS      = []string{"ps", "-aq", "--no-trunc"}
)

const zeroID = "00000000-0000-0000-0000-000000000000"

// harness is a fake host: siblings root/home, root/ws, root/config,
// root/state, root/share, root/hostfs (filesystem root for host files),
// a real unix socket and a fake docker binary.
type harness struct {
	t          *testing.T
	root       string
	ws         string
	sock       string
	fake       *dockertest.Fake
	env        Env
	runnerOpts []docker.Options
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, root: root, ws: filepath.Join(root, "ws"), fake: dockertest.New(t)}
	dirs := paths.Dirs{
		Config: filepath.Join(root, "config", "warden"),
		State:  filepath.Join(root, "state", "warden"),
		Share:  filepath.Join(root, "share", "warden"),
	}
	for _, d := range []string{filepath.Join(root, "home"), h.ws, dirs.Config, dirs.State, dirs.Share, dirs.DockerConfigDir(), filepath.Join(root, "hostfs/sys/fs/cgroup"), filepath.Join(root, "bin")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h.write("hostfs/sys/fs/cgroup/cgroup.controllers", "cpu memory pids\n", 0o644)
	h.write("bin/docker", "", 0o755)

	h.sock = filepath.Join(root, "d.sock")
	l, err := net.Listen("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	h.writeConfig(h.ws, h.sock)
	h.env = Env{
		Mode:        ModeInit,
		EUID:        os.Geteuid(),
		UID:         os.Getuid(),
		Home:        filepath.Join(root, "home"),
		Dirs:        dirs,
		Root:        filepath.Join(root, "hostfs"),
		GOOS:        "linux",
		GOARCH:      "amd64",
		DockerPaths: []string{filepath.Join(root, "bin/docker")},
		NewRunner: func(o docker.Options) (docker.Runner, error) {
			h.runnerOpts = append(h.runnerOpts, o)
			return h.fake, nil
		},
		Ctx: context.Background(),
	}
	h.fake.OnFile(argsCompose, "testdata/compose-version.json")
	h.fake.OnFile(argsInfo, "testdata/docker-info-rootful.json")
	h.fake.OnFile(argsVersion, "testdata/docker-version.json")
	h.fake.On(argsPS, dockertest.Response{})
	return h
}

func (h *harness) write(rel, content string, mode os.FileMode) {
	h.t.Helper()
	p := filepath.Join(h.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) writeConfig(workspace, socket string) {
	h.t.Helper()
	digest := "sha256:" + strings.Repeat("0", 64)
	cfg := `{
  "version": 1,
  "docker": {"socket": "` + socket + `"},
  "runtime_image": "busybox@` + digest + `",
  "egress": {"allow": ["api.anthropic.com"]},
  "controller": {"image": "` + digest + `", "workspace": "` + workspace + `",
    "remote_control_name": "warden", "resources": {"memory_mb": 1536, "cpus": 1.5, "pids": 512}}
}`
	if err := os.WriteFile(filepath.Join(h.root, "config/warden/config.json"), []byte(cfg), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// fixture reads testdata/name with @ROOT@ replaced by the harness root.
func (h *harness) fixture(name string) string {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "@ROOT@", h.root)
}

func (h *harness) run() *Report {
	h.t.Helper()
	return Run(h.env)
}

func result(t *testing.T, rep *Report, id string) Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no result for %s in %v", id, ids(rep))
	return Result{}
}

func ids(rep *Report) []string {
	var out []string
	for _, r := range rep.Results {
		out = append(out, r.ID)
	}
	return out
}

func expect(t *testing.T, rep *Report, id string, st Status, detail string) Result {
	t.Helper()
	r := result(t, rep, id)
	if r.Status != st || !strings.Contains(r.Detail, detail) {
		t.Fatalf("%s: got %s %q, want %s containing %q", id, r.Status, r.Detail, st, detail)
	}
	return r
}

func TestAllPassInit(t *testing.T) {
	h := newHarness(t)
	rep := h.run()
	for _, r := range rep.Results {
		if r.Status != Pass {
			t.Errorf("%s: %s %q", r.ID, r.Status, r.Detail)
		}
	}
	if !rep.OK() {
		t.Fatal("report not OK")
	}
	want := []string{"config.valid", "workspace.valid", "host.not-root", "host.os", "host.cgroup2",
		"host.docker-cli", "host.docker-access", "host.compose", "daemon.reachable", "daemon.mode",
		"daemon.cgroup", "daemon.seccomp", "daemon.apparmor", "daemon.version", "host.shared-mounts"}
	if !slices.Equal(ids(rep), want) {
		t.Fatalf("checks %v\nwant %v", ids(rep), want)
	}
	wantDaemon := state.Daemon{ID: zeroID, Socket: h.sock, ServerVersion: "29.1.3", Runc: "1.4.0-0ubuntu1", Containerd: "2.2.2", Compose: "2.40.3+ds1-0ubuntu1"}
	if rep.Daemon != wantDaemon {
		t.Fatalf("daemon %+v", rep.Daemon)
	}
	if rep.Workspace != h.ws {
		t.Fatalf("workspace %q", rep.Workspace)
	}
	expect(t, rep, "host.docker-access", Pass, RootEquivalent)
	expect(t, rep, "daemon.version", Pass, "29.1.3, on the tested list; runc 1.4.0-0ubuntu1, containerd 2.2.2")
	expect(t, rep, "host.shared-mounts", Pass, "no containers")
	o := h.runnerOpts[0]
	if len(h.runnerOpts) != 1 || o.Socket != h.sock || o.StateDir != h.env.Dirs.State || o.Binary != h.env.DockerPaths[0] {
		t.Fatalf("runner options %+v", h.runnerOpts)
	}
}

func pin(t *testing.T, h *harness, id, sock string) {
	t.Helper()
	err := state.Save(h.env.Dirs.StateFile(), &state.State{
		Version: 1, WardenVersion: "test",
		Daemon:        state.Daemon{ID: id, Socket: sock},
		InitializedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckModePin(t *testing.T) {
	h := newHarness(t)
	h.env.Mode = ModeCheck

	rep := h.run()
	expect(t, rep, "daemon.pin", Fail, "no pinned daemon")
	if result(t, rep, "daemon.pin").Fix != "run warden init" {
		t.Fatal("fix")
	}

	pin(t, h, zeroID, h.sock)
	rep = h.run()
	expect(t, rep, "daemon.pin", Pass, "pinned "+zeroID)
	if !rep.OK() {
		t.Fatal("not OK")
	}

	pin(t, h, "11111111-1111-1111-1111-111111111111", h.sock)
	r := expect(t, h.run(), "daemon.pin", Fail, "daemon changed")
	if r.Fix != "daemon changed; re-run init" {
		t.Fatalf("fix %q", r.Fix)
	}

	pin(t, h, zeroID, "/other/docker.sock")
	expect(t, h.run(), "daemon.pin", Fail, "pinned "+zeroID+" at /other/docker.sock")

	os.WriteFile(h.env.Dirs.StateFile(), []byte("{"), 0o600)
	expect(t, h.run(), "daemon.pin", Fail, "state")
}

func TestInitModeHasNoPinCheck(t *testing.T) {
	h := newHarness(t)
	pin(t, h, "11111111-1111-1111-1111-111111111111", h.sock)
	rep := h.run()
	if slices.Contains(ids(rep), "daemon.pin") {
		t.Fatal("init ran daemon.pin")
	}
}

func TestCheckModeCreatesNothing(t *testing.T) {
	h := newHarness(t)
	h.env.Mode = ModeCheck
	os.Remove(h.env.Dirs.DockerConfigDir())
	rep := h.run()
	r := expect(t, rep, "host.compose", Fail, "does not exist")
	if r.Fix != "run warden init" {
		t.Fatalf("fix %q", r.Fix)
	}
	if len(h.runnerOpts) != 0 {
		t.Fatal("check created a runner (which would create docker-config)")
	}
	if _, err := os.Stat(h.env.Dirs.DockerConfigDir()); err == nil {
		t.Fatal("docker-config was created")
	}
}

func TestDaemonFixtures(t *testing.T) {
	cases := []struct {
		fixture string
		id      string
		st      Status
		detail  string
	}{
		{"docker-info-rootless.json", "daemon.mode", Fail, "name=rootless: not supported in v1"},
		{"docker-info-userns.json", "daemon.mode", Fail, "name=userns: not supported in v1"},
		{"docker-info-cgroupv1.json", "daemon.cgroup", Fail, `CgroupVersion is "1"`},
		{"docker-info-no-apparmor.json", "daemon.apparmor", Warn, "weaker isolation"},
		{"docker-info-rootful.json", "daemon.seccomp", Pass, "seccomp"},
	}
	for _, c := range cases {
		h := newHarness(t)
		h.fake.OnFile(argsInfo, "testdata/"+c.fixture)
		rep := h.run()
		expect(t, rep, c.id, c.st, c.detail)
		if c.st == Warn && !rep.OK() {
			t.Errorf("%s: a warning must not fail the run", c.fixture)
		}
	}
}

func TestNoSeccomp(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsInfo, dockertest.Response{Stdout: `{"ID":"x","CgroupVersion":"2","SecurityOptions":["name=seccompx","name=apparmor"]}`})
	expect(t, h.run(), "daemon.seccomp", Fail, "no name=seccomp")
}

func TestCgroupVersionMustBeAString(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsInfo, dockertest.Response{Stdout: `{"ID":"x","CgroupVersion":2,"SecurityOptions":["name=seccomp"]}`})
	expect(t, h.run(), "daemon.reachable", Fail, "unexpected docker info output")
}

func TestUnreachable(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsInfo, dockertest.Response{Stdout: h.fixture("docker-info-unreachable.json"), ExitCode: 1})
	rep := h.run()
	expect(t, rep, "daemon.reachable", Fail, "Cannot connect to the Docker daemon")
	for _, id := range []string{"daemon.mode", "daemon.cgroup", "daemon.seccomp", "daemon.apparmor", "daemon.version", "host.shared-mounts"} {
		expect(t, rep, id, Fail, "not run: depends on daemon.reachable")
	}
	if rep.OK() {
		t.Fatal("unreachable daemon reported OK")
	}

	h = newHarness(t)
	h.fake.On(argsInfo, dockertest.Response{Stderr: "permission denied while trying to connect", ExitCode: 1})
	expect(t, h.run(), "daemon.reachable", Fail, "permission denied")

	h = newHarness(t)
	h.fake.On(argsInfo, dockertest.Response{Stdout: `{"ID":""}`})
	expect(t, h.run(), "daemon.reachable", Fail, "no daemon ID")

	h = newHarness(t)
	h.fake.On(argsInfo, dockertest.Response{Err: context.DeadlineExceeded})
	expect(t, h.run(), "daemon.reachable", Fail, "deadline exceeded")
}

func TestConfigMissing(t *testing.T) {
	h := newHarness(t)
	os.Remove(filepath.Join(h.root, "config/warden/config.json"))
	rep := h.run()
	r := expect(t, rep, "config.valid", Fail, "does not exist")
	if !strings.Contains(r.Fix, "warden init prints an example") {
		t.Fatalf("fix %q", r.Fix)
	}
	for _, id := range []string{"workspace.valid", "host.docker-access", "host.compose", "daemon.reachable"} {
		expect(t, rep, id, Fail, "not run: depends on config.valid")
	}
	expect(t, rep, "host.docker-cli", Pass, "docker") // independent checks still run
	if len(h.fake.Calls) != 0 {
		t.Fatalf("docker called without a config: %v", h.fake.Calls)
	}
}

func TestConfigInvalid(t *testing.T) {
	h := newHarness(t)
	os.WriteFile(filepath.Join(h.root, "config/warden/config.json"), []byte(`{"version":2}`), 0o600)
	expect(t, h.run(), "config.valid", Fail, "version: must be 1")
}

func TestWorkspaceInvalid(t *testing.T) {
	h := newHarness(t)
	h.writeConfig(h.env.Home, h.sock)
	rep := h.run()
	expect(t, rep, "workspace.valid", Fail, "[rule home]")
	expect(t, rep, "host.shared-mounts", Fail, "not run: depends on workspace.valid")

	h = newHarness(t)
	h.writeConfig(filepath.Join(h.root, "state"), h.sock) // contains Warden's state dir
	expect(t, h.run(), "workspace.valid", Fail, "[rule warden-dir]")
}

func TestHostChecks(t *testing.T) {
	h := newHarness(t)
	h.env.EUID = 0
	expect(t, h.run(), "host.not-root", Fail, "effective UID is 0")

	for _, oa := range [][2]string{{"darwin", "arm64"}, {"linux", "386"}, {"linux", "riscv64"}} {
		h = newHarness(t)
		h.env.GOOS, h.env.GOARCH = oa[0], oa[1]
		expect(t, h.run(), "host.os", Fail, "is not supported")
	}
	h = newHarness(t)
	h.env.GOARCH = "arm64"
	expect(t, h.run(), "host.os", Pass, "linux/arm64")

	h = newHarness(t)
	os.Remove(filepath.Join(h.root, "hostfs/sys/fs/cgroup/cgroup.controllers"))
	expect(t, h.run(), "host.cgroup2", Fail, "not found")
}

func TestDockerCLIMissing(t *testing.T) {
	h := newHarness(t)
	h.env.DockerPaths = []string{filepath.Join(h.root, "bin/nope")}
	rep := h.run()
	expect(t, rep, "host.docker-cli", Fail, "not found")
	expect(t, rep, "host.compose", Fail, "not run: depends on host.docker-cli")
	expect(t, rep, "daemon.reachable", Fail, "not run: depends on host.docker-cli")
}

func TestDockerAccess(t *testing.T) {
	h := newHarness(t)
	h.writeConfig(h.ws, filepath.Join(h.root, "missing.sock"))
	rep := h.run()
	expect(t, rep, "host.docker-access", Fail, RootEquivalent)
	expect(t, rep, "daemon.reachable", Fail, "not run: depends on host.docker-access")

	h = newHarness(t)
	h.write("plain.sock", "", 0o600)
	h.writeConfig(h.ws, filepath.Join(h.root, "plain.sock"))
	expect(t, h.run(), "host.docker-access", Fail, "is not a socket")

	if os.Geteuid() != 0 { // root bypasses permission bits
		h = newHarness(t)
		os.Chmod(h.sock, 0o000)
		r := expect(t, h.run(), "host.docker-access", Fail, "no read/write access")
		if !strings.Contains(r.Fix, "usermod -aG docker") || !strings.Contains(r.Detail, RootEquivalent) {
			t.Fatalf("got %+v", r)
		}
	}
}

func TestCompose(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsCompose, dockertest.Response{Stderr: "docker: 'compose' is not a docker command.", ExitCode: 1})
	expect(t, h.run(), "host.compose", Fail, "'compose' is not a docker command")

	h = newHarness(t)
	h.fake.On(argsCompose, dockertest.Response{Stdout: `{"version":""}`})
	expect(t, h.run(), "host.compose", Fail, "unexpected output")

	h = newHarness(t)
	h.fake.On(argsCompose, dockertest.Response{Stdout: `Docker Compose version v2.40.3`})
	expect(t, h.run(), "host.compose", Fail, "unexpected output")
}

func versionJSON(v string) string {
	return `{"Server":{"Version":"` + v + `","Components":[{"Name":"runc","Version":"1.1.0"}]}}`
}

func TestDaemonVersion(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsVersion, dockertest.Response{Stdout: versionJSON("24.0.7")})
	rep := h.run()
	expect(t, rep, "daemon.version", Warn, "older than 25.0")
	if !rep.OK() {
		t.Fatal("a version warning must not fail the run")
	}

	h = newHarness(t)
	h.fake.On(argsVersion, dockertest.Response{Stdout: versionJSON("25.0.0")})
	expect(t, h.run(), "daemon.version", Pass, "not on the tested list (29.1.3)")

	h = newHarness(t)
	h.fake.On(argsVersion, dockertest.Response{Stdout: versionJSON("30.0.1+distro")})
	r := expect(t, h.run(), "daemon.version", Pass, "Engine 30.0.1+distro, not on the tested list")
	if !strings.Contains(r.Detail, "containerd unknown") {
		t.Fatalf("detail %q", r.Detail)
	}

	h = newHarness(t)
	h.fake.On(argsVersion, dockertest.Response{Stdout: versionJSON("dev")})
	expect(t, h.run(), "daemon.version", Fail, `cannot parse engine version "dev"`)

	h = newHarness(t)
	h.fake.On(argsVersion, dockertest.Response{Stdout: `{"Server":null}`, ExitCode: 0})
	expect(t, h.run(), "daemon.version", Fail, "unexpected docker version output")
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string][3]int{
		"29.1.3": {29, 1, 3}, "2.40.3+ds1-0ubuntu1": {2, 40, 3}, "1.4.0-0ubuntu1": {1, 4, 0}, "25.0.10": {25, 0, 10},
	} {
		if got, ok := ParseVersion(in); !ok || got != want {
			t.Errorf("ParseVersion(%q) = %v, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "v29.1.3", "29.1", "dev", "x.1.2"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
	if !less([3]int{24, 9, 9}, MinEngineVersion) || less([3]int{25, 0, 0}, MinEngineVersion) {
		t.Fatal("version comparison")
	}
}

func inspectArgs(ids ...string) []string {
	return append([]string{"inspect", "--type", "container"}, ids...)
}

var fixtureIDs = []string{
	"1111111111111111111111111111111111111111111111111111111111111111",
	"2222222222222222222222222222222222222222222222222222222222222222",
	"3333333333333333333333333333333333333333333333333333333333333333",
	"4444444444444444444444444444444444444444444444444444444444444444",
}

func TestSharedMounts(t *testing.T) {
	h := newHarness(t)
	os.MkdirAll(filepath.Join(h.root, "srv/data"), 0o700)
	h.fake.On(argsPS, dockertest.Response{Stdout: strings.Join(fixtureIDs, "\n") + "\n"})
	h.fake.On(inspectArgs(fixtureIDs...), dockertest.Response{Stdout: h.fixture("docker-inspect-shared.json")})
	h.fake.On([]string{"volume", "inspect", "wsvol", "plainvol"}, dockertest.Response{Stdout: h.fixture("docker-volume-inspect.json")})
	rep := h.run()
	r := expect(t, rep, "host.shared-mounts", Fail, "container mounts-workspace (222222222222): bind mount "+h.ws+" -> /src is "+h.ws)
	for _, want := range []string{
		"container mounts-parent-of-state (333333333333): bind mount " + h.root + " -> /host contains",
		"container bind-volume (444444444444): volume wsvol (o=bind) " + h.ws + "/sub -> /w is inside " + h.ws,
	} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("detail lacks %q:\n%s", want, r.Detail)
		}
	}
	for _, not := range []string{"unrelated", "plainvol", "/run"} {
		if strings.Contains(r.Detail, not) {
			t.Errorf("detail mentions %q:\n%s", not, r.Detail)
		}
	}
	if r.Fix != "remove that container (docker rm -f <name>) or recreate it without the mount" {
		t.Errorf("fix %q", r.Fix)
	}
	if rep.OK() {
		t.Fatal("shared mounts reported OK")
	}
}

func TestSharedMountsUnrelatedPasses(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsPS, dockertest.Response{Stdout: fixtureIDs[0] + "\n"})
	insp := `[{"Id":"` + fixtureIDs[0] + `","Name":"/unrelated","Mounts":[{"Type":"bind","Source":"` + h.root + `/srv/data","Destination":"/data"}]}]`
	h.fake.On(inspectArgs(fixtureIDs[0]), dockertest.Response{Stdout: insp})
	expect(t, h.run(), "host.shared-mounts", Pass, "1 containers inspected")
}

func TestSharedMountsResolvesSymlinkedSource(t *testing.T) {
	// The container's recorded source is a symlink to the workspace.
	h := newHarness(t)
	link := filepath.Join(h.root, "link-to-ws")
	os.Symlink(h.ws, link)
	h.fake.On(argsPS, dockertest.Response{Stdout: fixtureIDs[0]})
	insp := `[{"Id":"` + fixtureIDs[0] + `","Name":"/sneaky","Mounts":[{"Type":"bind","Source":"` + link + `","Destination":"/x"}]}]`
	h.fake.On(inspectArgs(fixtureIDs[0]), dockertest.Response{Stdout: insp})
	expect(t, h.run(), "host.shared-mounts", Fail, "container sneaky")
}

func TestSharedMountsMountingWardenDirs(t *testing.T) {
	h := newHarness(t)
	for i, dir := range []string{h.env.Dirs.Config, h.env.Dirs.State + "/compose", filepath.Join(h.root, "share")} {
		h.fake.On(argsPS, dockertest.Response{Stdout: fixtureIDs[0]})
		insp := `[{"Id":"` + fixtureIDs[0] + `","Name":"/c","Mounts":[{"Type":"bind","Source":"` + dir + `","Destination":"/x"}]}]`
		h.fake.On(inspectArgs(fixtureIDs[0]), dockertest.Response{Stdout: insp})
		if r := result(t, h.run(), "host.shared-mounts"); r.Status != Fail {
			t.Errorf("case %d (%s): %+v", i, dir, r)
		}
	}
}

func TestSharedMountsFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.fake.On(argsPS, dockertest.Response{Stdout: fixtureIDs[0]})
	h.fake.On(inspectArgs(fixtureIDs[0]), dockertest.Response{Stderr: "Error: No such object", ExitCode: 1})
	expect(t, h.run(), "host.shared-mounts", Fail, "No such object")

	h = newHarness(t)
	h.fake.On(argsPS, dockertest.Response{Stdout: fixtureIDs[0]})
	h.fake.On(inspectArgs(fixtureIDs[0]), dockertest.Response{Stdout: "not json"})
	expect(t, h.run(), "host.shared-mounts", Fail, "unexpected docker inspect output")

	h = newHarness(t)
	h.fake.On(argsPS, dockertest.Response{Stdout: fixtureIDs[0]})
	insp := `[{"Id":"` + fixtureIDs[0] + `","Name":"/v","Mounts":[{"Type":"volume","Name":"gone","Destination":"/x"}]}]`
	h.fake.On(inspectArgs(fixtureIDs[0]), dockertest.Response{Stdout: insp})
	h.fake.On([]string{"volume", "inspect", "gone"}, dockertest.Response{Stdout: "[]"})
	expect(t, h.run(), "host.shared-mounts", Fail, `volume "gone" was not inspected`)

	h = newHarness(t)
	h.fake.On(argsPS, dockertest.Response{Stdout: fixtureIDs[0]})
	insp = `[{"Id":"` + fixtureIDs[0] + `","Name":"/r","Mounts":[{"Type":"bind","Source":"relative/path","Destination":"/x"}]}]`
	h.fake.On(inspectArgs(fixtureIDs[0]), dockertest.Response{Stdout: insp})
	expect(t, h.run(), "host.shared-mounts", Fail, "non-absolute source")

	h = newHarness(t)
	h.fake.On(argsPS, dockertest.Response{Stderr: "boom", ExitCode: 1})
	expect(t, h.run(), "host.shared-mounts", Fail, "boom")
}

func TestBindDevice(t *testing.T) {
	cases := []struct {
		opts map[string]string
		dev  string
		ok   bool
	}{
		{map[string]string{"o": "bind", "device": "/a", "type": "none"}, "/a", true},
		{map[string]string{"o": "rw,bind", "device": "/a"}, "/a", true},
		{map[string]string{"o": "rbind", "device": "/a"}, "", false},
		{map[string]string{"o": "bind"}, "", false},
		{map[string]string{"device": "/a"}, "", false},
		{nil, "", false},
	}
	for _, c := range cases {
		dev, ok := inspectedVolume{Options: c.opts}.bindDevice()
		if dev != c.dev || ok != c.ok {
			t.Errorf("%v: got %q %v", c.opts, dev, ok)
		}
	}
}

func TestSecurityOption(t *testing.T) {
	i := &dockerInfo{SecurityOptions: []string{"name=seccomp,profile=builtin", "name=cgroupns"}}
	if !i.securityOption("seccomp") || !i.securityOption("cgroupns") || i.securityOption("apparmor") || i.securityOption("profile=builtin") {
		t.Fatal("securityOption")
	}
}

func TestTestedVersions(t *testing.T) {
	if !slices.Equal(TestedEngineVersions, []string{"29.1.3"}) || MinEngineVersion != [3]int{25, 0, 0} {
		t.Fatalf("tested %v min %v", TestedEngineVersions, MinEngineVersion)
	}
}
