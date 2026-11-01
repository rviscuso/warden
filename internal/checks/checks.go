// Package checks runs Warden's host, config and daemon checks. Each check
// returns a Result; a check whose dependency failed is itself a fail ("not
// run: depends on …"), so nothing is ever assumed to hold (fail closed).
//
// Everything outside the process comes in through Env: the filesystem root
// for host files, the IDs, the docker runner. Tests need no Docker.
package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/docker"
	"github.com/rviscuso/warden/internal/mounts"
	"github.com/rviscuso/warden/internal/paths"
	"github.com/rviscuso/warden/internal/state"
)

// Status of one check.
type Status string

// Statuses.
const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Result is one check's outcome.
type Result struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// Mode selects which checks run.
type Mode int

// Modes.
const (
	ModeInit  Mode = iota // every check except daemon.pin
	ModeCheck             // every check, read-only
)

// MinEngineVersion: daemon.version warns below it.
var MinEngineVersion = [3]int{25, 0, 0}

// TestedEngineVersions are the Docker Engine versions Warden has been
// verified on, live. daemon.version reports whether the daemon is one.
var TestedEngineVersions = []string{"29.1.3"}

// RootEquivalent is printed with host.docker-access on every run.
const RootEquivalent = "Docker socket access is root-equivalent on this host"

// Env is everything the checks may touch.
type Env struct {
	Mode        Mode
	EUID        int
	UID         int
	Home        string
	Dirs        paths.Dirs
	Root        string // filesystem root for host files: "/" in production
	GOOS        string
	GOARCH      string
	DockerPaths []string
	// SystemDirs overrides mounts.DefaultSystemDirs for workspace validation.
	// Tests point it at fixtures so they pass wherever the temp dir lives;
	// empty means the default list (it can never switch the rule off).
	SystemDirs []string
	// NewRunner builds the docker runner (production: docker.New).
	NewRunner func(docker.Options) (docker.Runner, error)
	Ctx       context.Context
}

// Report is the outcome of a run, plus what init needs to pin the daemon.
type Report struct {
	Results   []Result
	Config    *config.Config
	Workspace string       // resolved, if workspace.valid passed
	Daemon    state.Daemon // what was observed (valid when OK())
}

// OK reports whether no check failed.
func (r *Report) OK() bool {
	for _, res := range r.Results {
		if res.Status == Fail {
			return false
		}
	}
	return true
}

type run struct {
	env    Env
	rep    *Report
	status map[string]Status

	runner    docker.Runner
	runnerErr error
	info      *dockerInfo
}

// Run runs the checks for env.Mode in dependency order.
func Run(env Env) *Report {
	if env.Ctx == nil {
		env.Ctx = context.Background()
	}
	r := &run{env: env, rep: &Report{}, status: map[string]Status{}}

	r.configValid()
	r.workspaceValid()
	r.notRoot()
	r.hostOS()
	r.cgroup2()
	r.dockerCLI()
	r.dockerAccess()
	r.compose()
	r.daemonReachable()
	r.daemonMode()
	r.daemonCgroup()
	r.daemonSeccomp()
	r.daemonAppArmor()
	r.daemonVersion()
	if env.Mode == ModeCheck {
		r.daemonPin()
	}
	r.sharedMounts()
	return r.rep
}

func (r *run) add(res Result) {
	r.rep.Results = append(r.rep.Results, res)
	r.status[res.ID] = res.Status
}

func (r *run) pass(id, title, detail string) {
	r.add(Result{ID: id, Title: title, Status: Pass, Detail: detail})
}
func (r *run) warn(id, title, detail, fix string) {
	r.add(Result{ID: id, Title: title, Status: Warn, Detail: detail, Fix: fix})
}
func (r *run) fail(id, title, detail, fix string) {
	r.add(Result{ID: id, Title: title, Status: Fail, Detail: detail, Fix: fix})
}

// need records a fail for id unless every dependency passed or warned.
func (r *run) need(id, title string, deps ...string) bool {
	for _, d := range deps {
		if s, ok := r.status[d]; !ok || s == Fail {
			r.fail(id, title, "not run: depends on "+d, "")
			return false
		}
	}
	return true
}

func oneLine(err error) string { return strings.ReplaceAll(err.Error(), "\n", "; ") }

// ---- config ----

func (r *run) configValid() {
	const id, title = "config.valid", "config.json is valid"
	file := r.env.Dirs.ConfigFile()
	c, err := config.Load(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.fail(id, title, file+" does not exist", "write "+paths.ShellQuote(file)+" (warden init prints an example)")
	case err != nil:
		r.fail(id, title, oneLine(err), "edit "+paths.ShellQuote(file))
	default:
		r.rep.Config = c
		r.pass(id, title, file)
	}
}

func (r *run) policy() mounts.Policy {
	return mounts.Policy{
		UID:        r.env.UID,
		Home:       r.env.Home,
		WardenDirs: r.wardenDirs(),
		Socket:     r.rep.Config.Docker.Socket,
		SystemDirs: r.env.SystemDirs,
	}
}

func (r *run) wardenDirs() []string {
	return []string{r.env.Dirs.Config, r.env.Dirs.State, r.env.Dirs.Share}
}

func (r *run) workspaceValid() {
	const id, title = "workspace.valid", "workspace passes mount validation"
	if !r.need(id, title, "config.valid") {
		return
	}
	ws, err := mounts.ValidateWorkspace(r.rep.Config.Controller.Workspace, r.policy())
	if err != nil {
		var me *mounts.Error
		rule := ""
		if errors.As(err, &me) {
			rule = " [rule " + string(me.Rule) + "]"
		}
		r.fail(id, title, err.Error()+rule, "point controller.workspace at the repository directory itself, owned by you")
		return
	}
	r.rep.Workspace = ws
	r.pass(id, title, ws)
}

// ---- host ----

func (r *run) notRoot() {
	const id, title = "host.not-root", "not running as root"
	if r.env.EUID == 0 {
		r.fail(id, title, "effective UID is 0", "run Warden as your own user, not root or sudo")
		return
	}
	r.pass(id, title, "uid "+strconv.Itoa(r.env.EUID))
}

func (r *run) hostOS() {
	const id, title = "host.os", "Linux on amd64 or arm64"
	osarch := r.env.GOOS + "/" + r.env.GOARCH
	if r.env.GOOS != "linux" || (r.env.GOARCH != "amd64" && r.env.GOARCH != "arm64") {
		r.fail(id, title, osarch+" is not supported", "run Warden on Linux, amd64 or arm64")
		return
	}
	r.pass(id, title, osarch)
}

func (r *run) cgroup2() {
	const id, title = "host.cgroup2", "cgroup v2"
	p := filepath.Join(r.env.Root, "sys/fs/cgroup/cgroup.controllers")
	if _, err := os.Stat(p); err != nil {
		r.fail(id, title, "/sys/fs/cgroup/cgroup.controllers not found: cgroup v2 is not mounted", "boot with the unified cgroup hierarchy (systemd.unified_cgroup_hierarchy=1)")
		return
	}
	r.pass(id, title, "unified hierarchy mounted")
}

func (r *run) dockerCLI() {
	const id, title = "host.docker-cli", "docker CLI at a fixed path"
	bin, err := docker.FindBinary(r.env.DockerPaths)
	if err != nil {
		r.fail(id, title, err.Error(), "install the Docker CLI (it must be at "+strings.Join(r.env.DockerPaths, " or ")+")")
		return
	}
	r.pass(id, title, bin)
}

const (
	accessR = 0x4 // R_OK
	accessW = 0x2 // W_OK
)

func (r *run) dockerAccess() {
	const id, title = "host.docker-access", "Docker socket accessible"
	if !r.need(id, title, "config.valid") {
		return
	}
	sock := r.rep.Config.Docker.Socket
	fi, err := os.Stat(sock)
	if err != nil {
		r.fail(id, title, sock+": "+err.Error()+"; "+RootEquivalent, "start Docker, or set docker.socket in config.json to the daemon's socket")
		return
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		r.fail(id, title, sock+" is not a socket; "+RootEquivalent, "set docker.socket in config.json to the daemon's socket")
		return
	}
	if err := syscall.Access(sock, accessR|accessW); err != nil {
		r.fail(id, title, sock+": no read/write access ("+err.Error()+"); "+RootEquivalent,
			"sudo usermod -aG docker \"$USER\", then log out and back in")
		return
	}
	r.pass(id, title, sock+"; "+RootEquivalent)
}

// dockerRunner builds the runner once. In check mode docker-config must
// already exist: check creates nothing.
func (r *run) dockerRunner() (docker.Runner, error) {
	if r.runner != nil || r.runnerErr != nil {
		return r.runner, r.runnerErr
	}
	if r.env.Mode == ModeCheck {
		if err := paths.CheckDir(r.env.Dirs.DockerConfigDir(), r.env.UID); err != nil {
			r.runnerErr = err
			return nil, err
		}
	}
	bin, err := docker.FindBinary(r.env.DockerPaths)
	if err != nil {
		r.runnerErr = err
		return nil, err
	}
	r.runner, r.runnerErr = r.env.NewRunner(docker.Options{
		Binary:   bin,
		Socket:   r.rep.Config.Docker.Socket,
		Home:     r.env.Home,
		StateDir: r.env.Dirs.State,
		UID:      r.env.UID,
	})
	return r.runner, r.runnerErr
}

// docker runs one docker command; any failure to run, or a non-zero exit,
// is an error carrying stderr.
func (r *run) docker(args ...string) ([]byte, error) {
	rn, err := r.dockerRunner()
	if err != nil {
		return nil, fmt.Errorf("cannot run docker: %w", err)
	}
	out, errOut, code, err := rn.Run(r.env.Ctx, args, nil)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		msg := strings.TrimSpace(string(errOut))
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		return out, fmt.Errorf("docker %s exited %d: %s", args[0], code, msg)
	}
	return out, nil
}

func fixOf(err error) string {
	var de *paths.DirError
	if errors.As(err, &de) {
		return de.Fix
	}
	return ""
}

func (r *run) compose() {
	const id, title = "host.compose", "docker compose works"
	if !r.need(id, title, "config.valid", "host.docker-cli") {
		return
	}
	out, err := r.docker("compose", "version", "--format", "json")
	if err != nil {
		r.fail(id, title, oneLine(err), or(fixOf(err), "install the Docker Compose v2 plugin"))
		return
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &v); err != nil || v.Version == "" {
		r.fail(id, title, "unexpected output from docker compose version: "+strings.TrimSpace(string(out)), "install the Docker Compose v2 plugin")
		return
	}
	r.rep.Daemon.Compose = v.Version
	r.pass(id, title, "Compose "+v.Version)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- daemon ----

type dockerInfo struct {
	ID              string   `json:"ID"`
	CgroupVersion   string   `json:"CgroupVersion"`
	SecurityOptions []string `json:"SecurityOptions"`
	ServerErrors    []string `json:"ServerErrors"`
}

// securityOption reports whether the daemon lists name=<name>
// ("name=seccomp,profile=builtin" counts as seccomp).
func (i *dockerInfo) securityOption(name string) bool {
	for _, opt := range i.SecurityOptions {
		for _, kv := range strings.Split(opt, ",") {
			if kv == "name="+name {
				return true
			}
		}
	}
	return false
}

func (r *run) daemonReachable() {
	const id, title = "daemon.reachable", "daemon answers on the configured socket"
	if !r.need(id, title, "config.valid", "host.docker-cli", "host.docker-access") {
		return
	}
	out, err := r.docker("info", "--format", "{{json .}}")
	var info dockerInfo
	if out != nil {
		if jerr := json.Unmarshal(out, &info); jerr != nil && err == nil {
			err = fmt.Errorf("unexpected docker info output: %v", jerr)
		}
	}
	switch {
	case len(info.ServerErrors) > 0:
		r.fail(id, title, strings.Join(info.ServerErrors, "; "), "start Docker (sudo systemctl start docker) or fix docker.socket in config.json")
		return
	case err != nil:
		r.fail(id, title, oneLine(err), or(fixOf(err), "start Docker (sudo systemctl start docker) or fix docker.socket in config.json"))
		return
	case info.ID == "":
		r.fail(id, title, "docker info returned no daemon ID", "")
		return
	}
	r.info = &info
	r.rep.Daemon.ID = info.ID
	r.rep.Daemon.Socket = r.rep.Config.Docker.Socket
	r.pass(id, title, "daemon "+info.ID)
}

func (r *run) daemonMode() {
	const id, title = "daemon.mode", "rootful daemon (no rootless, no userns-remap)"
	if !r.need(id, title, "daemon.reachable") {
		return
	}
	for _, m := range []string{"rootless", "userns"} {
		if r.info.securityOption(m) {
			r.fail(id, title, "daemon runs with name="+m+": not supported in v1 (container UIDs no longer map to host UIDs)", "use Docker's default rootful daemon")
			return
		}
	}
	r.pass(id, title, "rootful")
}

func (r *run) daemonCgroup() {
	const id, title = "daemon.cgroup", "daemon uses cgroup v2"
	if !r.need(id, title, "daemon.reachable") {
		return
	}
	if r.info.CgroupVersion != "2" {
		r.fail(id, title, fmt.Sprintf("CgroupVersion is %q", r.info.CgroupVersion), "boot with the unified cgroup hierarchy and restart Docker")
		return
	}
	r.pass(id, title, "CgroupVersion 2")
}

func (r *run) daemonSeccomp() {
	const id, title = "daemon.seccomp", "seccomp available"
	if !r.need(id, title, "daemon.reachable") {
		return
	}
	if !r.info.securityOption("seccomp") {
		r.fail(id, title, "SecurityOptions has no name=seccomp", "use a Docker build with seccomp support")
		return
	}
	r.pass(id, title, "seccomp")
}

func (r *run) daemonAppArmor() {
	const id, title = "daemon.apparmor", "AppArmor available"
	if !r.need(id, title, "daemon.reachable") {
		return
	}
	if !r.info.securityOption("apparmor") {
		r.warn(id, title, "SecurityOptions has no name=apparmor: weaker isolation", "enable AppArmor on the host and restart Docker")
		return
	}
	r.pass(id, title, "apparmor")
}

type dockerVersion struct {
	Server *struct {
		Version    string `json:"Version"`
		Components []struct {
			Name    string `json:"Name"`
			Version string `json:"Version"`
		} `json:"Components"`
	} `json:"Server"`
}

var leadingVersion = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

// ParseVersion reads the leading major.minor.patch of a version string
// ("2.40.3+ds1-0ubuntu1" → 2, 40, 3).
func ParseVersion(s string) ([3]int, bool) {
	m := leadingVersion.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		v[i] = n
	}
	return v, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func (r *run) daemonVersion() {
	const id, title = "daemon.version", "Docker Engine version"
	if !r.need(id, title, "daemon.reachable") {
		return
	}
	out, err := r.docker("version", "--format", "{{json .}}")
	if err != nil {
		r.fail(id, title, oneLine(err), "")
		return
	}
	var dv dockerVersion
	if err := json.Unmarshal(out, &dv); err != nil || dv.Server == nil {
		r.fail(id, title, "unexpected docker version output", "")
		return
	}
	d := &r.rep.Daemon
	d.ServerVersion = dv.Server.Version
	for _, c := range dv.Server.Components {
		switch c.Name {
		case "runc":
			d.Runc = c.Version
		case "containerd":
			d.Containerd = c.Version
		}
	}
	v, ok := ParseVersion(d.ServerVersion)
	if !ok {
		r.fail(id, title, fmt.Sprintf("cannot parse engine version %q", d.ServerVersion), "")
		return
	}
	tested := "on the tested list"
	if !slices.Contains(TestedEngineVersions, d.ServerVersion) {
		tested = "not on the tested list (" + strings.Join(TestedEngineVersions, ", ") + ")"
	}
	detail := fmt.Sprintf("Engine %s, %s; runc %s, containerd %s", d.ServerVersion, tested, or(d.Runc, "unknown"), or(d.Containerd, "unknown"))
	if less(v, MinEngineVersion) {
		r.warn(id, title, detail+fmt.Sprintf("; older than %d.%d", MinEngineVersion[0], MinEngineVersion[1]), "upgrade Docker Engine")
		return
	}
	r.pass(id, title, detail)
}

func (r *run) daemonPin() {
	const id, title = "daemon.pin", "daemon matches the pin"
	if !r.need(id, title, "daemon.reachable") {
		return
	}
	st, err := state.Load(r.env.Dirs.StateFile())
	if errors.Is(err, fs.ErrNotExist) {
		r.fail(id, title, "no pinned daemon", "run warden init")
		return
	}
	if err != nil {
		r.fail(id, title, oneLine(err), "inspect "+paths.ShellQuote(r.env.Dirs.StateFile())+"; warden init re-pins after approval")
		return
	}
	cur := r.rep.Daemon
	if st.Daemon.ID != cur.ID || st.Daemon.Socket != cur.Socket {
		r.fail(id, title, fmt.Sprintf("daemon changed: pinned %s at %s, now %s at %s", st.Daemon.ID, st.Daemon.Socket, cur.ID, cur.Socket), "daemon changed; re-run init")
		return
	}
	r.pass(id, title, "pinned "+st.Daemon.ID)
}

// ---- shared mounts ----

type inspectedContainer struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}

type inspectedVolume struct {
	Name    string            `json:"Name"`
	Options map[string]string `json:"Options"`
}

// bindDevice returns the host path a named volume binds, if its options
// say o=bind (among comma-separated o options) with a device.
func (v inspectedVolume) bindDevice() (string, bool) {
	dev := v.Options["device"]
	if dev == "" {
		return "", false
	}
	if slices.Contains(strings.Split(v.Options["o"], ","), "bind") {
		return dev, true
	}
	return "", false
}

func (r *run) sharedMounts() {
	const id, title = "host.shared-mounts", "no other container mounts the workspace or a Warden directory"
	if !r.need(id, title, "daemon.reachable", "workspace.valid") {
		return
	}
	fix := "remove that container (docker rm -f <name>) or recreate it without the mount"
	out, err := r.docker("ps", "-aq", "--no-trunc")
	if err != nil {
		r.fail(id, title, oneLine(err), "")
		return
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		r.pass(id, title, "no containers")
		return
	}
	// TODO(milestones 4 and 6): skip Warden's own containers by the IDs
	// Warden recorded (state, current canary run). Never by name or label.
	out, err = r.docker(append([]string{"inspect", "--type", "container"}, ids...)...)
	if err != nil {
		r.fail(id, title, oneLine(err), "re-run the check")
		return
	}
	var containers []inspectedContainer
	if err := json.Unmarshal(out, &containers); err != nil {
		r.fail(id, title, "unexpected docker inspect output: "+err.Error(), "")
		return
	}
	var volNames []string
	for _, c := range containers {
		for _, m := range c.Mounts {
			if m.Type == "volume" && m.Name != "" && !slices.Contains(volNames, m.Name) {
				volNames = append(volNames, m.Name)
			}
		}
	}
	volumes := map[string]inspectedVolume{}
	if len(volNames) > 0 {
		out, err = r.docker(append([]string{"volume", "inspect"}, volNames...)...)
		if err != nil {
			r.fail(id, title, oneLine(err), "re-run the check")
			return
		}
		var vs []inspectedVolume
		if err := json.Unmarshal(out, &vs); err != nil {
			r.fail(id, title, "unexpected docker volume inspect output: "+err.Error(), "")
			return
		}
		for _, v := range vs {
			volumes[v.Name] = v
		}
	}

	protected := append([]string{r.rep.Workspace}, r.wardenDirs()...)
	var findings []string
	for _, c := range containers {
		name := strings.TrimPrefix(c.Name, "/")
		for _, m := range c.Mounts {
			src, what := "", ""
			switch m.Type {
			case "bind":
				src, what = m.Source, "bind mount"
			case "volume":
				v, ok := volumes[m.Name]
				if !ok {
					r.fail(id, title, fmt.Sprintf("container %s: volume %q was not inspected", name, m.Name), "re-run the check")
					return
				}
				dev, ok := v.bindDevice()
				if !ok {
					continue
				}
				src, what = dev, "volume "+m.Name+" (o=bind)"
			default:
				continue
			}
			if !filepath.IsAbs(src) {
				r.fail(id, title, fmt.Sprintf("container %s: %s has a non-absolute source %q", name, what, src), fix)
				return
			}
			for _, p := range protected {
				rel, _, formP, err := mounts.Overlap(src, p)
				if err != nil {
					r.fail(id, title, fmt.Sprintf("container %s: cannot resolve %s: %v", name, src, err), "")
					return
				}
				if rel != "" {
					findings = append(findings, fmt.Sprintf("container %s (%s): %s %s -> %s %s %s",
						name, short(c.ID), what, src, m.Destination, rel, formP))
					break
				}
			}
		}
	}
	if len(findings) > 0 {
		r.fail(id, title, strings.Join(findings, "; "), fix)
		return
	}
	r.pass(id, title, inspected(len(containers)))
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func inspected(n int) string {
	if n == 1 {
		return "1 container inspected"
	}
	return fmt.Sprintf("%d containers inspected", n)
}
