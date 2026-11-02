package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rviscuso/warden/internal/compose"
	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/docker"
	"github.com/rviscuso/warden/internal/hardening"
	"github.com/rviscuso/warden/internal/mounts"
	"github.com/rviscuso/warden/internal/paths"
	"github.com/rviscuso/warden/internal/state"
	"github.com/rviscuso/warden/internal/wardenbin"
)

// Timing. Variables so tests can shorten the polls; the CLI never changes
// them.
var (
	ComposeTimeout = 5 * time.Minute
	ChildWait      = 10 * time.Second // for the container's main process to appear
	ChildPoll      = 200 * time.Millisecond
	URLWait        = 60 * time.Second // for the Remote Control URL in the log
	URLPoll        = 2 * time.Second
)

// AgentName is the controller's agent home under <share>/agents/.
const AgentName = "controller"

// Env is everything up, down, status and logs touch.
type Env struct {
	Ctx            context.Context
	Dirs           paths.Dirs
	Home           string
	UID, GID       int
	GOARCH         string
	Root           string // the host's filesystem root, for /proc: "/" in production
	DockerPaths    []string
	NewRunner      func(docker.Options) (docker.Runner, error)
	SystemDirs     []string // nil: mounts.DefaultSystemDirs
	Executable     func() (string, error)
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Now            func() time.Time
	Sleep          func(time.Duration)
}

// Error is a failure with the exact fix for the user, if there is one.
type Error struct {
	Problem, Fix string
}

func (e *Error) Error() string { return e.Problem }

func fail(fix, format string, a ...any) error {
	return &Error{Problem: fmt.Sprintf(format, a...), Fix: fix}
}

// Fix returns err's fix, if it carries one.
func Fix(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Fix
	}
	var de *paths.DirError
	if errors.As(err, &de) {
		return de.Fix
	}
	var we *wardenbin.Error
	if errors.As(err, &we) {
		return we.Fix
	}
	return ""
}

// session is an opened Warden: config, state and a runner for the pinned
// daemon, with the pin checked.
type session struct {
	env Env
	cfg *config.Config
	st  *state.State
	r   docker.Runner
}

const runInit = "run warden init"

// open loads config and state and checks the daemon pin. Every command
// here starts with it: a different daemon's containers mean nothing.
func open(env Env) (*session, error) {
	if env.Ctx == nil {
		env.Ctx = context.Background()
	}
	for _, d := range []string{env.Dirs.Config, env.Dirs.State, env.Dirs.Share} { // docker-config: the runner's
		if err := paths.CheckDir(d, env.UID); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fail(runInit, "%s does not exist", d)
			}
			return nil, err
		}
	}
	cfgFile := env.Dirs.ConfigFile()
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fail("edit "+paths.ShellQuote(cfgFile)+", then run warden check", "%v", err)
	}
	st, err := state.Load(env.Dirs.StateFile())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fail(runInit, "no pinned daemon")
	}
	if err != nil {
		return nil, fail("inspect "+paths.ShellQuote(env.Dirs.StateFile())+"; warden init re-pins after approval", "%v", err)
	}
	if cfg.Docker.Socket != st.Daemon.Socket {
		return nil, fail("daemon changed; re-run init",
			"docker.socket %s is not the pinned socket %s", cfg.Docker.Socket, st.Daemon.Socket)
	}
	bin, err := docker.FindBinary(env.DockerPaths)
	if err != nil {
		return nil, err
	}
	r, err := env.NewRunner(docker.Options{
		Binary: bin, Socket: st.Daemon.Socket, Home: env.Home, StateDir: env.Dirs.State, UID: env.UID,
	})
	if err != nil {
		return nil, err
	}
	s := &session{env: env, cfg: cfg, st: st, r: r}
	out, err := s.docker(env.Ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return nil, fail("make sure Docker is running, then try again", "daemon not reachable: %v", err)
	}
	var info struct{ ID string }
	if err := json.Unmarshal(out, &info); err != nil || info.ID == "" {
		return nil, fail("", "unexpected docker info output")
	}
	if info.ID != st.Daemon.ID {
		return nil, fail("daemon changed; re-run init", "daemon changed: pinned %s, now %s", st.Daemon.ID, info.ID)
	}
	return s, nil
}

// docker runs one docker command; a non-zero exit is an error with stderr.
func (s *session) docker(ctx context.Context, args ...string) ([]byte, error) {
	out, errOut, code, err := s.r.Run(ctx, args, nil)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		msg := strings.TrimSpace(string(errOut))
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		return out, fmt.Errorf("docker %s exited %d: %s", strings.Join(firstArgs(args, 2), " "), code, msg)
	}
	return out, nil
}

func firstArgs(a []string, n int) []string {
	if len(a) > n {
		return a[:n]
	}
	return a
}

func (s *session) save() error { return state.Save(s.env.Dirs.StateFile(), s.st) }

// ensurePrivateDir creates dir (0700) if missing, and requires it to be a
// private directory of uid. Never repairs an existing one.
func ensurePrivateDir(dir string, uid int) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return paths.CheckDir(dir, uid)
}

// writeAtomic writes data to path with mode 0600: temp file, sync, rename.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// confirmed reads one line and accepts exactly "y" (surrounding spaces
// ignored). EOF or anything else is a no.
func confirmed(r io.Reader) bool {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(line) == "y"
}

// ComposeFile is where up writes the applied compose file.
func ComposeFile(d paths.Dirs) string { return filepath.Join(d.ComposeDir(), "warden.json") }

// Up generates the compose file, shows it with a diff against the last
// applied one, and on "y" starts the proxy and the controller, verifies
// them and reads the Remote Control URL.
func Up(env Env) error {
	s, err := open(env)
	if err != nil {
		return err
	}
	env, cfg := s.env, s.cfg
	ws, err := mounts.ValidateWorkspace(cfg.Controller.Workspace, mounts.Policy{
		UID: env.UID, Home: env.Home, WardenDirs: []string{env.Dirs.Config, env.Dirs.State, env.Dirs.Share},
		Socket: cfg.Docker.Socket, SystemDirs: env.SystemDirs,
	})
	if err != nil {
		return fail("point controller.workspace at the repository directory itself, owned by you", "workspace: %v", err)
	}
	exe, err := env.Executable()
	if err != nil {
		return fmt.Errorf("cannot find the running warden binary: %w", err)
	}
	bin, err := wardenbin.Find(exe, env.Dirs.BinDir(), env.UID, env.GOARCH)
	if err != nil {
		return err
	}
	home, err := agentHome(env.Dirs, env.UID)
	if err != nil {
		return err
	}
	mptcp, err := hardening.HostMPTCP(env.Root)
	if err != nil {
		return err
	}
	res := cfg.Controller.Resources
	f, err := Project(Params{
		UID: env.UID, GID: env.GID,
		RuntimeImage: cfg.RuntimeImage, Binary: bin, Allow: cfg.Egress.Allow,
		Image: cfg.Controller.Image, Workspace: ws, AgentHome: home,
		RemoteControlName: cfg.Controller.RemoteControlName,
		Resources:         hardening.Resources{MemoryMB: res.MemoryMB, CPUs: res.CPUs, Pids: res.PIDs},
		Host:              hardening.Host{MPTCP: mptcp},
	})
	if err != nil {
		return err
	}
	b, err := compose.Render(f, compose.Policy{UID: env.UID, GID: env.GID, Socket: cfg.Docker.Socket, MPTCP: mptcp})
	if err != nil {
		return err
	}

	file := ComposeFile(env.Dirs)
	fmt.Fprintf(env.Stdout, "Compose file to apply (%s):\n\n", file)
	env.Stdout.Write(b)
	fmt.Fprintln(env.Stdout)
	prev := ""
	if s.st.Controller != nil {
		prev = s.st.Controller.AppliedCompose
	}
	switch {
	case prev == "":
		fmt.Fprintln(env.Stdout, "First apply: no previous file.")
	case prev == string(b):
		fmt.Fprintln(env.Stdout, "No changes since the last apply.")
	default:
		fmt.Fprintf(env.Stdout, "Changes since the last apply:\n\n%s\n", Diff([]byte(prev), b))
	}
	fmt.Fprint(env.Stderr, "Apply? [y/N] ")
	if !confirmed(env.Stdin) {
		return fail("", "nothing applied")
	}

	if err := ensurePrivateDir(env.Dirs.ComposeDir(), env.UID); err != nil {
		return err
	}
	if err := writeAtomic(file, b); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	ctx, cancel := context.WithTimeout(env.Ctx, ComposeTimeout)
	defer cancel()
	if _, err := s.docker(ctx, "compose", "-p", ProjectName, "-f", file, "up", "-d"); err != nil {
		return err
	}
	ids, err := s.containerIDs()
	if err != nil {
		return err
	}
	c := &state.Controller{AppliedCompose: string(b), AppliedAt: env.Now().UTC(), ProxyID: ids[0], ControllerID: ids[1]}
	if old := s.st.Controller; old != nil && old.ControllerID == ids[1] && old.RemoteControlURL != "" {
		c.RemoteControlURL, c.URLFoundAt = old.RemoteControlURL, old.URLFoundAt // the same container: its URL
	}
	s.st.Controller = c
	if err := s.save(); err != nil {
		return err
	}

	for _, name := range []string{ProxyName, ControllerName} {
		if verr := s.verify(name); verr != nil {
			fmt.Fprintf(env.Stderr, "%v\nStopping everything.\n", verr)
			_, derr := s.docker(ctx, "compose", "-p", ProjectName, "-f", file, "down")
			c.ProxyID, c.ControllerID = "", ""
			if err := s.save(); err != nil {
				return err
			}
			if derr != nil {
				return fail("remove them yourself: docker compose -p warden down", "%v; and stopping failed: %v", verr, derr)
			}
			return verr
		}
	}
	fmt.Fprintln(env.Stdout, "Verified warden-proxy and warden-controller: your UID and GID, no capabilities, no new privileges.")

	if c.RemoteControlURL != "" {
		fmt.Fprintf(env.Stdout, "Remote Control: %s (the controller wasn't recreated)\n", c.RemoteControlURL)
		return nil
	}
	url, log, err := s.waitURL()
	if err != nil {
		return err
	}
	if url == "" {
		fmt.Fprintf(env.Stderr, "No Remote Control URL in the controller's log within %v. Its last lines:\n", URLWait)
		for _, l := range lastLines(log, 20) {
			fmt.Fprintf(env.Stderr, "  %s\n", l)
		}
		return fail("first run? log in with `docker attach warden-controller` (detach with Ctrl-P Ctrl-Q), then run `warden status`; or run `warden down` to stop",
			"no Remote Control URL yet; the containers are still running")
	}
	t := env.Now().UTC()
	c.RemoteControlURL, c.URLFoundAt = url, &t
	if err := s.save(); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Remote Control: %s\n", url)
	return nil
}

// agentHome creates <share>/agents/controller (and agents/), 0700, or
// requires the existing ones to be private directories of uid.
func agentHome(d paths.Dirs, uid int) (string, error) {
	home, err := d.AgentHome(AgentName)
	if err != nil {
		return "", err
	}
	for _, dir := range []string{d.AgentsDir(), home} {
		if err := ensurePrivateDir(dir, uid); err != nil {
			return "", err
		}
	}
	return home, nil
}

var fullID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// containerIDs returns the proxy's and the controller's full IDs.
func (s *session) containerIDs() ([2]string, error) {
	out, err := s.docker(s.env.Ctx, "inspect", "--type", "container", "--format", "{{.Id}}", ProxyName, ControllerName)
	if err != nil {
		return [2]string{}, err
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || !fullID.MatchString(f[0]) || !fullID.MatchString(f[1]) {
		return [2]string{}, fmt.Errorf("unexpected container IDs from docker inspect: %q", out)
	}
	return [2]string{f[0], f[1]}, nil
}

// running returns whether name is running and its main PID (docker-init).
func (s *session) running(name string) (bool, int, error) {
	out, err := s.docker(s.env.Ctx, "inspect", "--type", "container", "--format", "{{.State.Running}} {{.State.Pid}}", name)
	if err != nil {
		return false, 0, err
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || (f[0] != "true" && f[0] != "false") {
		return false, 0, fmt.Errorf("unexpected docker inspect output for %s: %q", name, out)
	}
	pid, err := strconv.Atoi(f[1])
	if err != nil || pid < 0 {
		return false, 0, fmt.Errorf("unexpected PID for %s: %q", name, f[1])
	}
	return f[0] == "true", pid, nil
}

// verify is post-start verification for one container: its init and main
// process, read from the host's /proc, waiting up to ChildWait for the
// main process to appear.
func (s *session) verify(name string) error {
	var last error
	for i := 0; i <= int(ChildWait/ChildPoll); i++ {
		if i > 0 {
			s.env.Sleep(ChildPoll)
		}
		up, pid, err := s.running(name)
		if err != nil {
			return &VerifyError{name, []string{err.Error()}}
		}
		if !up || pid == 0 {
			return &VerifyError{name, []string{"not running"}}
		}
		done, err := verifyProcesses(s.env.Root, name, pid, s.env.UID, s.env.GID)
		if done {
			return err
		}
		last = err
	}
	return last
}

// startedAt is the controller's .State.StartedAt, checked to be a time.
func (s *session) startedAt() (string, error) {
	out, err := s.docker(s.env.Ctx, "inspect", "--type", "container", "--format", "{{.State.StartedAt}}", ControllerName)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(out))
	if _, err := time.Parse(time.RFC3339Nano, t); err != nil {
		return "", fmt.Errorf("unexpected start time for %s: %q", ControllerName, t)
	}
	return t, nil
}

// readURL reads the controller's log since the container started, so a
// URL from an earlier run can never match, and finds the URL in it.
func (s *session) readURL(since string) (string, []byte, error) {
	out, errOut, code, err := s.r.Run(s.env.Ctx, []string{"logs", "--since", since, ControllerName}, nil)
	if err != nil {
		return "", nil, err
	}
	if code != 0 {
		return "", nil, fmt.Errorf("docker logs %s exited %d: %s", ControllerName, code, strings.TrimSpace(string(errOut)))
	}
	log := append(out, errOut...)
	url, _ := FindURL(log)
	return url, log, nil
}

// waitURL polls the controller's log for the Remote Control URL. It
// returns "" and the last log when the wait ends without one.
func (s *session) waitURL() (string, []byte, error) {
	since, err := s.startedAt()
	if err != nil {
		return "", nil, err
	}
	var log []byte
	for i := 0; i <= int(URLWait/URLPoll); i++ {
		if i > 0 {
			s.env.Sleep(URLPoll)
		}
		url, l, err := s.readURL(since)
		if err != nil {
			return "", nil, err
		}
		if log = l; url != "" {
			return url, log, nil
		}
		up, _, err := s.running(ControllerName)
		if err != nil {
			return "", nil, err
		}
		if !up {
			fmt.Fprintf(s.env.Stderr, "%s stopped.\n", ControllerName)
			break
		}
	}
	return "", log, nil
}

// Down stops and removes Warden's containers and networks, never volumes.
func Down(env Env) error {
	s, err := open(env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.env.Ctx, ComposeTimeout)
	defer cancel()
	if _, err := s.docker(ctx, "compose", "-p", ProjectName, "down"); err != nil {
		return err
	}
	if c := s.st.Controller; c != nil {
		c.ProxyID, c.ControllerID = "", ""
		if err := s.save(); err != nil {
			return err
		}
	}
	fmt.Fprintln(env.Stdout, "Stopped and removed warden-proxy and warden-controller. The agent home and the workspace are kept.")
	return nil
}

// ContainerStatus is one container in status output.
type ContainerStatus struct {
	Name      string `json:"name"`
	State     string `json:"state"` // docker's .State.Status, or "not found"
	Image     string `json:"image,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	ID        string `json:"id,omitempty"`
	Recorded  bool   `json:"started_by_warden"` // the ID is the one up recorded
}

// StatusReport is status's output.
type StatusReport struct {
	Daemon struct {
		ID     string `json:"id"`
		Socket string `json:"socket"`
	} `json:"daemon"`
	Containers []ContainerStatus `json:"containers"`
	URL        string            `json:"remote_control_url,omitempty"`
	URLFoundAt *time.Time        `json:"url_found_at,omitempty"`
}

// Status reports the pin, both containers and the last URL.
func Status(env Env, jsonOut bool) error {
	s, err := open(env)
	if err != nil {
		return err
	}
	var rep StatusReport
	rep.Daemon.ID, rep.Daemon.Socket = s.st.Daemon.ID, s.st.Daemon.Socket
	c := s.st.Controller
	if c != nil {
		rep.URL, rep.URLFoundAt = c.RemoteControlURL, c.URLFoundAt
	}
	for _, name := range []string{ProxyName, ControllerName} {
		cs, err := s.inspect(name)
		if err != nil {
			return err
		}
		if c != nil && cs.ID != "" {
			cs.Recorded = (name == ProxyName && cs.ID == c.ProxyID) || (name == ControllerName && cs.ID == c.ControllerID)
		}
		rep.Containers = append(rep.Containers, cs)
	}
	// After a first login the URL appears in the log: one look, exactly as up
	// does it, for the controller up started, and it's recorded.
	if c.Running() && c.RemoteControlURL == "" && len(rep.Containers) == 2 &&
		rep.Containers[1].Recorded && rep.Containers[1].State == "running" {
		since, err := s.startedAt()
		if err != nil {
			return err
		}
		url, _, err := s.readURL(since)
		if err != nil {
			return err
		}
		if url != "" {
			t := env.Now().UTC()
			c.RemoteControlURL, c.URLFoundAt = url, &t
			if err := s.save(); err != nil {
				return err
			}
			rep.URL, rep.URLFoundAt = url, &t
		}
	}
	if jsonOut {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	fmt.Fprintf(env.Stdout, "Daemon: %s at %s (matches the pin)\n\n", rep.Daemon.ID, rep.Daemon.Socket)
	for _, cs := range rep.Containers {
		if cs.State == "not found" {
			fmt.Fprintf(env.Stdout, "%s: not found\n", cs.Name)
			continue
		}
		who := "started by Warden"
		if !cs.Recorded {
			who = "NOT started by Warden: its ID isn't the one up recorded"
		}
		fmt.Fprintf(env.Stdout, "%s: %s, started %s, image %s, ID %s (%s)\n", cs.Name, cs.State, cs.StartedAt, cs.Image, cs.ID[:12], who)
	}
	if rep.URL != "" {
		fmt.Fprintf(env.Stdout, "\nLast Remote Control URL: %s (found %s)\n", rep.URL, rep.URLFoundAt.Format(time.RFC3339))
	} else {
		fmt.Fprintln(env.Stdout, "\nNo Remote Control URL recorded.")
	}
	return nil
}

func (s *session) inspect(name string) (ContainerStatus, error) {
	out, errOut, code, err := s.r.Run(s.env.Ctx, []string{"inspect", "--type", "container", name}, nil)
	if err != nil {
		return ContainerStatus{}, err
	}
	if code != 0 {
		if strings.Contains(string(errOut), "No such container") {
			return ContainerStatus{Name: name, State: "not found"}, nil
		}
		return ContainerStatus{}, fmt.Errorf("docker inspect %s exited %d: %s", name, code, strings.TrimSpace(string(errOut)))
	}
	var got []struct {
		ID     string `json:"Id"`
		Config struct{ Image string }
		State  struct{ Status, StartedAt string }
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 1 || !fullID.MatchString(got[0].ID) {
		return ContainerStatus{}, fmt.Errorf("unexpected docker inspect output for %s", name)
	}
	g := got[0]
	return ContainerStatus{Name: name, State: g.State.Status, Image: g.Config.Image, StartedAt: g.State.StartedAt, ID: g.ID}, nil
}

// Logs prints the last n lines of the proxy's or the controller's log.
func Logs(env Env, which string, n int) error {
	name := map[string]string{"proxy": ProxyName, "controller": ControllerName}[which]
	if name == "" || n <= 0 {
		return fmt.Errorf("logs: bad arguments %q %d", which, n)
	}
	s, err := open(env)
	if err != nil {
		return err
	}
	out, errOut, code, err := s.r.Run(s.env.Ctx, []string{"logs", "--tail", strconv.Itoa(n), name}, nil)
	if err != nil {
		return err
	}
	env.Stdout.Write(out)
	env.Stderr.Write(errOut)
	if code != 0 {
		return fail("", "docker logs %s exited %d", name, code)
	}
	return nil
}
