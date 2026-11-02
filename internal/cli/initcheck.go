package cli

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
	"strings"
	"text/tabwriter"

	"github.com/rviscuso/warden/internal/checks"
	"github.com/rviscuso/warden/internal/paths"
	"github.com/rviscuso/warden/internal/state"
)

// setup resolves Warden's directories for the invoking user.
func (e *env) setup() (paths.Dirs, string, error) {
	home, err := e.home()
	if err != nil {
		return paths.Dirs{}, "", fmt.Errorf("cannot determine the home directory: %w", err)
	}
	dirs, err := paths.Resolve(home, e.getenv)
	return dirs, filepath.Clean(home), err
}

func (e *env) checksEnv(mode checks.Mode, dirs paths.Dirs, home string) checks.Env {
	return checks.Env{
		Mode:        mode,
		EUID:        e.geteuid(),
		UID:         e.getuid(),
		GID:         e.getgid(),
		Home:        home,
		Dirs:        dirs,
		Root:        e.root,
		GOOS:        e.goos,
		GOARCH:      e.goarch,
		DockerPaths: e.dockerPaths,
		NewRunner:   e.newRunner,
		SystemDirs:  e.systemDirs,
		Ctx:         context.Background(),
		Now:         e.now,
		Canary: checks.CanaryEnv{
			Executable: e.executable,
			Resolver:   e.resolver,
			Dialer:     e.dialer,
			Listen:     e.canaryListen,
			Rand:       e.rand,
		},
	}
}

func baseDirs(d paths.Dirs) []string { return []string{d.Config, d.State, d.Share} }

func runInit(e *env, jsonOut bool) int {
	dirs, home, err := e.setup()
	if err != nil {
		fmt.Fprintf(e.stderr, "warden init: %v\n", err)
		return ExitFail
	}
	for _, d := range baseDirs(dirs) {
		if err := ensureDir(d, e.getuid()); err != nil {
			fmt.Fprintf(e.stderr, "warden init: %v\n", err)
			return ExitFail
		}
	}
	cfgFile := dirs.ConfigFile()
	if _, err := os.Lstat(cfgFile); errors.Is(err, fs.ErrNotExist) {
		q := paths.ShellQuote(cfgFile)
		fmt.Fprintf(e.stderr, "warden init: no config at %s\n\n%s\nSave it, edit it, then run warden init again:\n  warden init > %s.new; mv %s.new %s\n\n",
			cfgFile, exampleExplanation, q, q, q)
		io.WriteString(e.stdout, exampleConfig)
		return ExitFail
	}

	rep := checks.Run(e.checksEnv(checks.ModeInit, dirs, home))
	printReport(e.stdout, rep, jsonOut)
	if !rep.OK() {
		if rep.CanaryRan {
			// A canary that ran and failed withdraws any earlier pass, so up
			// can't start containers on its strength.
			recordCanary(e, "init", dirs, nil)
		}
		return ExitFail
	}
	return pinDaemon(e, dirs, rep.Daemon, rep.CanaryPass, jsonOut)
}

// pinDaemon records the daemon. Changing an existing pin to another daemon
// or socket is a trust change and needs an explicit "y".
func pinDaemon(e *env, dirs paths.Dirs, d state.Daemon, cp *state.CanaryPass, jsonOut bool) int {
	msg := e.stdout
	if jsonOut {
		msg = e.stderr // keep stdout pure JSON
	}
	file := dirs.StateFile()
	old, err := state.Load(file)
	var keep *state.Controller // what up applied, if the daemon is the same one
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		fmt.Fprintf(e.stderr, "warden init: %v\n  fix: inspect %s; remove it only if you mean to re-pin from scratch\n", err, paths.ShellQuote(file))
		return ExitFail
	case old.Daemon.ID != d.ID || old.Daemon.Socket != d.Socket:
		fmt.Fprintf(e.stderr, "The daemon differs from the pinned one:\n  pinned: %s at %s\n  now:    %s at %s\nRe-pin to the new daemon? [y/N] ",
			old.Daemon.ID, old.Daemon.Socket, d.ID, d.Socket)
		if !confirmed(e.stdin) {
			fmt.Fprintln(e.stderr, "Kept the existing pin.")
			return ExitFail
		}
	default:
		keep = old.Controller
	}
	s := &state.State{
		Version:       1,
		WardenVersion: e.wardenVersion(),
		Daemon:        d,
		InitializedAt: e.now().UTC(),
		Controller:    keep,
		CanaryPass:    cp,
	}
	if err := state.Save(file, s); err != nil {
		fmt.Fprintf(e.stderr, "warden init: %v\n", err)
		return ExitFail
	}
	fmt.Fprintf(msg, "Pinned daemon %s at %s.\n", d.ID, d.Socket)
	return ExitOK
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

func runCheck(e *env, jsonOut bool) int {
	dirs, home, err := e.setup()
	if err != nil {
		fmt.Fprintf(e.stderr, "warden check: %v\n", err)
		return ExitFail
	}
	for _, d := range baseDirs(dirs) {
		if err := paths.CheckDir(d, e.getuid()); err != nil {
			fmt.Fprintf(e.stderr, "warden check: %v\n", err)
			return ExitFail
		}
	}
	rep := checks.Run(e.checksEnv(checks.ModeCheck, dirs, home))
	printReport(e.stdout, rep, jsonOut)
	// check's one write: the canary record up requires (set on a pass,
	// cleared on a failure).
	if rep.CanaryRan && !recordCanary(e, "check", dirs, rep.CanaryPass) {
		return ExitFail
	}
	if !rep.OK() {
		return ExitFail
	}
	return ExitOK
}

// ensureDir creates dir (and missing parents) with mode 0700, then requires
// it to be a private directory of uid. An existing unsafe one is never
// repaired: the error carries the fix.
func ensureDir(dir string, uid int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return paths.CheckDir(dir, uid)
}

func printReport(w io.Writer, rep *checks.Report, jsonOut bool) {
	if jsonOut {
		out := struct {
			OK     bool            `json:"ok"`
			Checks []checks.Result `json:"checks"`
		}{rep.OK(), rep.Results}
		if out.Checks == nil {
			out.Checks = []checks.Result{}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tID\tDETAIL")
	for _, r := range rep.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Status, r.ID, r.Detail)
		if r.Fix != "" && r.Status != checks.Pass {
			fmt.Fprintf(tw, "\t\tfix: %s\n", r.Fix)
		}
	}
	tw.Flush()
	if rep.OK() {
		fmt.Fprintln(w, "\nAll checks passed.")
	} else {
		fmt.Fprintln(w, "\nSome checks failed.")
	}
}

// exampleConfig is printed by init when config.json is missing. It must
// pass config validation (a test enforces it); the zero digests and the
// workspace are placeholders to replace.
const exampleConfig = `{
  "version": 1,
  "docker": { "socket": "/var/run/docker.sock" },
  "runtime_image": "` + exampleRuntimeImage + `",
  "egress": { "allow": ["api.anthropic.com", "platform.claude.com"] },
  "controller": {
    "image": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "workspace": "/path/to/your/repo",
    "remote_control_name": "warden",
    "resources": { "memory_mb": 1536, "cpus": 1.5, "pids": 512 }
  }
}
`

const exampleExplanation = `An example config is printed on stdout. Fields:
  version                  always 1
  docker.socket            the Docker daemon's socket (optional; this is the default)
  runtime_image            stock image for Warden's own containers (proxy, canary), pinned by
                           digest (name@sha256:<64 hex>); it must be local: docker pull it first
  egress.allow             hostnames the sandbox may reach; a leading dot allows subdomains
  controller.image         the controller image ID (sha256:<64 hex>): docker build -t
                           warden-controller images/controller, then
                           docker image inspect --format '{{.Id}}' warden-controller
  controller.workspace     absolute path of the repository the agent may change
  controller.remote_control_name   name shown in Claude's Remote Control
  controller.resources     memory_mb 256-65536, cpus 0.25-64, pids 64-32768`

// exampleRuntimeImage is the example config's placeholder runtime_image.
const exampleRuntimeImage = "busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// recordCanary sets (cp != nil) or clears the canary record in an existing
// state.json. Nothing to clear without a state file.
func recordCanary(e *env, cmd string, dirs paths.Dirs, cp *state.CanaryPass) bool {
	file := dirs.StateFile()
	s, err := state.Load(file)
	if errors.Is(err, fs.ErrNotExist) && cp == nil {
		return true
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "warden %s: recording the canary result: %v\n", cmd, err)
		return false
	}
	if cp == nil && s.CanaryPass == nil {
		return true
	}
	if cp != nil && cp.DaemonID != s.Daemon.ID {
		fmt.Fprintf(e.stderr, "warden %s: the canary ran on daemon %s, not the pinned %s; not recorded\n", cmd, cp.DaemonID, s.Daemon.ID)
		return false
	}
	s.CanaryPass = cp
	if err := state.Save(file, s); err != nil {
		fmt.Fprintf(e.stderr, "warden %s: recording the canary result: %v\n", cmd, err)
		return false
	}
	return true
}
