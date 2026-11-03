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

	summary := !jsonOut && e.terminal()
	rep := checks.Run(e.checksEnv(checks.ModeInit, dirs, home))
	if summary {
		printSummary(e.stdout, rep)
	} else {
		printReport(e.stdout, rep, jsonOut)
	}
	if !rep.OK() {
		return ExitFail
	}
	return pinDaemon(e, dirs, rep.Daemon, jsonOut, summary)
}

// pinDaemon records the daemon. Changing an existing pin to another daemon
// or socket is a trust change and needs an explicit "y".
func pinDaemon(e *env, dirs paths.Dirs, d state.Daemon, jsonOut, summary bool) int {
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
	}
	if err := state.Save(file, s); err != nil {
		fmt.Fprintf(e.stderr, "warden init: %v\n", err)
		return ExitFail
	}
	if summary {
		fmt.Fprintf(msg, "All checks passed. Pinned daemon %s at %s.\nNext: warden up\n", d.ID, d.Socket)
		return ExitOK
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
  egress.allow             hostnames the sandbox may reach; a leading dot allows subdomains
  controller.image         the controller image ID (sha256:<64 hex>); to build Warden's reference
                           image, run warden init in a terminal
  controller.workspace     absolute path of the repository the agent may change
  controller.remote_control_name   name shown in Claude's Remote Control
  controller.resources     memory_mb 256-65536, cpus 0.25-64, pids 64-32768`

// terminal reports whether stdin is a terminal.
func (e *env) terminal() bool { return e.isTerminal != nil && e.isTerminal(e.stdin) }

// summaryGroups are the check groups of the summary, in order, and the ID
// prefixes each holds.
var summaryGroups = []struct {
	name     string
	prefixes []string
}{
	{"config", []string{"config.", "workspace."}},
	{"host", []string{"host."}},
	{"daemon", []string{"daemon."}},
	{"canary", []string{"canary."}},
}

// printSummary prints one line per group, then every failing or warning
// check in full with its fix. A check in no group is printed in full, so
// nothing is ever hidden by the grouping.
func printSummary(w io.Writer, rep *checks.Report) {
	grouped := make([]bool, len(rep.Results))
	for _, g := range summaryGroups {
		var pass, warn, fail int
		for i, r := range rep.Results {
			if !hasAnyPrefix(r.ID, g.prefixes) {
				continue
			}
			grouped[i] = true
			switch r.Status {
			case checks.Pass:
				pass++
			case checks.Warn:
				warn++
			default:
				fail++
			}
		}
		if pass+warn+fail == 0 {
			continue
		}
		mark, parts := "✓", []string{}
		if fail > 0 {
			mark = "✗"
			parts = append(parts, fmt.Sprintf("%d failed", fail))
		} else if warn > 0 {
			mark = "!"
		}
		parts = append(parts, fmt.Sprintf("%d passed", pass))
		if warn > 0 {
			parts = append(parts, plural(warn, "warning"))
		}
		fmt.Fprintf(w, "%s %-7s %s\n", mark, g.name, strings.Join(parts, ", "))
	}
	for i, r := range rep.Results {
		if r.Status == checks.Pass && grouped[i] {
			continue
		}
		mark := map[checks.Status]string{checks.Pass: "✓", checks.Warn: "!"}[r.Status]
		if mark == "" {
			mark = "✗"
		}
		fmt.Fprintf(w, "  %s %s  %s\n", mark, r.ID, r.Detail)
		if r.Fix != "" && r.Status != checks.Pass {
			fmt.Fprintf(w, "    fix: %s\n", r.Fix)
		}
	}
	if !rep.OK() {
		fmt.Fprintln(w, "Some checks failed.")
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
