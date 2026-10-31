// Package paths works out Warden's directories with the XDG base-directory
// rules. It only computes and inspects locations; it never creates anything
// (commands that need a directory create it).
package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Dirs holds Warden's three base directories.
type Dirs struct {
	Config string // $XDG_CONFIG_HOME/warden, default ~/.config/warden
	State  string // $XDG_STATE_HOME/warden, default ~/.local/state/warden
	Share  string // $XDG_DATA_HOME/warden, default ~/.local/share/warden
}

// Resolve computes Warden's directories for the user whose home directory is
// home. getenv reads XDG_CONFIG_HOME, XDG_STATE_HOME and XDG_DATA_HOME; a
// relative or empty value is ignored, as the XDG spec requires, and the
// default under home is used instead.
func Resolve(home string, getenv func(string) string) (Dirs, error) {
	if home == "" || !filepath.IsAbs(home) {
		return Dirs{}, fmt.Errorf("home directory %q is not an absolute path", home)
	}
	home = filepath.Clean(home)
	base := func(env, def string) string {
		if v := getenv(env); v != "" && filepath.IsAbs(v) {
			return filepath.Join(filepath.Clean(v), "warden")
		}
		return filepath.Join(home, def, "warden")
	}
	return Dirs{
		Config: base("XDG_CONFIG_HOME", ".config"),
		State:  base("XDG_STATE_HOME", filepath.Join(".local", "state")),
		Share:  base("XDG_DATA_HOME", filepath.Join(".local", "share")),
	}, nil
}

// ConfigFile is config.json in the config directory.
func (d Dirs) ConfigFile() string { return filepath.Join(d.Config, "config.json") }

// StateFile is state.json in the state directory.
func (d Dirs) StateFile() string { return filepath.Join(d.State, "state.json") }

// ComposeDir holds generated compose files.
func (d Dirs) ComposeDir() string { return filepath.Join(d.State, "compose") }

// DockerConfigDir is the empty DOCKER_CONFIG Warden passes to the docker CLI.
func (d Dirs) DockerConfigDir() string { return filepath.Join(d.State, "docker-config") }

// AgentsDir holds one home directory per agent.
func (d Dirs) AgentsDir() string { return filepath.Join(d.Share, "agents") }

var agentName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// AgentHome is the home directory of the named agent. The name must be a
// simple lowercase identifier, so it can't escape AgentsDir.
func (d Dirs) AgentHome(name string) (string, error) {
	if !agentName.MatchString(name) {
		return "", fmt.Errorf("invalid agent name %q", name)
	}
	return filepath.Join(d.AgentsDir(), name), nil
}

// DirError reports a Warden directory that is missing or unsafe, with the
// exact fix for the user.
type DirError struct {
	Path    string
	Problem string
	Fix     string
	Err     error // fs.ErrNotExist when the directory is missing
}

func (e *DirError) Error() string {
	s := e.Path + ": " + e.Problem
	if e.Fix != "" {
		s += " (fix: " + e.Fix + ")"
	}
	return s
}

func (e *DirError) Unwrap() error { return e.Err }

// CheckDir requires path to be a real directory (not a symlink) owned by uid
// with no permissions for group or others. It never changes anything: an
// unsafe directory is an error carrying the exact fix. A missing directory is
// a *DirError that matches fs.ErrNotExist.
func CheckDir(path string, uid int) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &DirError{Path: path, Problem: "does not exist", Fix: "run warden init", Err: fs.ErrNotExist}
	}
	if err != nil {
		return &DirError{Path: path, Problem: "cannot inspect: " + err.Error(), Err: err}
	}
	q := ShellQuote(path)
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return &DirError{Path: path, Problem: "is a symlink, not a directory", Fix: "rm " + q + " and run warden init"}
	case !fi.IsDir():
		return &DirError{Path: path, Problem: "is not a directory", Fix: "move " + q + " aside and run warden init"}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return &DirError{Path: path, Problem: "cannot determine the owner"}
	}
	if int(st.Uid) != uid {
		return &DirError{
			Path:    path,
			Problem: fmt.Sprintf("is owned by uid %d, not %d", st.Uid, uid),
			Fix:     fmt.Sprintf("sudo chown %d %s", uid, q),
		}
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return &DirError{
			Path:    path,
			Problem: fmt.Sprintf("has mode %04o, looser than 0700", perm),
			Fix:     "chmod 700 " + q,
		}
	}
	return nil
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// ShellQuote quotes s for display in a fix command the user may paste into a
// POSIX shell. It is for messages only; Warden itself never runs a shell.
func ShellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
