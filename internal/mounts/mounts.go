// Package mounts validates host paths before they are mounted into a
// container. Security-critical.
//
// The agent runs with the user's UID, so file permissions don't protect the
// user's files: anything mounted is writable to it. What keeps the rest of
// the user's files out of reach is that they aren't mounted at all, so this
// validation is what enforces "repo only" (DESIGN.md, section 6).
package mounts

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DefaultSystemDirs are refused as, inside or containing a workspace.
var DefaultSystemDirs = []string{
	"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/var",
	"/boot", "/proc", "/sys", "/dev", "/run", "/root", "/tmp", "/snap",
}

// Dotfiles are the home-directory entries refused as, inside or containing
// a workspace.
var Dotfiles = []string{
	".ssh", ".config", ".local", ".aws", ".azure", ".docker", ".gnupg",
	".kube", ".netrc", ".bashrc", ".profile", ".zshrc",
}

// Policy is what a workspace is validated against.
type Policy struct {
	UID        int      // the invoking user's UID; the workspace must be owned by it
	Home       string   // the user's home directory, absolute
	WardenDirs []string // Warden's config, state and share directories, absolute
	Socket     string   // the Docker socket path, absolute
	// SystemDirs overrides DefaultSystemDirs (tests point it at fixtures).
	// Empty means DefaultSystemDirs: an empty list never disables the rule.
	SystemDirs []string
}

// Rule identifies which rule refused a workspace.
type Rule string

// Rules, in the order they are checked.
const (
	RuleInvalid      Rule = "invalid"       // bad policy or input, or a path that can't be resolved
	RuleMissing      Rule = "missing"       // the workspace doesn't exist
	RuleNotDir       Rule = "not-dir"       // the workspace isn't a directory
	RuleRoot         Rule = "root"          // the workspace is /
	RuleHome         Rule = "home"          // the home directory or an ancestor of it
	RuleWardenDir    Rule = "warden-dir"    // is, is inside or contains a Warden directory
	RuleDotfile      Rule = "dotfile"       // is, is inside or contains a listed dotfile path
	RuleSystemDir    Rule = "system-dir"    // is, is inside or contains a system directory
	RuleDockerSocket Rule = "docker-socket" // is, is inside or contains the Docker socket
	RuleNotOwner     Rule = "not-owner"     // not owned by the invoking user
)

// Error reports a refused workspace.
type Error struct {
	Rule      Rule
	Workspace string // the resolved workspace, or the input if it couldn't be resolved
	Forbidden string // the forbidden path involved, if any
	Msg       string
}

func (e *Error) Error() string {
	return fmt.Sprintf("workspace %s refused: %s", e.Workspace, e.Msg)
}

// ValidateWorkspace resolves path (symlinks followed) and checks it against
// every rule. It returns the resolved path, which is the only path a caller
// may mount: mounting the input instead would reopen the symlink race this
// function closes.
func ValidateWorkspace(path string, p Policy) (string, error) {
	if err := p.check(); err != nil {
		return "", &Error{Rule: RuleInvalid, Workspace: path, Msg: err.Error()}
	}
	if path == "" {
		return "", &Error{Rule: RuleInvalid, Workspace: path, Msg: "empty path"}
	}

	abs := path
	if !filepath.IsAbs(abs) {
		wd, err := os.Getwd()
		if err != nil {
			return "", &Error{Rule: RuleInvalid, Workspace: path, Msg: "cannot make the path absolute: " + err.Error()}
		}
		// Concatenate rather than filepath.Join: Join would clean ".."
		// lexically, but EvalSymlinks must see it to resolve it the way the
		// kernel does (relative to a symlink's target, not its name).
		abs = wd + string(filepath.Separator) + abs
	}
	w, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if isNotExist(err) {
			return "", &Error{Rule: RuleMissing, Workspace: path, Msg: "does not exist"}
		}
		return "", &Error{Rule: RuleInvalid, Workspace: path, Msg: "cannot resolve: " + err.Error()}
	}
	fi, err := os.Stat(w)
	if err != nil {
		return "", &Error{Rule: RuleInvalid, Workspace: w, Msg: "cannot inspect: " + err.Error()}
	}
	if !fi.IsDir() {
		return "", &Error{Rule: RuleNotDir, Workspace: w, Msg: "is not a directory"}
	}

	if w == "/" {
		return "", &Error{Rule: RuleRoot, Workspace: w, Msg: "is the root directory"}
	}

	homes, err := forms(p.Home)
	if err != nil {
		return "", &Error{Rule: RuleInvalid, Workspace: w, Forbidden: p.Home, Msg: err.Error()}
	}
	for _, h := range homes {
		if w == h || within(h, w) {
			return "", &Error{Rule: RuleHome, Workspace: w, Forbidden: h, Msg: "is the home directory or an ancestor of it (" + h + ")"}
		}
	}

	type group struct {
		rule  Rule
		what  string
		paths []string
	}
	dotfiles := make([]string, len(Dotfiles))
	for i, d := range Dotfiles {
		dotfiles[i] = filepath.Join(p.Home, d)
	}
	system := p.SystemDirs
	if len(system) == 0 {
		system = DefaultSystemDirs
	}
	groups := []group{
		{RuleWardenDir, "Warden directory", p.WardenDirs},
		{RuleDotfile, "sensitive home-directory path", dotfiles},
		{RuleSystemDir, "system directory", system},
		{RuleDockerSocket, "Docker socket", []string{p.Socket}},
	}
	for _, g := range groups {
		for _, f := range g.paths {
			variants, err := forms(f)
			if err != nil {
				return "", &Error{Rule: RuleInvalid, Workspace: w, Forbidden: f, Msg: err.Error()}
			}
			for _, ff := range variants {
				if rel := relation(w, ff); rel != "" {
					return "", &Error{Rule: g.rule, Workspace: w, Forbidden: ff, Msg: fmt.Sprintf("%s the %s %s", rel, g.what, ff)}
				}
			}
		}
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", &Error{Rule: RuleInvalid, Workspace: w, Msg: "cannot determine the owner"}
	}
	if int(st.Uid) != p.UID {
		return "", &Error{Rule: RuleNotOwner, Workspace: w, Msg: fmt.Sprintf("is owned by uid %d, not the invoking user (uid %d)", st.Uid, p.UID)}
	}
	return w, nil
}

func (p Policy) check() error {
	if p.Home == "" || !filepath.IsAbs(p.Home) {
		return fmt.Errorf("policy: home %q is not an absolute path", p.Home)
	}
	if len(p.WardenDirs) == 0 {
		return errors.New("policy: no Warden directories given")
	}
	for _, d := range p.WardenDirs {
		if d == "" || !filepath.IsAbs(d) {
			return fmt.Errorf("policy: Warden directory %q is not an absolute path", d)
		}
	}
	for _, d := range p.SystemDirs {
		if d == "" || !filepath.IsAbs(d) {
			return fmt.Errorf("policy: system directory %q is not an absolute path", d)
		}
	}
	if p.Socket == "" || !filepath.IsAbs(p.Socket) {
		return fmt.Errorf("policy: socket %q is not an absolute path", p.Socket)
	}
	return nil
}

// forms returns the forbidden path f as written (cleaned) and, when it
// exists, as resolved by EvalSymlinks. A path that doesn't exist is compared
// as written only; any other resolution error fails closed.
func forms(f string) ([]string, error) {
	clean := filepath.Clean(f)
	r, err := filepath.EvalSymlinks(clean)
	switch {
	case err == nil:
		if r == clean {
			return []string{clean}, nil
		}
		return []string{clean, r}, nil
	case isNotExist(err):
		return []string{clean}, nil
	default:
		return nil, fmt.Errorf("cannot resolve forbidden path %s: %v", clean, err)
	}
}

// isNotExist reports whether err means a path doesn't exist: ENOENT, or
// ENOTDIR when a component of the path is a file.
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// relation describes how workspace w relates to forbidden path f, or
// returns "" if they are unrelated. Both are clean absolute paths.
func relation(w, f string) string {
	switch {
	case w == f:
		return "is"
	case within(w, f):
		return "is inside"
	case within(f, w):
		return "contains"
	}
	return ""
}

// within reports whether child is strictly below parent. Both are clean
// absolute paths, so a separator check avoids "/etc" matching "/etcetera".
func within(child, parent string) bool {
	if parent == "/" {
		return child != "/"
	}
	return strings.HasPrefix(child, parent+"/")
}
