package mounts

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func (f *fixture) newRefused(path string, rule Rule, msg string) {
	f.t.Helper()
	got, err := ValidateNewWorkspace(path, f.policy)
	var me *Error
	if !errors.As(err, &me) {
		f.t.Fatalf("%s: got %q, %v; want a refusal (%s)", path, got, err, rule)
	}
	if me.Rule != rule || !strings.Contains(me.Msg, msg) {
		f.t.Fatalf("%s: rule %s %q, want %s containing %q", path, me.Rule, me.Msg, rule, msg)
	}
}

func TestNewWorkspaceAllowed(t *testing.T) {
	f := newFixture(t)
	for in, want := range map[string]string{
		f.path("home/u/code/new"):  f.path("home/u/code/new"),
		f.path("home/u/code/new/"): f.path("home/u/code/new"),
		f.path("srv/new"):          f.path("srv/new"),
	} {
		got, err := ValidateNewWorkspace(in, f.policy)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", in, got, err, want)
		}
	}
	// Through a symlinked parent: the result is the resolved parent's child.
	f.symlink("code", "home/u/c")
	got, err := ValidateNewWorkspace(f.path("home/u/c/new"), f.policy)
	if err != nil || got != f.path("home/u/code/new") {
		t.Fatalf("got %q, %v", got, err)
	}
	// Nothing was created.
	if _, err := os.Lstat(f.path("home/u/code/new")); !os.IsNotExist(err) {
		t.Fatal("validation created the folder")
	}
}

func TestNewWorkspaceRefused(t *testing.T) {
	f := newFixture(t)
	f.newRefused("code/new", RuleInvalid, "not an absolute path")
	f.newRefused(f.path("home/u/code/repo"), RuleInvalid, "already exists")
	f.newRefused(f.root+"/home/u/code/x/..", RuleInvalid, ".. segments")
	f.newRefused(f.root+"/home/u/code/../code/new", RuleInvalid, ".. segments")
	f.newRefused(f.path("home/u/nope/new"), RuleMissing, "does not exist")
	f.write("home/u/file")
	f.newRefused(f.path("home/u/file/new"), RuleNotDir, "is not a directory")
	// Every forbidden-path rule applies to the would-be path.
	f.newRefused(f.path("home/u/.ssh"), RuleDotfile, "")
	f.newRefused(f.path("home/u/.config/warden/new"), RuleWardenDir, "")
	f.newRefused(f.path("home/u/.local/new"), RuleDotfile, "")
	f.newRefused(f.path("sys/etc/new"), RuleSystemDir, "")
	f.newRefused(f.path("sys/missing"), RuleSystemDir, "")
	// A parent symlinked into a forbidden directory is caught after resolution.
	f.symlink("../../sys/etc", "home/u/etc-link")
	f.newRefused(f.path("home/u/etc-link/new"), RuleSystemDir, "")
	// A dangling symlink at the path itself "exists".
	f.symlink("/nowhere", "home/u/code/dangling")
	f.newRefused(f.path("home/u/code/dangling"), RuleInvalid, "already exists")
}

func TestNewWorkspaceParentNotOwned(t *testing.T) {
	f := newFixture(t)
	f.policy.UID = os.Getuid() + 1
	f.newRefused(f.path("home/u/code/new"), RuleNotOwner, "is owned by uid")
}
