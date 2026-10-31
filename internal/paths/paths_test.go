package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolveDefaults(t *testing.T) {
	d, err := Resolve("/home/u", envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Dirs{
		Config: "/home/u/.config/warden",
		State:  "/home/u/.local/state/warden",
		Share:  "/home/u/.local/share/warden",
	}
	if d != want {
		t.Fatalf("got %+v, want %+v", d, want)
	}
	for got, want := range map[string]string{
		d.ConfigFile():      "/home/u/.config/warden/config.json",
		d.StateFile():       "/home/u/.local/state/warden/state.json",
		d.ComposeDir():      "/home/u/.local/state/warden/compose",
		d.DockerConfigDir(): "/home/u/.local/state/warden/docker-config",
		d.AgentsDir():       "/home/u/.local/share/warden/agents",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestResolveXDG(t *testing.T) {
	d, err := Resolve("/home/u/", envMap(map[string]string{
		"XDG_CONFIG_HOME": "/x/config/",
		"XDG_STATE_HOME":  "/x/state",
		"XDG_DATA_HOME":   "/x/data/../share",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Dirs{Config: "/x/config/warden", State: "/x/state/warden", Share: "/x/share/warden"}
	if d != want {
		t.Fatalf("got %+v, want %+v", d, want)
	}
}

func TestResolveIgnoresRelativeXDG(t *testing.T) {
	d, err := Resolve("/home/u", envMap(map[string]string{
		"XDG_CONFIG_HOME": "config",
		"XDG_STATE_HOME":  "./state",
		"XDG_DATA_HOME":   "../data",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Dirs{
		Config: "/home/u/.config/warden",
		State:  "/home/u/.local/state/warden",
		Share:  "/home/u/.local/share/warden",
	}
	if d != want {
		t.Fatalf("got %+v, want %+v", d, want)
	}
}

func TestResolveRejectsBadHome(t *testing.T) {
	for _, home := range []string{"", "home/u", "./u"} {
		if _, err := Resolve(home, envMap(nil)); err == nil {
			t.Errorf("home %q: expected an error", home)
		}
	}
}

func TestResolveCreatesNothing(t *testing.T) {
	home := t.TempDir()
	if _, err := Resolve(home, envMap(nil)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Resolve created %v", entries)
	}
}

func TestAgentHome(t *testing.T) {
	d := Dirs{Share: "/s/warden"}
	got, err := d.AgentHome("controller")
	if err != nil || got != "/s/warden/agents/controller" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", ".", "..", "../x", "a/b", "Controller", "-x", strings.Repeat("a", 65)} {
		if _, err := d.AgentHome(bad); err == nil {
			t.Errorf("agent name %q: expected an error", bad)
		}
	}
}

func dirErr(t *testing.T, err error) *DirError {
	t.Helper()
	var de *DirError
	if !errors.As(err, &de) {
		t.Fatalf("expected *DirError, got %v", err)
	}
	return de
}

func TestCheckDirOK(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(dir, os.Getuid()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckDirMissing(t *testing.T) {
	err := CheckDir(filepath.Join(t.TempDir(), "nope"), os.Getuid())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected ErrNotExist, got %v", err)
	}
	if de := dirErr(t, err); de.Fix != "run warden init" {
		t.Fatalf("fix %q", de.Fix)
	}
}

func TestCheckDirLoosePermissions(t *testing.T) {
	for _, mode := range []fs.FileMode{0o755, 0o750, 0o701, 0o770, 0o707} {
		dir := filepath.Join(t.TempDir(), "d")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		de := dirErr(t, CheckDir(dir, os.Getuid()))
		if de.Fix != "chmod 700 "+dir {
			t.Errorf("mode %o: fix %q", mode, de.Fix)
		}
		// Checking must not repair anything.
		fi, _ := os.Stat(dir)
		if fi.Mode().Perm() != mode {
			t.Errorf("mode changed to %o", fi.Mode().Perm())
		}
	}
}

func TestCheckDirWrongOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	other := os.Getuid() + 1
	de := dirErr(t, CheckDir(dir, other))
	if !strings.Contains(de.Problem, "is owned by uid") || !strings.HasPrefix(de.Fix, "sudo chown ") {
		t.Fatalf("got %v", de)
	}
}

func TestCheckDirSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	de := dirErr(t, CheckDir(link, os.Getuid()))
	if !strings.Contains(de.Problem, "symlink") {
		t.Fatalf("got %v", de)
	}
}

func TestCheckDirNotADirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	de := dirErr(t, CheckDir(f, os.Getuid()))
	if de.Problem != "is not a directory" {
		t.Fatalf("got %v", de)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u/.config/warden": "/home/u/.config/warden",
		"/a b":                   "'/a b'",
		"/it's":                  `'/it'\''s'`,
		"/$(x)":                  "'/$(x)'",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
