package mounts

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fixture is a fake host under a temp directory:
//
//	R/home/u                      home
//	R/home/u/code/repo            a valid workspace
//	R/home/u/.config/warden       config dir
//	R/home/u/.local/state/warden  state dir
//	R/home/u/.local/share/warden  share dir
//	R/sys/{etc,usr,usr/bin}       system dirs; R/sys/bin -> usr/bin
//	R/sys/run/docker.sock         the socket, configured as R/sys/var/run/docker.sock
//	R/sys/var/run -> ../run
type fixture struct {
	t      *testing.T
	root   string
	home   string
	policy Policy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, root: root, home: filepath.Join(root, "home/u")}
	for _, d := range []string{
		"home/u/code/repo",
		"home/u/.config/warden",
		"home/u/.local/state/warden",
		"home/u/.local/share/warden/agents/controller",
		"sys/etc", "sys/usr/bin", "sys/var", "sys/run",
		"srv/repo",
	} {
		f.mkdir(d)
	}
	f.symlink("usr/bin", "sys/bin")
	f.symlink("../run", "sys/var/run")
	f.write("sys/run/docker.sock")
	f.policy = Policy{
		UID:  os.Getuid(),
		Home: f.home,
		WardenDirs: []string{
			f.path("home/u/.config/warden"),
			f.path("home/u/.local/state/warden"),
			f.path("home/u/.local/share/warden"),
		},
		Socket:     f.path("sys/var/run/docker.sock"),
		SystemDirs: []string{f.path("sys/etc"), f.path("sys/usr"), f.path("sys/bin"), f.path("sys/var"), f.path("sys/missing")},
	}
	return f
}

func (f *fixture) path(rel string) string { return filepath.Join(f.root, rel) }

func (f *fixture) mkdir(rel string) string {
	f.t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(p, 0o700); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) write(rel string) string {
	f.t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// symlink creates R/rel pointing at target (relative targets are relative
// to the link's directory, as usual).
func (f *fixture) symlink(target, rel string) string {
	f.t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) ok(path string, want string) {
	f.t.Helper()
	got, err := ValidateWorkspace(path, f.policy)
	if err != nil {
		f.t.Fatalf("%s: unexpected refusal: %v", path, err)
	}
	if got != want {
		f.t.Fatalf("%s: resolved to %s, want %s", path, got, want)
	}
}

func (f *fixture) refused(path string, rule Rule) *Error {
	f.t.Helper()
	got, err := ValidateWorkspace(path, f.policy)
	var e *Error
	if !errors.As(err, &e) {
		f.t.Fatalf("%s: expected refusal by %s, got %q, %v", path, rule, got, err)
	}
	if e.Rule != rule {
		f.t.Fatalf("%s: refused by %s (%v), want %s", path, e.Rule, e, rule)
	}
	if got != "" {
		f.t.Fatalf("%s: a refusal must not return a path, got %q", path, got)
	}
	return e
}

func TestValidWorkspaces(t *testing.T) {
	f := newFixture(t)
	repo := f.path("home/u/code/repo")
	f.ok(repo, repo)
	f.ok(repo+"/", repo)                               // trailing slash
	f.ok(repo+"//", repo)                              // doubled slash
	f.ok(f.path("home/u/code/../code/./repo"), repo)   // .. and . segments
	f.ok(f.symlink(repo, "home/u/link-to-repo"), repo) // symlink is resolved
	f.ok(f.path("srv/repo"), f.path("srv/repo"))       // outside home
	f.ok(f.path("home/u/code"), f.path("home/u/code")) // contains nothing forbidden
	f.ok(f.symlink("../../srv/repo", "home/u/rel"), f.path("srv/repo"))
}

func TestRelativePath(t *testing.T) {
	f := newFixture(t)
	t.Chdir(f.path("home/u/code"))
	f.ok("repo", f.path("home/u/code/repo"))
	f.ok("./repo/", f.path("home/u/code/repo"))
	f.refused("..", RuleHome)
}

func TestDotDotFollowsSymlinkTarget(t *testing.T) {
	// The kernel resolves "link/.." relative to the link's target, not by
	// deleting the last name. A lexical clean would validate one directory
	// while Docker mounted another.
	f := newFixture(t)
	f.mkdir("srv/a/b")
	link := f.symlink(f.path("srv/a/b"), "home/u/code/link")
	f.ok(link+"/..", f.path("srv/a"))

	// And a "safe-looking" path whose physical parent is the home directory.
	f.symlink(f.path("home/u/code/repo"), "srv/to-repo")
	f.refused(f.path("srv/to-repo/../.."), RuleHome)
}

func TestMissingAndNotDir(t *testing.T) {
	f := newFixture(t)
	f.refused(f.path("home/u/code/nope"), RuleMissing)
	f.refused(f.symlink(f.path("nowhere"), "home/u/dangling"), RuleMissing)
	f.refused(f.write("home/u/code/file"), RuleNotDir)
	f.refused(f.path("sys/run/docker.sock"), RuleNotDir)
	f.refused("", RuleInvalid)
}

func TestNotOwner(t *testing.T) {
	f := newFixture(t)
	f.policy.UID = os.Getuid() + 1
	f.refused(f.path("home/u/code/repo"), RuleNotOwner)
}

func TestRoot(t *testing.T) {
	f := newFixture(t)
	f.refused("/", RuleRoot)
	f.refused("//", RuleRoot)
	f.refused("/..", RuleRoot)
}

func TestHomeAndAncestors(t *testing.T) {
	f := newFixture(t)
	f.refused(f.home, RuleHome)
	f.refused(f.home+"/", RuleHome)
	f.refused(f.path("home/u/code/.."), RuleHome)
	f.refused(f.path("home"), RuleHome)
	f.refused(f.root, RuleHome)
	f.refused(f.symlink(f.home, "srv/homelink"), RuleHome)
}

func TestHomeViaSymlink(t *testing.T) {
	// Home is configured through a symlink (/home -> /data/home style); the
	// resolved home and its ancestors are refused too.
	f := newFixture(t)
	f.mkdir("data/home/v/code")
	f.symlink(f.path("data/home"), "linkhome")
	f.policy.Home = f.path("linkhome/v")
	f.refused(f.path("data/home/v"), RuleHome)
	f.refused(f.path("data/home"), RuleHome)
	f.ok(f.path("data/home/v/code"), f.path("data/home/v/code"))
}

func TestWardenDirs(t *testing.T) {
	f := newFixture(t)
	for _, d := range f.policy.WardenDirs {
		e := f.refused(d, RuleWardenDir)
		if !strings.HasPrefix(e.Msg, "is the Warden directory") {
			t.Errorf("msg %q", e.Msg)
		}
		if err := os.MkdirAll(d+"/sub", 0o700); err != nil {
			t.Fatal(err)
		}
		f.refused(d+"/sub/..", RuleWardenDir)
	}
	f.refused(f.path("home/u/.local/share/warden/agents/controller"), RuleWardenDir) // inside
	e := f.refused(f.path("home/u/.local/share"), RuleWardenDir)                     // contains
	if !strings.HasPrefix(e.Msg, "contains") {
		t.Errorf("msg %q", e.Msg)
	}
}

func TestWardenDirsOutsideHome(t *testing.T) {
	// XDG directories can live outside home.
	f := newFixture(t)
	f.mkdir("xdg/config/warden/sub")
	f.policy.WardenDirs = append(f.policy.WardenDirs, f.path("xdg/config/warden"))
	f.refused(f.path("xdg/config/warden"), RuleWardenDir)
	f.refused(f.path("xdg/config/warden/sub"), RuleWardenDir)
	f.refused(f.path("xdg/config"), RuleWardenDir)
	f.refused(f.path("xdg"), RuleWardenDir)
}

func TestWardenDirViaSymlink(t *testing.T) {
	f := newFixture(t)
	f.mkdir("elsewhere/state")
	f.policy.WardenDirs = append(f.policy.WardenDirs, f.symlink(f.path("elsewhere/state"), "srv/state-link"))
	f.refused(f.path("elsewhere/state"), RuleWardenDir)
	f.refused(f.path("elsewhere"), RuleWardenDir)
}

func TestDotfiles(t *testing.T) {
	f := newFixture(t)
	for _, d := range Dotfiles {
		p := filepath.Join(f.home, d)
		if strings.HasPrefix(d, ".ssh") || d == ".aws" || d == ".kube" {
			f.mkdir("home/u/" + d + "/sub")
			f.refused(p, RuleDotfile)        // is
			f.refused(p+"/sub", RuleDotfile) // inside
		}
	}
	// .config and .local exist in the fixture; inside them is refused, even
	// away from Warden's own directories (autostart, ~/.local/bin on PATH).
	f.mkdir("home/u/.config/autostart")
	f.mkdir("home/u/.local/bin")
	f.refused(f.path("home/u/.config/autostart"), RuleDotfile)
	f.refused(f.path("home/u/.local/bin"), RuleDotfile)
	// A symlink into a dotfile directory is resolved and refused.
	f.mkdir("home/u/.ssh")
	f.refused(f.symlink(f.path("home/u/.ssh"), "srv/ssh-link"), RuleDotfile)
}

func TestDotfileSymlinkedOutOfHome(t *testing.T) {
	// ~/.gnupg -> R/dots/gnupg: the resolved form is forbidden too, so a
	// workspace that contains it, is it, or is inside it is refused.
	f := newFixture(t)
	f.mkdir("dots/gnupg/private")
	f.mkdir("dots/other")
	f.symlink(f.path("dots/gnupg"), "home/u/.gnupg")
	f.refused(f.path("dots"), RuleDotfile)
	f.refused(f.path("dots/gnupg"), RuleDotfile)
	f.refused(f.path("dots/gnupg/private"), RuleDotfile)
	f.ok(f.path("dots/other"), f.path("dots/other"))
}

func TestDotfileFiles(t *testing.T) {
	// File dotfiles (.netrc, .bashrc, …) symlinked into a directory make
	// that directory unmountable.
	f := newFixture(t)
	for _, d := range []string{".netrc", ".bashrc", ".profile", ".zshrc"} {
		dir := "dotrepo-" + strings.TrimPrefix(d, ".")
		target := f.write(dir + "/" + d)
		f.symlink(target, "home/u/"+d)
		f.refused(f.path(dir), RuleDotfile)
	}
}

func TestMissingForbiddenPathsAreComparedAsWritten(t *testing.T) {
	f := newFixture(t)
	// ~/.azure doesn't exist and ~/.docker is a dangling symlink: neither
	// is an error, and unrelated workspaces stay valid.
	f.symlink(f.path("nowhere/docker"), "home/u/.docker")
	f.ok(f.path("home/u/code/repo"), f.path("home/u/code/repo"))
	// The system dir R/sys/missing doesn't exist; fine as well.
	f.ok(f.path("srv/repo"), f.path("srv/repo"))
}

func TestForbiddenPathResolutionErrorFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.symlink(".kube", "home/u/.kube") // ~/.kube -> ~/.kube: ELOOP
	e := f.refused(f.path("home/u/code/repo"), RuleInvalid)
	if !strings.Contains(e.Msg, "cannot resolve forbidden path") {
		t.Fatalf("msg %q", e.Msg)
	}
}

func TestSystemDirs(t *testing.T) {
	f := newFixture(t)
	f.mkdir("sys/etc/ssl")
	f.refused(f.path("sys/etc"), RuleSystemDir)     // is
	f.refused(f.path("sys/etc/ssl"), RuleSystemDir) // inside
	f.refused(f.path("sys"), RuleSystemDir)         // contains
	f.refused(f.path("sys/usr/bin"), RuleSystemDir) // inside /usr
	f.refused(f.path("sys/etc/."), RuleSystemDir)
	// R/sys/bin -> usr/bin: the link itself and its target.
	f.refused(f.path("sys/bin"), RuleSystemDir)
	// A symlinked system dir pointing outside: its target is forbidden too.
	f.mkdir("opt/lib64-real/x")
	f.symlink(f.path("opt/lib64-real"), "sys/lib64")
	f.policy.SystemDirs = append(f.policy.SystemDirs, f.path("sys/lib64"))
	f.refused(f.path("opt/lib64-real"), RuleSystemDir)
	f.refused(f.path("opt/lib64-real/x"), RuleSystemDir)
	f.refused(f.path("opt"), RuleSystemDir)
}

func TestNoPrefixConfusion(t *testing.T) {
	// "/etc" must not match "/etcetera", nor ~/.ssh match ~/.sshfoo.
	f := newFixture(t)
	f.mkdir("sys2/etcetera")
	f.mkdir("home/u/.sshfoo")
	f.mkdir("home/u/.config-not")
	f.policy.SystemDirs = []string{f.path("sys2/etc")}
	f.ok(f.path("sys2/etcetera"), f.path("sys2/etcetera"))
	f.ok(f.path("home/u/.sshfoo"), f.path("home/u/.sshfoo"))
	f.ok(f.path("home/u/.config-not"), f.path("home/u/.config-not"))
}

func TestDockerSocket(t *testing.T) {
	f := newFixture(t)
	// The socket's directory isn't in this fixture's system list, so only
	// the socket rule can refuse it.
	f.policy.SystemDirs = []string{f.path("sys/etc")}
	f.refused(f.path("sys/run"), RuleDockerSocket) // contains the resolved socket
	f.refused(f.path("sys/var"), RuleDockerSocket) // contains the socket as written
	f.ok(f.path("sys/usr"), f.path("sys/usr"))
}

func TestDefaultSystemDirsAndDotfiles(t *testing.T) {
	wantSys := []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/var", "/boot", "/proc", "/sys", "/dev", "/run", "/root", "/tmp", "/snap"}
	if !slices.Equal(DefaultSystemDirs, wantSys) {
		t.Errorf("DefaultSystemDirs = %v", DefaultSystemDirs)
	}
	wantDot := []string{".ssh", ".config", ".local", ".aws", ".azure", ".docker", ".gnupg", ".kube", ".netrc", ".bashrc", ".profile", ".zshrc"}
	if !slices.Equal(Dotfiles, wantDot) {
		t.Errorf("Dotfiles = %v", Dotfiles)
	}
}

func TestEmptySystemDirsMeansDefault(t *testing.T) {
	f := newFixture(t)
	f.policy.SystemDirs = nil
	f.refused("/etc", RuleSystemDir)
	f.refused("/usr/bin", RuleSystemDir)
	f.policy.SystemDirs = []string{}
	f.refused("/etc", RuleSystemDir)
}

func TestInvalidPolicyFailsClosed(t *testing.T) {
	f := newFixture(t)
	repo := f.path("home/u/code/repo")
	for name, mod := range map[string]func(*Policy){
		"empty home":         func(p *Policy) { p.Home = "" },
		"relative home":      func(p *Policy) { p.Home = "home/u" },
		"no warden dirs":     func(p *Policy) { p.WardenDirs = nil },
		"relative warden":    func(p *Policy) { p.WardenDirs = []string{"state"} },
		"empty socket":       func(p *Policy) { p.Socket = "" },
		"relative socket":    func(p *Policy) { p.Socket = "docker.sock" },
		"relative system":    func(p *Policy) { p.SystemDirs = []string{"etc"} },
		"empty system entry": func(p *Policy) { p.SystemDirs = []string{""} },
	} {
		p := f.policy
		mod(&p)
		if _, err := ValidateWorkspace(repo, p); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if e := (*Error)(nil); !errors.As(err, &e) || e.Rule != RuleInvalid {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestErrorMessage(t *testing.T) {
	f := newFixture(t)
	_, err := ValidateWorkspace(f.path("sys/etc"), f.policy)
	want := "workspace " + f.path("sys/etc") + " refused: is the system directory " + f.path("sys/etc")
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}

func TestDanglingDotfileSymlink(t *testing.T) {
	// ~/.ssh -> R/data/ssh, and R/data/ssh doesn't exist yet. A workspace
	// R/data would let the agent create R/data/ssh/authorized_keys, which
	// the user's ssh then reads through the link.
	f := newFixture(t)
	f.mkdir("data/other")
	f.symlink(f.path("data/ssh"), "home/u/.ssh")
	e := f.refused(f.path("data"), RuleDotfile)
	if e.Forbidden != f.path("data/ssh") {
		t.Fatalf("forbidden %q", e.Forbidden)
	}
	f.ok(f.path("data/other"), f.path("data/other"))
}

func TestDanglingRelativeAndChainedSymlinks(t *testing.T) {
	f := newFixture(t)
	f.mkdir("data2")
	f.mkdir("data3")
	// Relative target: ~/.aws -> ../../data2/aws (missing).
	f.symlink("../../data2/aws", "home/u/.aws")
	f.refused(f.path("data2"), RuleDotfile)
	// Chain: ~/.kube -> R/hop -> R/data3/kube (missing).
	f.symlink(f.path("data3/kube"), "hop")
	f.symlink(f.path("hop"), "home/u/.kube")
	f.refused(f.path("data3"), RuleDotfile)
}

func TestMissingWardenDirBehindSymlinkedParent(t *testing.T) {
	// XDG_STATE_HOME=R/srv/link with R/srv/link -> R/x/state, and warden/
	// not created yet: init would later create Warden's state inside a
	// workspace R/x/state.
	f := newFixture(t)
	f.mkdir("x/state")
	f.symlink(f.path("x/state"), "srv/link")
	f.policy.WardenDirs = append(f.policy.WardenDirs, f.path("srv/link/warden"))
	f.refused(f.path("x/state"), RuleWardenDir)
	f.refused(f.path("x"), RuleWardenDir)
}

func TestResolvePartial(t *testing.T) {
	f := newFixture(t)
	f.mkdir("a/b")
	f.symlink(f.path("a/b"), "lnk")
	f.symlink("..", "a/b/up") // relative: a/b/up -> a
	f.symlink(f.path("gone/deeper"), "dangling")
	cases := map[string]string{
		f.path("a/b"):                     f.path("a/b"),
		f.path("lnk"):                     f.path("a/b"),
		f.path("lnk/missing/x"):           f.path("a/b/missing/x"),
		f.path("lnk/up/b"):                f.path("a/b"),
		f.path("dangling"):                f.path("gone/deeper"),
		f.path("dangling/x"):              f.path("gone/deeper/x"),
		f.path("missing") + "/../lnk":     f.path("a/b"), // ".." after a missing component
		f.path("lnk") + "/..":             f.path("a"),   // physical, not lexical
		f.path("sys/var/run/docker.sock"): f.path("sys/run/docker.sock"),
	}
	for in, want := range cases {
		got, err := resolvePartial(in)
		if err != nil || got != want {
			t.Errorf("resolvePartial(%s) = %q, %v; want %q", in, got, err, want)
		}
	}
	// For existing paths it agrees with EvalSymlinks.
	for _, in := range []string{f.path("lnk"), f.path("lnk/up/b"), f.path("sys/bin"), f.path("sys/var/run")} {
		want, err := filepath.EvalSymlinks(in)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := resolvePartial(in); err != nil || got != want {
			t.Errorf("resolvePartial(%s) = %q, %v; EvalSymlinks says %q", in, got, err, want)
		}
	}
}

func TestResolvePartialLoopFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.symlink("b", "loop/a")
	f.symlink("a", "loop/b")
	if _, err := resolvePartial(f.path("loop/a/x")); err == nil || !strings.Contains(err.Error(), "too many levels") {
		t.Fatalf("got %v", err)
	}
	// A dangling-loop forbidden path refuses the workspace.
	f.symlink(f.path("loop/a/kube"), "home/u/.kube")
	f.refused(f.path("home/u/code/repo"), RuleInvalid)
}

func TestOverlap(t *testing.T) {
	f := newFixture(t)
	f.mkdir("data/ws")
	f.symlink(f.path("data/ws"), "srv/ws-link")
	f.symlink(f.path("data/future"), "srv/dangling") // target missing
	ws := f.path("data/ws")
	cases := []struct {
		a, b string
		want string
	}{
		{ws, ws, "is"},
		{f.path("data/ws/sub"), ws, "is inside"},
		{f.path("data"), ws, "contains"},
		{f.path("srv/ws-link"), ws, "is"},                              // resolved form of a
		{f.path("srv/ws-link/x"), ws, "is inside"},                     // missing below a link
		{f.path("data/future/x"), f.path("srv/dangling"), "is inside"}, // dangling b
		{f.path("srv/repo"), ws, ""},
		{f.path("data/wsx"), ws, ""}, // no prefix confusion
	}
	for _, c := range cases {
		rel, _, _, err := Overlap(c.a, c.b)
		if err != nil || rel != c.want {
			t.Errorf("Overlap(%s, %s) = %q, %v; want %q", c.a, c.b, rel, err, c.want)
		}
	}
	if _, _, _, err := Overlap("rel", ws); err == nil {
		t.Error("relative path accepted")
	}
	f.symlink("l2", "loop2/l1")
	f.symlink("l1", "loop2/l2")
	if _, _, _, err := Overlap(f.path("loop2/l1/x"), ws); err == nil {
		t.Error("loop accepted")
	}
}
