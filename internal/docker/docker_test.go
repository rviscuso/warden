package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/paths"
)

// The test binary doubles as a fake docker CLI. Warden passes a clean
// environment, so helper mode is signalled through argv:
//
//	<test binary> -test.run=^TestHelperProcess$ -- warden-helper <mode> [args...]
func TestHelperProcess(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 || i+2 >= len(os.Args) || os.Args[i+1] != "warden-helper" {
		return
	}
	mode, args := os.Args[i+2], os.Args[i+3:]
	switch mode {
	case "env":
		env := os.Environ()
		slices.Sort(env)
		fmt.Println(strings.Join(env, "\n"))
	case "args":
		for _, a := range args {
			fmt.Printf("[%s]\n", a)
		}
	case "pwd":
		wd, _ := os.Getwd()
		fmt.Println(wd)
	case "cat":
		io.Copy(os.Stdout, os.Stdin)
	case "exit":
		fmt.Fprint(os.Stdout, "out")
		fmt.Fprint(os.Stderr, "err")
		code, _ := strconv.Atoi(args[0])
		os.Exit(code)
	case "sleep":
		d, _ := time.ParseDuration(args[0])
		time.Sleep(d)
		fmt.Print("woke")
	}
	os.Exit(0)
}

func helperArgs(mode string, args ...string) []string {
	return append([]string{"-test.run=^TestHelperProcess$", "--", "warden-helper", mode}, args...)
}

type setup struct {
	state string
	opts  Options
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return &setup{state: state, opts: Options{
		Binary:   bin,
		Socket:   "/run/test/docker.sock",
		Home:     "/home/test",
		StateDir: state,
		UID:      os.Getuid(),
	}}
}

func (s *setup) runner(t *testing.T) *Exec {
	t.Helper()
	r, err := New(s.opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEnvironmentIsExactlyTheSanitizedOne(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://evil:2375")
	t.Setenv("DOCKER_CONTEXT", "evil")
	t.Setenv("DOCKER_CONFIG", "/evil")
	t.Setenv("DOCKER_CERT_PATH", "/evil")
	t.Setenv("COMPOSE_FILE", "/evil.yaml")
	t.Setenv("SOME_SECRET", "hunter2")
	s := newSetup(t)
	r := s.runner(t)
	out, errOut, code, err := r.Run(context.Background(), helperArgs("env"), nil)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v stderr %s", code, err, errOut)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{
		"DOCKER_CONFIG=" + filepath.Join(s.state, "docker-config"),
		"DOCKER_HOST=unix:///run/test/docker.sock",
		"HOME=/home/test",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("environment:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(r.Env(), []string{want[3], want[2], want[1], want[0]}) {
		t.Fatalf("Env() = %v", r.Env())
	}
}

func TestArgvIsPassedVerbatim(t *testing.T) {
	r := newSetup(t).runner(t)
	tricky := []string{"a b", "$(id)", "; rm -rf /", "'quoted'", "`x`", "", "--flag=v w"}
	out, _, code, err := r.Run(context.Background(), helperArgs("args", tricky...), nil)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	var want strings.Builder
	for _, a := range tricky {
		fmt.Fprintf(&want, "[%s]\n", a)
	}
	if string(out) != want.String() {
		t.Fatalf("got\n%s\nwant\n%s", out, want.String())
	}
}

func TestWorkingDirectoryIsRoot(t *testing.T) {
	r := newSetup(t).runner(t)
	t.Chdir(t.TempDir()) // a directory that could hold an agent-written .env
	out, _, _, err := r.Run(context.Background(), helperArgs("pwd"), nil)
	if err != nil || strings.TrimSpace(string(out)) != "/" {
		t.Fatalf("pwd %q err %v", out, err)
	}
}

func TestStdin(t *testing.T) {
	r := newSetup(t).runner(t)
	out, _, _, err := r.Run(context.Background(), helperArgs("cat"), strings.NewReader("hello"))
	if err != nil || string(out) != "hello" {
		t.Fatalf("out %q err %v", out, err)
	}
}

func TestNonZeroExitIsNotAnError(t *testing.T) {
	r := newSetup(t).runner(t)
	out, errOut, code, err := r.Run(context.Background(), helperArgs("exit", "3"), nil)
	if err != nil || code != 3 || string(out) != "out" || string(errOut) != "err" {
		t.Fatalf("out %q stderr %q code %d err %v", out, errOut, code, err)
	}
}

func TestDefaultTimeout(t *testing.T) {
	s := newSetup(t)
	s.opts.Timeout = 200 * time.Millisecond
	r := s.runner(t)
	start := time.Now()
	_, _, code, err := r.Run(context.Background(), helperArgs("sleep", "20s"), nil)
	if !errors.Is(err, context.DeadlineExceeded) || code != -1 {
		t.Fatalf("code %d err %v", code, err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestCallerDeadlineOverridesDefault(t *testing.T) {
	s := newSetup(t)
	s.opts.Timeout = 50 * time.Millisecond
	r := s.runner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, _, code, err := r.Run(ctx, helperArgs("sleep", "300ms"), nil)
	if err != nil || code != 0 || string(out) != "woke" {
		t.Fatalf("out %q code %d err %v", out, code, err)
	}
}

func TestDefaultTimeoutValue(t *testing.T) {
	if r := newSetup(t).runner(t); r.timeout != 30*time.Second {
		t.Fatalf("default timeout %v", r.timeout)
	}
	if ComposeTimeout != 5*time.Minute {
		t.Fatalf("compose timeout %v", ComposeTimeout)
	}
}

func TestMissingBinaryIsAnError(t *testing.T) {
	s := newSetup(t)
	s.opts.Binary = filepath.Join(t.TempDir(), "no-docker")
	r := s.runner(t)
	if _, _, code, err := r.Run(context.Background(), []string{"version"}, nil); err == nil || code != -1 {
		t.Fatalf("code %d err %v", code, err)
	}
}

func TestDockerConfigCreated(t *testing.T) {
	s := newSetup(t)
	s.runner(t)
	dc := filepath.Join(s.state, "docker-config")
	fi, err := os.Lstat(dc)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("docker-config mode %v", fi.Mode())
	}
	entries, _ := os.ReadDir(dc)
	if len(entries) != 0 {
		t.Fatalf("docker-config not empty: %v", entries)
	}
	s.runner(t) // an existing correct directory is accepted
}

func TestDockerConfigLoosePermissions(t *testing.T) {
	s := newSetup(t)
	dc := filepath.Join(s.state, "docker-config")
	if err := os.Mkdir(dc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dc, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := New(s.opts)
	var de *paths.DirError
	if !errors.As(err, &de) || de.Fix != "chmod 700 "+paths.ShellQuote(dc) {
		t.Fatalf("got %v", err)
	}
	if fi, _ := os.Stat(dc); fi.Mode().Perm() != 0o755 {
		t.Fatalf("permissions were changed to %v", fi.Mode().Perm())
	}
}

func TestDockerConfigWrongOwner(t *testing.T) {
	s := newSetup(t)
	if err := os.Mkdir(filepath.Join(s.state, "docker-config"), 0o700); err != nil {
		t.Fatal(err)
	}
	// We can't chown without root, so check the state dir against another
	// UID: it fails before docker-config is touched, with a chown fix.
	s.opts.UID = os.Getuid() + 1
	_, err := New(s.opts)
	var de *paths.DirError
	if !errors.As(err, &de) || !strings.HasPrefix(de.Fix, "sudo chown ") {
		t.Fatalf("got %v", err)
	}
}

func TestDockerConfigWrongOwnerDirect(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "docker-config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := ensurePrivateDir(dir, os.Getuid()+1)
	var de *paths.DirError
	if !errors.As(err, &de) || !strings.Contains(de.Problem, "owned by uid") {
		t.Fatalf("got %v", err)
	}
}

func TestDockerConfigSymlinkRefused(t *testing.T) {
	s := newSetup(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(s.state, "docker-config")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(s.opts); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("got %v", err)
	}
}

func TestStateDirMustExist(t *testing.T) {
	s := newSetup(t)
	s.opts.StateDir = filepath.Join(t.TempDir(), "missing")
	_, err := New(s.opts)
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "run warden init") {
		t.Fatalf("got %v", err)
	}
	if _, statErr := os.Stat(s.opts.StateDir); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatal("New created the state directory")
	}
}

func TestStateDirLoosePermissions(t *testing.T) {
	s := newSetup(t)
	if err := os.Chmod(s.state, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(s.opts); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRejectsRelativePaths(t *testing.T) {
	for name, mod := range map[string]func(*Options){
		"binary":       func(o *Options) { o.Binary = "docker" },
		"socket":       func(o *Options) { o.Socket = "docker.sock" },
		"empty socket": func(o *Options) { o.Socket = "" },
		"home":         func(o *Options) { o.Home = "~" },
		"state":        func(o *Options) { o.StateDir = "state" },
	} {
		s := newSetup(t)
		mod(&s.opts)
		if _, err := New(s.opts); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestFindBinary(t *testing.T) {
	dir := t.TempDir()
	notExec := filepath.Join(dir, "not-exec")
	os.WriteFile(notExec, nil, 0o644)
	aDir := filepath.Join(dir, "a-dir")
	os.Mkdir(aDir, 0o755)
	good := filepath.Join(dir, "docker")
	os.WriteFile(good, nil, 0o755)
	second := filepath.Join(dir, "docker2")
	os.WriteFile(second, nil, 0o755)
	link := filepath.Join(dir, "link")
	os.Symlink(good, link)

	got, err := FindBinary([]string{filepath.Join(dir, "missing"), notExec, aDir, good, second})
	if err != nil || got != good {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := FindBinary([]string{link}); err != nil || got != link {
		t.Fatalf("symlinked binary: got %q, %v", got, err)
	}
	if _, err := FindBinary([]string{notExec, aDir}); err == nil {
		t.Fatal("expected not found")
	}
	if _, err := FindBinary([]string{"docker"}); err == nil {
		t.Fatal("relative candidate accepted")
	}
	if _, err := FindBinary(nil); err == nil {
		t.Fatal("expected not found for no candidates")
	}
}

func TestBinaryPaths(t *testing.T) {
	if !slices.Equal(BinaryPaths, []string{"/usr/bin/docker", "/usr/local/bin/docker"}) {
		t.Fatalf("BinaryPaths = %v", BinaryPaths)
	}
}
