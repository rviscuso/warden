//go:build e2e

// Package e2e holds Warden's live tests: against a real Docker daemon and
// the real filesystem, run by scripts/e2e.sh on the user's host. They change
// nothing outside the temp root, with the one exception documented in
// docs/phase-1.md (host.shared-mounts).
//
// This file is the milestone 1 live test, first run by hand on the real host
// at 48b3b39 (Docker 29.1.3).
//
// scripts/e2e.sh builds it in a throwaway container and runs it on the host
// as the normal user. By hand:
//
//	go test -c -tags e2e -o e2e.test ./test/e2e
//	WARDEN_E2E_WORKSPACE=/path/to/a/repo ./e2e.test -test.v
package e2e

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/docker"
	"github.com/rviscuso/warden/internal/mounts"
	"github.com/rviscuso/warden/internal/paths"
)

var socket = envOr("WARDEN_E2E_SOCKET", "/var/run/docker.sock")

// newRunner creates a runner with a private, freshly made state directory.
func newRunner(t *testing.T, state string) *docker.Exec {
	t.Helper()
	bin, err := docker.FindBinary(docker.BinaryPaths)
	if err != nil {
		t.Fatalf("FindBinary: %v", err)
	}
	home, _ := os.UserHomeDir()
	r, err := docker.New(docker.Options{Binary: bin, Socket: socket, Home: home, StateDir: state, UID: os.Getuid()})
	if err != nil {
		t.Fatalf("docker.New: %v", err)
	}
	return r
}

func privateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRunnerTalksToRealDaemonAndIgnoresDockerEnv(t *testing.T) {
	// If the runner inherited these, every call below would fail.
	t.Setenv("DOCKER_HOST", "tcp://warden-e2e.invalid:2375")
	t.Setenv("DOCKER_CONTEXT", "does-not-exist")
	t.Setenv("DOCKER_CONFIG", "/nonexistent")

	r := newRunner(t, privateDir(t))
	out, errOut, code, err := r.Run(context.Background(), []string{"version", "--format", "{{.Server.Version}}"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("docker version: code=%d err=%v stderr=%s", code, err, errOut)
	}
	t.Logf("daemon version %s", strings.TrimSpace(string(out)))
	for _, e := range r.Env() {
		t.Logf("env: %s", e)
	}
}

func TestDockerConfigStaysEmptyAfterRealUse(t *testing.T) {
	state := privateDir(t)
	r := newRunner(t, state)
	for _, args := range [][]string{
		{"version"}, {"info"}, {"ps", "-a"}, {"images"}, {"network", "ls"},
		{"volume", "ls"}, {"compose", "version"}, {"compose", "ls"},
	} {
		_, errOut, code, err := r.Run(context.Background(), args, nil)
		if err != nil || code != 0 {
			t.Errorf("docker %v: code=%d err=%v stderr=%s", args, code, err, errOut)
		}
	}
	entries, err := os.ReadDir(filepath.Join(state, "docker-config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("docker-config is not empty: docker wrote %q", e.Name())
	}
	// And a second runner on the same state must still accept it.
	newRunner(t, state)
}

func TestTimeoutIsEnforced(t *testing.T) {
	r := newRunner(t, privateDir(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	if _, _, code, err := r.Run(ctx, []string{"info"}, nil); err == nil {
		t.Fatalf("expected a timeout error, got code=%d", code)
	}
}

func TestMountValidationOnRealPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := paths.Resolve(home, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	p := mounts.Policy{UID: os.Getuid(), Home: home, WardenDirs: []string{dirs.Config, dirs.State, dirs.Share}, Socket: socket}

	// Each must be refused; the rule that fires first is logged (several can apply).
	refused := []string{
		"/", home, filepath.Dir(home), "/etc", "/var/run", "/run", "/tmp",
		filepath.Join(home, ".ssh"), filepath.Join(home, ".config"), filepath.Join(home, ".local", "bin"),
	}
	for _, path := range refused {
		_, err := mounts.ValidateWorkspace(path, p)
		var me *mounts.Error
		switch {
		case err == nil:
			t.Errorf("%s: accepted, want refused", path)
		case errors.As(err, &me):
			t.Logf("%s: refused [%s]: %v", path, me.Rule, err)
		default:
			t.Errorf("%s: unexpected error type: %v", path, err)
		}
	}

	ws := os.Getenv("WARDEN_E2E_WORKSPACE")
	if ws == "" {
		t.Skip("set WARDEN_E2E_WORKSPACE to a repo you own to test the accept path")
	}
	got, err := mounts.ValidateWorkspace(ws, p)
	if err != nil {
		t.Fatalf("%s: refused, want accepted: %v", ws, err)
	}
	t.Logf("%s: accepted as %s", ws, got)
}
