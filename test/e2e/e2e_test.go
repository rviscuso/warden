//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/docker"
)

// Environment set by scripts/e2e.sh:
//
//	WARDEN_E2E_BIN         the warden binary built from the tested commit
//	WARDEN_E2E_SHA         the commit being tested
//	WARDEN_E2E_GO_IMAGE    the Go build image (pinned by digest, already local)
//	WARDEN_E2E_CONTAINERS  file to append created container IDs to, for the trap
//	WARDEN_E2E_SOCKET      the Docker socket (default /var/run/docker.sock)
//	WARDEN_E2E_WORKSPACE   a workspace inside the temp root
//	TMPDIR                 inside the temp root, so t.TempDir() is too

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s is not set: run the live tests through scripts/e2e.sh", key)
	}
	return v
}

// sandbox is one isolated Warden setup: workspace and XDG dirs as siblings
// under a fresh temp dir, never nested.
type sandbox struct {
	root, ws, config, state, share string
}

func newSandbox(t *testing.T) sandbox {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(root, "/tmp/") {
		t.Fatalf("temp dir %s is under /tmp, which mount validation forbids: set TMPDIR (scripts/e2e.sh does)", root)
	}
	s := sandbox{
		root:   root,
		ws:     filepath.Join(root, "ws"),
		config: filepath.Join(root, "config"),
		state:  filepath.Join(root, "state"),
		share:  filepath.Join(root, "share"),
	}
	for _, d := range []string{s.ws, s.config, s.state, s.share} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s sandbox) configFile() string { return filepath.Join(s.config, "warden", "config.json") }
func (s sandbox) stateFile() string  { return filepath.Join(s.state, "warden", "state.json") }

// warden runs the real binary with only HOME, PATH and the sandbox's XDG
// directories in its environment.
func (s sandbox) warden(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, mustEnv(t, "WARDEN_E2E_BIN"), args...)
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"XDG_CONFIG_HOME=" + s.config,
		"XDG_STATE_HOME=" + s.state,
		"XDG_DATA_HOME=" + s.share,
	}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("warden %v: %v", args, err)
	}
	return out.String(), errb.String(), code
}

// initialized runs warden init twice the way a user would: once to get the
// example config, which is then pointed at the sandbox, once for real.
func (s sandbox) initialized(t *testing.T) {
	t.Helper()
	example, _, code := s.warden(t, "", "init")
	if code != 1 {
		t.Fatalf("first init: exit %d, want 1 (no config yet)", code)
	}
	cfg := strings.Replace(example, `"/path/to/your/repo"`, `"`+s.ws+`"`, 1)
	cfg = strings.Replace(cfg, `"/var/run/docker.sock"`, `"`+socket+`"`, 1)
	if err := os.WriteFile(s.configFile(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := s.warden(t, "", "init")
	t.Logf("warden init:\n%s%s", out, errOut)
	if code != 0 {
		t.Fatalf("init: exit %d", code)
	}
}

// dockerRunner is a sanitized runner for the tests' own docker calls.
func dockerRunner(t *testing.T) *docker.Exec {
	t.Helper()
	return newRunner(t, privateDir(t))
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// recordContainer appends id to the file the script's trap cleans up from.
func recordContainer(t *testing.T, id string) {
	t.Helper()
	f, err := os.OpenFile(mustEnv(t, "WARDEN_E2E_CONTAINERS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(id + "\n"); err != nil {
		t.Fatal(err)
	}
}
