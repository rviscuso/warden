//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/state"
)

// Milestone 2 live tests: the real warden binary against the real daemon.

func TestVersionIsTheTestedCommit(t *testing.T) {
	s := newSandbox(t)
	out, _, code := s.warden(t, "", "version")
	t.Logf("warden version:\n%s", out)
	sha := mustEnv(t, "WARDEN_E2E_SHA")
	if code != 0 || !strings.Contains(out, "revision: "+sha) || !strings.Contains(out, "modified: false") {
		t.Fatalf("exit %d, want revision %s and modified: false", code, sha)
	}
}

func TestInitWithoutConfig(t *testing.T) {
	s := newSandbox(t)
	out, errOut, code := s.warden(t, "", "init")
	if code != 1 || !strings.Contains(errOut, "no config at "+s.configFile()) {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if _, err := config.Parse([]byte(out)); err != nil {
		t.Fatalf("example config is invalid: %v\n%s", err, out)
	}
	for _, d := range []string{"config", "state", "share"} {
		fi, err := os.Stat(filepath.Join(s.root, d, "warden"))
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s/warden: %v %v", d, fi, err)
		}
	}
	if _, err := os.Stat(s.stateFile()); err == nil {
		t.Fatal("state written without a config")
	}
}

func TestInitAndCheckOnRealDaemon(t *testing.T) {
	s := newSandbox(t)
	s.initialized(t)
	st, err := state.Load(s.stateFile())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pinned: %+v", st.Daemon)
	if st.Daemon.ID == "" || st.Daemon.Socket != socket || st.Daemon.ServerVersion == "" || st.Daemon.Compose == "" {
		t.Fatalf("incomplete pin: %+v", st.Daemon)
	}

	out, errOut, code := s.warden(t, "", "check")
	t.Logf("warden check:\n%s%s", out, errOut)
	if code != 0 {
		t.Fatalf("check: exit %d", code)
	}
	out, _, code = s.warden(t, "", "check", "--json")
	var rep struct {
		OK     bool `json:"ok"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 0 || !rep.OK {
		t.Fatalf("check --json: exit %d, ok %v, err %v\n%s", code, rep.OK, err, out)
	}
	if last := rep.Checks[len(rep.Checks)-1]; last.ID != "host.shared-mounts" || last.Status != "pass" {
		t.Fatalf("shared-mounts: %+v", last)
	}
}

type entry struct {
	mode  fs.FileMode
	size  int64
	mtime time.Time
}

func snapshot(t *testing.T, root string) map[string]entry {
	t.Helper()
	m := map[string]entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		m[p] = entry{fi.Mode(), fi.Size(), fi.ModTime()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCheckIsReadOnly(t *testing.T) {
	s := newSandbox(t)
	s.initialized(t)
	before := snapshot(t, s.root)
	if _, _, code := s.warden(t, "", "check"); code != 0 {
		t.Fatalf("check: exit %d", code)
	}
	after := snapshot(t, s.root)
	for p, e := range after {
		if b, ok := before[p]; !ok || b != e {
			t.Errorf("check changed %s", p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("check removed %s", p)
		}
	}
}

func TestRepinNeedsApproval(t *testing.T) {
	s := newSandbox(t)
	s.initialized(t)
	real, err := state.Load(s.stateFile())
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the pin belongs to another daemon.
	fake := *real
	fake.Daemon.ID = "warden-e2e-not-this-daemon"
	if err := state.Save(s.stateFile(), &fake); err != nil {
		t.Fatal(err)
	}

	out, _, code := s.warden(t, "", "check")
	if code != 1 || !strings.Contains(out, "daemon changed; re-run init") {
		t.Fatalf("check with a foreign pin: exit %d\n%s", code, out)
	}
	for _, answer := range []string{"", "n\n", "yes\n"} {
		_, errOut, code := s.warden(t, answer, "init")
		if code != 1 || !strings.Contains(errOut, "Re-pin to the new daemon? [y/N]") || !strings.Contains(errOut, "Kept the existing pin.") {
			t.Fatalf("answer %q: exit %d\n%s", answer, code, errOut)
		}
		if st, _ := state.Load(s.stateFile()); st.Daemon.ID != fake.Daemon.ID {
			t.Fatalf("answer %q changed the pin", answer)
		}
	}
	if _, errOut, code := s.warden(t, "y\n", "init"); code != 0 {
		t.Fatalf("answer y: exit %d\n%s", code, errOut)
	}
	if st, _ := state.Load(s.stateFile()); st.Daemon.ID != real.Daemon.ID {
		t.Fatalf("pin after y: %s, want %s", st.Daemon.ID, real.Daemon.ID)
	}
}

// TestSharedMountDetected is the one live test that changes Docker state:
// it creates (never starts) one container from the already-local Go build
// image, mounting the sandbox workspace read-only, and always removes it.
func TestSharedMountDetected(t *testing.T) {
	image := mustEnv(t, "WARDEN_E2E_GO_IMAGE")
	r := dockerRunner(t)
	ctx := context.Background()
	if _, _, code, err := r.Run(ctx, []string{"image", "inspect", "--format", "{{.Id}}", image}, nil); err != nil || code != 0 {
		t.Skipf("SKIP: %s is not local; nothing is pulled", image)
	}

	s := newSandbox(t)
	s.initialized(t)

	name := "warden-e2e-" + randomSuffix(t)
	out, errOut, code, err := r.Run(ctx, []string{
		"create", "--name", name, "--label", "warden.e2e=1", "--network", "none",
		"--volume", s.ws + ":/w:ro", image, "true",
	}, nil)
	if err != nil || code != 0 {
		t.Fatalf("docker create: exit %d, %v: %s", code, err, errOut)
	}
	id := strings.TrimSpace(string(out))
	recordContainer(t, id)
	defer func() {
		if _, errOut, code, err := r.Run(context.Background(), []string{"rm", "-f", id}, nil); err != nil || code != 0 {
			t.Errorf("docker rm -f %s: exit %d, %v: %s", id, code, err, errOut)
		}
	}()

	out2, _, code := s.warden(t, "", "check")
	t.Logf("warden check with %s present:\n%s", name, out2)
	if code != 1 || !strings.Contains(out2, "container "+name) || !strings.Contains(out2, "-> /w is "+s.ws) {
		t.Fatalf("check: exit %d, want a host.shared-mounts failure naming %s", code, name)
	}

	status, _, _, err := r.Run(ctx, []string{"inspect", "--format", "{{.State.Status}}", id}, nil)
	if err != nil || strings.TrimSpace(string(status)) != "created" {
		t.Fatalf("container state %q (%v): it must never be started", status, err)
	}
}
