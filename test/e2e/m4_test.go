//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/canary"
	"github.com/rviscuso/warden/internal/hardening"
)

// Milestone 4 live tests: the real canary on the real daemon, and a
// negative control proving the probe doesn't pass vacuously.

type checkJSON struct {
	OK     bool `json:"ok"`
	Checks []struct {
		ID, Status, Detail, Fix string
	} `json:"checks"`
}

func (s sandbox) checkJSON(t *testing.T, cmd string) checkJSON {
	t.Helper()
	out, errOut, code := s.warden(t, "", cmd, "--json")
	var rep checkJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%s --json: %v\n%s\n%s", cmd, err, out, errOut)
	}
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.ID, "canary.") {
			t.Logf("%s %-20s %s", c.Status, c.ID, c.Detail)
		}
	}
	if (code == 0) != rep.OK {
		t.Fatalf("%s: exit %d but ok %v", cmd, code, rep.OK)
	}
	return rep
}

// noCanaryLeft requires that no canary container, network or run
// directory exists.
func noCanaryLeft(t *testing.T, s sandbox) {
	t.Helper()
	r := dockerRunner(t)
	ctx := context.Background()
	for _, args := range [][]string{
		{"inspect", "--type", "container", "--format", "{{.Name}}", canary.ProxyName, canary.CanaryName},
		{"network", "inspect", "--format", "{{.Name}}", canary.SandboxNet, canary.EgressNet},
	} {
		out, _, _, err := r.Run(ctx, args, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(out)) != "" {
			t.Errorf("left behind: %s", out)
		}
	}
	entries, err := os.ReadDir(s.canaryDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("run directories left in %s: %v", s.canaryDir(), entries)
	}
}

func TestCanaryLive(t *testing.T) {
	s := newSandbox(t)
	s.initialized(t) // init runs the canary and must pass
	noCanaryLeft(t, s)

	rep := s.checkJSON(t, "check")
	if !rep.OK {
		t.Fatal("check failed")
	}
	n := 0
	for _, c := range rep.Checks {
		if !strings.HasPrefix(c.ID, "canary.") {
			continue
		}
		n++
		if c.Status == "fail" || (c.Status == "warn" && c.ID != "canary.apparmor") {
			t.Errorf("%s: %s %s", c.ID, c.Status, c.Detail)
		}
	}
	if n != 19 {
		t.Errorf("%d canary checks, want 19", n)
	}
	noCanaryLeft(t, s)

	bins, _ := filepath.Glob(filepath.Join(s.state, "warden", "bin", "warden-*"))
	if len(bins) != 1 {
		t.Fatalf("binary copies: %v", bins)
	}
	if fi, err := os.Stat(bins[0]); err != nil || fi.Mode().Perm() != 0o500 {
		t.Errorf("%s: %v %v", bins[0], fi.Mode(), err)
	}
}

// TestCanaryNegativeControl runs the probe in a deliberately unhardened
// container (no --cap-drop, no no-new-privileges, writable root, no
// --sysctl, another non-root UID and GID) and requires canary.caps,
// canary.nnp, canary.rootfs, canary.uid and (on a host with MPTCP)
// canary.mptcp to fail.
func TestCanaryNegativeControl(t *testing.T) {
	image := mustEnv(t, "WARDEN_E2E_RUNTIME_IMAGE")
	r := dockerRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, _, code, err := r.Run(ctx, []string{"image", "inspect", "--format", "{{.Id}}", image}, nil); err != nil || code != 0 {
		t.Skipf("SKIP: %s is not local; nothing is pulled", image)
	}
	s := newSandbox(t)
	dir := filepath.Join(s.root, "probe")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "control"), []byte("no_host=skip\n"), 0o600)

	uid, gid := os.Getuid(), os.Getgid()
	name := "warden-e2e-" + randomSuffix(t)
	recordContainer(t, name)
	args := []string{
		"run", "--rm", "--name", name, "--label", "warden.e2e=1",
		"--network", "none", "--pids-limit", "64", "--memory", "256m",
		"--user", strconv.Itoa(uid+1) + ":" + strconv.Itoa(gid+1),
		"--env", "WARDEN_ROLE=canary",
		"--volume", mustEnv(t, "WARDEN_E2E_BIN") + ":/warden:ro",
		"--volume", dir + ":/canary",
		"--entrypoint", "/warden", image,
		"probe", "--proxy", "warden-canary-proxy:3128", "--allow-host", "api.anthropic.com",
		"--deny-host", canary.DenyHost, "--dns-host", "api.anthropic.com", "--route", canary.RouteControl, "--dir", "/canary",
	}
	out, errOut, code, err := r.Run(ctx, args, nil)
	defer r.Run(context.Background(), []string{"rm", "-f", name}, nil)
	if err != nil || code != 0 {
		t.Fatalf("docker run: exit %d, %v: %s", code, err, errOut)
	}
	t.Logf("unhardened probe:\n%s", out)
	obs, err := canary.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	mptcp, err := hardening.HostMPTCP("/")
	if err != nil {
		t.Fatal(err)
	}
	vs := canary.Evaluate(obs, canary.Expect{
		UID: uid, GID: gid, Resources: hardening.Resources{MemoryMB: 1536, CPUs: 1.5, Pids: 512}, DaemonAppArmor: true, MPTCP: mptcp,
	}, canary.Host{})
	got := map[string]canary.Verdict{}
	for _, v := range vs {
		got[v.ID] = v
	}
	mustFail := []string{"canary.caps", "canary.nnp", "canary.rootfs", "canary.uid"}
	if mptcp {
		// Without MPTCP in the kernel there is nothing to turn off: an
		// unhardened container passes canary.mptcp there, correctly.
		mustFail = append(mustFail, "canary.mptcp")
	}
	for _, id := range mustFail {
		if got[id].Status != canary.Fail {
			t.Errorf("%s: %s (%s) in an unhardened container, want fail", id, got[id].Status, got[id].Detail)
		}
	}
}
