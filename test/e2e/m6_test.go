//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rviscuso/warden/internal/controller"
)

// Milestone 6 live test: warden up, check while up, status, down, against
// the real daemon, with the controller image the operator built.

// wardenPresent lists any of up's containers or networks that exist now.
func wardenPresent(t *testing.T) []string {
	t.Helper()
	r := dockerRunner(t)
	ctx := context.Background()
	var found []string
	for _, args := range [][]string{
		{"inspect", "--type", "container", "--format", "{{.Name}}", controller.ProxyName, controller.ControllerName},
		{"network", "inspect", "--format", "{{.Name}}", controller.SandboxNet, controller.EgressNet},
	} {
		out, _, _, err := r.Run(ctx, args, nil)
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, strings.Fields(string(out))...)
	}
	return found
}

func TestUpDown(t *testing.T) {
	image := os.Getenv("WARDEN_E2E_CONTROLLER_IMAGE")
	if image == "" {
		t.Skip("SKIP: no CONTROLLER_IMAGE given to scripts/e2e.sh")
	}
	// up uses the real project name: never touch a Warden that is up.
	if found := wardenPresent(t); len(found) > 0 {
		t.Skipf("SKIP: Warden's containers or networks already exist on this host (%v); run warden down first", found)
	}
	s := newSandbox(t)
	s.initialized(t)
	cfg, err := os.ReadFile(s.configFile())
	if err != nil {
		t.Fatal(err)
	}
	placeholder := `"image": "sha256:` + strings.Repeat("0", 64) + `"`
	if !strings.Contains(string(cfg), placeholder) {
		t.Fatalf("no controller.image placeholder in:\n%s", cfg)
	}
	os.WriteFile(s.configFile(), []byte(strings.Replace(string(cfg), placeholder, `"image": "`+image+`"`, 1)), 0o600)

	recordContainer(t, controller.ProxyName)
	recordContainer(t, controller.ControllerName)
	defer func() {
		s.warden(t, "", "down")
		if left := wardenPresent(t); len(left) > 0 {
			t.Errorf("left behind after down: %v", left)
		}
	}()

	out, errOut, code := s.warden(t, "y\n", "up")
	t.Logf("warden up: exit %d\n%s\n%s", code, out, errOut)
	if !strings.Contains(out, "Verified warden-proxy and warden-controller") {
		t.Fatalf("post-start verification didn't pass (exit %d)", code)
	}
	// A fresh agent home isn't logged in, so no URL is expected; either
	// way the containers must be up and verified.
	if code != 0 && !strings.Contains(errOut, "docker attach warden-controller") {
		t.Fatalf("up failed after verification: exit %d", code)
	}

	rep := s.checkJSON(t, "check")
	for _, c := range rep.Checks {
		if c.ID == "host.shared-mounts" && (c.Status != "pass" || !strings.Contains(c.Detail, "Warden's own mounts allowed")) {
			t.Errorf("host.shared-mounts while up: %s %s", c.Status, c.Detail)
		}
	}
	if !rep.OK {
		t.Error("check failed while Warden is up")
	}

	out, errOut, code = s.warden(t, "", "status")
	t.Logf("warden status: exit %d\n%s%s", code, out, errOut)
	for _, name := range []string{controller.ProxyName, controller.ControllerName} {
		if !strings.Contains(out, name+": running") {
			t.Errorf("status: %s not running", name)
		}
	}
	if code != 0 || strings.Contains(out, "NOT started by Warden") {
		t.Errorf("status exit %d", code)
	}

	out, errOut, code = s.warden(t, "", "logs", "proxy", "-n", "1000")
	if code != 0 || !strings.Contains(out, `"event":"start"`) {
		t.Errorf("logs proxy: exit %d\n%s%s", code, out, errOut)
	}

	out, errOut, code = s.warden(t, "", "down")
	if code != 0 {
		t.Fatalf("down: exit %d\n%s%s", code, out, errOut)
	}
	if left := wardenPresent(t); len(left) > 0 {
		t.Fatalf("left behind after down: %v", left)
	}
}
