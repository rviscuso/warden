//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Milestone 5 live test: the controller image the operator built meets the
// image contract (DESIGN.md section 6) under Warden's hardening. Nothing is
// built or pulled: scripts/e2e.sh passes CONTROLLER_IMAGE only if it's local.

func TestControllerImage(t *testing.T) {
	image := os.Getenv("WARDEN_E2E_CONTROLLER_IMAGE")
	if image == "" {
		t.Skip("SKIP: no CONTROLLER_IMAGE given to scripts/e2e.sh")
	}
	r := dockerRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	out, errOut, code, err := r.Run(ctx, []string{"image", "inspect", "--format", "{{json .Config}}", image}, nil)
	if err != nil || code != 0 {
		t.Fatalf("image inspect %s: exit %d, %v: %s", image, code, err, errOut)
	}
	var cfg struct {
		User       string
		Env        []string
		WorkingDir string
		Entrypoint []string
		Cmd        []string
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if u, _, _ := strings.Cut(cfg.User, ":"); u == "" || u == "0" || u == "root" {
		t.Errorf("image User %q: must be non-root", cfg.User)
	}
	if !contains(cfg.Env, "HOME=/home/agent") || !contains(cfg.Env, "DISABLE_AUTOUPDATER=1") {
		t.Errorf("image Env %v: want HOME=/home/agent and DISABLE_AUTOUPDATER=1", cfg.Env)
	}
	if cfg.WorkingDir != "/workspace" {
		t.Errorf("image WorkingDir %q, want /workspace", cfg.WorkingDir)
	}
	if len(cfg.Entrypoint) != 0 {
		t.Errorf("image Entrypoint %v: Warden sets every service's entrypoint", cfg.Entrypoint)
	}

	// Another non-root UID than the user's: the image must not depend on it.
	user := strconv.Itoa(os.Getuid()+1) + ":" + strconv.Itoa(os.Getgid()+1)
	run := func(readOnly bool, entrypoint string, args ...string) (string, int) {
		t.Helper()
		name := "warden-e2e-" + randomSuffix(t)
		recordContainer(t, name)
		argv := []string{"run", "--rm", "--name", name, "--label", "warden.e2e=1",
			"--network", "none", "--user", user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
			"--pids-limit", "256", "--memory", "1g",
			"--tmpfs", "/tmp:rw,exec,nosuid,nodev,mode=1777", "--tmpfs", "/home/agent:rw,nosuid,nodev,mode=1777",
			"--pull", "never"}
		if readOnly {
			argv = append(argv, "--read-only")
		}
		argv = append(argv, "--entrypoint", entrypoint, image)
		argv = append(argv, args...)
		out, errOut, code, err := r.Run(ctx, argv, nil)
		defer r.Run(context.Background(), []string{"rm", "-f", name}, nil)
		if err != nil {
			t.Fatalf("docker run %s: %v", entrypoint, err)
		}
		return strings.TrimSpace(string(out) + string(errOut)), code
	}

	version := regexp.MustCompile(`\d+\.\d+\.\d+`)
	for _, tool := range [][]string{{"claude", "--version"}, {"git", "--version"}, {"rg", "--version"}, {"less", "--version"}, {"ps", "--version"}} {
		out, code := run(true, tool[0], tool[1:]...)
		t.Logf("%s: exit %d: %s", tool[0], code, firstLine(out))
		if code != 0 || !version.MatchString(out) {
			t.Errorf("%s %s as %s, read-only, no capabilities: exit %d: %s", tool[0], tool[1], user, code, out)
		}
	}

	// Writable root this time, so only permissions decide: the tools must
	// not be writable by the agent's UID. test exits 1 when neither is.
	w, code := run(false, "test", "-w", "/usr/local/bin", "-o", "-w", "/usr/local/bin/claude")
	if code != 1 {
		t.Errorf("/usr/local/bin or claude is writable by %s (test exit %d: %s)", user, code, w)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
