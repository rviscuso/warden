//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/rviscuso/warden/images"
	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/refimage"
)

// openPTY opens a pseudo-terminal with the standard library only.
func openPTY(t *testing.T) (ptmx, tty *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Fatal(e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Fatal(e)
	}
	tty, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ptmx, tty
}

// wardenTTY runs warden with stdin, stdout and stderr on a pseudo-terminal
// and types the answers, one line each, as each prompt appears. It returns
// everything the terminal showed.
func (s sandbox) wardenTTY(t *testing.T, timeout time.Duration, answers []string, args ...string) (string, int) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	ptmx, tty := openPTY(t)
	defer ptmx.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, mustEnv(t, "WARDEN_E2E_BIN"), args...)
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"XDG_CONFIG_HOME=" + s.config,
		"XDG_STATE_HOME=" + s.state,
		"XDG_DATA_HOME=" + s.share,
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	tty.Close() // the child holds it now; EIO on ptmx once it exits

	var mu sync.Mutex
	var screen bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			mu.Lock()
			screen.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	// Type each answer once the screen has grown since the last one ended
	// with a prompt (": " or "] ").
	go func() {
		seen := 0
		for _, a := range answers {
			for {
				mu.Lock()
				cur := screen.String()
				mu.Unlock()
				tail := strings.TrimRight(cur[seen:], "\r\n")
				if len(cur) > seen && (strings.HasSuffix(cur, ": ") || strings.HasSuffix(cur, "] ")) && tail != "" {
					seen = len(cur)
					break
				}
				select {
				case <-done:
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
			io.WriteString(ptmx, a+"\n")
		}
	}()
	err = cmd.Wait()
	<-done
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("warden %v: %v", args, err)
	}
	mu.Lock()
	defer mu.Unlock()
	return screen.String(), code
}

func (s sandbox) loadConfig(t *testing.T) *config.Config {
	t.Helper()
	fi, err := os.Stat(s.configFile())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, want 0600", fi.Mode().Perm())
	}
	c, err := config.Load(s.configFile())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestGuidedInit drives warden init through a pseudo-terminal: a workspace
// that doesn't exist yet (created and git-inited), one added domain,
// defaults elsewhere, the given controller image, y at the review. The
// checks and the canary must pass. Nothing is pulled.
func TestGuidedInit(t *testing.T) {
	build := os.Getenv("WARDEN_E2E_BUILD") == "1"
	image := os.Getenv("WARDEN_E2E_CONTROLLER_IMAGE")
	if image == "" && !build {
		t.Skip("SKIP: no CONTROLLER_IMAGE given to scripts/e2e.sh (or WARDEN_E2E_BUILD=1)")
	}
	if socket != "/var/run/docker.sock" {
		t.Skipf("SKIP: the guided init uses the default socket; this host uses %s", socket)
	}
	requireLocal(t, images.RuntimeImage)
	s := newSandbox(t)
	ws := filepath.Join(s.root, "created")

	var before map[string]bool
	answers := []string{ws, "y", "github.com", "", "", "", "", ""}
	if build {
		before = imageIDs(t)
		answers = append(answers, "build", "y", "y")
	} else {
		answers = append(answers, image, "y")
	}
	out, code := s.wardenTTY(t, 30*time.Minute, answers, "init")
	t.Logf("terminal:\n%s", out)
	if code != 0 {
		t.Fatalf("guided init: exit %d", code)
	}
	for _, want := range []string{"created " + ws + " (git init, branch main)", "✓ runtime image " + images.RuntimeImage, "All checks passed. Pinned daemon ", "Next: warden up"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal lacks %q", want)
		}
	}
	c := s.loadConfig(t)
	if c.Controller.Workspace != ws || strings.Join(c.Egress.Allow, ",") != "api.anthropic.com,platform.claude.com,github.com" ||
		c.Controller.RemoteControlName != "warden" || c.Controller.Resources != (config.Resources{MemoryMB: 1536, CPUs: 1.5, PIDs: 512}) {
		t.Errorf("config %+v", c)
	}
	head, err := os.ReadFile(filepath.Join(ws, ".git", "HEAD"))
	if err != nil || strings.TrimSpace(string(head)) != "ref: refs/heads/main" {
		t.Errorf("HEAD %q %v", head, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(ws, ".git", "hooks")); len(entries) != 0 {
		t.Errorf("hooks copied: %v", entries)
	}
	if fi, err := os.Stat(ws); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("workspace %v %v", fi, err)
	}
	if !build {
		id := imageID(t, image)
		if c.Controller.Image != id {
			t.Errorf("controller.image %s, want %s", c.Controller.Image, id)
		}
		return
	}

	// The build path: the image meets the contract, and a second guided
	// init offers it as the default without rebuilding.
	built := c.Controller.Image
	if !before[built] {
		t.Cleanup(func() { removeImage(t, built) })
	}
	if _, err := refimage.Check(context.Background(), dockerRunner(t), built, runtime.GOARCH); err != nil {
		t.Fatalf("built image: %v", err)
	}
	if err := os.Remove(s.configFile()); err != nil {
		t.Fatal(err)
	}
	out, code = s.wardenTTY(t, 5*time.Minute, []string{ws, "", "", "", "", "", "", "y"}, "init")
	t.Logf("second run:\n%s", out)
	if code != 0 || !strings.Contains(out, `"build" [`+built+`]: `) || strings.Contains(out, "building") {
		t.Fatalf("second guided init: exit %d", code)
	}
	if s.loadConfig(t).Controller.Image != built {
		t.Fatal("second run didn't reuse the build")
	}
}

// TestGuidedInitReviewNo: N at the review writes nothing.
func TestGuidedInitReviewNo(t *testing.T) {
	image := os.Getenv("WARDEN_E2E_CONTROLLER_IMAGE")
	if image == "" {
		t.Skip("SKIP: no CONTROLLER_IMAGE given to scripts/e2e.sh")
	}
	if socket != "/var/run/docker.sock" {
		t.Skipf("SKIP: the guided init uses the default socket; this host uses %s", socket)
	}
	requireLocal(t, images.RuntimeImage)
	s := newSandbox(t)
	out, code := s.wardenTTY(t, 2*time.Minute, []string{s.ws, "", "", "", "", "", image, "n"}, "init")
	if code != 1 || !strings.Contains(out, "nothing written") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(s.configFile()); !os.IsNotExist(err) {
		t.Fatal("config written after N")
	}
}

func requireLocal(t *testing.T, ref string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, _, code, err := dockerRunner(t).Run(ctx, []string{"image", "inspect", "--format", "{{.Id}}", ref}, nil); err != nil || code != 0 {
		t.Fatalf("%s is not local and nothing is pulled: docker pull %s", ref, ref)
	}
}

func imageID(t *testing.T, ref string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _, code, err := dockerRunner(t).Run(ctx, []string{"image", "inspect", "--format", "{{.Id}}", ref}, nil)
	if err != nil || code != 0 {
		t.Fatalf("inspect %s: %v exit %d", ref, err, code)
	}
	return strings.TrimSpace(string(out))
}

func imageIDs(t *testing.T) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _, code, err := dockerRunner(t).Run(ctx, []string{"image", "ls", "-q", "--no-trunc"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("docker image ls: %v exit %d", err, code)
	}
	ids := map[string]bool{}
	for _, l := range strings.Fields(string(out)) {
		ids[l] = true
	}
	return ids
}

func removeImage(t *testing.T, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, stderr, code, err := dockerRunner(t).Run(ctx, []string{"image", "rm", id}, nil); err != nil || code != 0 {
		t.Errorf("docker image rm %s: %v exit %d %s", id, err, code, stderr)
	}
}
