package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rviscuso/warden/internal/checks/checkstest"
	"github.com/rviscuso/warden/internal/docker/dockertest"
)

// interruptAt makes the host's signal context cancel when the docker call
// argv is made, as a Ctrl-C at that moment would: that call still returns,
// and every later call on the same context fails. signals is asked for a
// fresh context each time (up asks twice: the checks, then the apply), and
// the one in use is the one canceled.
func (h *host) interruptAt(argv []string, resp dockertest.Response) {
	var cancel context.CancelFunc
	h.envHook = func(e *env) {
		e.signals = func() (context.Context, context.CancelFunc) {
			ctx, c := context.WithCancel(context.Background())
			cancel = c
			return ctx, c
		}
	}
	resp.Do = func([]byte) { cancel() }
	h.fake.On(argv, resp)
}

// TestCheckInterruptedRemovesTheCanary: Ctrl-C during the canary used to
// kill warden and leave its containers, networks and run directory, and
// every later init, check and up failed on the leftovers. Now the canary
// stops and its cleanup still runs.
func TestCheckInterruptedRemovesTheCanary(t *testing.T) {
	h := upHost(t)
	h.interruptAt(checkstest.ArgsCreate, dockertest.Response{})
	// upHost's init already ran one canary: count from here.
	starts, downs := countCalls(h, checkstest.ArgsStart...), countCalls(h, checkstest.ArgsDown...)
	r := h.run("check")
	if r.code != ExitFail || !strings.Contains(r.stderr, "warden check: interrupted") {
		t.Fatalf("%d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if countCalls(h, checkstest.ArgsDown...) != downs+1 {
		t.Error("the canary project was not taken down")
	}
	if countCalls(h, checkstest.ArgsStart...) != starts {
		t.Error("the canary was started after the interrupt")
	}
	if _, err := os.Stat(h.cn.RunDir()); !os.IsNotExist(err) {
		t.Errorf("the run directory is still there: %v", err)
	}
	if !strings.Contains(r.stdout, "pass    canary.cleanup") || !strings.Contains(r.stdout, "context canceled") {
		t.Errorf("report:\n%s", r.stdout)
	}
	// The next run is not blocked by leftovers or a held lock.
	h.envHook = nil
	h.fake.On(checkstest.ArgsCreate, dockertest.Response{})
	if r := h.run("check"); r.code != ExitOK {
		t.Fatalf("check after an interrupted one: %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// TestInitInterruptedDoesNotPin: an interrupted init never pins the daemon.
func TestInitInterruptedDoesNotPin(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.interruptAt(checkstest.ArgsWait, dockertest.Response{Stdout: "0\n"})
	r := h.run("init")
	if r.code != ExitFail || !strings.Contains(r.stderr, "warden init: interrupted") {
		t.Fatalf("%d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(h.stateFile()); !os.IsNotExist(err) {
		t.Errorf("state was written: %v", err)
	}
	if !h.called(checkstest.ArgsDown...) {
		t.Error("the canary project was not taken down")
	}
}

// TestUpInterrupted: from the apply on, an interrupt before verification
// stops what was started; it is never an incident. After verification the
// containers keep running and the message says so.
func TestUpInterrupted(t *testing.T) {
	running := func(name string) []string {
		return []string{"inspect", "--type", "container", "--format", "{{.State.Running}} {{.State.Pid}}", name}
	}
	t.Run("during the canary", func(t *testing.T) {
		h := upHost(t)
		h.interruptAt(checkstest.ArgsCreate, dockertest.Response{})
		downs := countCalls(h, checkstest.ArgsDown...)
		r := h.run("up")
		if r.code != ExitFail || !strings.Contains(r.stderr, "warden up: interrupted") || strings.Contains(r.stderr, "Apply?") {
			t.Fatalf("%d\n%s", r.code, r.stderr)
		}
		if countCalls(h, checkstest.ArgsDown...) != downs+1 || h.called("compose", "-p", "warden", "-f", h.composeFile(), "up", "-d") {
			t.Error("the canary was not removed, or up went on to apply")
		}
	})
	t.Run("during up -d", func(t *testing.T) {
		h := upHost(t)
		h.interruptAt([]string{"compose", "-p", "warden", "-f", h.composeFile(), "up", "-d"}, dockertest.Response{})
		r := h.run("up")
		if r.code != ExitFail || !strings.Contains(r.stderr, "what it started was stopped") || strings.Contains(r.stdout, "Verified") {
			t.Fatalf("%d\n%s", r.code, r.stderr)
		}
		if !h.called("compose", "-p", "warden", "-f", h.composeFile(), "stop", "-t", "0") {
			t.Error("nothing was stopped")
		}
	})
	t.Run("during verification", func(t *testing.T) {
		h := upHost(t)
		h.interruptAt(running("warden-proxy"), dockertest.Response{Stdout: "true 600\n"})
		r := h.run("up")
		if r.code != ExitFail || !strings.Contains(r.stderr, "interrupted during verification") ||
			!strings.Contains(r.stderr, "what it started was stopped") || strings.Contains(r.stdout, "Verified") {
			t.Fatalf("%d\n%s", r.code, r.stderr)
		}
		if !h.called("compose", "-p", "warden", "-f", h.composeFile(), "stop", "-t", "0") {
			t.Error("nothing was stopped")
		}
		if c := h.loadState().Controller; c == nil || c.Incident != "" {
			t.Errorf("an interrupt was recorded as an incident: %+v", c)
		}
	})
	t.Run("while waiting for the URL", func(t *testing.T) {
		h := upHost(t)
		h.interruptAt([]string{"inspect", "--type", "container", "--format", "{{.State.StartedAt}}", "warden-controller"},
			dockertest.Response{Stdout: testStarted + "\n"})
		r := h.run("up")
		if r.code != ExitFail || !strings.Contains(r.stdout, "Verified warden-proxy and warden-controller") ||
			!strings.Contains(r.stderr, "the containers are verified and still running") ||
			!strings.Contains(r.stderr, "fix: run warden status to look for the URL again, or warden down to stop") {
			t.Fatalf("%d\n%s\n%s", r.code, r.stdout, r.stderr)
		}
		if h.called("compose", "-p", "warden", "-f", h.composeFile(), "stop", "-t", "0") {
			t.Error("verified containers were stopped")
		}
	})
}
