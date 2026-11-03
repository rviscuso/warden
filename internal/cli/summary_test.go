package cli

import (
	"strings"
	"testing"

	"github.com/rviscuso/warden/internal/checks"
)

func TestInitSummaryOnTerminal(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.tty = true
	r := h.run("init")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	t.Logf("\n%s", r.stdout)
	for _, want := range []string{"✓ config  2 passed\n", "✓ host    ", "✓ daemon  ", "✓ canary  ",
		"All checks passed. Pinned daemon " + zeroID + " at " + h.sock + ".\nNext: warden up\n"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(r.stdout, "STATUS") {
		t.Error("printed the table")
	}
}

// --json and a non-terminal stdin keep the full output.
func TestInitNoSummaryOffTerminal(t *testing.T) {
	for _, tc := range []struct {
		tty  bool
		args []string
	}{{false, []string{"init"}}, {true, []string{"init", "--json"}}} {
		h := newHost(t)
		h.writeConfig()
		h.tty = tc.tty
		r := h.run(tc.args...)
		if r.code != 0 || strings.Contains(r.stdout, "✓ host") || strings.Contains(r.stdout, "Next: warden up") {
			t.Fatalf("%v: exit %d\n%s", tc.args, r.code, r.stdout)
		}
	}
}

// check prints the table even on a terminal.
func TestCheckTableOnTerminal(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	if r := h.run("init"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	h.tty = true
	r := h.run("check")
	if !strings.Contains(r.stdout, "STATUS") || strings.Contains(r.stdout, "✓ host") {
		t.Fatalf("\n%s", r.stdout)
	}
}

func TestPrintSummary(t *testing.T) {
	rep := &checks.Report{Results: []checks.Result{
		{ID: "config.valid", Status: checks.Pass},
		{ID: "host.os", Status: checks.Pass},
		{ID: "daemon.apparmor", Status: checks.Warn, Detail: "no AppArmor", Fix: "enable it"},
		{ID: "daemon.mode", Status: checks.Pass},
		{ID: "canary.caps", Status: checks.Fail, Detail: "CapEff not zero", Fix: "see docs"},
		{ID: "canary.nnp", Status: checks.Pass},
		{ID: "other.thing", Status: checks.Pass, Detail: "ungrouped"},
	}}
	var b strings.Builder
	printSummary(&b, rep)
	want := `✓ config  1 passed
✓ host    1 passed
! daemon  1 passed, 1 warning
✗ canary  1 failed, 1 passed
  ! daemon.apparmor  no AppArmor
    fix: enable it
  ✗ canary.caps  CapEff not zero
    fix: see docs
  ✓ other.thing  ungrouped
Some checks failed.
`
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}
