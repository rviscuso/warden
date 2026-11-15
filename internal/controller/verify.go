package controller

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/rviscuso/warden/internal/termsafe"
)

const zeroCaps = "0000000000000000"

// ProcStatus is the part of /proc/<pid>/status that verification reads.
// Uid and Gid hold all four fields, space-separated.
type ProcStatus struct {
	PID                            int
	Name, PPid                     string
	Uid, Gid                       string
	CapEff, CapBnd, CapPrm, CapAmb string
	NoNewPrivs, Seccomp            string
}

// readProcStatus reads <root>/proc/<pid>/status. A missing field is an
// error: verification never guesses.
func readProcStatus(root string, pid int) (ProcStatus, error) {
	path := filepath.Join(root, "proc", strconv.Itoa(pid), "status")
	f, err := os.Open(path)
	if err != nil {
		return ProcStatus{}, err
	}
	defer f.Close()
	fields := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields[k] = strings.Join(strings.Fields(v), " ")
	}
	if err := sc.Err(); err != nil {
		return ProcStatus{}, fmt.Errorf("%s: %w", path, err)
	}
	s := ProcStatus{PID: pid}
	for name, dst := range map[string]*string{
		"Name": &s.Name, "PPid": &s.PPid, "Uid": &s.Uid, "Gid": &s.Gid,
		"CapEff": &s.CapEff, "CapBnd": &s.CapBnd, "CapPrm": &s.CapPrm, "CapAmb": &s.CapAmb,
		"NoNewPrivs": &s.NoNewPrivs, "Seccomp": &s.Seccomp,
	} {
		v, ok := fields[name]
		if !ok {
			return ProcStatus{}, fmt.Errorf("%s: no %s field", path, name)
		}
		*dst = v
	}
	// A process sets its own name, and a failed verification prints it.
	s.Name = termsafe.String(s.Name)
	return s, nil
}

// Problems lists every way s differs from a hardened process of uid:gid.
func (s ProcStatus) Problems(uid, gid int) []string {
	var out []string
	u, g := strconv.Itoa(uid), strconv.Itoa(gid)
	if s.Uid != strings.Repeat(u+" ", 3)+u {
		out = append(out, fmt.Sprintf("Uid %q, want %s in all four fields", s.Uid, u))
	}
	if s.Gid != strings.Repeat(g+" ", 3)+g {
		out = append(out, fmt.Sprintf("Gid %q, want %s in all four fields", s.Gid, g))
	}
	for _, c := range []struct{ name, v string }{
		{"CapEff", s.CapEff}, {"CapBnd", s.CapBnd}, {"CapPrm", s.CapPrm}, {"CapAmb", s.CapAmb},
	} {
		if c.v != zeroCaps {
			out = append(out, c.name+" "+c.v+", want "+zeroCaps)
		}
	}
	if s.NoNewPrivs != "1" {
		out = append(out, "NoNewPrivs "+s.NoNewPrivs+", want 1")
	}
	if s.Seccomp != "2" {
		out = append(out, "Seccomp "+s.Seccomp+", want 2 (filter mode)")
	}
	return out
}

// gone reports whether err means the process no longer exists: the status
// file is missing (it exited before the open), or reading it returned ESRCH
// (it exited between the open and the read).
func gone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// children returns the PIDs whose PPid is pid, by reading every
// <root>/proc/<n>/status: it doesn't rely on CONFIG_PROC_CHILDREN. A
// process that exits during the scan is skipped; any other read error
// fails.
func children(root string, pid int) ([]int, error) {
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return nil, err
	}
	want := strconv.Itoa(pid)
	var out []int
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 0 {
			continue
		}
		s, err := readProcStatus(root, n)
		if gone(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if s.PPid == want {
			out = append(out, n)
		}
	}
	return out, nil
}

// VerifyError is a failed post-start verification.
type VerifyError struct {
	Container string
	Problems  []string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("post-start verification failed for %s: %s", e.Container, strings.Join(e.Problems, "; "))
}

// verifyProcesses checks a container's init (pid, from docker inspect) and
// every child of it, as seen from the host. It is called again until a
// child exists or the caller gives up.
//
// Right after a start init has one child, the container's main process.
// Later it can have more: a process whose parent exited is re-parented to
// init, so a background job the agent left behind sits next to the main
// process. up verifies a container that is already running whenever it is
// run again, so more than one child is normal and each one is checked; the
// count itself proves nothing about hardening.
func verifyProcesses(root, container string, pid, uid, gid int) (done bool, err error) {
	init, err := readProcStatus(root, pid)
	if err != nil {
		return true, &VerifyError{container, []string{"init process " + strconv.Itoa(pid) + ": " + err.Error()}}
	}
	kids, err := children(root, pid)
	if err != nil {
		return true, &VerifyError{container, []string{"listing processes: " + err.Error()}}
	}
	var problems []string
	for _, p := range init.Problems(uid, gid) {
		problems = append(problems, fmt.Sprintf("init (pid %d, %s): %s", pid, init.Name, p))
	}
	checked := 0
	for _, k := range kids {
		child, err := readProcStatus(root, k)
		if gone(err) {
			continue // exited since it was listed
		}
		if err != nil {
			return true, &VerifyError{container, []string{"child process " + strconv.Itoa(k) + ": " + err.Error()}}
		}
		checked++
		for _, p := range child.Problems(uid, gid) {
			problems = append(problems, fmt.Sprintf("child process (pid %d, %s): %s", child.PID, child.Name, p))
		}
	}
	switch {
	case len(problems) > 0:
		return true, &VerifyError{container, problems}
	case checked == 0:
		return false, &VerifyError{container, []string{"init process " + strconv.Itoa(pid) + " has no child (main process) yet"}}
	}
	return true, nil
}
