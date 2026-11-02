package controller

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const zeroCaps = "0000000000000000"

// ProcStatus is the part of /proc/<pid>/status that verification reads.
// Uid and Gid hold all four fields, space-separated.
type ProcStatus struct {
	PID                        int
	Name, PPid                 string
	Uid, Gid                   string
	CapEff, CapBnd, NoNewPrivs string
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
		"CapEff": &s.CapEff, "CapBnd": &s.CapBnd, "NoNewPrivs": &s.NoNewPrivs,
	} {
		v, ok := fields[name]
		if !ok {
			return ProcStatus{}, fmt.Errorf("%s: no %s field", path, name)
		}
		*dst = v
	}
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
	if s.CapEff != zeroCaps {
		out = append(out, "CapEff "+s.CapEff+", want "+zeroCaps)
	}
	if s.CapBnd != zeroCaps {
		out = append(out, "CapBnd "+s.CapBnd+", want "+zeroCaps)
	}
	if s.NoNewPrivs != "1" {
		out = append(out, "NoNewPrivs "+s.NoNewPrivs+", want 1")
	}
	return out
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
		if errors.Is(err, os.ErrNotExist) {
			continue // exited
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
// its one child, the container's main process, as seen from the host.
// It is called again until the child exists or the caller gives up.
func verifyProcesses(root, container string, pid, uid, gid int) (done bool, err error) {
	init, err := readProcStatus(root, pid)
	if err != nil {
		return true, &VerifyError{container, []string{"init process " + strconv.Itoa(pid) + ": " + err.Error()}}
	}
	kids, err := children(root, pid)
	if err != nil {
		return true, &VerifyError{container, []string{"listing processes: " + err.Error()}}
	}
	switch {
	case len(kids) == 0:
		return false, &VerifyError{container, []string{"init process " + strconv.Itoa(pid) + " has no child (main process) yet"}}
	case len(kids) > 1:
		return true, &VerifyError{container, []string{fmt.Sprintf("init process %d has %d children %v, want exactly one main process", pid, len(kids), kids)}}
	}
	main, err := readProcStatus(root, kids[0])
	if err != nil {
		return true, &VerifyError{container, []string{"main process " + strconv.Itoa(kids[0]) + ": " + err.Error()}}
	}
	var problems []string
	for _, p := range init.Problems(uid, gid) {
		problems = append(problems, fmt.Sprintf("init (pid %d, %s): %s", pid, init.Name, p))
	}
	for _, p := range main.Problems(uid, gid) {
		problems = append(problems, fmt.Sprintf("main process (pid %d, %s): %s", main.PID, main.Name, p))
	}
	if len(problems) > 0 {
		return true, &VerifyError{container, problems}
	}
	return true, nil
}
