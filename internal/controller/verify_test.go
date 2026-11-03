package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// procStatus is a fixture /proc/<pid>/status. Fields in tabs, as the
// kernel writes them.
func procStatus(name string, ppid, uid, gid int, capEff, capBnd string, nnp int) string {
	return procStatusFull(name, ppid, uid, gid, capEff, capBnd, zeroCaps, zeroCaps, nnp, 2)
}

func procStatusFull(name string, ppid, uid, gid int, capEff, capBnd, capPrm, capAmb string, nnp, seccomp int) string {
	return fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nGroups:\t\n"+
		"CapInh:\t0000000000000000\nCapPrm:\t%s\nCapEff:\t%s\nCapBnd:\t%s\nCapAmb:\t%s\nNoNewPrivs:\t%d\nSeccomp:\t%d\n",
		name, ppid, uid, uid, uid, uid, gid, gid, gid, gid, capPrm, capEff, capBnd, capAmb, nnp, seccomp)
}

// FakeProc writes <root>/proc/<pid>/status for each pid.
func fakeProc(t *testing.T, root string, procs map[int]string) {
	t.Helper()
	for pid, status := range procs {
		dir := filepath.Join(root, "proc", fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func hardenedTree(uid, gid int) map[int]string {
	return map[int]string{
		1:   procStatus("systemd", 0, 0, 0, "000001ffffffffff", "000001ffffffffff", 0), // the host's own init: never inspected
		500: procStatus("docker-init", 1, uid, gid, zeroCaps, zeroCaps, 1),
		501: procStatus("claude", 500, uid, gid, zeroCaps, zeroCaps, 1),
		502: procStatus("rg", 501, uid, gid, zeroCaps, zeroCaps, 1), // a grandchild doesn't count
	}
}

func TestVerifyHardened(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, hardenedTree(1000, 1000))
	done, err := verifyProcesses(root, ControllerName, 500, 1000, 1000)
	if !done || err != nil {
		t.Fatalf("done %v err %v", done, err)
	}
}

func TestVerifyFails(t *testing.T) {
	cases := map[string]struct {
		edit func(m map[int]string)
		want string
	}{
		"main as root":   {func(m map[int]string) { m[501] = procStatus("claude", 500, 0, 0, zeroCaps, zeroCaps, 1) }, "main process (pid 501, claude): Uid"},
		"main other uid": {func(m map[int]string) { m[501] = procStatus("claude", 500, 1001, 1000, zeroCaps, zeroCaps, 1) }, "Uid \"1001 1001 1001 1001\""},
		"main other gid": {func(m map[int]string) { m[501] = procStatus("claude", 500, 1000, 1001, zeroCaps, zeroCaps, 1) }, "Gid"},
		"main capabilities": {func(m map[int]string) {
			m[501] = procStatus("claude", 500, 1000, 1000, "00000000a80425fb", zeroCaps, 1)
		}, "CapEff 00000000a80425fb"},
		"main bounding set": {func(m map[int]string) {
			m[501] = procStatus("claude", 500, 1000, 1000, zeroCaps, "00000000a80425fb", 1)
		}, "CapBnd"},
		"main permitted caps": {func(m map[int]string) {
			m[501] = procStatusFull("claude", 500, 1000, 1000, zeroCaps, zeroCaps, "0000000000000400", zeroCaps, 1, 2)
		}, "CapPrm 0000000000000400"},
		"main ambient caps": {func(m map[int]string) {
			m[501] = procStatusFull("claude", 500, 1000, 1000, zeroCaps, zeroCaps, zeroCaps, "0000000000000400", 1, 2)
		}, "CapAmb 0000000000000400"},
		"main no seccomp": {func(m map[int]string) {
			m[501] = procStatusFull("claude", 500, 1000, 1000, zeroCaps, zeroCaps, zeroCaps, zeroCaps, 1, 0)
		}, "Seccomp 0, want 2"},
		"init no seccomp": {func(m map[int]string) {
			m[500] = procStatusFull("docker-init", 1, 1000, 1000, zeroCaps, zeroCaps, zeroCaps, zeroCaps, 1, 0)
		}, "init (pid 500, docker-init): Seccomp"},
		"main new privs": {func(m map[int]string) { m[501] = procStatus("claude", 500, 1000, 1000, zeroCaps, zeroCaps, 0) }, "NoNewPrivs 0"},
		"init capabilities": {func(m map[int]string) {
			m[500] = procStatus("docker-init", 1, 1000, 1000, "00000000a80425fb", zeroCaps, 1)
		}, "init (pid 500, docker-init): CapEff"},
		"init as root":  {func(m map[int]string) { m[500] = procStatus("docker-init", 1, 0, 0, zeroCaps, zeroCaps, 1) }, "init (pid 500"},
		"two children":  {func(m map[int]string) { m[503] = procStatus("sh", 500, 1000, 1000, zeroCaps, zeroCaps, 1) }, "has 2 children"},
		"no init":       {func(m map[int]string) { delete(m, 500) }, "init process 500"},
		"missing field": {func(m map[int]string) { m[501] = "Name:\tclaude\nPPid:\t500\nUid:\t1000\t1000\t1000\t1000\n" }, "no "},
		"uid partly changed": {func(m map[int]string) {
			m[501] = strings.Replace(m[501], "Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t0\t1000\t1000", 1)
		}, "Uid"},
	}
	for name, c := range cases {
		root := t.TempDir()
		m := hardenedTree(1000, 1000)
		c.edit(m)
		fakeProc(t, root, m)
		done, err := verifyProcesses(root, ControllerName, 500, 1000, 1000)
		if !done || err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: done %v err %v, want an error containing %q", name, done, err, c.want)
		}
	}
}

// TestVerifyWaitsForChild: no child yet is "not done", so the caller
// retries instead of failing or passing.
func TestVerifyWaitsForChild(t *testing.T) {
	root := t.TempDir()
	m := hardenedTree(1000, 1000)
	delete(m, 501)
	delete(m, 502)
	fakeProc(t, root, m)
	done, err := verifyProcesses(root, ProxyName, 500, 1000, 1000)
	if done || err == nil {
		t.Fatalf("done %v err %v", done, err)
	}
}
