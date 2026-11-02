package hardening

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var res = Resources{MemoryMB: 1536, CPUs: 1.5, Pids: 512}

func TestSettings(t *testing.T) {
	f, err := Settings(1000, 1001, res, Host{MPTCP: MPTCPPresent})
	if err != nil {
		t.Fatal(err)
	}
	want := Fields{
		User:         "1000:1001",
		CapDrop:      []string{"ALL"},
		SecurityOpt:  []string{"no-new-privileges:true"},
		ReadOnly:     true,
		Tmpfs:        []string{"/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777"},
		MemLimit:     1536 << 20,
		MemswapLimit: 1536 << 20,
		CPUs:         1.5,
		PidsLimit:    512,
		Init:         true,
		IPC:          "private",
		Cgroup:       "private",
		Sysctls:      &Sysctls{},
		Restart:      "no",
		PullPolicy:   "never",
	}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("Settings:\n got %+v\nwant %+v", f, want)
	}
}

func TestSettingsRefusesRoot(t *testing.T) {
	for _, ids := range [][2]int{{0, 1000}, {1000, 0}, {0, 0}, {-1, 1000}, {1000, -1}} {
		if _, err := Settings(ids[0], ids[1], res, Host{MPTCP: MPTCPPresent}); err == nil {
			t.Errorf("Settings(%d, %d) accepted", ids[0], ids[1])
		}
	}
}

func TestSettingsRefusesBadResources(t *testing.T) {
	for _, r := range []Resources{
		{0, 1, 64}, {-1, 1, 64}, {256, 0, 64}, {256, -1, 64}, {256, math.NaN(), 64},
		{256, math.Inf(1), 64}, {256, 1, 0}, {256, 1, -5},
	} {
		if _, err := Settings(1000, 1000, r, Host{MPTCP: MPTCPPresent}); err == nil {
			t.Errorf("Settings accepted %+v", r)
		}
	}
}

func TestProxyResources(t *testing.T) {
	if ProxyResources != (Resources{256, 0.5, 128}) {
		t.Fatalf("ProxyResources = %+v", ProxyResources)
	}
	if _, err := Settings(1000, 1000, ProxyResources, Host{MPTCP: MPTCPPresent}); err != nil {
		t.Fatal(err)
	}
}

// TestFieldsCannotExpressUnsafeSettings: the type itself has no field for
// any setting the invariants forbid. compose.Validate checks the rendered
// JSON as well.
func TestFieldsCannotExpressUnsafeSettings(t *testing.T) {
	b, err := json.Marshal(Fields{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"privileged", "cap_add", "devices", "pid", "network_mode", "userns_mode", "uts",
		"volumes", "volumes_from", "ports", "device_cgroup_rules", "cgroup_parent", "extra_hosts"} {
		if _, ok := m[k]; ok {
			t.Errorf("Fields can express %q", k)
		}
	}
	// sysctls: absent unless set, and its type marshals only to SysctlValues.
	if _, ok := m["sysctls"]; ok {
		t.Errorf("zero Fields has sysctls")
	}
	if s, _ := json.Marshal(Fields{Sysctls: &Sysctls{}}); !strings.Contains(string(s), `"sysctls":{"net.mptcp.enabled":"0"}`) {
		t.Errorf("sysctls marshal to %s", s)
	}
	for k := range m {
		if strings.ToLower(k) != k {
			t.Errorf("key %q is not a compose key", k)
		}
	}
}

// TestSettingsWithoutMPTCP: on a kernel without MPTCP there is nothing to
// turn off, and no sysctls key at all.
func TestSettingsWithoutMPTCP(t *testing.T) {
	f, err := Settings(1000, 1000, res, Host{MPTCP: MPTCPAbsent})
	if err != nil {
		t.Fatal(err)
	}
	if f.Sysctls != nil {
		t.Fatalf("Sysctls = %+v", f.Sysctls)
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "sysctls") {
		t.Fatalf("rendered %s", b)
	}
	f, _ = Settings(1000, 1000, res, Host{MPTCP: MPTCPPresent})
	if b, _ := json.Marshal(f); !strings.Contains(string(b), `"sysctls":{"net.mptcp.enabled":"0"}`) {
		t.Fatalf("rendered %s", b)
	}
}

func TestHostMPTCP(t *testing.T) {
	root := t.TempDir()
	if got, err := HostMPTCP(root); got != MPTCPAbsent || err != nil {
		t.Fatalf("no /proc/sys/net/mptcp: %v %v", got, err)
	}
	os.MkdirAll(filepath.Join(root, "proc/sys/net/mptcp"), 0o755)
	if got, err := HostMPTCP(root); got != MPTCPPresent || err != nil {
		t.Fatalf("directory present: %v %v", got, err)
	}
	// Anything else fails closed: a file where the directory should be, or
	// a path that can't be resolved.
	odd := t.TempDir()
	os.MkdirAll(filepath.Join(odd, "proc/sys/net"), 0o755)
	os.WriteFile(filepath.Join(odd, "proc/sys/net/mptcp"), nil, 0o644)
	if _, err := HostMPTCP(odd); err == nil {
		t.Error("a file at mptcp: no error")
	}
	blocked := t.TempDir()
	os.MkdirAll(filepath.Join(blocked, "proc/sys"), 0o755)
	os.WriteFile(filepath.Join(blocked, "proc/sys/net"), nil, 0o644) // ENOTDIR, not ENOENT
	if _, err := HostMPTCP(blocked); err == nil {
		t.Error("ENOTDIR: no error")
	}
}

// TestSettingsRefusesUnknownMPTCP: forgetting the host's MPTCP status is
// an error, never "no MPTCP".
func TestSettingsRefusesUnknownMPTCP(t *testing.T) {
	for _, h := range []Host{{}, {MPTCP: MPTCPUnknown}, {MPTCP: MPTCP(7)}} {
		if _, err := Settings(1000, 1000, res, h); err == nil || !strings.Contains(err.Error(), "MPTCP status is unknown") {
			t.Errorf("%+v: %v", h, err)
		}
	}
	if MPTCPUnknown.String() != "unknown" || MPTCPPresent.String() != "present" || MPTCPAbsent.String() != "absent" {
		t.Error("String")
	}
}

// TestDigest: the same inputs give the same digest; any change to what the
// canary proves (UID, GID, limits, MPTCP status) changes it.
func TestDigest(t *testing.T) {
	present := Host{MPTCP: MPTCPPresent}
	base, err := Digest(1000, 1000, res, present)
	if err != nil || len(base) != 64 {
		t.Fatalf("%q %v", base, err)
	}
	if again, _ := Digest(1000, 1000, res, present); again != base {
		t.Fatal("not deterministic")
	}
	for name, d := range map[string]func() (string, error){
		"uid":   func() (string, error) { return Digest(1001, 1000, res, present) },
		"gid":   func() (string, error) { return Digest(1000, 1001, res, present) },
		"mem":   func() (string, error) { return Digest(1000, 1000, Resources{2048, 1.5, 512}, present) },
		"cpus":  func() (string, error) { return Digest(1000, 1000, Resources{1536, 2, 512}, present) },
		"pids":  func() (string, error) { return Digest(1000, 1000, Resources{1536, 1.5, 1024}, present) },
		"mptcp": func() (string, error) { return Digest(1000, 1000, res, Host{MPTCP: MPTCPAbsent}) },
	} {
		if got, err := d(); err != nil || got == base {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	if _, err := Digest(1000, 1000, res, Host{}); err == nil {
		t.Error("unknown MPTCP: no error")
	}
}
