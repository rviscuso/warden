package hardening

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

var res = Resources{MemoryMB: 1536, CPUs: 1.5, Pids: 512}

func TestSettings(t *testing.T) {
	f, err := Settings(1000, 1001, res)
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
		Restart:      "no",
		PullPolicy:   "never",
	}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("Settings:\n got %+v\nwant %+v", f, want)
	}
}

func TestSettingsRefusesRoot(t *testing.T) {
	for _, ids := range [][2]int{{0, 1000}, {1000, 0}, {0, 0}, {-1, 1000}, {1000, -1}} {
		if _, err := Settings(ids[0], ids[1], res); err == nil {
			t.Errorf("Settings(%d, %d) accepted", ids[0], ids[1])
		}
	}
}

func TestSettingsRefusesBadResources(t *testing.T) {
	for _, r := range []Resources{
		{0, 1, 64}, {-1, 1, 64}, {256, 0, 64}, {256, -1, 64}, {256, math.NaN(), 64},
		{256, math.Inf(1), 64}, {256, 1, 0}, {256, 1, -5},
	} {
		if _, err := Settings(1000, 1000, r); err == nil {
			t.Errorf("Settings accepted %+v", r)
		}
	}
}

func TestProxyResources(t *testing.T) {
	if ProxyResources != (Resources{256, 0.5, 128}) {
		t.Fatalf("ProxyResources = %+v", ProxyResources)
	}
	if _, err := Settings(1000, 1000, ProxyResources); err != nil {
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
		"volumes", "volumes_from", "ports", "device_cgroup_rules", "cgroup_parent", "sysctls", "extra_hosts"} {
		if _, ok := m[k]; ok {
			t.Errorf("Fields can express %q", k)
		}
	}
	for k := range m {
		if strings.ToLower(k) != k {
			t.Errorf("key %q is not a compose key", k)
		}
	}
}
