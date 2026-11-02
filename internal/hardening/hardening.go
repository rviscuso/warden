// Package hardening is the single source of container security settings.
// Every container Warden runs (proxy, canary, controller) gets its
// hardening from Settings and nowhere else. See docs/phase-1.md,
// "Hardening".
package hardening

import (
	"errors"
	"fmt"
	"math"
)

// Resources are a container's limits.
type Resources struct {
	MemoryMB int
	CPUs     float64
	Pids     int
}

// ProxyResources are the egress proxy's limits. Constants, not config.
var ProxyResources = Resources{MemoryMB: 256, CPUs: 0.5, Pids: 128}

// Tmpfs is the only writable path in a container's root filesystem. exec
// is allowed: the agent runs builds and tests from /tmp, and noexec adds
// nothing when the workspace is writable and executable.
const Tmpfs = "/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777"

// Fields are the hardened fields of one compose service, with their
// compose keys. Embedded into compose.Service. There is deliberately no
// field for privileged mode, added capabilities, devices, host
// namespaces, ports or extra mounts.
type Fields struct {
	User         string   `json:"user"`
	CapDrop      []string `json:"cap_drop"`
	SecurityOpt  []string `json:"security_opt"`
	ReadOnly     bool     `json:"read_only"`
	Tmpfs        []string `json:"tmpfs"`
	MemLimit     int64    `json:"mem_limit"`     // bytes
	MemswapLimit int64    `json:"memswap_limit"` // bytes; equal to MemLimit: no swap
	CPUs         float64  `json:"cpus"`
	PidsLimit    int      `json:"pids_limit"`
	Init         bool     `json:"init"`
	// Explicit, so daemon defaults (default-ipc-mode, default-cgroupns-mode)
	// can't weaken them.
	IPC        string `json:"ipc"`
	Cgroup     string `json:"cgroup"`
	Restart    string `json:"restart"`
	PullPolicy string `json:"pull_policy"`
}

// Settings returns the hardened fields for a container running as
// uid:gid with limits r. Seccomp and AppArmor stay at Docker's defaults
// (naming AppArmor would stop containers starting on hosts without it);
// the canary verifies both.
func Settings(uid, gid int, r Resources) (Fields, error) {
	if uid <= 0 || gid <= 0 {
		return Fields{}, fmt.Errorf("hardening: refusing uid %d gid %d: containers never run as root or the root group", uid, gid)
	}
	if err := r.validate(); err != nil {
		return Fields{}, err
	}
	mem := MemoryBytes(r)
	return Fields{
		User:         fmt.Sprintf("%d:%d", uid, gid),
		CapDrop:      []string{"ALL"},
		SecurityOpt:  []string{"no-new-privileges:true"},
		ReadOnly:     true,
		Tmpfs:        []string{Tmpfs},
		MemLimit:     mem,
		MemswapLimit: mem,
		CPUs:         r.CPUs,
		PidsLimit:    r.Pids,
		Init:         true,
		IPC:          "private",
		Cgroup:       "private",
		Restart:      "no",
		PullPolicy:   "never",
	}, nil
}

func (r Resources) validate() error {
	switch {
	case r.MemoryMB <= 0:
		return errors.New("hardening: memory limit must be positive")
	case r.Pids <= 0:
		return errors.New("hardening: PID limit must be positive")
	case !(r.CPUs > 0) || math.IsInf(r.CPUs, 0):
		return errors.New("hardening: CPU limit must be positive")
	}
	return nil
}

// MemoryBytes is the memory limit in bytes, as memory.max shows it.
func MemoryBytes(r Resources) int64 { return int64(r.MemoryMB) << 20 }

// CPUPeriod is the CFS period Docker uses for --cpus: cpu.max reads
// "<quota> 100000".
const CPUPeriod = 100000
