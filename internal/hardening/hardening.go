// Package hardening is the single source of container security settings.
// Every container Warden runs (proxy, canary, controller) gets its
// hardening from Settings and nowhere else. See docs/phase-1.md,
// "Hardening".
package hardening

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
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
	IPC        string   `json:"ipc"`
	Cgroup     string   `json:"cgroup"`
	Sysctls    *Sysctls `json:"sysctls,omitempty"` // nil on a host without MPTCP
	Restart    string   `json:"restart"`
	PullPolicy string   `json:"pull_policy"`
}

// MPTCP is the host kernel's MPTCP status. The zero value is unknown, and
// everything that depends on it refuses unknown: a caller that forgets to
// set it fails instead of silently dropping the sysctl.
type MPTCP int

const (
	MPTCPUnknown MPTCP = iota
	MPTCPPresent       // the kernel has MPTCP: every container turns it off
	MPTCPAbsent        // the kernel has no MPTCP: nothing to turn off
)

func (m MPTCP) String() string {
	switch m {
	case MPTCPPresent:
		return "present"
	case MPTCPAbsent:
		return "absent"
	}
	return "unknown"
}

// Host is what the hardening depends on about the host.
type Host struct {
	MPTCP MPTCP // from HostMPTCP; MPTCPUnknown is refused
}

// Settings returns the hardened fields for a container running as
// uid:gid with limits r on host h. Seccomp and AppArmor stay at Docker's defaults
// (naming AppArmor would stop containers starting on hosts without it);
// the canary verifies both.
func Settings(uid, gid int, r Resources, h Host) (Fields, error) {
	if uid <= 0 || gid <= 0 {
		return Fields{}, fmt.Errorf("hardening: refusing uid %d gid %d: containers never run as root or the root group", uid, gid)
	}
	if err := r.validate(); err != nil {
		return Fields{}, err
	}
	mem := MemoryBytes(r)
	var sysctls *Sysctls
	switch h.MPTCP {
	case MPTCPPresent:
		sysctls = &Sysctls{}
	case MPTCPAbsent:
	default:
		return Fields{}, errors.New("hardening: the host's MPTCP status is unknown: read it with HostMPTCP")
	}
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
		Sysctls:      sysctls,
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

// Sysctls are a container's kernel parameters on a host with MPTCP: MPTCP
// off, a separate protocol stack the agent has no use for. The sysctl is
// per network namespace, so each container gets it whatever the host has.
// The type has no fields, so it can't express any other sysctl; it always
// marshals to SysctlValues. On a host without MPTCP there is nothing to
// turn off, and Fields.Sysctls is nil.
type Sysctls struct{}

// SysctlValues is the map Sysctls marshals to, fresh on each call.
func SysctlValues() map[string]string { return map[string]string{"net.mptcp.enabled": "0"} }

func (Sysctls) MarshalJSON() ([]byte, error) { return json.Marshal(SysctlValues()) }

// HostMPTCP reports whether the kernel under root has MPTCP: whether
// <root>/proc/sys/net/mptcp is a directory. CONFIG_MPTCP is built in, never
// a module, so a missing directory means no MPTCP at all. Any other error
// is returned: the caller fails closed.
func HostMPTCP(root string) (MPTCP, error) {
	fi, err := os.Stat(filepath.Join(root, "proc", "sys", "net", "mptcp"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return MPTCPAbsent, nil
	case err != nil:
		return MPTCPUnknown, fmt.Errorf("hardening: cannot tell whether the kernel has MPTCP: %w", err)
	case !fi.IsDir():
		return MPTCPUnknown, fmt.Errorf("hardening: %s is not a directory", filepath.Join(root, "proc", "sys", "net", "mptcp"))
	}
	return MPTCPPresent, nil
}

// Digest is the SHA-256 (hex) of the hardening a canary run proves: the
// JSON of Settings for the proxy's limits and for the controller's, for
// uid:gid on host h. The canary record stores it; up compares it, so up
// never starts containers with settings the canary hasn't proven.
func Digest(uid, gid int, controller Resources, h Host) (string, error) {
	var all []Fields
	for _, r := range []Resources{ProxyResources, controller} {
		f, err := Settings(uid, gid, r, h)
		if err != nil {
			return "", err
		}
		all = append(all, f)
	}
	b, err := json.Marshal(all)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
