package canary

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/rviscuso/warden/internal/hardening"
)

// Parse reads the probe's output strictly: exactly the keys in Keys, each
// once, as key=value lines.
func Parse(out []byte) (map[string]string, error) {
	known := map[string]bool{}
	for _, k := range Keys {
		known[k] = true
	}
	obs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		switch {
		case !ok:
			return nil, fmt.Errorf("probe output: not key=value: %q", line)
		case !known[k]:
			return nil, fmt.Errorf("probe output: unknown key %q", k)
		case hasKey(obs, k):
			return nil, fmt.Errorf("probe output: duplicate key %q", k)
		}
		obs[k] = v
	}
	for _, k := range Keys {
		if !hasKey(obs, k) {
			return nil, fmt.Errorf("probe output: missing key %q", k)
		}
	}
	return obs, nil
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

// Status is a check outcome, with the same values as checks.Status.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Verdict is one canary check's outcome.
type Verdict struct {
	ID, Title string
	Status    Status
	Detail    string
	Fix       string
}

// Expect is what the canary was started with.
type Expect struct {
	UID, GID       int
	Resources      hardening.Resources
	DaemonAppArmor bool
}

// Host is what Warden observed on the host side of the canary run.
type Host struct {
	RouteControl error // dialing the no-route control address from the host
	DNSControl   error // resolving the no-dns host from the host
	DNSHost      string

	NoHostSkipped bool   // the host has no address on the sandbox network
	NoHostAddr    string // the listener's address
	NoHostAccepts int    // connections the listener received
	NoHostErr     error  // Warden couldn't set up the listener: cannot prove

	OwnerUID, OwnerGID int
	OwnerErr           error

	ProxyLog []byte // the canary proxy's stdout
}

// ProbeChecks are the IDs and titles Evaluate returns, in order.
var ProbeChecks = []struct{ ID, Title string }{
	{"canary.caps", "No capabilities"},
	{"canary.nnp", "No new privileges"},
	{"canary.seccomp", "Seccomp filter on"},
	{"canary.uid", "Runs as you"},
	{"canary.memory", "Memory limit enforced"},
	{"canary.pids", "PID limit enforced"},
	{"canary.cpu", "CPU limit enforced"},
	{"canary.apparmor", "AppArmor profile"},
	{"canary.rootfs", "Read-only root filesystem"},
	{"canary.tmp", "Writable /tmp tmpfs"},
	{"canary.no-route", "No direct route out"},
	{"canary.no-dns", "No outside DNS"},
	{"canary.no-host", "Host unreachable"},
	{"canary.proxy-allow", "Proxy allows the allowlist"},
	{"canary.proxy-deny", "Proxy refuses other hosts"},
	{"canary.owner", "Bind-mount files are yours"},
}

// Evaluate decides every probe-based check from the probe's observations
// and the host's.
func Evaluate(obs map[string]string, e Expect, h Host) []Verdict {
	var out []Verdict
	for _, c := range ProbeChecks {
		st, detail := evaluate(c.ID, obs, e, h)
		v := Verdict{ID: c.ID, Title: c.Title, Status: st, Detail: detail}
		if st != Pass {
			v.Fix = fixes[c.ID]
		}
		out = append(out, v)
	}
	return out
}

var fixes = map[string]string{
	"canary.apparmor":    "enable AppArmor on the host and restart Docker",
	"canary.no-route":    "make sure Warden can reach the internet from the host, then run it again",
	"canary.no-dns":      "make sure the host resolves the first allowlisted host, then run it again",
	"canary.proxy-allow": "make sure the host can reach the first allowlisted host on port 443",
}

const zeroCaps = "0000000000000000"

func evaluate(id string, o map[string]string, e Expect, h Host) (Status, string) {
	pf := func(ok bool, detail string) (Status, string) {
		if ok {
			return Pass, detail
		}
		return Fail, detail
	}
	switch id {
	case "canary.caps":
		return pf(o["caps_eff"] == zeroCaps && o["caps_bnd"] == zeroCaps,
			fmt.Sprintf("CapEff %s, CapBnd %s", o["caps_eff"], o["caps_bnd"]))
	case "canary.nnp":
		return pf(o["nnp"] == "1", "NoNewPrivs "+o["nnp"])
	case "canary.seccomp":
		return pf(o["seccomp"] == "2", "Seccomp "+o["seccomp"]+" (2 is filter mode)")
	case "canary.uid":
		u, g := strconv.Itoa(e.UID), strconv.Itoa(e.GID)
		groupsOK := o["groups"] == "" || o["groups"] == g
		return pf(o["uid"] == strings.Repeat(u+" ", 3)+u && o["gid"] == strings.Repeat(g+" ", 3)+g && groupsOK,
			fmt.Sprintf("Uid %s, Gid %s, Groups %q; want %s:%s and no other groups", o["uid"], o["gid"], o["groups"], u, g))
	case "canary.memory":
		want := strconv.FormatInt(hardening.MemoryBytes(e.Resources), 10)
		return pf(o["memory_max"] == want && o["memory_swap_max"] == "0",
			fmt.Sprintf("memory.max %s (want %s), memory.swap.max %s (want 0)", o["memory_max"], want, o["memory_swap_max"]))
	case "canary.pids":
		want := strconv.Itoa(e.Resources.Pids)
		return pf(o["pids_max"] == want, fmt.Sprintf("pids.max %s (want %s)", o["pids_max"], want))
	case "canary.cpu":
		return pf(cpuMatches(o["cpu_max"], e.Resources.CPUs),
			fmt.Sprintf("cpu.max %q (want %v CPUs: about %.0f %d)", o["cpu_max"], e.Resources.CPUs, e.Resources.CPUs*hardening.CPUPeriod, hardening.CPUPeriod))
	case "canary.apparmor":
		if !e.DaemonAppArmor {
			return Warn, "the daemon has no AppArmor: weaker isolation (profile " + o["apparmor"] + ")"
		}
		return pf(o["apparmor"] == "docker-default (enforce)", "profile "+o["apparmor"])
	case "canary.rootfs":
		return pf(o["rootfs"] == "erofs", "writing to /: "+o["rootfs"])
	case "canary.tmp":
		ok, why := tmpOK(o["tmp_mount"])
		return pf(o["tmp_write"] == "ok" && ok, fmt.Sprintf("write %s; %s%s", o["tmp_write"], o["tmp_mount"], why))
	case "canary.no-route":
		if h.RouteControl != nil {
			return Fail, "cannot prove: host has no route to the control address (" + h.RouteControl.Error() + ")"
		}
		return pf(strings.HasPrefix(o["no_route"], "failed: "), "direct connection to "+RouteControl+": "+o["no_route"])
	case "canary.no-dns":
		if h.DNSControl != nil {
			return Fail, fmt.Sprintf("cannot prove: the host doesn't resolve %s either (%v)", h.DNSHost, h.DNSControl)
		}
		return pf(strings.HasPrefix(o["no_dns"], "failed: "), h.DNSHost+" inside the sandbox: "+o["no_dns"])
	case "canary.no-host":
		if h.NoHostErr != nil {
			return Fail, "cannot prove: " + h.NoHostErr.Error()
		}
		if h.NoHostSkipped {
			return pf(o["no_host"] == "skipped", "host has no address on the sandbox network")
		}
		return pf(strings.HasPrefix(o["no_host"], "failed: ") && h.NoHostAccepts == 0,
			fmt.Sprintf("connection to the host at %s: %s; listener received %d", h.NoHostAddr, o["no_host"], h.NoHostAccepts))
	case "canary.proxy-allow":
		return pf(o["proxy_allow"] == "status=200", "CONNECT to the first allowlisted host: "+o["proxy_allow"])
	case "canary.proxy-deny":
		logged := proxyLogged(h.ProxyLog, DenyHost, "host not allowed")
		return pf(o["proxy_deny"] == "status=403" && logged,
			fmt.Sprintf("CONNECT %s: %s; logged as host not allowed: %v", DenyHost, o["proxy_deny"], logged))
	case "canary.owner":
		if h.OwnerErr != nil {
			return Fail, "probe " + o["owner"] + "; on the host: " + h.OwnerErr.Error()
		}
		return pf(o["owner"] == "written" && h.OwnerUID == e.UID && h.OwnerGID == e.GID,
			fmt.Sprintf("probe %s; owner on the host %d:%d (want %d:%d)", o["owner"], h.OwnerUID, h.OwnerGID, e.UID, e.GID))
	}
	return Fail, "unknown check"
}

// cpuMatches: "<quota> 100000" with quota within 0.1% of cpus x period.
func cpuMatches(s string, cpus float64) bool {
	f := strings.Fields(s)
	if len(f) != 2 || f[1] != strconv.Itoa(hardening.CPUPeriod) {
		return false
	}
	q, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return false
	}
	want := cpus * hardening.CPUPeriod
	return math.Abs(q-want) <= math.Max(1, want/1000)
}

// tmpOK checks the tmpfs options: rw, nosuid, nodev, not noexec, the size
// and the mode from hardening.Tmpfs.
func tmpOK(s string) (bool, string) {
	f := strings.Fields(s)
	if len(f) != 3 || f[0] != "fstype=tmpfs" {
		return false, " (want a tmpfs)"
	}
	mount := opts(strings.TrimPrefix(f[1], "mount="))
	super := opts(strings.TrimPrefix(f[2], "super="))
	switch {
	case !mount["rw"] || !mount["nosuid"] || !mount["nodev"]:
		return false, " (want rw,nosuid,nodev)"
	case mount["noexec"]:
		return false, " (want exec allowed)"
	case !super["size=524288k"] || !super["mode=1777"]:
		return false, " (want size=512m, mode=1777)"
	}
	return true, ""
}

func opts(s string) map[string]bool {
	m := map[string]bool{}
	for _, o := range strings.Split(s, ",") {
		m[o] = true
	}
	return m
}

// proxyLogged reports whether the proxy log has a deny line for host with
// reason.
func proxyLogged(log []byte, host, reason string) bool {
	sc := bufio.NewScanner(bytes.NewReader(log))
	for sc.Scan() {
		var l struct{ Event, Host, Decision, Reason string }
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Event == "deny" && l.Decision == "deny" && l.Host == host && l.Reason == reason {
			return true
		}
	}
	return false
}
