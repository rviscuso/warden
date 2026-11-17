// Contract test for the Dockerfiles under images/.
package images

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

var (
	digestFrom     = regexp.MustCompile(`^debian:trixie-slim@sha256:[0-9a-f]{64} AS base$`)
	stageFrom      = regexp.MustCompile(`^(base|claude-amd64|claude-arm64|claude-\$\{TARGETARCH\})( AS [a-z0-9-]+)?$`)
	claudeAdd      = regexp.MustCompile(`^--checksum=sha256:[0-9a-f]{64} --chmod=0755 https://downloads\.claude\.ai/claude-code-releases/(\d+\.\d+\.\d+)/(linux-x64|linux-arm64)/claude /usr/local/bin/claude$`)
	numericNonRoot = regexp.MustCompile(`^([1-9][0-9]*):([1-9][0-9]*)$`)
)

// forbidden are words that must not appear in any instruction: firewall
// tools (egress control lives in the network), privilege tools, and
// installers that fetch unpinned code.
var forbidden = []string{
	"iptables", "nft ", "nftables", "ufw", "sudo", "setcap", "chmod u+s", "chmod +s", "chmod 4", "curl", "wget",
	"install.sh", "| sh", "| bash", "npm ", "--privileged",
}

func TestControllerDockerfile(t *testing.T) {
	src, err := os.ReadFile("controller/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(string(src)); err != nil {
		t.Fatal(err)
	}
	for _, p := range contract(string(src)) {
		t.Error(p)
	}
}

// contract returns every way src breaks the controller image contract.
func contract(src string) (problems []string) {
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	ins, err := parse(src)
	if err != nil {
		return []string{err.Error()}
	}
	if len(ins) == 0 {
		return []string{"empty Dockerfile"}
	}
	if ins[0].cmd != "FROM" || !digestFrom.MatchString(ins[0].args) {
		bad("line %d: the first instruction must be FROM debian:trixie-slim@sha256:<64 hex> AS base, got %s %s",
			ins[0].line, ins[0].cmd, ins[0].args)
	}
	if strings.Contains(ins[0].args, "sha256:"+strings.Repeat("0", 64)) {
		bad("line %d: the base digest is the all-zero placeholder: fill in the real digest", ins[0].line)
	}
	var lastUser, home, workdir string
	autoupdaterOff := false
	versions := map[string]string{} // platform -> version
	finalStage := 0
	for i, in := range ins {
		lower := strings.ToLower(in.cmd + " " + in.args)
		for _, w := range forbidden {
			if strings.Contains(lower, w) {
				bad("line %d: %q is not allowed: %s %s", in.line, strings.TrimSpace(w), in.cmd, in.args)
			}
		}
		switch in.cmd {
		case "FROM":
			finalStage = i
			if i > 0 && !stageFrom.MatchString(in.args) {
				bad("line %d: FROM %s: later stages must build on the pinned base", in.line, in.args)
			}
		case "USER":
			lastUser = in.args
			if !numericNonRoot.MatchString(in.args) {
				bad("line %d: USER %s: must be a numeric non-root uid:gid", in.line, in.args)
			}
		case "ADD":
			m := claudeAdd.FindStringSubmatch(in.args)
			if m == nil {
				bad("line %d: ADD %s: only Claude Code, by version and checksum, to /usr/local/bin/claude", in.line, in.args)
				continue
			}
			if _, dup := versions[m[2]]; dup {
				bad("line %d: a second download for %s", in.line, m[2])
			}
			versions[m[2]] = m[1]
		case "COPY":
			bad("line %d: COPY: the reference image takes nothing from the build context", in.line)
		case "ENTRYPOINT", "CMD":
			bad("line %d: %s: Warden sets every service's entrypoint", in.line, in.cmd)
		case "ENV":
			for _, kv := range strings.Fields(in.args) {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "HOME":
					home = v
				case "DISABLE_AUTOUPDATER":
					autoupdaterOff = v == "1"
				}
			}
		case "WORKDIR":
			workdir = in.args
		case "ARG", "RUN":
		default:
			bad("line %d: %s: not an instruction the contract knows", in.line, in.cmd)
		}
	}
	if lastUser == "" {
		bad("no USER: the image would default to root")
	}
	for i := finalStage; i < len(ins); i++ {
		if ins[i].cmd == "USER" {
			break
		}
		if i == len(ins)-1 {
			bad("the final stage has no USER")
		}
	}
	if home != "/home/agent" {
		bad("HOME = %q, want /home/agent", home)
	}
	if workdir != "/workspace" {
		bad("WORKDIR = %q, want /workspace", workdir)
	}
	if !autoupdaterOff {
		bad("DISABLE_AUTOUPDATER=1 is not set")
	}
	if len(versions) != 2 || versions["linux-x64"] == "" || versions["linux-x64"] != versions["linux-arm64"] {
		bad("Claude Code downloads %v: want linux-x64 and linux-arm64, at one version", versions)
	}
	if !strings.Contains(src, "ca-certificates git ripgrep less procps") {
		bad("the packages must be ca-certificates git ripgrep less procps")
	}
	return problems
}

// TestContractRefuses: each rule above has a failing case.
func TestContractRefuses(t *testing.T) {
	good, err := os.ReadFile("controller/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("0", 64)
	cases := map[string][2]string{
		"base by tag":      {"@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS base", " AS base"},
		"zero digest":      {"sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4", digest},
		"older base":       {"debian:trixie-slim@", "debian:bookworm-slim@"},
		"other base":       {"FROM base AS claude-amd64", "FROM ubuntu:24.04 AS claude-amd64"},
		"user root":        {"USER 65534:65534", "USER root"},
		"user 0":           {"USER 65534:65534", "USER 0:0"},
		"no user":          {"USER 65534:65534", ""},
		"user by name":     {"USER 65534:65534", "USER nobody"},
		"iptables":         {"less procps", "less procps iptables"},
		"sudo":             {"less procps", "less procps sudo"},
		"curl":             {"less procps", "less procps curl"},
		"installer":        {"RUN mkdir -m 0755 /home/agent", "RUN mkdir -m 0755 /home/agent && bash install.sh"},
		"setuid":           {"RUN mkdir -m 0755 /home/agent", "RUN mkdir -m 0755 /home/agent && chmod u+s /usr/bin/git"},
		"unpinned claude":  {"releases/2.1.309/linux-x64", "releases/latest/linux-x64"},
		"no checksum":      {"--checksum=sha256:4d704a8aecbe038affa3000f498ae17c1b4f753add8facb8764120affc99b658 ", ""},
		"claude in home":   {"linux-x64/claude /usr/local/bin/claude", "linux-x64/claude /home/agent/.local/bin/claude"},
		"version mismatch": {"releases/2.1.309/linux-arm64", "releases/2.1.308/linux-arm64"},
		"home":             {"HOME=/home/agent", "HOME=/root"},
		"workdir":          {"WORKDIR /workspace", "WORKDIR /"},
		"autoupdater":      {"DISABLE_AUTOUPDATER=1", "DISABLE_AUTOUPDATER=0"},
		"entrypoint":       {"WORKDIR /workspace", "WORKDIR /workspace\nENTRYPOINT [\"claude\"]"},
		"copy":             {"WORKDIR /workspace", "WORKDIR /workspace\nCOPY . /opt"},
		"unknown":          {"WORKDIR /workspace", "WORKDIR /workspace\nVOLUME /data"},
		"packages":         {"ca-certificates git ripgrep less procps", "ca-certificates git less procps"},
	}
	for name, c := range cases {
		if !strings.Contains(string(good), c[0]) {
			t.Fatalf("%s: %q is not in the Dockerfile", name, c[0])
		}
		bad := strings.Replace(string(good), c[0], c[1], 1)
		if len(contract(bad)) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}
