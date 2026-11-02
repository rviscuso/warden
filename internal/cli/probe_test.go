package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/internal/canary"
)

var probeArgs = []string{"probe", "--proxy", "warden-canary-proxy:3128", "--allow-host", "api.anthropic.com",
	"--deny-host", "warden-canary.invalid", "--dns-host", "api.anthropic.com", "--route", "1.1.1.1:443", "--dir", "/canary"}

func TestProbeRequiresRole(t *testing.T) {
	for _, role := range []string{"", "proxy", "CANARY"} {
		r := runWith(t, map[string]string{"WARDEN_ROLE": role}, nil, probeArgs...)
		if r.code != ExitFail || !strings.Contains(r.stderr, "WARDEN_ROLE=canary is not set") || r.stdout != "" {
			t.Errorf("role %q: %+v", role, r)
		}
	}
	if r := runCLI(t, "probe", "--help"); r.code != ExitOK || !strings.Contains(r.stdout, "Usage: warden probe") {
		t.Errorf("probe --help without a role: %+v", r)
	}
}

func TestProbeFlagsRequired(t *testing.T) {
	for i := 1; i < len(probeArgs); i += 2 {
		args := append(append([]string(nil), probeArgs[:i]...), probeArgs[i+2:]...)
		r := runWith(t, map[string]string{"WARDEN_ROLE": "canary"}, nil, args...)
		if r.code != ExitUsage || !strings.Contains(r.stderr, probeArgs[i]+" is required") {
			t.Errorf("without %s: %+v", probeArgs[i], r)
		}
	}
	r := runWith(t, map[string]string{"WARDEN_ROLE": "canary"}, nil, append(probeArgs, "extra")...)
	if r.code != ExitUsage || !strings.Contains(r.stderr, "unexpected arguments: extra") {
		t.Errorf("extra argument: %+v", r)
	}
}

type deadNet struct{}

func (deadNet) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("network is unreachable")
}
func (deadNet) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("no such host")
}

// TestProbeRuns: with an empty filesystem root and no network, the probe
// still prints every key, and the output parses.
func TestProbeRuns(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "canary")
	os.Mkdir(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "control"), []byte("no_host=skip\n"), 0o600)
	var out, errb bytes.Buffer
	e := &env{
		stdin: strings.NewReader(""), stdout: &out, stderr: &errb,
		getenv:    func(k string) string { return map[string]string{"WARDEN_ROLE": "canary"}[k] },
		buildInfo: func() (*debug.BuildInfo, bool) { return nil, false },
		geteuid:   func() int { return 1000 },
		probeEnv: func() canary.ProbeEnv {
			return canary.ProbeEnv{
				Root:      root,
				WriteFile: func(name string, data []byte) error { return os.WriteFile(name, data, 0o600) },
				Resolver:  deadNet{}, Dialer: deadNet{},
				ControlWait: time.Second, ProxyWait: 100 * time.Millisecond, StepTimeout: 100 * time.Millisecond,
			}
		},
	}
	args := append([]string{"warden"}, probeArgs...)
	args[len(args)-1] = dir
	if code := run(e, args); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	obs, err := canary.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if obs["no_host"] != "skipped" || obs["owner"] != "written" || !strings.HasPrefix(obs["proxy_allow"], "error:") {
		t.Errorf("observations %v", obs)
	}
}
