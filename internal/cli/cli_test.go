package cli

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

type result struct {
	code           int
	stdout, stderr string
}

func runWith(t *testing.T, vars map[string]string, bi *debug.BuildInfo, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	e := &env{
		stdin:  strings.NewReader(""),
		stdout: &out,
		stderr: &errb,
		getenv: func(k string) string { return vars[k] },
		buildInfo: func() (*debug.BuildInfo, bool) {
			return bi, bi != nil
		},
	}
	code := run(e, append([]string{"warden"}, args...))
	return result{code, out.String(), errb.String()}
}

func runCLI(t *testing.T, args ...string) result {
	t.Helper()
	return runWith(t, nil, nil, args...)
}

var allCommands = []string{"version", "init", "check", "up", "down", "status", "logs", "proxy"}

func TestMainHelp(t *testing.T) {
	for _, arg := range []string{"--help", "-h", "-help"} {
		r := runCLI(t, arg)
		if r.code != ExitOK || r.stderr != "" {
			t.Fatalf("%s: code %d, stderr %q", arg, r.code, r.stderr)
		}
		if !strings.HasPrefix(r.stdout, "Usage: warden <command>") {
			t.Fatalf("%s: unexpected usage:\n%s", arg, r.stdout)
		}
		for _, name := range allCommands {
			listed := strings.Contains(r.stdout, "\n  "+name+" ")
			if name == "proxy" && listed {
				t.Errorf("proxy must not be listed in the main help")
			}
			if name != "proxy" && !listed {
				t.Errorf("%s missing from the main help", name)
			}
		}
	}
}

func TestNoCommandIsUsageError(t *testing.T) {
	r := runCLI(t)
	if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, "Usage: warden") {
		t.Fatalf("got %+v", r)
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	r := runCLI(t, "frobnicate")
	if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, `unknown command "frobnicate"`) {
		t.Fatalf("got %+v", r)
	}
}

func TestEveryCommandHasHelp(t *testing.T) {
	for _, name := range allCommands {
		for _, flag := range []string{"--help", "-h"} {
			r := runCLI(t, name, flag) // no WARDEN_ROLE: proxy help must still work
			if r.code != ExitOK || r.stderr != "" {
				t.Errorf("%s %s: code %d, stderr %q", name, flag, r.code, r.stderr)
			}
			if !strings.HasPrefix(r.stdout, "Usage: warden "+name) {
				t.Errorf("%s %s: unexpected usage:\n%s", name, flag, r.stdout)
			}
		}
	}
}

func TestHelpListsFlags(t *testing.T) {
	for _, name := range []string{"init", "check", "status"} {
		if r := runCLI(t, name, "--help"); !strings.Contains(r.stdout, "-json") {
			t.Errorf("%s help doesn't list -json:\n%s", name, r.stdout)
		}
	}
	if r := runCLI(t, "logs", "--help"); !strings.Contains(r.stdout, "-n int") {
		t.Errorf("logs help doesn't list -n:\n%s", r.stdout)
	}
}

func TestUnknownFlagIsUsageError(t *testing.T) {
	for _, name := range allCommands {
		r := runCLI(t, name, "--bogus")
		if r.code != ExitUsage || r.stdout != "" {
			t.Errorf("%s --bogus: got %+v", name, r)
		}
		if !strings.Contains(r.stderr, "flag provided but not defined") || !strings.Contains(r.stderr, "Usage: warden "+name) {
			t.Errorf("%s --bogus: stderr %q", name, r.stderr)
		}
	}
}

func TestNotImplemented(t *testing.T) {
	cases := [][]string{
		{"init"}, {"init", "--json"},
		{"check"}, {"check", "--json"},
		{"up"}, {"down"},
		{"status"}, {"status", "--json"},
		{"logs", "proxy"}, {"logs", "controller", "-n", "5"}, {"logs", "-n", "5", "proxy"},
	}
	for _, args := range cases {
		r := runCLI(t, args...)
		if r.code != ExitFail || r.stdout != "" || r.stderr != "warden "+args[0]+": not implemented\n" {
			t.Errorf("%v: got %+v", args, r)
		}
	}
}

func TestUnexpectedArgumentsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"version", "x"}, {"init", "x"}, {"check", "x"}, {"up", "x"}, {"down", "x"}, {"status", "x"},
	} {
		r := runCLI(t, args...)
		if r.code != ExitUsage || !strings.Contains(r.stderr, "unexpected arguments: x") {
			t.Errorf("%v: got %+v", args, r)
		}
	}
}

func TestLogsArguments(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"logs"}, "expected exactly one of: proxy, controller"},
		{[]string{"logs", "proxy", "controller"}, "expected exactly one of: proxy, controller"},
		{[]string{"logs", "canary"}, `unknown container "canary"`},
		{[]string{"logs", "proxy", "-n", "0"}, "-n must be positive"},
		{[]string{"logs", "proxy", "-n", "-3"}, "-n must be positive"},
		{[]string{"logs", "proxy", "-n", "x"}, "invalid value"},
	}
	for _, c := range cases {
		r := runCLI(t, c.args...)
		if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, c.want) {
			t.Errorf("%v: got %+v, want stderr containing %q", c.args, r, c.want)
		}
	}
}

func TestProxyRequiresRole(t *testing.T) {
	for _, role := range []string{"", "controller", "PROXY"} {
		r := runWith(t, map[string]string{"WARDEN_ROLE": role}, nil, "proxy")
		if r.code != ExitFail || !strings.Contains(r.stderr, "WARDEN_ROLE=proxy is not set") {
			t.Errorf("role %q: got %+v", role, r)
		}
	}
	r := runWith(t, map[string]string{"WARDEN_ROLE": "proxy"}, nil, "proxy")
	if r.code != ExitFail || r.stderr != "warden proxy: not implemented\n" {
		t.Errorf("role proxy: got %+v", r)
	}
}

func TestVersionFromBuildInfo(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.27.3",
		Main:      debug.Module{Path: "github.com/rviscuso/warden", Version: "v0.1.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	r := runWith(t, nil, bi, "version")
	want := "warden v0.1.0\n  revision: 0123456789abcdef\n  modified: true\n  go:       go1.27.3\n"
	if r.code != ExitOK || r.stdout != want || r.stderr != "" {
		t.Fatalf("got %+v\nwant stdout %q", r, want)
	}
}

func TestVersionWithoutBuildInfo(t *testing.T) {
	r := runCLI(t, "version")
	want := "warden unknown\n  revision: unknown\n  modified: unknown\n  go:       unknown\n"
	if r.code != ExitOK || r.stdout != want {
		t.Fatalf("got %+v", r)
	}
}

func TestVersionWithoutVCS(t *testing.T) {
	bi := &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}}
	r := runWith(t, nil, bi, "version")
	if !strings.Contains(r.stdout, "warden (devel)\n  revision: unknown\n  modified: unknown\n") {
		t.Fatalf("got %q", r.stdout)
	}
}

func TestRunUsesRealProcess(t *testing.T) {
	// Run wires the real environment; "version" has no side effects.
	var out, errb bytes.Buffer
	if code := Run([]string{"warden", "version"}, strings.NewReader(""), &out, &errb); code != ExitOK {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "warden ") {
		t.Fatalf("stdout %q", out.String())
	}
}
