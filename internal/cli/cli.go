// Package cli implements Warden's command line: subcommand dispatch, one
// flag.FlagSet per subcommand, and help text.
//
// Conventions (docs/phase-1.md):
//   - --help / -h prints usage to stdout and exits 0;
//   - a usage error prints the error and usage to stderr and exits 2;
//   - a failed check or operation exits 1.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

// env is everything a command may touch outside its arguments. Tests
// replace it; Run fills it from the real process.
type env struct {
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	getenv    func(string) string
	buildInfo func() (*debug.BuildInfo, bool)
	geteuid   func() int
}

// Run executes the command line args (args[0] is the program name) and
// returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return run(&env{
		stdin:     stdin,
		stdout:    stdout,
		stderr:    stderr,
		getenv:    os.Getenv,
		buildInfo: debug.ReadBuildInfo,
		geteuid:   os.Geteuid,
	}, args)
}

// command is one subcommand. define registers the command's flags on fs
// and returns the function that runs it with the positional arguments.
type command struct {
	name    string
	args    string // synopsis after "warden <name>", e.g. "[--json]"
	summary string
	detail  string
	hidden  bool // left out of the main help (warden proxy)
	define  func(fs *flag.FlagSet) func(e *env, pos []string) int
}

func commands() []*command {
	return []*command{
		{
			name:    "version",
			summary: "Print version information",
			detail:  "Print Warden's version, VCS revision and Go version from the binary's embedded build info.",
			define: func(fs *flag.FlagSet) func(*env, []string) int {
				return func(e *env, pos []string) int {
					if len(pos) > 0 {
						return usageError(e, "version", "unexpected arguments: "+strings.Join(pos, " "))
					}
					return runVersion(e)
				}
			},
		},
		{
			name:    "init",
			args:    "[--json]",
			summary: "Run host, daemon and canary checks; on success record state",
			detail:  "Run every check, prove isolation with a canary container, and on success record the daemon pin in Warden's state.",
			define:  jsonNotImplemented("init"),
		},
		{
			name:    "check",
			args:    "[--json]",
			summary: "Re-run the checks and canary without changing state",
			detail:  "Run the same checks and canary as init, read-only, to re-prove that the sandbox holds.",
			define:  jsonNotImplemented("check"),
		},
		{
			name:    "up",
			summary: "Start the egress proxy and the controller (asks y/N)",
			detail:  "Generate the compose file, show it with a diff against the last applied one, and start the proxy and the controller after approval.",
			define:  plainNotImplemented("up"),
		},
		{
			name:    "down",
			summary: "Stop and remove the proxy and the controller",
			detail:  "Stop and remove Warden's containers and networks. The agent home and the workspace are kept.",
			define:  plainNotImplemented("down"),
		},
		{
			name:    "status",
			args:    "[--json]",
			summary: "Show the daemon pin, container states and Remote Control URL",
			detail:  "Show the daemon pin, container states, images, start times and the last Remote Control URL.",
			define:  jsonNotImplemented("status"),
		},
		{
			name:    "logs",
			args:    "proxy|controller [-n N]",
			summary: "Print the last N lines of a container's log",
			detail:  "Print the last N lines of the proxy's or the controller's log.",
			define: func(fs *flag.FlagSet) func(*env, []string) int {
				n := fs.Int("n", 100, "number of lines to print (positive)")
				return func(e *env, pos []string) int {
					if len(pos) != 1 {
						return usageError(e, "logs", "expected exactly one of: proxy, controller")
					}
					if pos[0] != "proxy" && pos[0] != "controller" {
						return usageError(e, "logs", fmt.Sprintf("unknown container %q: expected proxy or controller", pos[0]))
					}
					if *n <= 0 {
						return usageError(e, "logs", "-n must be positive")
					}
					return notImplemented(e, "logs")
				}
			},
		},
		{
			name:    "proxy",
			args:    "[flags]",
			summary: "The egress proxy (internal)",
			detail:  "The egress proxy itself. Internal: it runs only inside Warden's proxy container, where WARDEN_ROLE=proxy is set.",
			hidden:  true,
			define: func(fs *flag.FlagSet) func(*env, []string) int {
				return func(e *env, pos []string) int {
					if e.getenv("WARDEN_ROLE") != "proxy" {
						fmt.Fprintln(e.stderr, "warden proxy: refusing to run: WARDEN_ROLE=proxy is not set (this command runs only inside Warden's proxy container)")
						return ExitFail
					}
					if len(pos) > 0 {
						return usageError(e, "proxy", "unexpected arguments: "+strings.Join(pos, " "))
					}
					return notImplemented(e, "proxy")
				}
			},
		},
	}
}

func jsonNotImplemented(name string) func(*flag.FlagSet) func(*env, []string) int {
	return func(fs *flag.FlagSet) func(*env, []string) int {
		fs.Bool("json", false, "print results as JSON")
		return plainNotImplemented(name)(nil)
	}
}

func plainNotImplemented(name string) func(*flag.FlagSet) func(*env, []string) int {
	return func(*flag.FlagSet) func(*env, []string) int {
		return func(e *env, pos []string) int {
			if len(pos) > 0 {
				return usageError(e, name, "unexpected arguments: "+strings.Join(pos, " "))
			}
			return notImplemented(e, name)
		}
	}
}

func notImplemented(e *env, name string) int {
	fmt.Fprintf(e.stderr, "warden %s: not implemented\n", name)
	return ExitFail
}

func findCommand(name string) *command {
	for _, c := range commands() {
		if c.name == name {
			return c
		}
	}
	return nil
}

func isHelp(arg string) bool {
	return arg == "-h" || arg == "-help" || arg == "--help"
}

func run(e *env, args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(e.stderr, "warden: missing command")
		printMainUsage(e.stderr)
		return ExitUsage
	}
	name := args[1]
	if isHelp(name) {
		printMainUsage(e.stdout)
		return ExitOK
	}
	c := findCommand(name)
	if c == nil {
		fmt.Fprintf(e.stderr, "warden: unknown command %q\n", name)
		printMainUsage(e.stderr)
		return ExitUsage
	}

	fs := flag.NewFlagSet("warden "+c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print errors and usage ourselves
	fs.Usage = func() {}
	runFn := c.define(fs)

	pos, err := parseInterspersed(fs, args[2:])
	if errors.Is(err, flag.ErrHelp) {
		printCommandUsage(e.stdout, c, fs)
		return ExitOK
	}
	if err != nil {
		return usageError(e, c.name, err.Error())
	}
	if c.name != "version" && e.geteuid() == 0 {
		fmt.Fprintf(e.stderr, "warden %s: refusing to run as root: run Warden as your own user, not root or sudo\n", c.name)
		return ExitFail
	}
	return runFn(e, pos)
}

// parseInterspersed parses flags that may appear before or after positional
// arguments ("warden logs proxy -n 5"). The standard flag package stops at
// the first positional argument, so parsing resumes after each one.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func usageError(e *env, name, msg string) int {
	fmt.Fprintf(e.stderr, "warden %s: %s\n", name, msg)
	c := findCommand(name)
	fs := flag.NewFlagSet("warden "+c.name, flag.ContinueOnError)
	c.define(fs)
	printCommandUsage(e.stderr, c, fs)
	return ExitUsage
}

func printMainUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString("Usage: warden <command> [flags]\n\n")
	b.WriteString("Warden runs a coding agent in a hardened container that can change the\n")
	b.WriteString("repository and nothing else, reaches only approved domains, and exposes no ports.\n\n")
	b.WriteString("Commands:\n")
	for _, c := range commands() {
		if c.hidden {
			continue
		}
		fmt.Fprintf(&b, "  %-8s  %s\n", c.name, c.summary)
	}
	b.WriteString("\nRun 'warden <command> --help' for a command's usage.\n")
	io.WriteString(w, b.String())
}

func printCommandUsage(w io.Writer, c *command, fs *flag.FlagSet) {
	synopsis := "warden " + c.name
	if c.args != "" {
		synopsis += " " + c.args
	}
	fmt.Fprintf(w, "Usage: %s\n\n%s\n", synopsis, c.detail)
	hasFlags := false
	fs.VisitAll(func(*flag.Flag) { hasFlags = true })
	if hasFlags {
		fmt.Fprint(w, "\nFlags:\n")
		fs.SetOutput(w)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
}
