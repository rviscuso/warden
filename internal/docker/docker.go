// Package docker runs the docker CLI. Everything that talks to Docker goes
// through the Runner interface, so tests need no daemon.
//
// The exec implementation finds docker at a fixed path (never $PATH), runs
// it with argv only (never a shell), with a fixed environment that inherits
// nothing from Warden's own (no DOCKER_HOST, DOCKER_CONTEXT, credential
// helpers or plugins from the user's Docker config), from "/" as the working
// directory, and with a timeout on every call.
package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/rviscuso/warden/internal/paths"
)

// Timeouts. DefaultTimeout applies when the caller's context has no
// deadline; a caller overrides it by passing a context with one.
const (
	DefaultTimeout = 30 * time.Second
	ComposeTimeout = 5 * time.Minute // docker compose up / down
)

// SafePath is the only PATH the docker CLI sees.
const SafePath = "/usr/sbin:/usr/bin:/sbin:/bin"

// BinaryPaths are the only places Warden looks for the docker CLI.
var BinaryPaths = []string{"/usr/bin/docker", "/usr/local/bin/docker"}

// Runner runs one docker CLI invocation.
//
// err is non-nil only when docker could not be run or did not finish
// (not found, timed out, killed). A command that ran and exited non-zero
// returns its exit code with err == nil; callers must check both.
type Runner interface {
	Run(ctx context.Context, args []string, stdin io.Reader) (stdout, stderr []byte, exitCode int, err error)
}

// FindBinary returns the first candidate that is an executable regular
// file. Candidates must be absolute.
func FindBinary(candidates []string) (string, error) {
	for _, c := range candidates {
		if !filepath.IsAbs(c) {
			return "", fmt.Errorf("docker binary candidate %q is not an absolute path", c)
		}
		fi, err := os.Stat(c)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		return c, nil
	}
	return "", fmt.Errorf("docker CLI not found at any of %v", candidates)
}

// Options configure an Exec runner.
type Options struct {
	Binary   string // absolute path of the docker CLI, usually from FindBinary
	Socket   string // absolute path of the daemon's socket (from config)
	Home     string // the user's home directory
	StateDir string // Warden's state directory; must exist (created by init)
	UID      int    // the invoking user; owns StateDir and docker-config
	Timeout  time.Duration
}

// Exec runs the real docker CLI.
type Exec struct {
	binary  string
	env     []string
	timeout time.Duration
}

var _ Runner = (*Exec)(nil)

// New validates opts and prepares <state>/docker-config: created with mode
// 0700 if missing; if it exists, it must already be a 0700 directory owned
// by the user. Nothing is ever chmod-ed or chown-ed.
func New(opts Options) (*Exec, error) {
	for name, p := range map[string]string{
		"docker binary": opts.Binary, "socket": opts.Socket,
		"home": opts.Home, "state directory": opts.StateDir,
	} {
		if p == "" || !filepath.IsAbs(p) {
			return nil, fmt.Errorf("docker: %s %q is not an absolute path", name, p)
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if err := paths.CheckDir(opts.StateDir, opts.UID); err != nil {
		return nil, fmt.Errorf("docker: state directory: %w", err)
	}
	dockerConfig := filepath.Join(opts.StateDir, "docker-config")
	if err := ensurePrivateDir(dockerConfig, opts.UID); err != nil {
		return nil, fmt.Errorf("docker: %w", err)
	}
	return &Exec{
		binary: opts.Binary,
		env: []string{
			"PATH=" + SafePath,
			"HOME=" + opts.Home,
			"DOCKER_HOST=unix://" + opts.Socket,
			"DOCKER_CONFIG=" + dockerConfig,
		},
		timeout: timeout,
	}, nil
}

func ensurePrivateDir(dir string, uid int) error {
	err := paths.CheckDir(dir, uid)
	if !errors.Is(err, fs.ErrNotExist) {
		return err // nil, or unsafe: never repaired here
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// Re-check what is actually there now (umask, or a concurrent creator).
	return paths.CheckDir(dir, uid)
}

// Env returns the exact environment docker runs with.
func (e *Exec) Env() []string { return slices.Clone(e.env) }

// Run runs docker with args as argv. If ctx has no deadline, the runner's
// timeout applies.
func (e *Exec) Run(ctx context.Context, args []string, stdin io.Reader) ([]byte, []byte, int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, e.binary, args...)
	cmd.Env = slices.Clone(e.env)
	cmd.Dir = "/"
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// If docker leaves a child holding our pipes, don't wait forever.
	cmd.WaitDelay = 5 * time.Second

	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return stdout.Bytes(), stderr.Bytes(), -1, fmt.Errorf("docker %s: %w", describe(args), ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Exited() {
			return stdout.Bytes(), stderr.Bytes(), exitErr.ExitCode(), nil
		}
		return stdout.Bytes(), stderr.Bytes(), -1, fmt.Errorf("docker %s: %v", describe(args), exitErr)
	}
	if err != nil {
		return stdout.Bytes(), stderr.Bytes(), -1, fmt.Errorf("docker %s: %w", describe(args), err)
	}
	return stdout.Bytes(), stderr.Bytes(), 0, nil
}

func describe(args []string) string {
	if len(args) == 0 {
		return "(no arguments)"
	}
	return args[0]
}
