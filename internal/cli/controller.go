package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/rviscuso/warden/internal/controller"
)

// controllerEnv is what up, down, status and logs touch.
func (e *env) controllerEnv() (controller.Env, error) {
	dirs, home, err := e.setup()
	if err != nil {
		return controller.Env{}, err
	}
	return controller.Env{
		Ctx: context.Background(), Dirs: dirs, Home: home,
		UID: e.getuid(), GID: e.getgid(), GOARCH: e.goarch, Root: e.root,
		DockerPaths: e.dockerPaths, NewRunner: e.newRunner, SystemDirs: e.systemDirs,
		Executable: e.executable, Stdin: e.stdin, Stdout: e.stdout, Stderr: e.stderr,
		Now: e.now, Sleep: e.sleep,
	}, nil
}

// runController runs one controller operation and prints its error and fix.
func runController(e *env, name string, fn func(controller.Env) error) int {
	ce, err := e.controllerEnv()
	if err == nil {
		err = fn(ce)
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "warden %s: %v\n", name, err)
		if fix := controller.Fix(err); fix != "" {
			fmt.Fprintf(e.stderr, "  fix: %s\n", fix)
		}
		return ExitFail
	}
	return ExitOK
}

func defineUp(*flag.FlagSet) func(*env, []string) int {
	return func(e *env, pos []string) int {
		if len(pos) > 0 {
			return usageError(e, "up", "unexpected arguments: "+strings.Join(pos, " "))
		}
		return runController(e, "up", controller.Up)
	}
}

func defineDown(*flag.FlagSet) func(*env, []string) int {
	return func(e *env, pos []string) int {
		if len(pos) > 0 {
			return usageError(e, "down", "unexpected arguments: "+strings.Join(pos, " "))
		}
		return runController(e, "down", controller.Down)
	}
}

func runStatus(e *env, jsonOut bool) int {
	return runController(e, "status", func(ce controller.Env) error { return controller.Status(ce, jsonOut) })
}
