// Package gitinit runs the only git command Warden ever runs on the host:
// git init in a folder Warden has just created, before any agent has run
// in it (DESIGN.md, section 2). Every later git operation runs in a
// sandboxed container.
package gitinit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// BinaryPaths are where git is looked for, in order; never $PATH.
var BinaryPaths = []string{"/usr/bin/git", "/usr/local/bin/git"}

// Timeout bounds the git run.
const Timeout = 30 * time.Second

// Find returns the first candidate that is an executable regular file.
func Find(candidates []string) (string, error) {
	for _, c := range candidates {
		if !filepath.IsAbs(c) {
			return "", fmt.Errorf("git candidate %q is not an absolute path", c)
		}
		fi, err := os.Stat(c)
		if err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("git not found at any of %v", candidates)
}

// Env is the whole environment git runs with: no system or user git
// config applies, and nothing else is inherited.
func Env(home string) []string {
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
	}
}

// Init runs "git init -q -b main --template= <dir>" with binary. dir must
// be absolute and an empty directory: Init refuses anything else, so it
// can never run in a folder that has content. --template= (empty) means no
// hook or other template files are copied in.
func Init(ctx context.Context, binary, dir, home string) error {
	if !filepath.IsAbs(dir) || !filepath.IsAbs(binary) || !filepath.IsAbs(home) {
		return errors.New("git init: paths must be absolute")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("git init: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("git init: %s is not empty; Warden runs git only in a folder it has just created", dir)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "init", "-q", "-b", "main", "--template=", dir)
	cmd.Env = Env(home)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git init: %s", msg)
	}
	return nil
}
