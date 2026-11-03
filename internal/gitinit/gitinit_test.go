package gitinit

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func realGit(t *testing.T) string {
	t.Helper()
	bin, err := Find(BinaryPaths)
	if err != nil {
		t.Skipf("SKIP: %v", err)
	}
	return bin
}

// A hostile user config (a template with a hook, another default branch,
// an fsmonitor command) and inherited GIT_* variables change nothing.
func TestInitIgnoresUserConfig(t *testing.T) {
	bin := realGit(t)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	tmpl := filepath.Join(root, "tmpl", "hooks")
	os.MkdirAll(tmpl, 0o700)
	os.WriteFile(filepath.Join(tmpl, "post-checkout"), []byte("#!/bin/sh\ntouch "+filepath.Join(root, "ran")+"\n"), 0o700)
	os.MkdirAll(home, 0o700)
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[init]\n\tdefaultBranch = master\n\ttemplateDir = "+filepath.Join(root, "tmpl")+"\n[core]\n\tfsmonitor = touch "+filepath.Join(root, "ran")+"\n"), 0o600)
	t.Setenv("GIT_DIR", filepath.Join(root, "elsewhere"))
	t.Setenv("GIT_TEMPLATE_DIR", filepath.Join(root, "tmpl"))

	dir := filepath.Join(root, "ws")
	os.Mkdir(dir, 0o700)
	if err := Init(context.Background(), bin, dir, home); err != nil {
		t.Fatal(err)
	}
	head, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD"))
	if err != nil || strings.TrimSpace(string(head)) != "ref: refs/heads/main" {
		t.Fatalf("HEAD = %q, %v", head, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "hooks", "post-checkout")); err == nil {
		t.Fatal("the user's template hook was copied")
	}
	if _, err := os.Stat(filepath.Join(root, "elsewhere")); err == nil {
		t.Fatal("GIT_DIR was inherited")
	}
	if _, err := os.Stat(filepath.Join(root, "ran")); err == nil {
		t.Fatal("a configured command ran")
	}
}

func TestInitRefusesNonEmpty(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x"), nil, 0o600)
	err := Init(context.Background(), "/usr/bin/git", dir, "/home")
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		t.Fatal("ran git")
	}
}

func TestInitRefusesRelative(t *testing.T) {
	if err := Init(context.Background(), "git", "/x", "/home"); err == nil {
		t.Fatal("relative binary accepted")
	}
	if err := Init(context.Background(), "/usr/bin/git", "x", "/home"); err == nil {
		t.Fatal("relative dir accepted")
	}
}

func TestEnv(t *testing.T) {
	want := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/h", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if !slices.Equal(Env("/h"), want) {
		t.Fatalf("Env = %v", Env("/h"))
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "git")
	os.WriteFile(exe, nil, 0o700)
	os.WriteFile(filepath.Join(dir, "noexec"), nil, 0o600)
	if got, err := Find([]string{filepath.Join(dir, "missing"), filepath.Join(dir, "noexec"), exe}); err != nil || got != exe {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := Find([]string{"git"}); err == nil {
		t.Fatal("relative candidate accepted")
	}
}
