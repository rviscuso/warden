// Package wardenbin keeps the copy of the warden binary that Warden's own
// containers (the proxy and the canary, never the controller) run from:
// <state>/bin/warden-<sha256>, mode 0500, verified by hash. Copy first,
// then verify the copy, then mount only the copy.
package wardenbin

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rviscuso/warden/internal/paths"
)

// MaxSize bounds the binary Warden will read and copy.
const MaxSize = 256 << 20

// Error is a failure with the exact fix.
type Error struct {
	Problem, Fix string
}

func (e *Error) Error() string { return e.Problem }

// Install copies exe into dir as warden-<sha256> (mode 0500) unless a
// verified copy is already there, and returns its path. dir must already
// exist with mode 0700.
func Install(exe, dir string, uid int, goarch string) (string, error) {
	data, sum, err := read(exe, goarch)
	if err != nil {
		return "", err
	}
	if err := paths.CheckDir(dir, uid); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, "warden-"+sum)
	if _, err := os.Lstat(dst); err == nil {
		return dst, verify(dst, sum, uid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".warden-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o500); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	return dst, verify(dst, sum, uid)
}

// Find returns the verified copy of exe in dir. It creates nothing: a
// missing copy means init hasn't run with this binary.
func Find(exe, dir string, uid int, goarch string) (string, error) {
	_, sum, err := read(exe, goarch)
	if err != nil {
		return "", err
	}
	if err := paths.CheckDir(dir, uid); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, "warden-"+sum)
	if _, err := os.Lstat(dst); errors.Is(err, os.ErrNotExist) {
		return "", &Error{
			Problem: fmt.Sprintf("no verified copy of this warden binary at %s (the binary changed since init?)", dst),
			Fix:     "run warden init",
		}
	}
	return dst, verify(dst, sum, uid)
}

// read loads exe, requires a static ELF for goarch, and hashes it.
func read(exe, goarch string) ([]byte, string, error) {
	f, err := os.Open(exe)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > MaxSize {
		return nil, "", fmt.Errorf("%s is larger than %d bytes", exe, MaxSize)
	}
	if err := CheckStatic(data, goarch); err != nil {
		return nil, "", &Error{Problem: fmt.Sprintf("%s: %v", exe, err), Fix: "build warden with CGO_ENABLED=0 for this host"}
	}
	s := sha256.Sum256(data)
	return data, hex.EncodeToString(s[:]), nil
}

var machines = map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}

// CheckStatic requires a 64-bit little-endian ELF executable for goarch
// with no program interpreter: it must run in an image with no libc.
func CheckStatic(data []byte, goarch string) error {
	want, ok := machines[goarch]
	if !ok {
		return fmt.Errorf("unsupported architecture %q", goarch)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("not an ELF binary: %w", err)
	}
	defer f.Close()
	switch {
	case f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB:
		return errors.New("not a 64-bit little-endian ELF binary")
	case f.Machine != want:
		return fmt.Errorf("built for %s, not %s", f.Machine, goarch)
	case f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN:
		return fmt.Errorf("ELF type %s is not an executable", f.Type)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("dynamically linked (has a program interpreter)")
		}
	}
	return nil
}

// verify requires dst to be a regular file (not a symlink), owned by uid,
// mode 0500, with exactly the expected hash.
func verify(dst, sum string, uid int) error {
	fix := "rm -f " + paths.ShellQuote(dst) + " and run warden init"
	fi, err := os.Lstat(dst)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return &Error{Problem: dst + " is not a regular file", Fix: fix}
	case !ok || int(st.Uid) != uid:
		return &Error{Problem: dst + " is not owned by you", Fix: fix}
	case fi.Mode().Perm() != 0o500:
		return &Error{Problem: fmt.Sprintf("%s has mode %04o, want 0500", dst, fi.Mode().Perm()), Fix: fix}
	}
	f, err := os.Open(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxSize+1)); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return &Error{Problem: fmt.Sprintf("%s has hash %s, want %s", dst, got, sum), Fix: fix}
	}
	return nil
}
