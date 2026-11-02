package wardenbin

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeELF builds a minimal ELF64 executable header with one PT_LOAD, and a
// PT_INTERP if interp is set.
func makeELF(t *testing.T, machine elf.Machine, interp bool, typ elf.Type) []byte {
	t.Helper()
	nprog := 1
	if interp {
		nprog = 2
	}
	var b bytes.Buffer
	h := elf.Header64{
		Type: uint16(typ), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT),
		Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: uint16(nprog),
	}
	copy(h.Ident[:], elf.ELFMAG)
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	binary.Write(&b, binary.LittleEndian, h)
	binary.Write(&b, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X)})
	if interp {
		binary.Write(&b, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_INTERP), Flags: uint32(elf.PF_R)})
	}
	b.WriteString("payload")
	return b.Bytes()
}

func writeExe(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "warden")
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func binDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCheckStatic(t *testing.T) {
	if err := CheckStatic(makeELF(t, elf.EM_X86_64, false, elf.ET_EXEC), "amd64"); err != nil {
		t.Errorf("static amd64: %v", err)
	}
	if err := CheckStatic(makeELF(t, elf.EM_AARCH64, false, elf.ET_DYN), "arm64"); err != nil { // static-pie
		t.Errorf("static-pie arm64: %v", err)
	}
	bad := map[string]struct {
		data   []byte
		goarch string
		want   string
	}{
		"dynamic":      {makeELF(t, elf.EM_X86_64, true, elf.ET_EXEC), "amd64", "dynamically linked"},
		"wrong arch":   {makeELF(t, elf.EM_AARCH64, false, elf.ET_EXEC), "amd64", "built for"},
		"object file":  {makeELF(t, elf.EM_X86_64, false, elf.ET_REL), "amd64", "not an executable"},
		"not ELF":      {[]byte("#!/bin/sh\necho hi\n"), "amd64", "not an ELF"},
		"unknown arch": {makeELF(t, elf.EM_X86_64, false, elf.ET_EXEC), "riscv64", "unsupported"},
	}
	for name, c := range bad {
		if err := CheckStatic(c.data, c.goarch); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestInstallAndFind(t *testing.T) {
	data := makeELF(t, elf.EM_X86_64, false, elf.ET_EXEC)
	exe := writeExe(t, data)
	dir := binDir(t)
	uid := os.Getuid()

	if _, err := Find(exe, dir, uid, "amd64"); err == nil || !strings.Contains(err.Error(), "no verified copy") {
		t.Fatalf("Find before Install: %v", err)
	}
	p, err := Install(exe, dir, uid, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if filepath.Base(p) != "warden-"+hex.EncodeToString(sum[:]) {
		t.Errorf("installed as %s", p)
	}
	fi, _ := os.Lstat(p)
	if fi.Mode().Perm() != 0o500 {
		t.Errorf("mode %v", fi.Mode())
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, data) {
		t.Error("copy differs")
	}
	if p2, err := Install(exe, dir, uid, "amd64"); err != nil || p2 != p {
		t.Errorf("second Install: %s, %v", p2, err)
	}
	if p3, err := Find(exe, dir, uid, "amd64"); err != nil || p3 != p {
		t.Errorf("Find: %s, %v", p3, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leftover files in %s: %v", dir, entries)
	}
}

func TestTamperedCopyIsRefused(t *testing.T) {
	data := makeELF(t, elf.EM_X86_64, false, elf.ET_EXEC)
	exe := writeExe(t, data)
	uid := os.Getuid()
	cases := map[string]func(p string){
		"content": func(p string) {
			os.Chmod(p, 0o700)
			os.WriteFile(p, append(data, 'x'), 0o700)
			os.Chmod(p, 0o500)
		},
		"mode": func(p string) { os.Chmod(p, 0o555) },
		"symlink": func(p string) {
			other := filepath.Join(filepath.Dir(filepath.Dir(p)), "other")
			os.WriteFile(other, data, 0o500)
			os.Remove(p)
			os.Symlink(other, p)
		},
	}
	for name, tamper := range cases {
		dir := binDir(t)
		p, err := Install(exe, dir, uid, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		tamper(p)
		var we *Error
		if _, err := Find(exe, dir, uid, "amd64"); !errors.As(err, &we) || !strings.Contains(we.Fix, "rm -f") {
			t.Errorf("%s: Find = %v", name, err)
		}
		if _, err := Install(exe, dir, uid, "amd64"); !errors.As(err, &we) {
			t.Errorf("%s: Install over a tampered copy = %v", name, err)
		}
	}
}

func TestInstallRefusesDynamicBinary(t *testing.T) {
	exe := writeExe(t, makeELF(t, elf.EM_X86_64, true, elf.ET_EXEC))
	dir := binDir(t)
	var we *Error
	if _, err := Install(exe, dir, os.Getuid(), "amd64"); !errors.As(err, &we) || !strings.Contains(we.Fix, "CGO_ENABLED=0") {
		t.Fatalf("Install = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("something was written: %v", entries)
	}
}

func TestInstallRefusesLooseDir(t *testing.T) {
	exe := writeExe(t, makeELF(t, elf.EM_X86_64, false, elf.ET_EXEC))
	dir := binDir(t)
	os.Chmod(dir, 0o755)
	if _, err := Install(exe, dir, os.Getuid(), "amd64"); err == nil {
		t.Fatal("Install into a 0755 directory")
	}
}
