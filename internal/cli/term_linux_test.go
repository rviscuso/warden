package cli

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// openPTY returns a pseudo-terminal's controller and terminal ends, with
// the standard library only.
func openPTY(t *testing.T) (ptmx, tty *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("SKIP: no /dev/ptmx: %v", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Fatal(e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Fatal(e)
	}
	tty, err = os.OpenFile("/dev/pts/"+itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("SKIP: cannot open the pty: %v", err)
	}
	t.Cleanup(func() { ptmx.Close(); tty.Close() })
	return ptmx, tty
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestIsTerminal(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	if isTerminal(devnull) {
		t.Error("/dev/null is a terminal")
	}
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if isTerminal(r) {
		t.Error("a pipe is a terminal")
	}
	if isTerminal(strings.NewReader("")) {
		t.Error("a strings.Reader is a terminal")
	}
	f, _ := os.CreateTemp(t.TempDir(), "x")
	defer f.Close()
	if isTerminal(f) {
		t.Error("a file is a terminal")
	}
	_, tty := openPTY(t)
	if !isTerminal(tty) {
		t.Error("a pty is not a terminal")
	}
}
