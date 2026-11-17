package cli

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether r is a terminal, by asking the kernel for its
// terminal attributes (TCGETS). A character-device test would also count
// /dev/null.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
