// Package termsafe makes untrusted output safe to copy to the user's
// terminal: container and build output can carry escape sequences that
// rewrite the screen, set the window title or write the clipboard
// (DESIGN.md, section 2, "Container output on the user's terminal").
package termsafe

import (
	"io"
	"sync"
)

// Writer copies text to W with every control character removed except
// newline and tab: C0 controls (ESC included), DEL, a bare carriage
// return, and the C1 controls U+0080 to U+009F in their UTF-8 form
// (0xC2 0x80-0x9F), which some terminals obey like ESC sequences. A
// carriage return before a newline is dropped too. The state carries over
// between writes, so a sequence split across two writes is still removed.
type Writer struct {
	W       io.Writer
	mu      sync.Mutex
	pending bool // the previous byte was 0xC2
}

// Write filters p and writes what remains. It reports len(p) on success.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, 0, len(p))
	for _, b := range p {
		if w.pending {
			w.pending = false
			if b >= 0x80 && b <= 0x9f {
				continue // a C1 control: drop both bytes
			}
			out = append(out, 0xc2)
		}
		switch {
		case b == 0xc2:
			w.pending = true
			continue
		case b == '\n' || b == '\t':
		case b < 0x20 || b == 0x7f:
			continue
		}
		out = append(out, b)
	}
	if _, err := w.W.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes a 0xC2 held back at the end of the stream (it can't start
// a C1 control any more).
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.pending {
		return nil
	}
	w.pending = false
	_, err := w.W.Write([]byte{0xc2})
	return err
}
