// Package dockertest provides a scripted docker.Runner for tests. Any call
// that wasn't scripted fails the test, so tests notice unexpected docker
// invocations instead of passing by accident.
package dockertest

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// Response is what one scripted invocation returns.
type Response struct {
	Stdout, Stderr string
	ExitCode       int
	Err            error
}

// Fake is a docker.Runner that answers from a script keyed by the
// space-joined argv.
type Fake struct {
	t     testing.TB
	mu    sync.Mutex
	resp  map[string]Response
	Calls [][]string
}

// New returns an empty Fake bound to t.
func New(t testing.TB) *Fake {
	return &Fake{t: t, resp: make(map[string]Response)}
}

// On scripts the response for argv.
func (f *Fake) On(argv []string, r Response) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp[strings.Join(argv, " ")] = r
	return f
}

// OnFile scripts a successful call whose stdout is the content of a file
// (a recorded fixture).
func (f *Fake) OnFile(argv []string, path string) *Fake {
	f.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatalf("fixture %s: %v", path, err)
	}
	return f.On(argv, Response{Stdout: string(data)})
}

// Run implements docker.Runner.
func (f *Fake) Run(_ context.Context, args []string, _ io.Reader) ([]byte, []byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, append([]string(nil), args...))
	r, ok := f.resp[strings.Join(args, " ")]
	if !ok {
		f.t.Errorf("unexpected docker call: docker %s", strings.Join(args, " "))
		return nil, nil, -1, fmt.Errorf("dockertest: unscripted call")
	}
	return []byte(r.Stdout), []byte(r.Stderr), r.ExitCode, r.Err
}

// Called reports whether argv was invoked.
func (f *Fake) Called(argv []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := strings.Join(argv, " ")
	for _, c := range f.Calls {
		if strings.Join(c, " ") == want {
			return true
		}
	}
	return false
}
