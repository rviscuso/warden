package netx

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestListenConfigMPTCPOff(t *testing.T) {
	if ListenConfig().MultipathTCP() {
		t.Fatal("ListenConfig().MultipathTCP() is true")
	}
}

// TestMPTCPOffWithoutGodebug re-runs the check with GODEBUG=multipathtcp=1,
// which turns Go's MPTCP default back on: only the explicit
// SetMultipathTCP(false) keeps ListenConfig off then.
func TestMPTCPOffWithoutGodebug(t *testing.T) {
	if os.Getenv("NETX_CHILD") == "1" {
		var zero net.ListenConfig
		fmt.Printf("zero=%v netx=%v\n", zero.MultipathTCP(), ListenConfig().MultipathTCP())
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMPTCPOffWithoutGodebug$")
	cmd.Env = append(os.Environ(), "NETX_CHILD=1", "GODEBUG=multipathtcp=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	switch {
	case strings.Contains(string(out), "zero=true netx=false"):
	case strings.Contains(string(out), "zero=false"):
		t.Fatalf("GODEBUG=multipathtcp=1 didn't turn the default on (%s): the test proves nothing", strings.TrimSpace(string(out)))
	default:
		t.Fatalf("netx turns MPTCP on when the default does: %s", out)
	}
}

// accepted dials ln with an MPTCP client and reports whether the server
// side of the connection is MPTCP.
func accepted(t *testing.T, ln net.Listener) bool {
	t.Helper()
	got := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		got <- c
	}()
	d := &net.Dialer{}
	d.SetMultipathTCP(true)
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := <-got
	if s == nil {
		t.Fatal("accept failed")
	}
	defer s.Close()
	mp, err := s.(*net.TCPConn).MultipathTCP()
	if err != nil {
		t.Fatal(err)
	}
	return mp
}

// TestListenerRefusesMPTCP: an MPTCP client gets a plain TCP connection.
// A control listener with MPTCP on shows whether this kernel can do MPTCP
// at all; where it can't (absent, or net.mptcp.enabled=0), nothing is
// proven, so the test skips.
func TestListenerRefusesMPTCP(t *testing.T) {
	ctl := &net.ListenConfig{}
	ctl.SetMultipathTCP(true)
	cl, err := ctl.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if !accepted(t, cl) {
		t.Skip("SKIP: this kernel doesn't do MPTCP (absent, or net.mptcp.enabled=0), so a plain TCP connection proves nothing")
	}
	ln, err := Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if accepted(t, ln) {
		t.Fatal("an MPTCP client got an MPTCP connection from netx.Listen")
	}
}

// opensListener are the net package's ways to open a listener (or to build
// one, ListenConfig). The net.Listener interface opens nothing.
var opensListener = map[string]bool{
	"Listen": true, "ListenConfig": true, "ListenTCP": true, "ListenPacket": true, "ListenUDP": true,
	"ListenIP": true, "ListenUnix": true, "ListenUnixgram": true, "ListenMulticastUDP": true,
}

// TestNoOtherListeners: in Warden's non-test code, only this package opens
// listeners. net.Listen*, net.ListenConfig and the like anywhere else fail.
func TestNoOtherListeners(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	self, _ := filepath.Abs(".")
	var found []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == self || strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		netName := ""
		for _, imp := range f.Imports {
			if imp.Path.Value == `"net"` {
				netName = "net"
				if imp.Name != nil {
					netName = imp.Name.Name
				}
			}
		}
		if netName == "" {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == netName && opensListener[sel.Sel.Name] {
				rel, _ := filepath.Rel(root, p)
				found = append(found, fmt.Sprintf("%s:%d: net.%s", rel, fset.Position(sel.Pos()).Line, sel.Sel.Name))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Errorf("%s: open listeners with netx.Listen", f)
	}
}
