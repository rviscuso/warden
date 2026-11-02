// Package netx is the one way Warden opens a listener: with MPTCP off,
// explicitly, not only through go.mod's godebug default. See DESIGN.md §2
// (CVE-2026-98432: the demonstrated exploit needs an MPTCP listener, and Go
// listeners use MPTCP by default on Linux). A test refuses any other
// listener in Warden's non-test code.
package netx

import (
	"context"
	"net"
)

// ListenConfig is the configuration every Warden listener uses.
func ListenConfig() *net.ListenConfig {
	lc := &net.ListenConfig{}
	lc.SetMultipathTCP(false)
	return lc
}

// Listen opens a listener with ListenConfig.
func Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return ListenConfig().Listen(ctx, network, address)
}
