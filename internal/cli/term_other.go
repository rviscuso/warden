//go:build !linux

package cli

import "io"

// isTerminal is false off Linux, where Warden doesn't run (host.os).
func isTerminal(io.Reader) bool { return false }
