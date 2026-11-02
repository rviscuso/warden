package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

// TestMPTCPOffByDefault: go.mod's godebug line is in the build, so every
// listener and dialer in this binary defaults to plain TCP. Test binaries
// get the main module's godebug defaults, like the warden binary.
func TestMPTCPOffByDefault(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info")
	}
	for _, s := range bi.Settings {
		if s.Key == "DefaultGODEBUG" {
			for _, kv := range strings.Split(s.Value, ",") {
				if kv == "multipathtcp=0" {
					return
				}
			}
			t.Fatalf("DefaultGODEBUG %q lacks multipathtcp=0", s.Value)
		}
	}
	t.Fatal("no DefaultGODEBUG in the build info: go.mod has no godebug multipathtcp=0")
}
