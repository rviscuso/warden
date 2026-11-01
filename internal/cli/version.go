package cli

import "fmt"

// runVersion prints the version from Go's embedded build info: the main
// module version, vcs.revision and vcs.modified. No -ldflags are involved,
// so the output can't disagree with what the toolchain recorded.
func runVersion(e *env) int {
	version, revision, modified, goVersion := "unknown", "unknown", "unknown", "unknown"
	if bi, ok := e.buildInfo(); ok && bi != nil {
		if bi.Main.Version != "" {
			version = bi.Main.Version
		}
		if bi.GoVersion != "" {
			goVersion = bi.GoVersion
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
	}
	fmt.Fprintf(e.stdout, "warden %s\n  revision: %s\n  modified: %s\n  go:       %s\n", version, revision, modified, goVersion)
	return ExitOK
}
