package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/rviscuso/warden/internal/canary"
)

func defineProbe(fs *flag.FlagSet) func(*env, []string) int {
	var o canary.ProbeOptions
	fs.StringVar(&o.Proxy, "proxy", "", "the proxy's `host:port`")
	fs.StringVar(&o.AllowHost, "allow-host", "", "an allowlisted `host`: CONNECT must succeed")
	fs.StringVar(&o.DenyHost, "deny-host", "", "a `host` not on the allowlist: CONNECT must be refused")
	fs.StringVar(&o.DNSHost, "dns-host", "", "an outside `host`name that must not resolve")
	fs.StringVar(&o.Route, "route", "", "an outside `IP:port` that must not be reachable")
	fs.StringVar(&o.Dir, "dir", "", "the bind-mounted `directory`")
	return func(e *env, pos []string) int {
		if e.getenv("WARDEN_ROLE") != "canary" {
			fmt.Fprintln(e.stderr, "warden probe: refusing to run: WARDEN_ROLE=canary is not set (this command runs only inside Warden's canary container)")
			return ExitFail
		}
		if len(pos) > 0 {
			return usageError(e, "probe", "unexpected arguments: "+strings.Join(pos, " "))
		}
		if err := o.Validate(); err != nil {
			return usageError(e, "probe", err.Error())
		}
		pe := canary.DefaultProbeEnv()
		if e.probeEnv != nil {
			pe = e.probeEnv()
		}
		if err := canary.Probe(context.Background(), o, pe, e.stdout); err != nil {
			fmt.Fprintf(e.stderr, "warden probe: %v\n", err)
			return ExitFail
		}
		return ExitOK
	}
}
