package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/rviscuso/warden/internal/proxy"
)

// allowFlag collects repeated --allow flags.
type allowFlag []string

func (a *allowFlag) String() string     { return strings.Join(*a, " ") }
func (a *allowFlag) Set(v string) error { *a = append(*a, v); return nil }

func defineProxy(fs *flag.FlagSet) func(*env, []string) int {
	listen := fs.String("listen", ":3128", "`address` to listen on")
	var allow allowFlag
	fs.Var(&allow, "allow", "allowed `host`name; repeat for each; a leading dot also allows subdomains")
	ports := fs.String("ports", "443", "comma-separated destination `ports`")
	return func(e *env, pos []string) int {
		if e.getenv("WARDEN_ROLE") != "proxy" {
			fmt.Fprintln(e.stderr, "warden proxy: refusing to run: WARDEN_ROLE=proxy is not set (this command runs only inside Warden's proxy container)")
			return ExitFail
		}
		if len(pos) > 0 {
			return usageError(e, "proxy", "unexpected arguments: "+strings.Join(pos, " "))
		}
		ps, err := proxy.ParsePorts(*ports)
		if err != nil {
			return usageError(e, "proxy", err.Error())
		}
		p, err := proxy.New(proxy.Config{
			Allow:    allow,
			Ports:    ps,
			Resolver: e.resolver,
			Dialer:   e.dialer,
			Log:      e.stdout,
			ErrorLog: e.stderr,
			Now:      func() time.Time { return e.now() },
		})
		if err != nil {
			return usageError(e, "proxy", err.Error())
		}
		ln, err := e.listen(*listen)
		if err != nil {
			fmt.Fprintf(e.stderr, "warden proxy: %v\n", err)
			return ExitFail
		}
		ctx, stop := e.signals()
		defer stop()
		if err := p.Serve(ctx, ln); err != nil {
			fmt.Fprintf(e.stderr, "warden proxy: %v\n", err)
			return ExitFail
		}
		return ExitOK
	}
}
