package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rviscuso/warden/internal/canary"
	"github.com/rviscuso/warden/internal/compose"
	"github.com/rviscuso/warden/internal/hardening"
	"github.com/rviscuso/warden/internal/paths"
	"github.com/rviscuso/warden/internal/state"
	"github.com/rviscuso/warden/internal/wardenbin"
)

// Canary timeouts: 90 s for the whole canary, cleanup included.
var (
	CanaryTimeout  = 70 * time.Second
	CleanupTimeout = 20 * time.Second
)

// CanaryEnv is what the canary touches on the host besides Docker.
type CanaryEnv struct {
	Executable func() (string, error) // the running warden binary
	Resolver   interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
	Dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	Listen func(network, address string) (net.Listener, error) // the no-host listener
	Rand   io.Reader                                           // names the run directory
}

const (
	idImage   = "canary.image"
	idCleanup = "canary.cleanup"
)

func canaryIDs() []struct{ ID, Title string } {
	ids := []struct{ ID, Title string }{{idImage, "Runtime image is local"}}
	ids = append(ids, canary.ProbeChecks...)
	return append(ids, struct{ ID, Title string }{idCleanup, "Canary removed"})
}

// canaryFail records a fail for canary checks [from, to); to < 0 means
// through the last one.
func (r *run) canaryFail(from, to int, detail, fix string) {
	ids := canaryIDs()
	if to < 0 {
		to = len(ids)
	}
	for _, c := range ids[from:to] {
		r.fail(c.ID, c.Title, detail, fix)
	}
}

func (r *run) canary() {
	for _, res := range r.rep.Results {
		if res.Status == Fail {
			r.canaryFail(0, -1, "not run: depends on "+res.ID, "")
			return
		}
	}
	// From here on the canary runs: whatever happens, its record is updated
	// (set if every check passes, cleared otherwise).
	r.rep.CanaryRan = true
	ctx, cancel := context.WithTimeout(r.env.Ctx, CanaryTimeout)
	defer cancel()
	cfg := r.rep.Config

	// canary.image: local, never pulled.
	if _, err := r.dockerIn(ctx, nil, "image", "inspect", "--format", "{{.Id}}", cfg.RuntimeImage); err != nil {
		fix := "docker pull " + cfg.RuntimeImage
		if !strings.Contains(cfg.RuntimeImage, "@sha256:") {
			fix = "load or build the image, then set runtime_image to its ID"
		}
		r.fail(idImage, "Runtime image is local", fmt.Sprintf("runtime_image %s is not local; Warden never pulls (%s)", cfg.RuntimeImage, oneLine(err)), fix)
		r.canaryFail(1, -1, "not run: depends on "+idImage, "")
		return
	}
	r.pass(idImage, "Runtime image is local", cfg.RuntimeImage)

	c := &canaryRun{r: r, ctx: ctx}
	verdicts, setupErr := c.run()
	cleanupErr := c.cleanup()

	if setupErr != nil {
		r.canaryFail(1, len(canaryIDs())-1, "canary setup failed: "+oneLine(setupErr), errFix(setupErr))
	} else {
		for _, v := range verdicts {
			r.add(Result{ID: v.ID, Title: v.Title, Status: Status(v.Status), Detail: v.Detail, Fix: v.Fix})
		}
	}
	if cleanupErr != nil {
		r.fail(idCleanup, "Canary removed", oneLine(cleanupErr), errFix(cleanupErr))
	} else {
		r.pass(idCleanup, "Canary removed", "containers, networks and the run directory removed")
	}

	// The record up requires: only if every canary check passed or warned.
	for _, res := range r.rep.Results {
		if strings.HasPrefix(res.ID, "canary.") && res.Status == Fail {
			return
		}
	}
	r.rep.CanaryPass = &state.CanaryPass{
		DaemonID: r.rep.Daemon.ID, BinarySHA256: c.binSHA, HardeningSHA256: c.digest, At: r.env.now().UTC(),
	}
}

// fixError carries an exact fix.
type fixError struct {
	err error
	fix string
}

func (e *fixError) Error() string { return e.err.Error() }
func (e *fixError) Unwrap() error { return e.err }

func withFix(fix string, format string, a ...any) error {
	return &fixError{fmt.Errorf(format, a...), fix}
}

func errFix(err error) string {
	var fe *fixError
	var we *wardenbin.Error
	switch {
	case errors.As(err, &fe):
		return fe.fix
	case errors.As(err, &we):
		return we.Fix
	}
	return fixOf(err)
}

// canaryRun is one canary: what it created, so cleanup removes exactly that.
type canaryRun struct {
	r   *run
	ctx context.Context

	lock       *os.File
	runDir     string
	file       []byte // the rendered compose file
	created    bool   // compose create was attempted
	containers []string
	networks   []string

	// What a passing run records (state.CanaryPass).
	binSHA, digest string
}

func (c *canaryRun) env() CanaryEnv {
	e := c.r.env.Canary
	if e.Rand == nil {
		e.Rand = rand.Reader
	}
	return e
}

func (c *canaryRun) run() ([]canary.Verdict, error) {
	r, cfg, dirs := c.r, c.r.rep.Config, c.r.env.Dirs
	init := r.env.Mode == ModeInit
	if e := c.env(); e.Executable == nil || e.Resolver == nil || e.Dialer == nil || e.Listen == nil {
		return nil, errors.New("canary: incomplete environment")
	}

	// Directories and the lock. check creates nothing.
	for _, d := range []string{dirs.BinDir(), dirs.CanaryDir()} {
		if init {
			if err := os.Mkdir(d, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, err
			}
		}
		if err := paths.CheckDir(d, r.env.UID); err != nil {
			return nil, withRunInit(err)
		}
	}
	lock, err := openLock(dirs.CanaryLock(), r.env.UID, init)
	if err != nil {
		return nil, err
	}
	c.lock = lock

	// The binary the proxy and the canary run from.
	exe, err := c.env().Executable()
	if err != nil {
		return nil, fmt.Errorf("finding the warden binary: %w", err)
	}
	var bin string
	if init {
		bin, err = wardenbin.Install(exe, dirs.BinDir(), r.env.UID, r.env.GOARCH)
	} else {
		bin, err = wardenbin.Find(exe, dirs.BinDir(), r.env.UID, r.env.GOARCH)
	}
	if err != nil {
		return nil, err
	}
	c.binSHA = strings.TrimPrefix(filepath.Base(bin), "warden-")

	// Leftovers from a crashed run fail; they are never removed for you.
	if err := c.noLeftovers(); err != nil {
		return nil, err
	}

	// Host-side controls, before anything starts.
	probeHost, err := canary.ProbeHost(cfg.Egress.Allow)
	if err != nil {
		return nil, err
	}
	host := canary.Host{DNSHost: probeHost}
	host.RouteControl = c.dialControl()
	if kb, err := canary.ReadSwapTotal(r.env.Root); err != nil {
		host.SwapErr = err
	} else {
		host.SwapTotalKB = &kb
	}
	host.DNSControl = c.resolveControl(probeHost)

	// The run directory and the project.
	name := make([]byte, 8)
	if _, err := io.ReadFull(c.env().Rand, name); err != nil {
		return nil, err
	}
	c.runDir = filepath.Join(dirs.CanaryDir(), hex.EncodeToString(name))
	mnt := filepath.Join(c.runDir, "mnt")
	if err := os.Mkdir(c.runDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(mnt, 0o700); err != nil {
		return nil, err
	}
	res := cfg.Controller.Resources
	resources := hardening.Resources{MemoryMB: res.MemoryMB, CPUs: res.CPUs, Pids: res.PIDs}
	mptcp, err := hardening.HostMPTCP(r.env.Root)
	if err != nil {
		return nil, err
	}
	hostH := hardening.Host{MPTCP: mptcp}
	if c.digest, err = hardening.Digest(r.env.UID, r.env.GID, resources, hostH); err != nil {
		return nil, err
	}
	f, err := canary.Project(canary.ProjectParams{
		UID: r.env.UID, GID: r.env.GID, RuntimeImage: cfg.RuntimeImage, Binary: bin, MountDir: mnt,
		Allow: cfg.Egress.Allow, Resources: resources, Host: hostH,
	})
	if err != nil {
		return nil, err
	}
	c.file, err = compose.Render(f, compose.Policy{UID: r.env.UID, GID: r.env.GID, Socket: cfg.Docker.Socket, MPTCP: mptcp})
	if err != nil {
		return nil, err
	}

	// Create (not started), so the gateway is known before the probe runs.
	c.created = true
	if _, err := c.compose("create"); err != nil {
		return nil, err
	}
	if c.containers, err = c.ids("inspect", "--type", "container", "--format", "{{.Id}}", canary.ProxyName, canary.CanaryName); err != nil {
		return nil, err
	}
	if c.networks, err = c.ids("network", "inspect", "--format", "{{.Id}}", canary.SandboxNet, canary.EgressNet); err != nil {
		return nil, err
	}

	// The no-host listener, on the gateway address only.
	lst := c.listen(&host)
	defer lst.close()
	control := "no_host=skip\n"
	if !host.NoHostSkipped && host.NoHostErr == nil {
		gw, port, _ := net.SplitHostPort(host.NoHostAddr)
		control = "gateway=" + gw + "\nport=" + port + "\n"
	}
	if err := writeAtomic(filepath.Join(mnt, "control"), control); err != nil {
		return nil, err
	}

	if _, err := c.compose("start"); err != nil {
		return nil, err
	}
	code, err := r.dockerIn(c.ctx, nil, "wait", canary.CanaryName)
	if err != nil {
		return nil, err
	}
	out, errOut, err := c.logs(canary.CanaryName)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(code)) != "0" {
		return nil, fmt.Errorf("the probe exited %s: %s", strings.TrimSpace(string(code)), strings.TrimSpace(string(errOut)))
	}
	host.ProxyLog, _, err = c.logs(canary.ProxyName)
	if err != nil {
		return nil, err
	}
	host.NoHostAccepts = lst.close()

	if fi, err := os.Lstat(filepath.Join(mnt, "owner")); err != nil {
		host.OwnerErr = err
	} else if st, ok := fi.Sys().(*syscall.Stat_t); !ok || !fi.Mode().IsRegular() {
		host.OwnerErr = errors.New("the owner file is not a regular file")
	} else {
		host.OwnerUID, host.OwnerGID = int(st.Uid), int(st.Gid)
	}

	obs, err := canary.Parse(out)
	if err != nil {
		return nil, err
	}
	return canary.Evaluate(obs, canary.Expect{
		UID: r.env.UID, GID: r.env.GID, Resources: resources, DaemonAppArmor: r.info.securityOption("apparmor"), MPTCP: mptcp,
	}, host), nil
}

func withRunInit(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return withFix("warden init", "%v: run warden init", err)
	}
	return err
}

// openLock takes the canary lock: one canary at a time. init creates the
// lock file; check needs it to exist.
func openLock(path string, uid int, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist) && !create:
		return nil, withFix("warden init", "%s is missing: run warden init", path)
	case err == nil && !fi.Mode().IsRegular():
		return nil, withFix("rm "+paths.ShellQuote(path)+" and run warden init", "%s is not a regular file", path)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || int(st.Sys().(*syscall.Stat_t).Uid) != uid {
		f.Close()
		return nil, withFix("rm "+paths.ShellQuote(path)+" and run warden init", "%s is not owned by you", path)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, withFix("wait for the other warden init or check to finish", "another warden init or check is running its canary")
		}
		return nil, err
	}
	return f, nil
}

func (c *canaryRun) compose(cmd ...string) ([]byte, error) {
	args := append([]string{"compose", "-p", canary.ProjectName, "-f", "-"}, cmd...)
	return c.r.dockerIn(c.ctx, c.file, args...)
}

func (c *canaryRun) logs(name string) (stdout, stderr []byte, err error) {
	rn, err := c.r.dockerRunner()
	if err != nil {
		return nil, nil, err
	}
	out, errOut, code, err := rn.Run(c.ctx, []string{"logs", name}, nil)
	if err == nil && code != 0 {
		err = fmt.Errorf("docker logs %s exited %d: %s", name, code, strings.TrimSpace(string(errOut)))
	}
	return out, errOut, err
}

func (c *canaryRun) ids(args ...string) ([]string, error) {
	out, err := c.r.dockerIn(c.ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// noLeftovers fails if any canary container or network exists.
func (c *canaryRun) noLeftovers() error {
	var fixes []string
	cs, err := c.existing(c.ctx, []string{"inspect", "--type", "container"}, canary.ProxyName, canary.CanaryName)
	if err != nil {
		return err
	}
	for _, n := range cs {
		fixes = append(fixes, "docker rm -f "+n)
	}
	ns, err := c.existing(c.ctx, []string{"network", "inspect"}, canary.SandboxNet, canary.EgressNet)
	if err != nil {
		return err
	}
	for _, n := range ns {
		fixes = append(fixes, "docker network rm "+n)
	}
	if len(fixes) > 0 {
		return withFix(strings.Join(fixes, " && "),
			"left over from an earlier canary run (or created by someone else): %s; Warden never removes them for you", strings.Join(append(cs, ns...), ", "))
	}
	return nil
}

// existing returns which of names exist, via docker inspect. A name that
// doesn't exist is reported by docker as "No such …" or "not found"; any
// other failure is an error.
func (c *canaryRun) existing(ctx context.Context, cmd []string, names ...string) ([]string, error) {
	rn, err := c.r.dockerRunner()
	if err != nil {
		return nil, err
	}
	args := append(append(append([]string(nil), cmd...), "--format", "{{.Name}}"), names...)
	out, errOut, code, err := rn.Run(ctx, args, nil)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		for _, l := range strings.Split(strings.TrimSpace(string(errOut)), "\n") {
			if l != "" && !strings.Contains(l, "No such") && !strings.Contains(l, "not found") {
				return nil, fmt.Errorf("docker %s: %s", strings.Join(cmd, " "), strings.TrimSpace(string(errOut)))
			}
		}
	}
	var found []string
	for _, n := range strings.Fields(string(out)) {
		found = append(found, strings.TrimPrefix(n, "/"))
	}
	return found, nil
}

func (c *canaryRun) dialControl() error {
	ctx, cancel := context.WithTimeout(c.ctx, canary.StepTimeout)
	defer cancel()
	conn, err := c.env().Dialer.DialContext(ctx, "tcp", canary.RouteControl)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (c *canaryRun) resolveControl(host string) error {
	ctx, cancel := context.WithTimeout(c.ctx, canary.StepTimeout)
	defer cancel()
	addrs, err := c.env().Resolver.LookupNetIP(ctx, "ip", host)
	if err == nil && len(addrs) == 0 {
		err = errors.New("no addresses")
	}
	return err
}

type listener struct {
	ln      net.Listener
	mu      sync.Mutex
	accepts int
	done    chan struct{}
	once    sync.Once
}

// close stops the listener and returns how many connections it received.
func (l *listener) close() int {
	if l.ln == nil {
		return 0
	}
	l.once.Do(func() { l.ln.Close(); <-l.done })
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.accepts
}

// listen opens the no-host listener on the sandbox network's gateway
// address only. No gateway, or a failure other than EADDRNOTAVAIL, means
// the check cannot prove anything.
func (c *canaryRun) listen(h *canary.Host) *listener {
	l := &listener{}
	out, err := c.r.dockerIn(c.ctx, nil, "network", "inspect", "--format", "{{json .IPAM.Config}}", canary.SandboxNet)
	if err != nil {
		h.NoHostErr = err
		return l
	}
	var ipam []struct{ Gateway string }
	if err := json.Unmarshal(out, &ipam); err != nil {
		h.NoHostErr = fmt.Errorf("parsing the sandbox network's IPAM config: %w", err)
		return l
	}
	var gw netip.Addr
	for _, c := range ipam {
		if a, err := netip.ParseAddr(c.Gateway); err == nil && a.Unmap().Is4() {
			gw = a.Unmap()
			break
		}
	}
	if !gw.IsValid() {
		h.NoHostErr = errors.New("no IPv4 gateway in docker network inspect " + canary.SandboxNet)
		return l
	}
	ln, err := c.env().Listen("tcp", net.JoinHostPort(gw.String(), "0"))
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		h.NoHostSkipped = true
		return l
	}
	if err != nil {
		h.NoHostErr = fmt.Errorf("listening on %s: %w", gw, err)
		return l
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	h.NoHostAddr = net.JoinHostPort(gw.String(), port)
	l.ln, l.done = ln, make(chan struct{})
	go func() {
		defer close(l.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
			l.mu.Lock()
			l.accepts++
			l.mu.Unlock()
		}
	}()
	return l
}

func writeAtomic(path, content string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".control-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// cleanup removes everything the run created, with its own time budget,
// and reports what it couldn't.
func (c *canaryRun) cleanup() error {
	defer func() {
		if c.lock != nil {
			c.lock.Close() // releases the flock
		}
	}()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.r.env.Ctx), CleanupTimeout)
	defer cancel()
	var problems, fixes []string
	if c.created {
		_, downErr := c.r.dockerIn(ctx, c.file, "compose", "-p", canary.ProjectName, "-f", "-", "down", "--timeout", "5")
		cs, err1 := c.existing(ctx, []string{"inspect", "--type", "container"}, canary.ProxyName, canary.CanaryName)
		ns, err2 := c.existing(ctx, []string{"network", "inspect"}, canary.SandboxNet, canary.EgressNet)
		if downErr != nil || err1 != nil || err2 != nil || len(cs)+len(ns) > 0 {
			// Fall back to the recorded IDs, then look again.
			for _, id := range c.containers {
				c.r.dockerIn(ctx, nil, "rm", "-f", id)
			}
			for _, id := range c.networks {
				c.r.dockerIn(ctx, nil, "network", "rm", id)
			}
			cs, err1 = c.existing(ctx, []string{"inspect", "--type", "container"}, canary.ProxyName, canary.CanaryName)
			ns, err2 = c.existing(ctx, []string{"network", "inspect"}, canary.SandboxNet, canary.EgressNet)
			for _, err := range []error{err1, err2} {
				if err != nil {
					problems = append(problems, oneLine(err))
				}
			}
			for _, n := range cs {
				problems = append(problems, "container "+n+" is still there")
				fixes = append(fixes, "docker rm -f "+n)
			}
			for _, n := range ns {
				problems = append(problems, "network "+n+" is still there")
				fixes = append(fixes, "docker network rm "+n)
			}
		}
	}
	if c.runDir != "" {
		if err := os.RemoveAll(c.runDir); err != nil {
			problems = append(problems, oneLine(err))
			fixes = append(fixes, "rm -r "+paths.ShellQuote(c.runDir))
		}
	}
	if len(problems) > 0 {
		return withFix(strings.Join(fixes, " && "), "%s", strings.Join(problems, "; "))
	}
	return nil
}

// dockerIn runs one docker command with a context and optional stdin;
// failure to run or a non-zero exit is an error carrying stderr.
func (r *run) dockerIn(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	rn, err := r.dockerRunner()
	if err != nil {
		return nil, fmt.Errorf("cannot run docker: %w", err)
	}
	var in io.Reader
	if stdin != nil {
		in = strings.NewReader(string(stdin))
	}
	out, errOut, code, err := rn.Run(ctx, args, in)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		msg := strings.TrimSpace(string(errOut))
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		return out, fmt.Errorf("docker %s exited %d: %s", strings.Join(firstN(args, 3), " "), code, msg)
	}
	return out, nil
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
