package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rviscuso/warden/images"
	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/docker"
	"github.com/rviscuso/warden/internal/gitinit"
	"github.com/rviscuso/warden/internal/mounts"
	"github.com/rviscuso/warden/internal/paths"
	"github.com/rviscuso/warden/internal/refimage"
)

// PullTimeout bounds the runtime image pull.
const PullTimeout = 10 * time.Minute

// Defaults offered by the guided init.
var (
	guidedAllow     = []string{"api.anthropic.com", "platform.claude.com"}
	guidedResources = config.Resources{MemoryMB: 1536, CPUs: 1.5, PIDs: 512}
)

const guidedName = "warden"

// errNoInput ends the guided init at EOF: nothing is written.
var errNoInput = errors.New("no input")

// guide is one guided init: prompts on stderr, answers from one buffered
// reader (so confirmed() later reads from the same buffer).
type guide struct {
	e    *env
	in   *bufio.Reader
	dirs paths.Dirs
	home string
	cwd  string
	ctx  context.Context
	r    docker.Runner
}

// runGuided asks for the config, writes it on "y", and returns ok. It
// returns false after printing why when init must stop.
func runGuided(e *env, dirs paths.Dirs, home string) bool {
	in, ok := e.stdin.(*bufio.Reader)
	if !ok {
		in = bufio.NewReader(e.stdin)
		e.stdin = in // the re-pin prompt reads from the same buffer
	}
	cwd, err := e.getwd()
	if err != nil {
		cwd = ""
	}
	g := &guide{e: e, in: in, dirs: dirs, home: home, cwd: cwd, ctx: context.Background()}
	if err := g.run(); err != nil {
		if errors.Is(err, errNoInput) {
			fmt.Fprintln(e.stderr, "\nwarden init: no input; nothing written")
		} else {
			fmt.Fprintf(e.stderr, "warden init: %v\n", err)
		}
		return false
	}
	return true
}

func (g *guide) say(format string, a ...any) { fmt.Fprintf(g.e.stderr, format+"\n", a...) }

// ask prints "label [def]: " and returns the trimmed answer, or def on Enter.
func (g *guide) ask(label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(g.e.stderr, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(g.e.stderr, "%s: ", label)
	}
	line, err := g.in.ReadString('\n')
	if err != nil { // EOF, even after a partial line: not an answer
		return "", errNoInput
	}
	ans := strings.TrimSpace(line)
	if ans == "" {
		return def, nil
	}
	return ans, nil
}

// yes asks a y/N question; only "y" is yes.
func (g *guide) yes(question string) (bool, error) {
	fmt.Fprintf(g.e.stderr, "%s [y/N] ", question)
	line, err := g.in.ReadString('\n')
	if err != nil {
		return false, errNoInput
	}
	return strings.TrimSpace(line) == "y", nil
}

func (g *guide) refuse(format string, a ...any) { g.say("  ✗ "+format, a...) }

func (g *guide) run() error {
	g.say("No config yet: answer a few questions (Enter accepts the [default]).")
	ws, err := g.workspace()
	if err != nil {
		return err
	}
	allow, err := g.domains()
	if err != nil {
		return err
	}
	res, err := g.limits()
	if err != nil {
		return err
	}
	name, err := g.askValid("Remote Control name", guidedName, func(s string) error {
		if config.ValidateRemoteControlName(s) != nil {
			return fmt.Errorf("%q: use 1 to 64 letters, digits, '.', '_' or '-', such as my-repo", s)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := g.runner(); err != nil {
		return err
	}
	if err := g.runtimeImage(); err != nil {
		return err
	}
	image, err := g.controllerImage()
	if err != nil {
		return err
	}
	cfg := config.Config{
		Version:    1,
		Docker:     config.Docker{Socket: g.e.defaultSocket},
		Egress:     config.Egress{Allow: allow},
		Controller: config.Controller{Image: image, Workspace: ws, RemoteControlName: name, Resources: res},
	}
	return g.review(cfg)
}

// askValid asks until check accepts the answer.
func (g *guide) askValid(label, def string, check func(string) error) (string, error) {
	for {
		ans, err := g.ask(label, def)
		if err != nil {
			return "", err
		}
		if err := check(ans); err != nil {
			g.refuse("%v", err)
			continue
		}
		return ans, nil
	}
}

func (g *guide) policy() mounts.Policy {
	return mounts.Policy{
		UID: g.e.getuid(), Home: g.home, WardenDirs: baseDirs(g.dirs),
		Socket: g.e.defaultSocket, SystemDirs: g.e.systemDirs,
	}
}

// workspace asks for the workspace and returns its resolved path. A path
// that doesn't exist is created, with git init, only on "y".
func (g *guide) workspace() (string, error) {
	def := ""
	if g.cwd != "" {
		if w, err := mounts.ValidateWorkspace(g.cwd, g.policy()); err == nil {
			def = w
		}
	}
	for {
		ans, err := g.ask("Workspace (the repository folder the agent may change)", def)
		if err != nil {
			return "", err
		}
		if ans == "" {
			g.refuse("a workspace is required: give the absolute path of a folder, such as %s", filepath.Join(g.home, "code", "project"))
			continue
		}
		if strings.HasPrefix(ans, "~/") {
			g.refuse("use an absolute path: %s", filepath.Join(g.home, ans[2:]))
			continue
		}
		if !filepath.IsAbs(ans) {
			g.refuse("use an absolute path: %s", filepath.Join(g.cwd, ans))
			continue
		}
		if _, err := os.Lstat(ans); err == nil {
			w, err := mounts.ValidateWorkspace(ans, g.policy())
			if err != nil {
				g.refuse("%s", workspaceHint(err, g.home))
				continue
			}
			return w, nil
		}
		w, err := mounts.ValidateNewWorkspace(ans, g.policy())
		if err != nil {
			g.refuse("%s", workspaceHint(err, g.home))
			continue
		}
		git, err := gitinit.Find(g.e.gitPaths)
		if err != nil {
			g.refuse("%s does not exist, and %v: install git, or create the folder yourself", w, err)
			continue
		}
		ok, err := g.yes(fmt.Sprintf("%s does not exist. Create it and run git init?", w))
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		if err := os.Mkdir(w, 0o700); err != nil {
			return "", fmt.Errorf("create %s: %w", w, err)
		}
		if err := g.e.gitInit(g.ctx, git, w, g.home); err != nil {
			return "", fmt.Errorf("created %s, but %w", w, err)
		}
		got, err := mounts.ValidateWorkspace(w, g.policy())
		if err != nil || got != w {
			return "", fmt.Errorf("created %s, but it no longer passes mount validation: %v", w, err)
		}
		g.say("  ✓ created %s (git init, branch main)", w)
		return w, nil
	}
}

// workspaceHint is a refusal plus how to pick a folder that works.
func workspaceHint(err error, home string) string {
	var me *mounts.Error
	if !errors.As(err, &me) {
		return err.Error()
	}
	example := filepath.Join(home, "code", "project")
	switch me.Rule {
	case mounts.RuleHome, mounts.RuleRoot:
		return fmt.Sprintf("%s %s: use the repository folder itself, such as %s", me.Workspace, me.Msg, example)
	case mounts.RuleWardenDir, mounts.RuleDotfile, mounts.RuleSystemDir, mounts.RuleDockerSocket:
		return fmt.Sprintf("%s %s: use a folder outside it, such as %s", me.Workspace, me.Msg, example)
	case mounts.RuleNotOwner:
		return fmt.Sprintf("%s %s: use a folder you own", me.Workspace, me.Msg)
	case mounts.RuleNotDir:
		return fmt.Sprintf("%s %s: give a folder, not a file", me.Workspace, me.Msg)
	case mounts.RuleMissing:
		return fmt.Sprintf("%s %s: create the parent folder first, or pick another place", me.Workspace, me.Msg)
	}
	return fmt.Sprintf("%s %s", me.Workspace, me.Msg)
}

// domains returns the allowlist: the built-ins, then each added entry.
func (g *guide) domains() ([]string, error) {
	allow := append([]string(nil), guidedAllow...)
	g.say("Allowed domains: %s (always included).", strings.Join(guidedAllow, ", "))
	for {
		ans, err := g.ask("Add a domain (Enter to finish)", "")
		if err != nil {
			return nil, err
		}
		if ans == "" {
			return allow, nil
		}
		if err := config.ValidateAllowEntry(ans); err != nil {
			if fixed := domainHint(ans); fixed != "" && fixed != ans && config.ValidateAllowEntry(fixed) == nil {
				g.refuse("%v: write it as %s", err, fixed)
			} else {
				g.refuse("%v: write a hostname such as github.com, or .github.com for its subdomains", err)
			}
			continue
		}
		if slices.Contains(allow, ans) {
			g.refuse("%s is already included", ans)
			continue
		}
		allow = append(allow, ans)
	}
}

// domainHint turns a URL, a wildcard or an uppercase name into the
// allowlist form the user most likely meant.
func domainHint(s string) string {
	s = strings.TrimSpace(s)
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if host, port, ok := strings.Cut(s, ":"); ok && port != "" && strings.Trim(port, "0123456789") == "" {
		s = host
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if strings.HasPrefix(s, "*.") {
		s = s[1:]
	}
	return s
}

func (g *guide) limits() (config.Resources, error) {
	var res config.Resources
	mem, err := g.askValid(fmt.Sprintf("Memory in MB (%d-%d)", config.MinMemoryMB, config.MaxMemoryMB), strconv.Itoa(guidedResources.MemoryMB), func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < config.MinMemoryMB || n > config.MaxMemoryMB {
			return fmt.Errorf("%q: give a whole number of MB between %d and %d, such as 2048", s, config.MinMemoryMB, config.MaxMemoryMB)
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	res.MemoryMB, _ = strconv.Atoi(mem)
	cpus, err := g.askValid(fmt.Sprintf("CPUs (%g-%g)", config.MinCPUs, float64(config.MaxCPUs)), strconv.FormatFloat(guidedResources.CPUs, 'f', -1, 64), func(s string) error {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || !(f >= config.MinCPUs && f <= config.MaxCPUs) {
			return fmt.Errorf("%q: give a number between %g and %g, such as 2 or 1.5", s, config.MinCPUs, float64(config.MaxCPUs))
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	res.CPUs, _ = strconv.ParseFloat(cpus, 64)
	pids, err := g.askValid(fmt.Sprintf("Process limit (%d-%d)", config.MinPIDs, config.MaxPIDs), strconv.Itoa(guidedResources.PIDs), func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < config.MinPIDs || n > config.MaxPIDs {
			return fmt.Errorf("%q: give a whole number between %d and %d, such as 1024", s, config.MinPIDs, config.MaxPIDs)
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	res.PIDs, _ = strconv.Atoi(pids)
	return res, nil
}

// runner creates the Docker runner for the image steps, on the default
// socket. If Docker can't be reached, init stops: nothing is written.
func (g *guide) runner() error {
	bin, err := docker.FindBinary(g.e.dockerPaths)
	if err != nil {
		return err
	}
	r, err := g.e.newRunner(docker.Options{
		Binary: bin, Socket: g.e.defaultSocket, Home: g.home,
		StateDir: g.dirs.State, UID: g.e.getuid(),
	})
	if err != nil {
		return err
	}
	g.r = r
	return nil
}

// local reports whether ref is a local image. Anything but "no such
// image" from Docker stops init.
func (g *guide) local(ref string) (bool, error) {
	ctx, cancel := context.WithTimeout(g.ctx, refimage.InspectTimeout)
	defer cancel()
	_, stderr, code, err := g.r.Run(ctx, []string{"image", "inspect", "--format", "{{.Id}}", ref}, nil)
	if err != nil {
		return false, fmt.Errorf("cannot reach Docker: %v; nothing written", err)
	}
	if code == 0 {
		return true, nil
	}
	if strings.Contains(strings.ToLower(string(stderr)), "no such image") {
		return false, nil
	}
	return false, fmt.Errorf("cannot reach Docker: %s; nothing written", strings.TrimSpace(string(stderr)))
}

// runtimeImage pulls the pinned runtime image on "y". Declining, or a
// failed pull, isn't fatal: the canary.image check will say what to do.
func (g *guide) runtimeImage() error {
	ref := images.RuntimeImage
	ok, err := g.local(ref)
	if err != nil {
		return err
	}
	if ok {
		g.say("  ✓ runtime image %s", ref)
		return nil
	}
	g.say("  ✗ runtime image not on this machine.")
	g.say("    docker pull %s", ref)
	pull, err := g.yes("Pull it now?")
	if err != nil || !pull {
		return err
	}
	g.say("  pulling…")
	ctx, cancel := context.WithTimeout(g.ctx, PullTimeout)
	defer cancel()
	out, stderr, code, err := g.r.Run(ctx, []string{"pull", ref}, nil)
	if err != nil || code != 0 {
		g.refuse("docker pull failed (%s)", firstNonEmpty(errString(err), "exit "+strconv.Itoa(code)))
		if t := lastLines(string(out)+string(stderr), 20); t != "" {
			g.say("%s", t)
		}
		return nil
	}
	if ok, err := g.local(ref); err != nil {
		return err
	} else if !ok {
		g.refuse("pulled, but %s is still not local", ref)
		return nil
	}
	g.say("  ✓ runtime image %s", ref)
	return nil
}

// controllerImage returns the controller image ID: one the user gives
// (local, contract-checked), or the reference image, reused or built.
func (g *guide) controllerImage() (string, error) {
	def := "build"
	rec, err := refimage.Reusable(g.ctx, g.r, g.dirs.State, g.e.goarch)
	if rec != nil {
		def = rec.ImageID
	} else if err != nil {
		g.say("  (the last reference build can't be reused: %v)", err)
	}
	for {
		ans, err := g.ask(`Controller image ID, or "build"`, def)
		if err != nil {
			return "", err
		}
		if ans == "build" {
			id, err := g.build()
			if err != nil {
				return "", err
			}
			if id != "" {
				return id, nil
			}
			continue
		}
		if err := config.ValidateImage(ans); err != nil {
			g.refuse(`%v; or type "build" for Warden's reference image`, err)
			continue
		}
		id, err := refimage.Check(g.ctx, g.r, ans, g.e.goarch)
		switch {
		case errors.Is(err, refimage.ErrNotLocal):
			g.refuse(`%s is not on this machine: load it first, or type "build"`, ans)
			continue
		case err != nil:
			g.refuse("%s %v", ans, err)
			continue
		}
		g.say("  ✓ controller image %s", id)
		return id, nil
	}
}

// build builds the reference image on "y". It returns "" (and no error)
// when the user should be asked again.
func (g *guide) build() (string, error) {
	if !refimage.BuildxAvailable(g.ctx, g.r) {
		g.refuse("%s", refimage.BuildxHint)
		return "", nil
	}
	ref, err := images.Describe(images.ControllerDockerfile)
	if err != nil {
		return "", fmt.Errorf("the embedded Dockerfile: %w", err)
	}
	b, err := refimage.Prepare(g.dirs.State, g.e.getuid(), g.e.rand)
	if err != nil {
		return "", err
	}
	defer b.Remove()
	g.say("Reference image: %s.", ref)
	g.say("    docker %s", strings.Join(b.Args(), " "))
	ok, err := g.yes("Build it now?")
	if err != nil || !ok {
		return "", err
	}
	s, ok := g.r.(docker.Streamer)
	if !ok {
		return "", errors.New("the Docker runner cannot stream output")
	}
	g.say("  building… (a few minutes; output follows)")
	id, err := b.Run(g.ctx, s, g.e.stderr)
	if err != nil {
		g.refuse("%v", err)
		return "", nil
	}
	got, err := refimage.Check(g.ctx, g.r, id, g.e.goarch)
	if err != nil || got != id {
		g.refuse("the built image %s %v", id, err)
		return "", nil
	}
	if err := refimage.SaveRecord(g.dirs.State, refimage.Record{ImageID: id, DockerfileSHA256: images.DockerfileSHA256(), BuiltAt: g.e.now().UTC()}); err != nil {
		return "", err
	}
	g.say("  ✓ built %s", id)
	return id, nil
}

// review shows the config and writes exactly those bytes on "y".
func (g *guide) review(cfg config.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := config.Parse(data); err != nil { // fail closed: never write what wouldn't load
		return err
	}
	file := g.dirs.ConfigFile()
	g.say("")
	g.e.stdout.Write(data)
	ok, err := g.yes(fmt.Sprintf("Write it to %s (mode 0600)?", file))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("nothing written")
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	_, err = io.Copy(f, bytes.NewReader(data))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(file)
		return fmt.Errorf("write config: %w", err)
	}
	g.say("  ✓ wrote %s", file)
	return nil
}

func lastLines(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
