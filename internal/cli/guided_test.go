package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rviscuso/warden/images"
	"github.com/rviscuso/warden/internal/checks/checkstest"
	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/docker/dockertest"
	"github.com/rviscuso/warden/internal/refimage"
)

var ctrlID = "sha256:" + strings.Repeat("c1", 32)

// goodImage is docker image inspect of an image that meets the contract.
func goodImage(id string) string {
	b, _ := json.Marshal(map[string]any{
		"Id": id, "Os": "linux", "Architecture": "amd64",
		"Config": map[string]any{
			"User": "65534:65534", "WorkingDir": "/workspace",
			"Env": []string{"PATH=/usr/bin", "HOME=/home/agent", "DISABLE_AUTOUPDATER=1"},
		},
	})
	return string(b)
}

func inspectJSONArgs(ref string) []string {
	return []string{"image", "inspect", "--format", "{{json .}}", ref}
}

// guided prepares h for a guided init with these answer lines.
func (h *host) guided(lines ...string) {
	h.tty = true
	h.stdin = strings.Join(lines, "\n") + "\n"
	h.fake.On(inspectJSONArgs(ctrlID), dockertest.Response{Stdout: goodImage(ctrlID)})
}

func (h *host) readConfig() *config.Config {
	h.t.Helper()
	file := filepath.Join(h.configDir(), "config.json")
	fi, err := os.Stat(file)
	if err != nil {
		h.t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		h.t.Errorf("config mode %v", fi.Mode())
	}
	c, err := config.Load(file)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

func (h *host) noConfig() {
	h.t.Helper()
	if _, err := os.Stat(filepath.Join(h.configDir(), "config.json")); !os.IsNotExist(err) {
		h.t.Fatalf("a config was written: %v", err)
	}
}

// The happy path, with a refusal at each prompt that has a rule.
func TestGuidedInit(t *testing.T) {
	h := newHost(t)
	h.guided(
		"code/repo", // relative
		h.home,      // the home directory
		h.ws,
		"https://github.com/rviscuso/warden", // a URL
		"*.githubusercontent.com",            // a wildcard
		"github.com",
		"api.anthropic.com", // a built-in
		".githubusercontent.com",
		"",
		"100", "", // memory
		"lots", "", // cpus
		"", // pids
		"bad name!", "",
		"busybox:latest", // a tag
		ctrlID,
		"y",
	)
	r := h.run("init")
	t.Logf("stderr:\n%s\nstdout:\n%s", r.stderr, r.stdout)
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	for _, want := range []string{
		"✗ use an absolute path: " + filepath.Join(h.cwd, "code/repo"),
		"is the home directory or an ancestor of it",
		"write it as github.com",
		"write it as .githubusercontent.com",
		"✗ api.anthropic.com is already included",
		`✗ "100": give a whole number of MB between 256 and 65536`,
		`✗ "lots": give a number between 0.25 and 64`,
		`✗ "bad name!": use 1 to 64 letters`,
		`has a tag; pin by digest only`,
		"✓ runtime image " + images.RuntimeImage,
		"✓ controller image " + ctrlID,
		"Write it to " + filepath.Join(h.configDir(), "config.json") + " (mode 0600)? [y/N] ",
		"Memory in MB (256-65536) [1536]: ",
		"Remote Control name [warden]: ",
		`Controller image ID, or "build" [build]: `,
	} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q", want)
		}
	}
	c := h.readConfig()
	if c.Controller.Workspace != h.ws || c.Controller.Image != ctrlID || c.Docker.Socket != h.sock ||
		c.Controller.RemoteControlName != "warden" || c.Controller.Resources != (config.Resources{MemoryMB: 1536, CPUs: 1.5, PIDs: 512}) ||
		strings.Join(c.Egress.Allow, ",") != "api.anthropic.com,platform.claude.com,github.com,.githubusercontent.com" {
		t.Errorf("config %+v", c)
	}
	// The shown config is exactly the written file.
	data, _ := os.ReadFile(filepath.Join(h.configDir(), "config.json"))
	if !strings.HasPrefix(r.stdout, string(data)) {
		t.Errorf("stdout doesn't start with the written config")
	}
	if !strings.Contains(r.stdout, "All checks passed. Pinned daemon "+zeroID) || !strings.Contains(r.stdout, "Next: warden up") {
		t.Error("no summary")
	}
	if len(h.gits) != 0 {
		t.Errorf("git ran: %v", h.gits)
	}
	if h.fake.Called([]string{"pull", images.RuntimeImage}) {
		t.Error("pulled a local image")
	}
}

func TestGuidedDefaultWorkspaceIsCwd(t *testing.T) {
	h := newHost(t)
	h.cwd = h.ws
	h.guided("", "", "", "", "", "", ctrlID, "y")
	r := h.run("init")
	if r.code != 0 || !strings.Contains(r.stderr, "["+h.ws+"]") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	// A cwd that fails mount validation is no default.
	h2 := newHost(t)
	h2.cwd = h2.home
	h2.guided("", h2.ws, "", "", "", "", "", ctrlID, "y")
	r = h2.run("init")
	if r.code != 0 || strings.Contains(r.stderr, "["+h2.home+"]") || !strings.Contains(r.stderr, "a workspace is required") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
}

func TestGuidedCreatesWorkspace(t *testing.T) {
	h := newHost(t)
	nw := filepath.Join(h.root, "new-repo")
	h.guided(nw, "n", nw, "y", "", "", "", "", "", ctrlID, "y")
	r := h.run("init")
	t.Log(r.stderr)
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	if strings.Count(r.stderr, nw+" does not exist. Create it and run git init? [y/N] ") != 2 {
		t.Error("didn't ask twice")
	}
	if len(h.gits) != 1 || h.gits[0] != nw {
		t.Fatalf("git init calls %v", h.gits)
	}
	if fi, err := os.Stat(nw); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", fi, err)
	}
	if h.readConfig().Controller.Workspace != nw {
		t.Error("workspace not the created folder")
	}
}

// A would-be workspace in a forbidden place is refused before anything is
// created, and git never runs.
func TestGuidedNewWorkspaceRefused(t *testing.T) {
	h := newHost(t)
	os.MkdirAll(filepath.Join(h.home, ".ssh"), 0o700)
	h.guided(filepath.Join(h.home, ".ssh", "repo"), filepath.Join(h.root, "nope", "repo"), h.ws, "", "", "", "", "", ctrlID, "y")
	r := h.run("init")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "use a folder outside it") || !strings.Contains(r.stderr, "create the parent folder first") {
		t.Fatalf("\n%s", r.stderr)
	}
	if len(h.gits) != 0 {
		t.Fatal("git ran")
	}
	if _, err := os.Stat(filepath.Join(h.home, ".ssh", "repo")); !os.IsNotExist(err) {
		t.Fatal("created a folder in .ssh")
	}
}

func TestGuidedNoGit(t *testing.T) {
	h := newHost(t)
	os.Remove(filepath.Join(h.root, "bin/git"))
	nw := filepath.Join(h.root, "new-repo")
	h.guided(nw, h.ws, "", "", "", "", "", ctrlID, "y")
	r := h.run("init")
	if r.code != 0 || !strings.Contains(r.stderr, "install git, or create the folder yourself") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	if _, err := os.Stat(nw); !os.IsNotExist(err) {
		t.Fatal("created the folder without git")
	}
}

// EOF at any prompt stops init with nothing written.
func TestGuidedEOFAnywhere(t *testing.T) {
	answers := []string{"<workspace>", "", "", "", "", "", ctrlID, "y"}
	for n := range len(answers) {
		h := newHost(t)
		a := append([]string(nil), answers...)
		a[0] = h.ws
		h.tty = true
		h.fake.On(inspectJSONArgs(ctrlID), dockertest.Response{Stdout: goodImage(ctrlID)})
		h.stdin = strings.Join(a[:n], "\n")
		if n > 0 {
			h.stdin += "\n"
		}
		r := h.run("init")
		if r.code != 1 || !strings.Contains(r.stderr, "no input; nothing written") {
			t.Fatalf("EOF after %d answers: exit %d\n%s", n, r.code, r.stderr)
		}
		h.noConfig()
		if _, err := os.Stat(h.stateFile()); !os.IsNotExist(err) {
			t.Fatalf("EOF after %d answers: state written", n)
		}
	}
}

func TestGuidedReviewNo(t *testing.T) {
	h := newHost(t)
	h.guided(h.ws, "", "", "", "", "", ctrlID, "")
	r := h.run("init")
	if r.code != 1 || !strings.Contains(r.stderr, "nothing written") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	h.noConfig()
	if !strings.Contains(r.stdout, `"workspace": "`+h.ws+`"`) {
		t.Error("config not shown")
	}
}

// Without a terminal, or with --json, init is exactly as before: no
// prompts, no docker calls, no git.
func TestGuidedNotWithoutTerminal(t *testing.T) {
	for _, tc := range []struct {
		tty  bool
		args []string
	}{{false, []string{"init"}}, {true, []string{"init", "--json"}}} {
		h := newHost(t)
		h.tty = tc.tty
		h.stdin = h.ws + "\n"
		r := h.run(tc.args...)
		if r.code != 1 || r.stdout != exampleConfig || strings.Contains(r.stderr, "Workspace") {
			t.Fatalf("%v: exit %d\n%s", tc.args, r.code, r.stderr)
		}
		if len(h.fake.Calls) != 0 || len(h.gits) != 0 {
			t.Fatalf("%v: docker %v git %v", tc.args, h.fake.Calls, h.gits)
		}
	}
}

// An existing config is never replaced by the guided setup.
func TestGuidedNotWithConfig(t *testing.T) {
	h := newHost(t)
	h.writeConfig()
	h.tty = true
	r := h.run("init")
	if r.code != 0 || strings.Contains(r.stderr, "Workspace") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
}

func TestGuidedPullsRuntimeImage(t *testing.T) {
	h := newHost(t)
	h.guided(h.ws, "", "", "", "", "", "y", ctrlID, "y")
	h.fake.On(checkstest.ArgsImage(images.RuntimeImage), dockertest.Response{ExitCode: 1, Stderr: "Error: No such image: " + images.RuntimeImage})
	h.fake.On([]string{"pull", images.RuntimeImage}, dockertest.Response{Do: func([]byte) {
		h.fake.On(checkstest.ArgsImage(images.RuntimeImage), dockertest.Response{Stdout: "sha256:" + strings.Repeat("a", 64) + "\n"})
	}})
	r := h.run("init")
	t.Log(r.stderr)
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	for _, want := range []string{"✗ runtime image not on this machine.\n", "    docker pull " + images.RuntimeImage + "\n", "Pull it now? [y/N] ", "✓ runtime image "} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q", want)
		}
	}
}

// Declining the pull isn't fatal; the checks then fail canary.image.
func TestGuidedDeclinesPull(t *testing.T) {
	h := newHost(t)
	h.guided(h.ws, "", "", "", "", "", "n", ctrlID, "y")
	h.fake.On(checkstest.ArgsImage(images.RuntimeImage), dockertest.Response{ExitCode: 1, Stderr: "Error: No such image: " + images.RuntimeImage})
	r := h.run("init")
	if r.code != 1 || !strings.Contains(r.stdout, "✗ canary.image") || !strings.Contains(r.stdout, "fix: docker pull "+images.RuntimeImage) {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if h.fake.Called([]string{"pull", images.RuntimeImage}) {
		t.Fatal("pulled without y")
	}
	h.readConfig()
}

// Docker unreachable during the image steps: init stops, nothing written.
func TestGuidedDockerUnreachable(t *testing.T) {
	h := newHost(t)
	h.guided(h.ws, "", "", "", "", "")
	h.fake.On(checkstest.ArgsImage(images.RuntimeImage), dockertest.Response{ExitCode: 1, Stderr: "Cannot connect to the Docker daemon"})
	r := h.run("init")
	if r.code != 1 || !strings.Contains(r.stderr, "cannot reach Docker: Cannot connect to the Docker daemon; nothing written") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	h.noConfig()
}

func TestGuidedControllerImageRefusals(t *testing.T) {
	h := newHost(t)
	missing := "sha256:" + strings.Repeat("d", 64)
	rooted := "sha256:" + strings.Repeat("e", 64)
	h.guided(h.ws, "", "", "", "", "", missing, rooted, ctrlID, "y")
	h.fake.On(inspectJSONArgs(missing), dockertest.Response{ExitCode: 1, Stderr: "Error: No such image: " + missing})
	var bad map[string]any
	json.Unmarshal([]byte(goodImage(rooted)), &bad)
	bad["Config"].(map[string]any)["User"] = "root"
	b, _ := json.Marshal(bad)
	h.fake.On(inspectJSONArgs(rooted), dockertest.Response{Stdout: string(b)})
	r := h.run("init")
	if r.code != 0 || !strings.Contains(r.stderr, missing+` is not on this machine: load it first, or type "build"`) || !strings.Contains(r.stderr, "USER is root") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
}

// buildPrep scripts a successful reference build.
func (h *host) scriptBuild(id string) []string {
	dir := filepath.Join(h.stateDir(), "build", strings.Repeat("00", 16))
	args := []string{"buildx", "build", "--progress=plain", "--iidfile", filepath.Join(dir, "iid"), filepath.Join(dir, "context")}
	h.fake.On([]string{"buildx", "version"}, dockertest.Response{Stdout: "buildx v0.20.0\n"})
	h.fake.On(args, dockertest.Response{Do: func([]byte) {
		got, _ := os.ReadFile(filepath.Join(dir, "context", "Dockerfile"))
		if string(got) != string(images.ControllerDockerfile) {
			h.t.Error("context isn't the embedded Dockerfile")
		}
		os.WriteFile(filepath.Join(dir, "iid"), []byte(id), 0o600)
	}})
	h.fake.On(inspectJSONArgs(id), dockertest.Response{Stdout: goodImage(id)})
	return args
}

func TestGuidedBuildsAndReuses(t *testing.T) {
	h := newHost(t)
	built := "sha256:" + strings.Repeat("b1", 32)
	args := h.scriptBuild(built)
	h.guided(h.ws, "", "", "", "", "", "", "n", "", "y", "y")
	r := h.run("init")
	t.Log(r.stderr)
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	ref, _ := images.Describe(images.ControllerDockerfile)
	for _, want := range []string{"Reference image: " + ref.String() + ".", "    docker " + strings.Join(args, " "), "Build it now? [y/N] ", "✓ built " + built} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q", want)
		}
	}
	if strings.Count(r.stderr, "Build it now?") != 2 {
		t.Error("n didn't ask again")
	}
	if h.readConfig().Controller.Image != built {
		t.Fatal("config lacks the built image")
	}
	rec, err := refimage.LoadRecord(h.stateDir())
	if err != nil || rec == nil || rec.ImageID != built || rec.DockerfileSHA256 != images.DockerfileSHA256() || !rec.BuiltAt.Equal(h.now) {
		t.Fatalf("record %+v %v", rec, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.stateDir(), "build")); len(entries) != 0 {
		t.Fatalf("build dirs left: %v", entries)
	}

	// A second guided init offers the build as the default; Enter takes it.
	os.Remove(filepath.Join(h.configDir(), "config.json"))
	h.fake.Calls = nil
	h.guided(h.ws, "", "", "", "", "", "", "y")
	r = h.run("init")
	if r.code != 0 || !strings.Contains(r.stderr, `Controller image ID, or "build" [`+built+`]: `) {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	if h.fake.Called(args) {
		t.Fatal("rebuilt")
	}
	if h.readConfig().Controller.Image != built {
		t.Fatal("config lacks the reused image")
	}
}

func TestGuidedNoBuildx(t *testing.T) {
	h := newHost(t)
	h.fake.On([]string{"buildx", "version"}, dockertest.Response{ExitCode: 1, Stderr: "docker: 'buildx' is not a docker command."})
	h.guided(h.ws, "", "", "", "", "", "build", ctrlID, "y")
	r := h.run("init")
	if r.code != 0 || !strings.Contains(r.stderr, refimage.BuildxHint) {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
}

func TestDomainHint(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/x/y":   "github.com",
		"GitHub.com":               "github.com",
		"*.example.com":            ".example.com",
		"example.com:443":          "example.com",
		"user@example.com":         "example.com",
		"http://a.example.com/?q":  "a.example.com",
		"example.com.":             "example.com",
		"https://*.example.com:8/": ".example.com",
	} {
		if got := domainHint(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestGuidedGitFails(t *testing.T) {
	h := newHost(t)
	nw := filepath.Join(h.root, "new-repo")
	h.guided(nw, "y")
	h.envHook = func(e *env) {
		e.gitInit = func(context.Context, string, string, string) error { return errors.New("git init: boom") }
	}
	r := h.run("init")
	if r.code != 1 || !strings.Contains(r.stderr, "created "+nw+", but git init: boom") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	h.noConfig()
	if _, err := os.Stat(nw); err != nil {
		t.Fatal("the created folder was removed; Warden never removes a folder")
	}
}

// A config that appears while the questions are asked is never replaced.
func TestGuidedNeverOverwrites(t *testing.T) {
	h := newHost(t)
	h.guided(h.ws, "", "", "", "", "", ctrlID, "y")
	file := filepath.Join(h.configDir(), "config.json")
	h.fake.On(inspectJSONArgs(ctrlID), dockertest.Response{Stdout: goodImage(ctrlID), Do: func([]byte) {
		os.WriteFile(file, []byte("theirs"), 0o600)
	}})
	r := h.run("init")
	if r.code != 1 || !strings.Contains(r.stderr, "write config:") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	if got, _ := os.ReadFile(file); string(got) != "theirs" {
		t.Fatalf("config replaced: %q", got)
	}
}

// The build output reaches the terminal as it runs, without escape
// sequences; a failed build asks again.
func TestGuidedBuildStreamsAndFails(t *testing.T) {
	h := newHost(t)
	args := h.scriptBuild("unused")
	h.fake.On(args, dockertest.Response{ExitCode: 1, Stdout: "#5 [base 2/2] RUN apt-get update\n", Stderr: "\x1b]0;pwned\x07E: Unable to fetch\n"})
	h.guided(h.ws, "", "", "", "", "", "", "y", ctrlID, "y")
	r := h.run("init")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{"output follows)\n#5 [base 2/2] RUN apt-get update\n]0;pwnedE: Unable to fetch\n", "✗ docker buildx build: exit 1"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "\x1b") || strings.Contains(r.stderr, "\x07") {
		t.Error("an escape sequence reached the terminal")
	}
	if h.readConfig().Controller.Image != ctrlID {
		t.Error("didn't ask again after the failed build")
	}
}
