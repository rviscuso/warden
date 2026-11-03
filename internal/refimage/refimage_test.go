package refimage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rviscuso/warden/images"
	"github.com/rviscuso/warden/internal/docker/dockertest"
)

var (
	goodID = "sha256:" + strings.Repeat("ab", 32)
	ctx    = context.Background()
)

func good() inspected {
	var im inspected
	im.ID, im.Os, im.Architecture = goodID, "linux", "amd64"
	im.Config.User = "65534:65534"
	im.Config.WorkingDir = "/workspace"
	im.Config.Env = []string{"PATH=/usr/bin", "HOME=/home/agent", "DISABLE_AUTOUPDATER=1"}
	return im
}

func inspectArgs(ref string) []string {
	return []string{"image", "inspect", "--format", "{{json .}}", ref}
}

func script(t *testing.T, f *dockertest.Fake, ref string, im inspected) {
	t.Helper()
	b, err := json.Marshal(im)
	if err != nil {
		t.Fatal(err)
	}
	f.On(inspectArgs(ref), dockertest.Response{Stdout: string(b) + "\n"})
}

func TestCheckPasses(t *testing.T) {
	f := dockertest.New(t)
	script(t, f, goodID, good())
	id, err := Check(ctx, f, goodID, "amd64")
	if err != nil || id != goodID {
		t.Fatalf("got %q, %v", id, err)
	}
}

func TestCheckRefuses(t *testing.T) {
	cases := map[string]struct {
		mut  func(*inspected)
		want string
	}{
		"root user":    {func(i *inspected) { i.Config.User = "root" }, "USER is root"},
		"uid 0":        {func(i *inspected) { i.Config.User = "0:1000" }, "USER is root"},
		"no user":      {func(i *inspected) { i.Config.User = "" }, "no USER"},
		"entrypoint":   {func(i *inspected) { i.Config.Entrypoint = []string{"/bin/sh"} }, "ENTRYPOINT"},
		"cmd":          {func(i *inspected) { i.Config.Cmd = []string{"bash"} }, "CMD"},
		"workdir":      {func(i *inspected) { i.Config.WorkingDir = "/" }, "WorkingDir"},
		"home":         {func(i *inspected) { i.Config.Env = []string{"HOME=/root", "DISABLE_AUTOUPDATER=1"} }, "HOME=/home/agent"},
		"autoupdater":  {func(i *inspected) { i.Config.Env = []string{"HOME=/home/agent"} }, "DISABLE_AUTOUPDATER=1"},
		"arch":         {func(i *inspected) { i.Architecture = "arm64" }, "Architecture"},
		"os":           {func(i *inspected) { i.Os = "windows" }, "Os"},
		"bad id":       {func(i *inspected) { i.ID = "sha256:xyz" }, "image ID"},
		"autoupd zero": {func(i *inspected) { i.Config.Env = []string{"HOME=/home/agent", "DISABLE_AUTOUPDATER=0"} }, "DISABLE_AUTOUPDATER=1"},
	}
	for name, c := range cases {
		f := dockertest.New(t)
		im := good()
		c.mut(&im)
		script(t, f, goodID, im)
		_, err := Check(ctx, f, goodID, "amd64")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

func TestCheckNotLocal(t *testing.T) {
	f := dockertest.New(t)
	f.On(inspectArgs(goodID), dockertest.Response{ExitCode: 1, Stderr: "Error: No such image: " + goodID})
	if _, err := Check(ctx, f, goodID, "amd64"); !errors.Is(err, ErrNotLocal) {
		t.Fatalf("got %v", err)
	}
	f.On(inspectArgs(goodID), dockertest.Response{ExitCode: 1, Stderr: "permission denied"})
	if _, err := Check(ctx, f, goodID, "amd64"); err == nil || errors.Is(err, ErrNotLocal) {
		t.Fatalf("got %v", err)
	}
}

func stateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// The context holds the embedded Dockerfile and nothing else, and is
// removed afterwards.
func TestBuild(t *testing.T) {
	st := stateDir(t)
	b, err := Prepare(st, os.Getuid(), bytes.NewReader(bytes.Repeat([]byte{7}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	f := dockertest.New(t)
	args := b.Args()
	want := []string{"buildx", "build", "--progress=plain", "--iidfile", filepath.Join(st, "build", strings.Repeat("07", 16), "iid"), filepath.Join(st, "build", strings.Repeat("07", 16), "context")}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args %v", args)
	}
	f.On(args, dockertest.Response{Do: func([]byte) {
		entries, _ := os.ReadDir(b.Context())
		if len(entries) != 1 || entries[0].Name() != "Dockerfile" {
			t.Errorf("context holds %v", entries)
		}
		got, _ := os.ReadFile(filepath.Join(b.Context(), "Dockerfile"))
		if !bytes.Equal(got, images.ControllerDockerfile) {
			t.Error("context Dockerfile isn't the embedded one")
		}
		for _, d := range []string{filepath.Join(st, "build"), b.dir, b.Context()} {
			if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
				t.Errorf("%s: %v %v", d, fi.Mode(), err)
			}
		}
		os.WriteFile(b.iidFile(), []byte(goodID), 0o600)
	}})
	id, err := b.Run(ctx, f, 20)
	if err != nil || id != goodID {
		t.Fatalf("got %q, %v", id, err)
	}
	if err := b.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.dir); !os.IsNotExist(err) {
		t.Fatal("build dir left")
	}
}

func TestBuildFailureTail(t *testing.T) {
	st := stateDir(t)
	b, err := Prepare(st, os.Getuid(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Remove()
	var out strings.Builder
	for i := range 30 {
		out.WriteString("line " + string(rune('a'+i%26)) + "\n")
	}
	f := dockertest.New(t)
	f.On(b.Args(), dockertest.Response{ExitCode: 1, Stderr: out.String()})
	_, err = b.Run(ctx, f, 20)
	if err == nil || strings.Count(err.Error(), "\n") != 20 || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("got %v", err)
	}
	// A build that "succeeds" without an ID file, or with a bad one, fails.
	f.On(b.Args(), dockertest.Response{})
	if _, err := b.Run(ctx, f, 20); err == nil {
		t.Fatal("no iid accepted")
	}
	os.WriteFile(b.iidFile(), []byte("latest"), 0o600)
	if _, err := b.Run(ctx, f, 20); err == nil {
		t.Fatal("bad iid accepted")
	}
}

func TestPrepareAlwaysFresh(t *testing.T) {
	st := stateDir(t)
	seed := bytes.Repeat([]byte{1}, 32)
	b, err := Prepare(st, os.Getuid(), bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Remove()
	if _, err := Prepare(st, os.Getuid(), bytes.NewReader(seed)); err == nil {
		t.Fatal("reused an existing build directory")
	}
	os.Chmod(filepath.Join(st, "build"), 0o755)
	if _, err := Prepare(st, os.Getuid(), nil); err == nil {
		t.Fatal("accepted a 0755 build directory")
	}
}

func TestBuildx(t *testing.T) {
	f := dockertest.New(t)
	f.On([]string{"buildx", "version"}, dockertest.Response{ExitCode: 1})
	if BuildxAvailable(ctx, f) {
		t.Fatal("missing buildx reported available")
	}
	f.On([]string{"buildx", "version"}, dockertest.Response{Stdout: "github.com/docker/buildx v0.20.0\n"})
	if !BuildxAvailable(ctx, f) {
		t.Fatal("buildx not found")
	}
}

func TestReusable(t *testing.T) {
	st := stateDir(t)
	f := dockertest.New(t)
	if rec, err := Reusable(ctx, f, st, "amd64"); rec != nil || err != nil {
		t.Fatalf("no record: %v %v", rec, err)
	}
	rec := Record{ImageID: goodID, DockerfileSHA256: images.DockerfileSHA256(), BuiltAt: time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)}
	if err := SaveRecord(st, rec); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(RecordFile(st)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v %v", fi, err)
	}
	script(t, f, goodID, good())
	got, err := Reusable(ctx, f, st, "amd64")
	if err != nil || got == nil || *got != rec {
		t.Fatalf("got %v, %v", got, err)
	}

	// Another Dockerfile: not reusable.
	other := rec
	other.DockerfileSHA256 = strings.Repeat("0", 64)
	SaveRecord(st, other)
	if got, err := Reusable(ctx, f, st, "amd64"); got != nil || err == nil {
		t.Fatalf("other Dockerfile: %v %v", got, err)
	}
	// Gone, or breaking the contract: not reusable.
	SaveRecord(st, rec)
	f.On(inspectArgs(goodID), dockertest.Response{ExitCode: 1, Stderr: "No such image"})
	if got, _ := Reusable(ctx, f, st, "amd64"); got != nil {
		t.Fatal("missing image reusable")
	}
	bad := good()
	bad.Config.User = "root"
	script(t, f, goodID, bad)
	if got, _ := Reusable(ctx, f, st, "amd64"); got != nil {
		t.Fatal("root image reusable")
	}
	// A record that names another image than inspect returns.
	moved := good()
	moved.ID = "sha256:" + strings.Repeat("cd", 32)
	script(t, f, goodID, moved)
	if got, _ := Reusable(ctx, f, st, "amd64"); got != nil {
		t.Fatal("mismatched ID reusable")
	}
	// A corrupt record is an error, not a default.
	os.WriteFile(RecordFile(st), []byte(`{"image_id":"latest"}`), 0o600)
	if got, err := Reusable(ctx, f, st, "amd64"); got != nil || err == nil {
		t.Fatalf("corrupt record: %v %v", got, err)
	}
	os.WriteFile(RecordFile(st), []byte(`{"image_id":"`+goodID+`","extra":1}`), 0o600)
	if _, err := LoadRecord(st); err == nil {
		t.Fatal("unknown field accepted")
	}
}
