// Package refimage builds Warden's reference controller image from the
// Dockerfile compiled into the binary, checks any controller image against
// the image contract (DESIGN.md, section 6), and keeps the record that lets
// a later init reuse a build.
//
// The build context is a fresh directory under Warden's state directory
// holding only the embedded Dockerfile: never the workspace or a path the
// user gives (DESIGN.md, section 2, "Image build context").
package refimage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rviscuso/warden/images"
	"github.com/rviscuso/warden/internal/docker"
	"github.com/rviscuso/warden/internal/paths"
	"github.com/rviscuso/warden/internal/termsafe"
)

// Timeouts.
const (
	BuildTimeout   = 20 * time.Minute
	InspectTimeout = 30 * time.Second
)

var imageID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// inspected is the part of docker image inspect the contract reads.
type inspected struct {
	ID           string `json:"Id"`
	Os           string `json:"Os"`
	Architecture string `json:"Architecture"`
	Config       struct {
		User       string   `json:"User"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		WorkingDir string   `json:"WorkingDir"`
		Env        []string `json:"Env"`
	} `json:"Config"`
}

// ErrNotLocal means docker image inspect found no such image.
var ErrNotLocal = errors.New("not on this machine")

// Check inspects ref (an image ID or name@sha256 digest) and checks it
// against the controller image contract for the host architecture goarch.
// It returns the image ID. A missing image is ErrNotLocal; a contract
// violation lists every problem.
func Check(ctx context.Context, r docker.Runner, ref, goarch string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, InspectTimeout)
	defer cancel()
	out, stderr, code, err := r.Run(ctx, []string{"image", "inspect", "--format", "{{json .}}", ref}, nil)
	if err != nil {
		return "", err
	}
	if code != 0 {
		if strings.Contains(strings.ToLower(string(stderr)), "no such image") {
			return "", ErrNotLocal
		}
		return "", fmt.Errorf("docker image inspect: exit %d: %s", code, strings.TrimSpace(string(stderr)))
	}
	var im inspected
	if err := json.Unmarshal(out, &im); err != nil {
		return "", fmt.Errorf("docker image inspect: %w", err)
	}
	if problems := contract(im, goarch); len(problems) > 0 {
		return "", fmt.Errorf("breaks the controller image contract: %s", strings.Join(problems, "; "))
	}
	return im.ID, nil
}

func contract(im inspected, goarch string) []string {
	var p []string
	if !imageID.MatchString(im.ID) {
		p = append(p, fmt.Sprintf("image ID %q is not sha256:<64 hex>", im.ID))
	}
	if im.Os != "linux" {
		p = append(p, fmt.Sprintf("Os is %q, want linux", im.Os))
	}
	if im.Architecture != goarch {
		p = append(p, fmt.Sprintf("Architecture is %q, want %s", im.Architecture, goarch))
	}
	user, _, _ := strings.Cut(im.Config.User, ":")
	switch user {
	case "":
		p = append(p, "no USER: it would run as root")
	case "0", "root":
		p = append(p, "USER is root")
	}
	if len(im.Config.Entrypoint) != 0 {
		p = append(p, "has an ENTRYPOINT: Warden sets every service's entrypoint")
	}
	if len(im.Config.Cmd) != 0 {
		p = append(p, "has a CMD: Warden sets every service's command")
	}
	if im.Config.WorkingDir != "/workspace" {
		p = append(p, fmt.Sprintf("WorkingDir is %q, want /workspace", im.Config.WorkingDir))
	}
	for _, kv := range []string{"HOME=/home/agent", "DISABLE_AUTOUPDATER=1"} {
		if !slices.Contains(im.Config.Env, kv) {
			p = append(p, "Env lacks "+kv)
		}
	}
	return p
}

// BuildxAvailable reports whether docker buildx runs. The reference
// Dockerfile needs BuildKit (ADD --checksum, ADD --chmod, TARGETARCH).
func BuildxAvailable(ctx context.Context, r docker.Runner) bool {
	ctx, cancel := context.WithTimeout(ctx, InspectTimeout)
	defer cancel()
	_, _, code, err := r.Run(ctx, []string{"buildx", "version"}, nil)
	return err == nil && code == 0
}

// BuildxHint is the one-line install hint when buildx is missing.
const BuildxHint = "docker buildx is not installed: install docker-buildx (Debian and Ubuntu's docker.io) or docker-buildx-plugin (Docker's docker-ce)"

// BuildDir is where build contexts are made, under the state directory.
func BuildDir(stateDir string) string { return filepath.Join(stateDir, "build") }

// Build is one prepared build: a fresh directory holding only the context.
type Build struct {
	dir string
}

// Prepare makes <state>/build/<random>/context/Dockerfile from the embedded
// Dockerfile (directories 0700, file 0600). rnd nil means crypto/rand.
func Prepare(stateDir string, uid int, rnd io.Reader) (*Build, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	base := BuildDir(stateDir)
	if err := os.Mkdir(base, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("build: %w", err)
	}
	if err := paths.CheckDir(base, uid); err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	var b [16]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	dir := filepath.Join(base, hex.EncodeToString(b[:]))
	if err := os.Mkdir(dir, 0o700); err != nil { // fails if it exists: always fresh
		return nil, fmt.Errorf("build: %w", err)
	}
	bd := &Build{dir: dir}
	if err := os.Mkdir(bd.Context(), 0o700); err != nil {
		bd.Remove()
		return nil, fmt.Errorf("build: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(bd.Context(), "Dockerfile"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_, err = f.Write(images.ControllerDockerfile)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		bd.Remove()
		return nil, fmt.Errorf("build: %w", err)
	}
	return bd, nil
}

// Context is the build context directory.
func (b *Build) Context() string { return filepath.Join(b.dir, "context") }

func (b *Build) iidFile() string { return filepath.Join(b.dir, "iid") }

// Args is the docker argv for the build, shown to the user before it runs.
func (b *Build) Args() []string {
	return []string{"buildx", "build", "--progress=plain", "--iidfile", b.iidFile(), b.Context()}
}

// Remove deletes the build directory.
func (b *Build) Remove() error { return os.RemoveAll(b.dir) }

// Run builds and returns the image ID. The build output streams to w as it
// arrives, through termsafe: it includes text from the build's RUN steps,
// which is untrusted (DESIGN.md, section 2).
func (b *Build) Run(ctx context.Context, r docker.Streamer, w io.Writer) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, BuildTimeout)
	defer cancel()
	safe := &termsafe.Writer{W: w}
	code, err := r.Stream(ctx, b.Args(), safe)
	safe.Flush()
	if err != nil {
		return "", fmt.Errorf("docker buildx build: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("docker buildx build: exit %d", code)
	}
	id, err := os.ReadFile(b.iidFile())
	if err != nil {
		return "", fmt.Errorf("docker buildx build: no image ID: %w", err)
	}
	s := strings.TrimSpace(string(id))
	if !imageID.MatchString(s) {
		return "", fmt.Errorf("docker buildx build: image ID %q is not sha256:<64 hex>", s)
	}
	return s, nil
}

// Record is <state>/reference-image.json: the last reference build.
type Record struct {
	ImageID          string    `json:"image_id"`
	DockerfileSHA256 string    `json:"dockerfile_sha256"`
	BuiltAt          time.Time `json:"built_at"`
}

// RecordFile is the record's path.
func RecordFile(stateDir string) string { return filepath.Join(stateDir, "reference-image.json") }

// LoadRecord reads the record; a missing file is (nil, nil).
func LoadRecord(stateDir string) (*Record, error) {
	data, err := os.ReadFile(RecordFile(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec Record
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("%s: %w", RecordFile(stateDir), err)
	}
	if !imageID.MatchString(rec.ImageID) {
		return nil, fmt.Errorf("%s: image_id %q is not sha256:<64 hex>", RecordFile(stateDir), rec.ImageID)
	}
	return &rec, nil
}

// SaveRecord writes the record atomically, mode 0600.
func SaveRecord(stateDir string, rec Record) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(stateDir, ".reference-image-*.json") // 0600
	if err != nil {
		return fmt.Errorf("write %s: %w", RecordFile(stateDir), err)
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), RecordFile(stateDir))
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", RecordFile(stateDir), err)
	}
	return nil
}

// Reusable returns the recorded build if it may be offered as
// the default: the record exists and is readable, it was built from the
// Dockerfile in this binary, and the image is still local and passes the
// contract. Otherwise nil, with the reason (nil, nil if there is no record).
func Reusable(ctx context.Context, r docker.Runner, stateDir, goarch string) (*Record, error) {
	rec, err := LoadRecord(stateDir)
	if err != nil || rec == nil {
		return nil, err
	}
	if rec.DockerfileSHA256 != images.DockerfileSHA256() {
		return nil, errors.New("the recorded build is from another Dockerfile")
	}
	id, err := Check(ctx, r, rec.ImageID, goarch)
	if err != nil {
		return nil, fmt.Errorf("the recorded build %s: %w", rec.ImageID, err)
	}
	if id != rec.ImageID {
		return nil, fmt.Errorf("the recorded build %s inspects as %s", rec.ImageID, id)
	}
	return rec, nil
}
