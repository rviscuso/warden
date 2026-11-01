// Package config loads and validates Warden's config.json.
//
// Decoding is strict: unknown fields, keys that differ from the schema only
// by case, duplicate keys and trailing data are all errors. This
// package validates format only; the workspace path is checked against the
// filesystem by internal/mounts, and the command layer runs both.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// DefaultSocket is used when docker.socket is absent.
const DefaultSocket = "/var/run/docker.sock"

// Resource bounds (docs/phase-1.md).
const (
	MinMemoryMB = 256
	MaxMemoryMB = 65536
	MinCPUs     = 0.25
	MaxCPUs     = 64
	MinPIDs     = 64
	MaxPIDs     = 32768
)

// Config is the whole of config.json. There is deliberately no field for a
// UID, privileged mode, capabilities, namespaces, devices, extra mounts,
// ports or the Docker socket as a mount.
type Config struct {
	Version      int        `json:"version"`
	Docker       Docker     `json:"docker"`
	RuntimeImage string     `json:"runtime_image"`
	Egress       Egress     `json:"egress"`
	Controller   Controller `json:"controller"`
}

// Docker locates the daemon.
type Docker struct {
	Socket string `json:"socket"`
}

// Egress is the proxy's allowlist.
type Egress struct {
	Allow []string `json:"allow"`
}

// Controller describes the agent container.
type Controller struct {
	Image             string    `json:"image"`
	Workspace         string    `json:"workspace"`
	RemoteControlName string    `json:"remote_control_name"`
	Resources         Resources `json:"resources"`
}

// Resources are the container's limits.
type Resources struct {
	MemoryMB int     `json:"memory_mb"`
	CPUs     float64 `json:"cpus"`
	PIDs     int     `json:"pids"`
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse decodes data strictly, applies defaults and validates the result.
func Parse(data []byte) (*Config, error) {
	if err := checkKeys(data, reflect.TypeFor[Config]()); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("config: unexpected data after the JSON object")
	}
	if c.Docker.Socket == "" {
		c.Docker.Socket = DefaultSocket
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks every rule and reports all violations at once.
func (c *Config) Validate() error {
	var errs []error
	add := func(field string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("config: %s: %w", field, err))
		}
	}

	if c.Version != 1 {
		add("version", fmt.Errorf("must be 1, got %d", c.Version))
	}
	if !filepath.IsAbs(c.Docker.Socket) {
		add("docker.socket", fmt.Errorf("must be an absolute path, got %q", c.Docker.Socket))
	}
	add("runtime_image", ValidateImage(c.RuntimeImage))
	add("controller.image", ValidateImage(c.Controller.Image))

	if len(c.Egress.Allow) == 0 {
		add("egress.allow", errors.New("must not be empty"))
	}
	seen := make(map[string]bool)
	for i, entry := range c.Egress.Allow {
		field := fmt.Sprintf("egress.allow[%d]", i)
		if err := ValidateAllowEntry(entry); err != nil {
			add(field, err)
			continue
		}
		if seen[entry] {
			add(field, fmt.Errorf("duplicate entry %q", entry))
		}
		seen[entry] = true
	}

	if c.Controller.Workspace == "" || !filepath.IsAbs(c.Controller.Workspace) {
		add("controller.workspace", fmt.Errorf("must be an absolute path, got %q", c.Controller.Workspace))
	}
	if !remoteControlName.MatchString(c.Controller.RemoteControlName) {
		add("controller.remote_control_name", fmt.Errorf("must match %s, got %q", remoteControlName, c.Controller.RemoteControlName))
	}

	r := c.Controller.Resources
	if r.MemoryMB < MinMemoryMB || r.MemoryMB > MaxMemoryMB {
		add("controller.resources.memory_mb", fmt.Errorf("must be between %d and %d, got %d", MinMemoryMB, MaxMemoryMB, r.MemoryMB))
	}
	if !(r.CPUs >= MinCPUs && r.CPUs <= MaxCPUs) {
		add("controller.resources.cpus", fmt.Errorf("must be between %g and %g, got %g", MinCPUs, float64(MaxCPUs), r.CPUs))
	}
	if r.PIDs < MinPIDs || r.PIDs > MaxPIDs {
		add("controller.resources.pids", fmt.Errorf("must be between %d and %d, got %d", MinPIDs, MaxPIDs, r.PIDs))
	}
	return errors.Join(errs...)
}

var remoteControlName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// Image references: a Docker repository name (optional registry host and
// port, lowercase path components) followed by @sha256:<64 hex>, or a bare
// local image ID sha256:<64 hex>. A tag is never accepted, even next to a
// digest, because it suggests a meaning the digest overrides.
var (
	imageID  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	imageRef = regexp.MustCompile(`^` +
		`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*(?::[0-9]+)?/)?` + // registry
		`[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*` + // first path component
		`(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*` + // more path components
		`@sha256:[a-f0-9]{64}$`)
)

// ValidateImage accepts name@sha256:<64 hex> or sha256:<64 hex>.
func ValidateImage(ref string) error {
	if imageID.MatchString(ref) || imageRef.MatchString(ref) {
		return nil
	}
	if strings.HasPrefix(ref, "sha256:") && !strings.Contains(ref, "@") {
		return fmt.Errorf("%q is not a valid image ID; use sha256:<64 lowercase hex>", ref)
	}
	name, _, hasDigest := strings.Cut(ref, "@")
	last := name[strings.LastIndex(name, "/")+1:]
	if strings.Contains(last, ":") {
		return fmt.Errorf("%q has a tag; pin by digest only (name@sha256:<64 hex>) or use an image ID (sha256:<64 hex>)", ref)
	}
	if !hasDigest {
		return fmt.Errorf("%q is not pinned; use name@sha256:<64 hex> or sha256:<64 hex>", ref)
	}
	return fmt.Errorf("%q is not a valid image reference; use name@sha256:<64 hex> (lowercase hex) or sha256:<64 hex>", ref)
}

// ValidateAllowEntry checks one egress allowlist entry: a lowercase
// hostname of LDH labels, at least two labels, optionally with a leading dot
// meaning "this domain and its subdomains". No trailing dot, no IP address,
// at most 253 characters (excluding the leading dot) and 63 per label.
func ValidateAllowEntry(entry string) error {
	if entry == "" {
		return errors.New("empty entry")
	}
	name, subdomains := strings.CutPrefix(entry, ".")
	if len(name) > 253 {
		return fmt.Errorf("%q is longer than 253 characters", entry)
	}
	if strings.HasSuffix(name, ".") {
		return fmt.Errorf("%q: trailing dot not allowed", entry)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("%q: IP addresses are not allowed, only hostnames", entry)
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if err := validateLabel(l); err != nil {
			return fmt.Errorf("%q: %w", entry, err)
		}
	}
	if len(labels) < 2 {
		if subdomains {
			return fmt.Errorf("%q: a leading-dot entry needs at least two labels after the dot", entry)
		}
		return fmt.Errorf("%q: a hostname needs at least two labels", entry)
	}
	// An all-numeric last label is never a real TLD and makes the name
	// parse as an IPv4 address in some resolvers ("127.1", "10.0.0.1").
	if allDigits(labels[len(labels)-1]) {
		return fmt.Errorf("%q: the last label is numeric (looks like an IP address)", entry)
	}
	return nil
}

func validateLabel(l string) error {
	if l == "" {
		return errors.New("empty label")
	}
	if len(l) > 63 {
		return fmt.Errorf("label %q is longer than 63 characters", l)
	}
	for _, r := range l {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		case r >= 'A' && r <= 'Z':
			return errors.New("must be lowercase")
		default:
			return fmt.Errorf("invalid character %q (only a-z, 0-9 and -; no schemes, paths, ports or wildcards)", r)
		}
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with a hyphen", l)
	}
	return nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
