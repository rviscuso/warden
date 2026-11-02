// Package compose is the typed compose file Warden hands to Docker.
// Render is the only producer of compose JSON: it marshals the typed file
// and runs Validate on the exact bytes, which checks them against an
// allowlist of keys and the hardened values from internal/hardening.
// See docs/phase-1.md, "Hardening".
package compose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/rviscuso/warden/internal/config"
	"github.com/rviscuso/warden/internal/hardening"
	"github.com/rviscuso/warden/internal/mounts"
)

// File is one compose project.
type File struct {
	Name     string             `json:"name"`
	Services map[string]Service `json:"services"`
	Networks map[string]Network `json:"networks"`
}

// Service is one container. Its security settings come only from the
// embedded hardening.Fields.
type Service struct {
	hardening.Fields
	ContainerName string            `json:"container_name"`
	Image         string            `json:"image"`
	Entrypoint    []string          `json:"entrypoint"`
	Command       []string          `json:"command"`
	Environment   map[string]string `json:"environment,omitempty"`
	Networks      []string          `json:"networks"`
	Volumes       []Bind            `json:"volumes,omitempty"`
	DependsOn     []string          `json:"depends_on,omitempty"`
}

// Bind is a bind mount. Make one with BindMount.
type Bind struct {
	Type     string   `json:"type"`
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	ReadOnly bool     `json:"read_only"`
	Bind     BindOpts `json:"bind"`
}

// BindOpts: Docker must never create a missing source (it would, as root).
type BindOpts struct {
	CreateHostPath bool `json:"create_host_path"`
}

// BindMount returns a bind mount of source at target.
func BindMount(source, target string, readOnly bool) Bind {
	return Bind{Type: "bind", Source: source, Target: target, ReadOnly: readOnly}
}

// Network is a project network. Internal networks have no route out.
type Network struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal,omitempty"`
}

// Policy is what Validate checks the file against.
type Policy struct {
	UID, GID int
	Socket   string // the configured Docker socket
}

// DefaultSockets are refused as mount sources on every host, besides the
// configured one.
var DefaultSockets = []string{"/var/run/docker.sock", "/run/docker.sock"}

// Render marshals f and validates the result. It is the only way Warden
// produces compose JSON.
func Render(f File, p Policy) ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if err := Validate(b, p); err != nil {
		return nil, err
	}
	return b, nil
}

// Validate checks rendered compose JSON. It works on the bytes, not the
// types, so it holds whatever produced them.
func Validate(b []byte, p Policy) error {
	if p.UID <= 0 || p.GID <= 0 {
		return fmt.Errorf("compose: policy uid %d gid %d: never root", p.UID, p.GID)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var top map[string]any
	if err := dec.Decode(&top); err != nil {
		return fmt.Errorf("compose: %w", err)
	}
	if dec.More() {
		return errors.New("compose: trailing data")
	}
	if err := onlyKeys("file", top, []string{"name", "services", "networks"}, []string{"name", "services", "networks"}); err != nil {
		return err
	}
	if s, ok := top["name"].(string); !ok || s == "" {
		return errors.New("compose: name must be a non-empty string")
	}
	nets, ok := top["networks"].(map[string]any)
	if !ok {
		return errors.New("compose: networks must be an object")
	}
	for k, v := range nets {
		if err := validateNetwork(k, v); err != nil {
			return err
		}
	}
	svcs, ok := top["services"].(map[string]any)
	if !ok || len(svcs) == 0 {
		return errors.New("compose: services must be a non-empty object")
	}
	for _, name := range sortedKeys(svcs) {
		m, ok := svcs[name].(map[string]any)
		if !ok {
			return fmt.Errorf("compose: service %s is not an object", name)
		}
		if err := validateService(m, nets, svcs, p); err != nil {
			return fmt.Errorf("compose: service %s: %w", name, err)
		}
	}
	return nil
}

func validateNetwork(key string, v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("compose: network %s is not an object", key)
	}
	if err := onlyKeys("network "+key, m, []string{"name", "internal"}, []string{"name"}); err != nil {
		return err
	}
	if s, ok := m["name"].(string); !ok || s == "" {
		return fmt.Errorf("compose: network %s: name must be a non-empty string", key)
	}
	if v, ok := m["internal"]; ok {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("compose: network %s: internal must be a boolean", key)
		}
	}
	return nil
}

var (
	requiredKeys = []string{
		"user", "cap_drop", "security_opt", "read_only", "tmpfs", "mem_limit", "memswap_limit", "cpus",
		"pids_limit", "init", "ipc", "cgroup", "sysctls", "restart", "pull_policy",
		"container_name", "image", "entrypoint", "command", "networks",
	}
	allowedKeys = append(append([]string(nil), requiredKeys...), "environment", "volumes", "depends_on")
)

func validateService(m map[string]any, nets, svcs map[string]any, p Policy) error {
	if err := onlyKeys("service", m, allowedKeys, requiredKeys); err != nil {
		return err
	}
	// The hardened values, exactly.
	if u := m["user"]; u != fmt.Sprintf("%d:%d", p.UID, p.GID) {
		return fmt.Errorf("user %v: must be %d:%d, never root or empty", u, p.UID, p.GID)
	}
	for key, want := range map[string][]string{
		"cap_drop":     {"ALL"},
		"security_opt": {"no-new-privileges:true"},
		"tmpfs":        {hardening.Tmpfs},
	} {
		got, err := stringList(m[key])
		if err != nil || len(got) != len(want) || got[0] != want[0] {
			return fmt.Errorf("%s %v: must be exactly %q", key, m[key], want)
		}
	}
	for key, want := range map[string]any{
		"read_only": true, "init": true, "ipc": "private", "cgroup": "private", "restart": "no", "pull_policy": "never",
	} {
		if m[key] != want {
			return fmt.Errorf("%s %v: must be %v", key, m[key], want)
		}
	}
	if err := exactSysctls(m["sysctls"]); err != nil {
		return err
	}
	mem, err1 := positiveInt(m["mem_limit"])
	swap, err2 := positiveInt(m["memswap_limit"])
	_, err3 := positiveInt(m["pids_limit"])
	cpus, err4 := number(m["cpus"])
	switch {
	case err1 != nil, err2 != nil, err3 != nil:
		return errors.New("mem_limit, memswap_limit and pids_limit must be positive integers")
	case swap != mem:
		return errors.New("memswap_limit must equal mem_limit: no swap")
	case err4 != nil || !(cpus > 0):
		return errors.New("cpus must be positive")
	}

	if s, ok := m["container_name"].(string); !ok || s == "" {
		return errors.New("container_name must be a non-empty string")
	}
	img, _ := m["image"].(string)
	if err := config.ValidateImage(img); err != nil {
		return fmt.Errorf("image: %w", err)
	}
	for _, key := range []string{"entrypoint", "command"} {
		if _, err := stringList(m[key]); err != nil {
			return fmt.Errorf("%s must be a list of strings (exec form)", key)
		}
	}
	if ep, _ := stringList(m["entrypoint"]); len(ep) == 0 {
		return errors.New("entrypoint must be set: an image's own entrypoint never wraps Warden's command")
	}
	sn, err := stringList(m["networks"])
	if err != nil || len(sn) == 0 {
		return errors.New("networks must be a non-empty list of strings")
	}
	for _, n := range sn {
		if _, ok := nets[n]; !ok {
			return fmt.Errorf("network %q is not defined", n)
		}
	}
	if v, ok := m["depends_on"]; ok {
		deps, err := stringList(v)
		if err != nil {
			return errors.New("depends_on must be a list of strings")
		}
		for _, d := range deps {
			if _, ok := svcs[d]; !ok {
				return fmt.Errorf("depends_on %q: no such service", d)
			}
		}
	}
	if v, ok := m["environment"]; ok {
		env, ok := v.(map[string]any)
		if !ok {
			return errors.New("environment must be an object")
		}
		for k, val := range env {
			if _, ok := val.(string); !ok || k == "" {
				return fmt.Errorf("environment %q must be a string", k)
			}
		}
	}
	if v, ok := m["volumes"]; ok {
		vols, ok := v.([]any)
		if !ok {
			return errors.New("volumes must be a list")
		}
		targets := map[string]bool{}
		for _, vv := range vols {
			if err := validateBind(vv, p, targets); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateBind(v any, p Policy, targets map[string]bool) error {
	m, ok := v.(map[string]any)
	if !ok {
		return errors.New("volumes: only long-syntax bind mounts")
	}
	keys := []string{"type", "source", "target", "read_only", "bind"}
	if err := onlyKeys("volume", m, keys, keys); err != nil {
		return err
	}
	if m["type"] != "bind" {
		return fmt.Errorf("volume type %v: only bind", m["type"])
	}
	src, _ := m["source"].(string)
	dst, _ := m["target"].(string)
	for _, path := range []string{src, dst} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("volume path %q must be absolute and clean", path)
		}
	}
	if dst == "/" || targets[dst] {
		return fmt.Errorf("volume target %q: not / and not twice", dst)
	}
	targets[dst] = true
	if _, ok := m["read_only"].(bool); !ok {
		return errors.New("volume read_only must be a boolean")
	}
	b, ok := m["bind"].(map[string]any)
	if !ok || len(b) != 1 || b["create_host_path"] != false {
		return errors.New(`volume bind must be exactly {"create_host_path": false}`)
	}
	sockets := append([]string{p.Socket}, DefaultSockets...)
	for _, s := range sockets {
		if s == "" {
			continue
		}
		rel, _, _, err := mounts.Overlap(src, s)
		if err != nil {
			return fmt.Errorf("volume source %s: %w", src, err)
		}
		if rel != "" {
			return fmt.Errorf("volume source %s %s the Docker socket %s: never mounted", src, rel, s)
		}
	}
	return nil
}

// onlyKeys refuses any key not in allowed and any required key missing.
func onlyKeys(what string, m map[string]any, allowed, required []string) error {
	ok := map[string]bool{}
	for _, k := range allowed {
		ok[k] = true
	}
	for _, k := range sortedKeys(m) {
		if !ok[k] {
			return fmt.Errorf("%s: key %q is not allowed", what, k)
		}
	}
	for _, k := range required {
		if _, has := m[k]; !has {
			return fmt.Errorf("%s: key %q is required", what, k)
		}
	}
	return nil
}

func stringList(v any) ([]string, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([]string, len(l))
	for i, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, errors.New("not a string")
		}
		out[i] = s
	}
	return out, nil
}

func positiveInt(v any) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("not a number")
	}
	i, err := n.Int64()
	if err != nil || i <= 0 {
		return 0, errors.New("not a positive integer")
	}
	return i, nil
}

func number(v any) (float64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("not a number")
	}
	return n.Float64()
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// exactSysctls requires sysctls to be exactly hardening.SysctlValues(): the
// same keys, each value the same string.
func exactSysctls(v any) error {
	want := hardening.SysctlValues()
	got, ok := v.(map[string]any)
	if ok && len(got) == len(want) {
		for k, w := range want {
			if s, isStr := got[k].(string); !isStr || s != w {
				ok = false
			}
		}
	} else {
		ok = false
	}
	if !ok {
		return fmt.Errorf("sysctls %v: must be exactly %v", v, want)
	}
	return nil
}
