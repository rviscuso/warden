// Package state reads and writes state.json: the daemon pin and what Warden
// recorded about the daemon when it was pinned. Warden is the only writer;
// anything unexpected in the file is an error (fail closed).
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// State is the whole of state.json.
type State struct {
	Version       int         `json:"version"`
	WardenVersion string      `json:"warden_version"`
	Daemon        Daemon      `json:"daemon"`
	InitializedAt time.Time   `json:"initialized_at"`
	Controller    *Controller `json:"controller,omitempty"`  // set by up
	CanaryPass    *CanaryPass `json:"canary_pass,omitempty"` // set by init and check; up requires it
}

// Daemon is the pinned daemon and the versions seen when it was pinned.
type Daemon struct {
	ID            string `json:"id"`
	Socket        string `json:"socket"`
	ServerVersion string `json:"server_version"`
	Runc          string `json:"runc"`
	Containerd    string `json:"containerd"`
	Compose       string `json:"compose"`
}

// CanaryPass records a canary run in which every canary check passed: on
// which daemon, with which warden binary and which hardening settings. up
// starts containers only if all three still match.
type CanaryPass struct {
	DaemonID        string    `json:"daemon_id"`
	BinarySHA256    string    `json:"binary_sha256"`
	HardeningSHA256 string    `json:"hardening_sha256"`
	At              time.Time `json:"at"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate checks the record's fields.
func (p *CanaryPass) Validate() error {
	switch {
	case p.DaemonID == "":
		return errors.New("state: canary_pass.daemon_id is empty")
	case !sha256Hex.MatchString(p.BinarySHA256) || !sha256Hex.MatchString(p.HardeningSHA256):
		return errors.New("state: canary_pass hashes must be 64 hex characters")
	case p.At.IsZero():
		return errors.New("state: canary_pass.at is missing")
	}
	return nil
}

// Controller is what up applied: the exact compose bytes, the containers
// it started (cleared by down) and the last Remote Control URL.
type Controller struct {
	AppliedCompose   string     `json:"applied_compose"`
	AppliedAt        time.Time  `json:"applied_at"`
	ProxyID          string     `json:"proxy_id,omitempty"`
	ControllerID     string     `json:"controller_id,omitempty"`
	RemoteControlURL string     `json:"remote_control_url,omitempty"`
	URLFoundAt       *time.Time `json:"url_found_at,omitempty"`
	// Incident is the evidence file of a failed post-start verification: the
	// containers were stopped and kept. up refuses until down clears it.
	Incident string `json:"incident,omitempty"`
}

var (
	containerID = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// RemoteControlURL is the URL pattern up looks for in the controller's log.
	RemoteControlURL = regexp.MustCompile(`^https://claude\.ai/code/\S+$`)
)

// Validate checks the controller record.
func (c *Controller) Validate() error {
	switch {
	case c.AppliedCompose == "":
		return errors.New("state: controller.applied_compose is empty")
	case c.AppliedAt.IsZero():
		return errors.New("state: controller.applied_at is missing")
	case (c.ProxyID == "") != (c.ControllerID == ""):
		return errors.New("state: controller: proxy_id and controller_id must be set together")
	case c.ProxyID != "" && (!containerID.MatchString(c.ProxyID) || !containerID.MatchString(c.ControllerID)):
		return errors.New("state: controller: container IDs must be 64 hex characters")
	case c.RemoteControlURL != "" && !RemoteControlURL.MatchString(c.RemoteControlURL):
		return fmt.Errorf("state: controller.remote_control_url %q is not a Remote Control URL", c.RemoteControlURL)
	case (c.RemoteControlURL == "") != (c.URLFoundAt == nil):
		return errors.New("state: controller: remote_control_url and url_found_at must be set together")
	case c.Incident != "" && !filepath.IsAbs(c.Incident):
		return fmt.Errorf("state: controller.incident %q is not an absolute path", c.Incident)
	}
	return nil
}

// Running reports whether up recorded containers that down hasn't cleared.
func (c *Controller) Running() bool { return c != nil && c.ControllerID != "" }

// Validate checks the fields the pin depends on.
func (s *State) Validate() error {
	switch {
	case s.Version != 1:
		return fmt.Errorf("state: version must be 1, got %d", s.Version)
	case s.Daemon.ID == "":
		return errors.New("state: daemon.id is empty")
	case !filepath.IsAbs(s.Daemon.Socket):
		return fmt.Errorf("state: daemon.socket %q is not an absolute path", s.Daemon.Socket)
	case s.InitializedAt.IsZero():
		return errors.New("state: initialized_at is missing")
	}
	if s.CanaryPass != nil {
		if err := s.CanaryPass.Validate(); err != nil {
			return err
		}
	}
	if s.Controller != nil {
		return s.Controller.Validate()
	}
	return nil
}

// Load reads and validates state.json. A missing file is an error matching
// fs.ErrNotExist.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("state %s: %w", path, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("state %s: unexpected data after the JSON object", path)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Save validates s and writes it atomically with mode 0600: a temp file in
// the same directory, synced, then renamed over path. A crash leaves either
// the old file or the new one, never a partial one.
func Save(path string, s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*.json") // created 0600
	if err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}
