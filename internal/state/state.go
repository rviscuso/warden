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
	"time"
)

// State is the whole of state.json.
type State struct {
	Version       int       `json:"version"`
	WardenVersion string    `json:"warden_version"`
	Daemon        Daemon    `json:"daemon"`
	InitializedAt time.Time `json:"initialized_at"`
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
