package state

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample() *State {
	return &State{
		Version:       1,
		WardenVersion: "v0.0.0-test",
		Daemon: Daemon{
			ID:            "00000000-0000-0000-0000-000000000000",
			Socket:        "/var/run/docker.sock",
			ServerVersion: "29.1.3",
			Runc:          "1.4.0",
			Containerd:    "2.2.2",
			Compose:       "2.40.3",
		},
		InitializedAt: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
	}
}

func TestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := Save(p, sample()); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *sample() {
		t.Fatalf("got %+v", got)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestSaveReplacesAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := Save(p, sample()); err != nil {
		t.Fatal(err)
	}
	s := sample()
	s.Daemon.ID = "11111111-1111-1111-1111-111111111111"
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	got, _ := Load(p)
	if got.Daemon.ID != s.Daemon.ID {
		t.Fatalf("not replaced: %+v", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestSaveRefusesInvalid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s := sample()
	s.Daemon.ID = ""
	if err := Save(p, s); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("invalid state was written")
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "state.json"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadRejects(t *testing.T) {
	good := `{"version":1,"warden_version":"x","daemon":{"id":"abc","socket":"/s","server_version":"","runc":"","containerd":"","compose":""},"initialized_at":"2026-11-01T12:00:00Z"}`
	cases := map[string]string{
		"syntax":        `{`,
		"unknown field": strings.Replace(good, `"version":1,`, `"version":1,"extra":1,`, 1),
		"trailing data": good + `{}`,
		"version":       strings.Replace(good, `"version":1`, `"version":2`, 1),
		"empty id":      strings.Replace(good, `"id":"abc"`, `"id":""`, 1),
		"relative sock": strings.Replace(good, `"socket":"/s"`, `"socket":"s"`, 1),
		"no time":       strings.Replace(good, `,"initialized_at":"2026-11-01T12:00:00Z"`, ``, 1),
	}
	for name, data := range cases {
		p := filepath.Join(t.TempDir(), "state.json")
		os.WriteFile(p, []byte(data), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	p := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(p, []byte(good), 0o600)
	if _, err := Load(p); err != nil {
		t.Fatalf("good state: %v", err)
	}
}

func sampleController() *Controller {
	at := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	return &Controller{
		AppliedCompose: "{\n  \"name\": \"warden\"\n}\n", AppliedAt: at,
		ProxyID: strings.Repeat("a", 64), ControllerID: strings.Repeat("b", 64),
		RemoteControlURL: "https://claude.ai/code/session_x", URLFoundAt: &at,
	}
}

// TestControllerRoundTrip: the applied bytes come back exactly.
func TestControllerRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s := sample()
	s.Controller = sampleController()
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Controller.AppliedCompose != s.Controller.AppliedCompose || got.Controller.ControllerID != s.Controller.ControllerID ||
		!got.Controller.URLFoundAt.Equal(*s.Controller.URLFoundAt) || !got.Controller.Running() {
		t.Fatalf("got %+v", got.Controller)
	}
}

func TestControllerRejects(t *testing.T) {
	cases := map[string]func(c *Controller){
		"no compose":     func(c *Controller) { c.AppliedCompose = "" },
		"no time":        func(c *Controller) { c.AppliedAt = time.Time{} },
		"one id":         func(c *Controller) { c.ProxyID = "" },
		"short id":       func(c *Controller) { c.ProxyID = "abc" },
		"upper id":       func(c *Controller) { c.ControllerID = strings.Repeat("B", 64) },
		"other url":      func(c *Controller) { c.RemoteControlURL = "https://example.com/code/x" },
		"url no time":    func(c *Controller) { c.URLFoundAt = nil },
		"time no url":    func(c *Controller) { c.RemoteControlURL = "" },
		"url with space": func(c *Controller) { c.RemoteControlURL = "https://claude.ai/code/a b" },
	}
	for name, fn := range cases {
		s := sample()
		s.Controller = sampleController()
		fn(s.Controller)
		if err := Save(filepath.Join(t.TempDir(), "state.json"), s); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
	// Down clears both IDs: still valid, not running.
	c := sampleController()
	c.ProxyID, c.ControllerID = "", ""
	if err := c.Validate(); err != nil || c.Running() {
		t.Fatalf("after down: %v %v", err, c.Running())
	}
	var none *Controller
	if none.Running() {
		t.Fatal("nil controller running")
	}
}
