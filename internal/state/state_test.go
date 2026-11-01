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
