package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample() *State {
	return &State{
		NiaURL:       "https://nia.example",
		MachineID:    "m1",
		Key:          "nia_secret",
		Role:         "research",
		Upstream:     "openai",
		KeyExpiresAt: time.Date(2027, 2, 13, 10, 0, 0, 0, time.UTC),
		EnrolledAt:   time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
	}
}

func TestSaveThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	if _, err := Load(path); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Load before Save: %v, want ErrNotEnrolled", err)
	}
	if err := Save(path, sample()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %04o, want 0600", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *sample() {
		t.Errorf("Load = %+v, want %+v", got, sample())
	}
	// Saving again replaces the file and leaves no temporary file behind.
	next := sample()
	next.Key = "nia_other"
	if err := Save(path, next); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(path); got == nil || got.Key != "nia_other" {
		t.Errorf("second Save was not read back: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("%d files next to the state file, want 1", len(entries))
	}
}

func TestLoadRefusesAFileOthersCanRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, sample()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "readable by other users") {
			t.Errorf("mode %04o: Load error %v, want a refusal", mode, err)
		}
	}
}

func TestLoadRefusesWhatSaveDidNotWrite(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not json":      "nia_secret",
		"unknown field": `{"nia_url":"https://nia.example","machine_id":"m","key":"k","role":"r","upstream":"u","admin":true}`,
		"no key":        `{"nia_url":"https://nia.example","machine_id":"m","key":""}`,
		"empty":         ``,
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("%s: Load accepted it", name)
		}
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load accepted a directory")
	}
}
