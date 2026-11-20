package inventory

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseUnits(t *testing.T) {
	raw := []byte("nginx.service loaded active running A high performance web server\n" +
		"caddy.service loaded failed failed Caddy\n" +
		"systemd-fsck@dev-disk-by\\x2duuid-1.service loaded inactive dead File System Check\n" +
		"ssh.socket loaded active listening OpenBSD socket\n" +
		"<evil>.service loaded active running x\n" +
		"short.service loaded\n")
	services, truncated := ParseUnits(raw)
	if truncated || len(services) != 3 {
		t.Fatalf("got %+v %v", services, truncated)
	}
	if services[0] != (Service{Name: "nginx.service", Active: "active", Sub: "running"}) || services[1].Active != "failed" {
		t.Fatalf("got %+v", services)
	}
}

func TestEtc(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	for _, dir := range []string{"nginx/sites-available", "a/b/c/d/e"} {
		if err := os.MkdirAll(filepath.Join(etc, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(etc, name), []byte("secret content"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("nginx/nginx.conf", 0o644)
	write("shadow", 0o640)
	write("bad\nname", 0o644)
	if err := os.Symlink("/root", filepath.Join(etc, "link")); err != nil {
		t.Fatal(err)
	}
	entries, truncated := Etc(etc)
	if truncated {
		t.Fatal("truncated")
	}
	byPath := map[string]Entry{}
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	if !byPath["/etc/nginx"].Dir || byPath["/etc/nginx/nginx.conf"].Private || !byPath["/etc/shadow"].Private {
		t.Fatalf("got %+v", entries)
	}
	if _, ok := byPath["/etc/bad\nname"]; ok {
		t.Fatal("a name Nia cannot read is listed")
	}
	if entry, ok := byPath["/etc/link"]; !ok || entry.Dir || entry.Private {
		t.Fatalf("a link is listed as itself: %+v", entry)
	}
	if _, ok := byPath["/etc/a/b/c/d"]; !ok {
		t.Fatal("depth 4 is listed")
	}
	if _, ok := byPath["/etc/a/b/c/d/e"]; ok {
		t.Fatal("past depth 4 is listed")
	}
}

func TestEtcBound(t *testing.T) {
	etc := filepath.Join(t.TempDir(), "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range MaxEtc + 3 {
		if err := os.WriteFile(filepath.Join(etc, "f"+strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, truncated := Etc(etc)
	if !truncated || len(entries) != MaxEtc {
		t.Fatalf("%d %v", len(entries), truncated)
	}
}
