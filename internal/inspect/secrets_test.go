package inspect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func conformanceDir() string {
	if dir := os.Getenv("NIA_CONFORMANCE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "..", "conformance")
}

// Every text of the conformance file gives the findings and the redacted
// text the server gives.
func TestSecretsOfTheServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(conformanceDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("reading the conformance cases: %v", err)
	}
	var file struct {
		Cases []struct {
			Text     string    `json:"text"`
			Findings []Finding `json:"findings"`
			Redacted string    `json:"redacted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 140 {
		t.Fatalf("%d cases", len(file.Cases))
	}
	found := 0
	for _, c := range file.Cases {
		name := c.Text
		if len(name) > 80 {
			name = name[:80] + "…"
		}
		got := Secrets(c.Text)
		if len(got) != len(c.Findings) {
			t.Errorf("%q: %d findings, the server has %d", name, len(got), len(c.Findings))
			continue
		}
		for i, want := range c.Findings {
			found++
			g := got[i]
			if g.Category != want.Category || g.Score != want.Score || g.Start != want.Start || g.End != want.End || g.Replacement != want.Replacement {
				t.Errorf("%q: finding %d is %s [%d,%d), the server has %s [%d,%d)", name, i, g.Category, g.Start, g.End, want.Category, want.Start, want.End)
			}
		}
		if redacted := RedactSecrets(c.Text); redacted != c.Redacted {
			t.Errorf("%q:\n got %q\nwant %q", name, redacted, c.Redacted)
		}
	}
	if found < 90 {
		t.Errorf("%d findings checked", found)
	}
}

// A text made of headers that never end is read in one pass.
func TestHostileTextStaysFast(t *testing.T) {
	text := strings.Repeat("-----BEGIN PRIVATE KEY-----", 80000) + strings.Repeat("password ", 100000) + strings.Repeat("eyJ", 100000)
	start := time.Now()
	if found := Secrets(text); len(found) != 0 {
		t.Fatalf("%d findings", len(found))
	}
	if spent := time.Since(start); spent > 3*time.Second {
		t.Fatalf("%v for %d bytes", spent, len(text))
	}
}
