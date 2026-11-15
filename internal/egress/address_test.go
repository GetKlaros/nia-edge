package egress

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// conformanceDir is where the server's cases are: the copy kept in this
// repository, or the directory NIA_CONFORMANCE_DIR names.
func conformanceDir() string {
	if dir := os.Getenv("NIA_CONFORMANCE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "..", "conformance")
}

func TestAddressesAsTheServerReadsThem(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(conformanceDir(), "addresses.json"))
	if err != nil {
		t.Fatalf("reading the conformance cases: %v", err)
	}
	var file struct {
		Version int `json:"version"`
		Cases   []struct {
			Address string `json:"address"`
			Private bool   `json:"private"`
		} `json:"cases"`
		Hosts []struct {
			Host     string   `json:"host"`
			Patterns []string `json:"patterns"`
			Matches  bool     `json:"matches"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decoding the conformance cases: %v", err)
	}
	if file.Version != 1 || len(file.Cases) < 2000 || len(file.Hosts) < 20 {
		t.Fatalf("version %d, %d addresses, %d hosts: the file is not the one expected", file.Version, len(file.Cases), len(file.Hosts))
	}
	internal := 0
	for _, c := range file.Cases {
		// Every case is an address both engines read as one.
		if _, err := netip.ParseAddr(c.Address); err != nil {
			t.Errorf("%q is an address for the server and not here: %v", c.Address, err)
			continue
		}
		if got := IsPrivate(c.Address); got != c.Private {
			t.Errorf("IsPrivate(%q) = %v, the server says %v", c.Address, got, c.Private)
		}
		if c.Private {
			internal++
		}
	}
	if internal < 100 || internal > len(file.Cases)-100 {
		t.Errorf("%d internal addresses out of %d: the cases do not cover both answers", internal, len(file.Cases))
	}
	for _, c := range file.Hosts {
		if got := HostMatches(c.Host, c.Patterns); got != c.Matches {
			t.Errorf("HostMatches(%q, %q) = %v, the server says %v", c.Host, c.Patterns, got, c.Matches)
		}
	}
}

// Spellings the two engines do not both read as an address. Whatever is not
// an address here is refused as one, and treated as a name: it is then
// resolved, and the addresses it resolves to are the ones checked and used.
func TestWhatIsNotAnAddressIsRefusedAsOne(t *testing.T) {
	for _, text := range []string{
		"", "localhost", "example.com", "0127.0.0.1", "127.1", "2130706433", "0x7f.0.0.1", "127.0.0.1.", "1.2.3", "1.2.3.4.5", "256.1.1.1",
		"::ffff:0127.0.0.1", ":::1", "1::2::3", "[::1]", "::1]", "12345::1", "g::1", "127.0.0.1:80", " 127.0.0.1", "127.0.0.1 ",
	} {
		if !IsPrivate(text) {
			t.Errorf("IsPrivate(%q) = false", text)
		}
	}
	// An interface of this machine is never a public host.
	for _, text := range []string{"fe80::1%eth0", "2606:4700:4700::1111%eth0", "::1%lo"} {
		if !IsPrivate(text) {
			t.Errorf("IsPrivate(%q) = false", text)
		}
	}
}
