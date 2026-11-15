package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func conformanceDir() string {
	if dir := os.Getenv("NIA_CONFORMANCE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "..", "conformance")
}

func readCases(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(conformanceDir(), name))
	if err != nil {
		t.Fatalf("reading the conformance cases: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

// Every pattern this engine accepts answers as JavaScript does, on every
// value it accepts for that pattern.
func TestPatternsAnswerAsJavaScript(t *testing.T) {
	var file struct {
		Values []string `json:"values"`
		Cases  []struct {
			Pattern string `json:"pattern"`
			Matches string `json:"matches"`
		} `json:"cases"`
	}
	readCases(t, "regex.json", &file)
	if len(file.Cases) < 500 || len(file.Values) < 200 {
		t.Fatalf("%d patterns, %d values", len(file.Cases), len(file.Values))
	}
	patterns, answers, declined := 0, 0, 0
	for _, c := range file.Cases {
		if len(c.Matches) != len(file.Values) {
			t.Fatalf("%q: %d answers for %d values", c.Pattern, len(c.Matches), len(file.Values))
		}
		pattern, err := compileJS(c.Pattern)
		if err != nil {
			if !errors.Is(err, ErrUndecidable) {
				t.Errorf("%q: %v", c.Pattern, err)
			}
			continue
		}
		patterns++
		for i, value := range file.Values {
			got, err := pattern.test(value)
			if err != nil {
				if !errors.Is(err, ErrUndecidable) {
					t.Errorf("%q on %q: %v", c.Pattern, value, err)
				}
				declined++
				continue
			}
			answers++
			if want := c.Matches[i] == '1'; got != want {
				t.Errorf("%q on %q: %v here, %v in JavaScript (translated to %s)", c.Pattern, value, got, want, pattern.re)
			}
		}
	}
	t.Logf("%d of %d patterns read here, %d answers checked, %d declined for the value", patterns, len(file.Cases), answers, declined)
	if patterns < len(file.Cases)*8/10 {
		t.Errorf("only %d of %d patterns are read here", patterns, len(file.Cases))
	}
}

func TestWhatIsReadAndWhatIsNot(t *testing.T) {
	read := []string{
		`^\s*(sudo|rm)\b`, `^(ls|cat|git status)( |$)`, `^https://`, `\.(png|jpe?g|gif)$`, `[^a-z0-9_-]`, `^[A-Za-z0-9._-]+$`,
		`^\d{1,3}(\.\d{1,3}){3}$`, `^(?:GET|HEAD)$`, `[\w.]`, `[^\s]`, `é`, `\x41`, `a{2,3}?`, `[\b]`, `\/`, `é`, `[[]`, `a|`,
	}
	for _, source := range read {
		if _, err := compileJS(source); err != nil {
			t.Errorf("%q should be read here: %v", source, err)
		}
	}
	refused := []string{
		`(?=a)b`, `(?!a)b`, `(?<=a)b`, `(?<!a)b`, `(a)\1`, `(?<n>a)`, `\p{L}`, `\cJ`, `\e`, `\a`, `\z`, `\A`, `\Q.\E`, `\x4`, `\u004`, `\u{41}`,
		`\01`, `[]`, `[^]`, `[a-\d]`, `[\d-a]`, `[[:alpha:]]`, `a]`, `a}`, `a{`, `a{,2}`, `a{1001}`, `(?i)a`, `(?s).`, `(?m)^a`, `\ud83d`,
		"\U0001f600", "[\U0001f600]", `[\ud800-\udbff]`, `[\u0000-￿]`, "�", `�`, `^*a`, `\b+`, `a**`, `[\S]`, `a\`, `(a`, `a)`, `[a`,
	}
	for _, source := range refused {
		if _, err := compileJS(source); !errors.Is(err, ErrUndecidable) {
			t.Errorf("%q should not be read here: %v", source, err)
		}
	}
}

func TestTextOutsideTheBMP(t *testing.T) {
	plain, _ := compileJS(`curl|wget`)
	if got, err := plain.test("echo \U0001f600 curl"); err != nil || !got {
		t.Errorf("a pattern of literals decides any text: %v, %v", got, err)
	}
	for _, source := range []string{`^.$`, `[^a]`, `\S`, `\W`, `\D`, `a\B`, `[\D]`} {
		pattern, err := compileJS(source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pattern.test("a\U0001f600"); !errors.Is(err, ErrUndecidable) {
			t.Errorf("%q decided text outside the BMP: %v", source, err)
		}
		if _, err := pattern.test("a�"); err != nil {
			t.Errorf("%q: U+FFFD and a lone surrogate are one unit to both engines: %v", source, err)
		}
	}
	high, err := compileJS(`[-￿]`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := high.test("�"); !errors.Is(err, ErrUndecidable) {
		t.Errorf("a class that holds U+FFFD decided a text that may have held a surrogate: %v", err)
	}
}
