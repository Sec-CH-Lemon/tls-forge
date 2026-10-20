package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWhatABrowserSaidIsItsLastLinesThatSaySomething(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, said, want string
	}{
		{"nothing", "", ""},
		{"only blank lines", "\n  \n\t\n", ""},
		{"fewer lines than are quoted", "one\n\ntwo", "; it said: one / two"},
		{"more", "a\nb\nc\nd\n", "; it said: b / c / d"},
		{"a line cut inside a character", strings.Repeat("a", saidWidth-1) + "é and on",
			"; it said: " + strings.Repeat("a", saidWidth-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.WriteFile(path, []byte(tc.said), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := lastSaid(path); got != tc.want {
				t.Errorf("lastSaid: %q, want %q", got, tc.want)
			}
		})
	}
	if got := lastSaid(filepath.Join(dir, "none")); got != "" {
		t.Errorf("lastSaid of no file: %q", got)
	}
}
