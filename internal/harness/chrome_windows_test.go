package harness

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestChromeOnWindowsIsAskedThroughPowerShell(t *testing.T) {
	// The real thing: cmd.exe holds Windows' product name and version, and a
	// Go test binary holds none.
	said, err := (Chrome{Path: os.Getenv("ComSpec")}).Version(context.Background())
	if err != nil || !strings.Contains(said, "Windows") || !regexp.MustCompile(` \d+\.\d+\.\d+`).MatchString(said) {
		t.Errorf("Version of cmd.exe: %q, %v", said, err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Chrome{Path: self}).Version(context.Background()); err == nil || !strings.HasSuffix(err.Error(), "it says none") {
		t.Errorf("Version of a file with none: %v", err)
	}
}
