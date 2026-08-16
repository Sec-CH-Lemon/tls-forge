package main

import (
	osexec "os/exec"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"a plain path needs nothing", "/home/me/.config/tls-forge/ca.pem", "/home/me/.config/tls-forge/ca.pem"},
		{"the flags and hosts around it need nothing", "127.0.0.1:8080", "127.0.0.1:8080"},
		{"a profile name needs nothing", "chrome_151", "chrome_151"},

		// The one that started this: macOS keeps a user's config under a
		// directory with a space in its name.
		{
			"the macOS config directory",
			"/Users/me/Library/Application Support/tls-forge/ca.pem",
			"'/Users/me/Library/Application Support/tls-forge/ca.pem'",
		},

		{"a tab is a separator too", "a\tb", "'a\tb'"},
		{"a newline most of all", "a\nb", "'a\nb'"},
		{"a quote closes, escapes and reopens", "it's here", `'it'\''s here'`},
		{"a variable is not expanded", "/tmp/$HOME/ca.pem", "'/tmp/$HOME/ca.pem'"},
		{"a subshell does not run", "/tmp/`id`/ca.pem", "'/tmp/`id`/ca.pem'"},
		{"a semicolon does not end the command", "ca.pem; rm -rf /", "'ca.pem; rm -rf /'"},
		{"a glob is not expanded", "/tmp/*/ca.pem", "'/tmp/*/ca.pem'"},
		{"a tilde is not a home directory", "~/ca.pem", "'~/ca.pem'"},

		// An argument that is empty still has to arrive as an argument.
		{"nothing at all", "", "''"},

		// Conservative rather than clever: no shell metacharacter is outside
		// ASCII, but the safe set is a whitelist and this is outside it.
		{"a non-ASCII path", "/Users/игорь/ca.pem", "'/Users/игорь/ca.pem'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shellQuote(tc.in); got != tc.want {
				t.Errorf("shellQuote(%q)\n = %s\nwant %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestShellQuoteAgainstARealShell is the test that matters: the point is not
// what the function returns but that a shell hands the value back unchanged.
func TestShellQuoteAgainstARealShell(t *testing.T) {
	sh, err := osexec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to check against")
	}
	for _, value := range []string{
		"/Users/me/Library/Application Support/tls-forge/ca.pem",
		"it's here",
		"/tmp/$HOME/ca.pem",
		"/tmp/`id`/ca.pem",
		"ca.pem; echo pwned",
		"/tmp/*/ca.pem",
		"~/ca.pem",
		"",
		"plain.pem",
		`a"b`,
		`back\slash`,
	} {
		t.Run(value, func(t *testing.T) {
			// printf '%s' with one argument: whatever the shell parsed as that
			// argument comes back, and anything it parsed as a second one does
			// not — so a split shows up as a truncation.
			out, err := osexec.Command(sh, "-c", "printf '%s' "+shellQuote(value)).Output()
			if err != nil {
				t.Fatalf("sh: %v", err)
			}
			if string(out) != value {
				t.Errorf("the shell read %q as %q", value, out)
			}
		})
	}
}

// TestPrintedCommandsAreQuoted guards the reason the function exists: every
// place that prints a command has to run it through this, and a new one is easy
// to add without noticing.
func TestPrintedCommandsAreQuoted(t *testing.T) {
	awkward := "/Users/me/Library/Application Support/tls-forge/ca.pem"
	line := "  curl --proxy http://127.0.0.1:8080 --cacert " + shellQuote(awkward) + " https://tls.browserleaks.com/json"

	// The path arrives as one argument, which is what the bug was about.
	sh, err := osexec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to check against")
	}
	out, err := osexec.Command(sh, "-c", "set -- "+strings.TrimSpace(line)+`; echo $#`).Output()
	if err != nil {
		t.Fatalf("sh: %v", err)
	}
	// curl, --proxy, its value, --cacert, the path, the URL: six words.
	if got := strings.TrimSpace(string(out)); got != "6" {
		t.Errorf("the shell split the command into %s words, want 6:\n%s", got, line)
	}
}
