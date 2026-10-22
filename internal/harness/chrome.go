package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/v5/internal/proctree"
)

// The seams the tests reach through: create is os.Create, which a test makes
// fail; goos and command are what Version asks by, which a test of another
// platform's way replaces.
var (
	create  = os.Create
	goos    = runtime.GOOS
	command = exec.CommandContext
)

// Chrome is the Browser at Path, run as the fixtures were measured: headless,
// in English, each example.com and example.net name the bench serves taken to
// the loopback address, and its certificate taken on trust.
type Chrome struct {
	Path string
	// Args are arguments after the bench's own, so that they win: for the
	// machine, not the measurement, as --no-sandbox on a hosted runner, where
	// Chrome's sandbox cannot start and Chrome loads no page without a word.
	Args []string
	// trusted is the key of the server whose certificate it takes as a
	// site's (trusting), or nothing.
	trusted string
	// rules are host resolver rules it is given before hostRules
	// (defaultPorts), or none.
	rules string
}

// trusting is c taking the certificate of the server whose key is spki, as
// --ignore-certificate-errors-spki-list names one, as a site's: one a public
// authority vouched for, with no error. Chrome sends a request over an HTTP/2
// connection to another name only when the certificate is one it takes so.
func (c Chrome) trusting(spki string) Browser {
	c.trusted = spki
	return c
}

// defaultPorts is c taking the names and ports portRules take to the bench's
// tls and plain ports: what the URL cases that name no port, 443, 80 or a
// port Chrome may block are measured with (urls.go).
func (c Chrome) defaultPorts(tls, plain int) Browser {
	c.rules = ""
	for _, r := range portRules {
		c.rules += fmt.Sprintf("MAP %s:%d 127.0.0.1:%d, ", r.host, r.port, benchPort(r.host, r.port, tls, plain))
	}
	return c
}

// hostRules take each example.com and example.net name the bench serves to
// the loopback address.
const hostRules = "MAP *.example.com 127.0.0.1, MAP *.example.net 127.0.0.1"

// flags are the browser's arguments for a profile in dir, taking the key
// trusted, when there is one, as a site's, and the host resolver rules rules
// before hostRules.
func flags(dir, trusted, rules string) []string {
	out := []string{
		"--headless=new",
		"--ignore-certificate-errors",
		"--host-resolver-rules=" + rules + hostRules,
		"--user-data-dir=" + dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		"--disable-default-apps",
		"--lang=en-US",
		"--accept-lang=en-US",
	}
	if trusted != "" {
		out = append(out, "--ignore-certificate-errors-spki-list="+trusted)
	}
	return out
}

// arguments are the browser's for a profile in dir: the bench's flags, then
// Args.
func (c Chrome) arguments(dir string) []string {
	return append(flags(dir, c.trusted, c.rules), c.Args...)
}

// Version is what the browser says it is, as "Google Chrome 155.0.8059.85":
// what its --version prints; but on Windows, where chrome.exe --version starts
// the browser rather than saying it, the product name and version its file
// holds, which PowerShell reads.
func (c Chrome) Version(ctx context.Context) (string, error) {
	var cmd *exec.Cmd
	if goos == "windows" {
		cmd = command(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"$v = (Get-Item -LiteralPath $env:TLSFORGE_BROWSER -ErrorAction Stop).VersionInfo; "+
				"$v.ProductName + ' ' + $v.ProductVersion")
		cmd.Env = append(os.Environ(), "TLSFORGE_BROWSER="+c.Path)
	} else {
		cmd = command(ctx, c.Path, "--version")
	}
	out, err := cmd.Output()
	said := strings.TrimSpace(string(out))
	if err == nil && said == "" {
		err = errors.New("it says none")
	}
	if err != nil {
		return "", fmt.Errorf("harness: asking %s its version: %w", c.Path, err)
	}
	return said, nil
}

// Open runs the browser at url until stop is called, or ctx is done, and
// either ends every process it started.
func (c Chrome) Open(ctx context.Context, url, dir string) (func(), error) {
	cmd := exec.CommandContext(ctx, c.Path, append(c.arguments(dir), url)...)
	proctree.Own(cmd)
	cmd.Cancel = func() error { return proctree.Kill(cmd.Process) }
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("harness: launching %s: %w", c.Path, err)
	}
	return func() {
		_ = proctree.Kill(cmd.Process)
		_ = cmd.Wait()
	}, nil
}

// DumpDOM runs the browser at url with --dump-dom in a profile made for it,
// and is what it wrote. A browser that fails, or does not end before ctx does,
// dumped nothing to go by, and the error ends with the last lines it said on
// its standard error. What it writes goes to files, not pipes: a pipe would
// keep the dump waiting on whatever it started that holds it open.
func (c Chrome) DumpDOM(ctx context.Context, url string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "tls-forge-harness-")
	if err != nil {
		return nil, fmt.Errorf("harness: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	out, err := create(filepath.Join(dir, "dump.html"))
	if err != nil {
		return nil, fmt.Errorf("harness: %w", err)
	}
	defer func() { _ = out.Close() }()
	said, err := create(filepath.Join(dir, "said.txt"))
	if err != nil {
		return nil, fmt.Errorf("harness: %w", err)
	}
	defer func() { _ = said.Close() }()
	profile := filepath.Join(dir, "profile")
	cmd := exec.CommandContext(ctx, c.Path, append(c.arguments(profile), "--dump-dom", url)...)
	proctree.Own(cmd)
	cmd.Cancel = func() error { return proctree.Kill(cmd.Process) }
	cmd.Stdout, cmd.Stderr = out, said
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("harness: launching %s: %w", c.Path, err)
	}
	err = cmd.Wait()
	// What it started may outlive it: a renderer still closing.
	_ = proctree.Kill(cmd.Process)
	if err != nil {
		return nil, fmt.Errorf("harness: %s --dump-dom %s: %w%s", c.Path, url, err, lastSaid(said.Name()))
	}
	return os.ReadFile(out.Name())
}

// saidLines is how many of the last lines a browser said on its standard error
// a failure quotes, and saidWidth how much of each, in bytes: enough for
// Chrome's reason, which it logs last, and never a whole log.
const (
	saidLines = 3
	saidWidth = 300
)

// lastSaid is the last lines of the file at path that say something, each cut
// to saidWidth bytes, as "; it said: a / b / c", or nothing when there are
// none: a file that cannot be read said nothing.
func lastSaid(path string) string {
	data, _ := os.ReadFile(path)
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > saidWidth {
				line = strings.ToValidUTF8(line[:saidWidth], "")
			}
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "; it said: " + strings.Join(lines[max(0, len(lines)-saidLines):], " / ")
}
