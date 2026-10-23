// Package browser finds and launches a locally installed Chromium browser.
//
// It exists so a capture can be taken from the browser the user actually has,
// rather than from a downloaded one that might differ from it. A profile is only
// as good as the browser it was measured from, and "some Chrome" is not the same
// claim as "this Chrome".
//
// Nothing here touches the user's real browser profile. Every launch gets a
// fresh temporary user-data directory, which keeps their history, cookies and
// extensions out of it — and, just as importantly, keeps the
// ignore-certificate-errors flag this capture needs from ever being applied to a
// profile they browse with.
package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/v6/internal/proctree"
)

// Browser is a launchable browser found on this machine.
type Browser struct {
	// Name is the key it was found under, e.g. "chrome".
	Name string
	// Path is the executable.
	Path string
}

// candidates lists where each browser lives, most-preferred first. On Windows
// a browser installed for everybody is under Program Files, either of them, and
// one installed for the user alone under %LOCALAPPDATA%, which is expanded
// where the search runs.
var candidates = map[string][]string{
	"chrome": {
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/opt/google/chrome/chrome",
		"google-chrome",
		"google-chrome-stable",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		`%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe`,
	},
	"chromium": {
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/chromium",
		"chromium",
		"chromium-browser",
		`%LOCALAPPDATA%\Chromium\Application\chrome.exe`,
	},
	"edge": {
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		"/opt/microsoft/msedge/msedge",
		"microsoft-edge",
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	},
	"brave": {
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/opt/brave.com/brave/brave",
		"brave-browser",
		`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
		`C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe`,
		`%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe`,
	},
}

// Order tried when the caller does not name one.
var searchOrder = []string{"chrome", "chromium", "edge", "brave"}

// finder is the search, with its tables as data.
//
// Split out from the package-level Find so the search can be tested against a
// directory of fakes. Testing it against whatever browsers happen to be
// installed would make the result depend on the machine, which for a test is
// the same as not testing it.
type finder struct {
	candidates map[string][]string
	order      []string
}

var defaultFinder = finder{candidates: candidates, order: searchOrder}

// Find locates a browser. An empty name searches; a name containing a path
// separator is taken as an executable path and used as given.
func Find(name string) (*Browser, error) { return defaultFinder.find(name) }

func (f finder) find(name string) (*Browser, error) {
	if strings.ContainsAny(name, `/\`) {
		info, err := os.Stat(name)
		if err != nil {
			return nil, fmt.Errorf("browser: %s: %w", name, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("browser: %s is a directory, not an executable", name)
		}
		return &Browser{Name: "custom", Path: name}, nil
	}

	names := f.order
	if name != "" {
		if _, ok := f.candidates[name]; !ok {
			return nil, fmt.Errorf("browser: unknown browser %q (known: %s)",
				name, strings.Join(f.order, ", "))
		}
		names = []string{name}
	}

	for _, candidate := range names {
		for _, location := range f.candidates[candidate] {
			if path, ok := resolve(location); ok {
				return &Browser{Name: candidate, Path: path}, nil
			}
		}
	}
	return nil, fmt.Errorf("browser: no Chromium-based browser found on this %s machine; "+
		"pass an explicit path", runtime.GOOS)
}

func resolve(location string) (string, bool) {
	location, ok := expand(location)
	if !ok {
		return "", false
	}
	if strings.ContainsAny(location, `/\`) {
		if info, err := os.Stat(location); err == nil && !info.IsDir() {
			return location, true
		}
		return "", false
	}
	path, err := exec.LookPath(location)
	return path, err == nil
}

// windowsVariable is how Windows writes an environment variable into a path.
var windowsVariable = regexp.MustCompile(`%[A-Za-z_][A-Za-z0-9_]*%`)

// getenv is os.Getenv, named so a test can say what is set.
var getenv = os.Getenv

// expand is location with each %NAME% in it replaced by that environment
// variable, and false when one is not set: a path under a folder this machine
// does not name is nowhere, and left as written it would be looked for in the
// working directory.
func expand(location string) (string, bool) {
	set := true
	expanded := windowsVariable.ReplaceAllStringFunc(location, func(named string) string {
		value := getenv(strings.Trim(named, "%"))
		if value == "" {
			set = false
		}
		return value
	})
	return expanded, set
}

// Options controls a launch.
type Options struct {
	// Headless runs without a window. Chrome's modern headless mode shares the
	// network stack with headed Chrome, and the handshakes were measured
	// identical — same JA4, same HTTP/2 fingerprint, same header order. Headed is
	// still the default for capture, because "identical today" is a measurement,
	// not a guarantee, and the browser the user is impersonating is a headed one.
	Headless bool

	// Args are appended last, so a caller can override anything below.
	Args []string
}

// Open launches the browser at a URL and returns a function that closes it.
//
// The temporary profile directory is removed by the returned function. The
// context kills the browser; the caller should still call the close function to
// clean up the directory. Either ends every process the browser started, not
// only its own: a browser is many processes.
func (b *Browser) Open(ctx context.Context, url string, opts Options) (close func(), err error) {
	userDataDir, err := os.MkdirTemp("", "tls-forge-profile-")
	if err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}

	args := []string{
		// A profile of its own, which is also a browser of its own: given the
		// profile a running browser has, the launch would be handed to that
		// browser, and the flags below dropped along with it.
		"--user-data-dir=" + userDataDir,
		// The echo server's certificate is generated per run and signs nothing
		// but itself. This flag is why the throwaway profile above is not
		// optional.
		"--ignore-certificate-errors",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		// The What's New page Chrome opens after an update, in a tab of its
		// own: a page of Google's loading beside the one being measured.
		"--disable-features=ChromeWhatsNewUI",
	}
	if opts.Headless {
		args = append(args, "--headless=new", "--disable-gpu")
	}
	args = append(args, opts.Args...)
	args = append(args, url)

	cmd := exec.CommandContext(ctx, b.Path, args...)
	proctree.Own(cmd)
	cmd.Cancel = func() error { return proctree.Kill(cmd.Process) }
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(userDataDir)
		return nil, fmt.Errorf("browser: launching %s: %w", b.Path, err)
	}

	return func() {
		_ = proctree.Kill(cmd.Process)
		_ = cmd.Wait()
		// Best effort: the directory is under the system temp root, so a
		// failure here leaves the OS to reclaim it.
		_ = os.RemoveAll(userDataDir)
	}, nil
}
