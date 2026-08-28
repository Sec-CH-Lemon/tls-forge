package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/internal/atomicfile"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func runCapture(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("capture", out)
	browserName := fs.StringP("browser", "b", "",
		"browser to measure: chrome, chromium, edge, brave, or a path")
	headless := fs.Bool("headless", false, "run the browser without a window")
	save := fs.StringP("save", "s", "",
		"write a reusable profile here; a directory gets <name>/<platform>.json")
	install := fs.Bool("install", false,
		"keep the profile in this machine's own directory, where --profile finds it by name")
	name := fs.StringP("name", "n", "", "profile name (default: derived from the browser's version)")
	asJSON := fs.BoolP("json", "j", false, "print the raw capture instead of a summary")
	timeout := fs.DurationP("timeout", "t", 2*time.Minute, "how long to wait for the browser")
	browserArgs := browserArgFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}

	// To stderr: --json makes standard output a document, and a line of
	// commentary in front of it is a document that will not parse.
	errOut.println("opening a browser… (it will show the result; you can close it)")
	measured, err := tlsforge.MeasureBrowser(ctx, tlsforge.MeasureOptions{
		Browser:     *browserName,
		Headless:    *headless,
		Timeout:     *timeout,
		BrowserArgs: *browserArgs,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		return printJSON(out, measured)
	}
	printCapture(out, measured)

	where := *save
	if *install {
		where = profile.DefaultDir()
		if where == "" {
			return fmt.Errorf("capture: nowhere to keep profiles; set TLSFORGE_PROFILES")
		}
		if err := os.MkdirAll(where, 0o755); err != nil {
			return fmt.Errorf("capture: %w", err)
		}
	}

	if where == "" {
		out.println("\nRe-run with --install to keep this profile, or --save <path> to write it out.")
		return nil
	}

	// --install means "the browser on this machine", and that is one thing
	// rather than one per version: measuring again after Chrome updates should
	// replace it, not leave two. --save is the other case — a profile going
	// somewhere to be kept or shipped — and that one is named for the browser.
	profileName := *name
	if profileName == "" {
		profileName = profileNameFor(measured.UserAgent())
		if *install {
			profileName = localName
		}
	}
	saved, path, err := saveProfile(where, profileName, measured)
	if err != nil {
		return err
	}
	out.printf("\nwrote profile %q to %s\n", saved, path)
	if *install {
		out.printf("use it with:  tls-forge fetch --profile %s <url>\n", shellQuote(saved))
	}
	return nil
}

// browserArgFlag registers --browser-arg on the two commands that drive a
// browser.
//
// Long-only and repeatable, like the other flags that get written once in a
// script and never typed: a letter for this would be a letter nobody remembers.
//
// It exists for the machine, not for the measurement. A CI runner needs
// `--no-sandbox` — Ubuntu 24.04 restricts the unprivileged user namespaces
// Chrome's sandbox is built on, and a Windows runner denies the sandbox access
// to the executable in its own tool cache — and without it Chrome starts, never
// loads the page, and the capture times out having watched a browser that was
// never going to answer.
func browserArgFlag(fs *pflag.FlagSet) *[]string {
	return fs.StringArray("browser-arg", nil,
		"extra flag for the browser, repeatable; for the machine, not the measurement")
}

// saveProfile turns a measurement into a profile and returns the name it was
// filed under and the file it went to.
//
// Given a directory, the file is named after the profile, which is also the name
// --profile will find it by. Naming a captured Chrome 151 anything other than
// chrome_151 is how a machine ends up with a profile nobody can guess the name
// of.
func saveProfile(where, name string, measured *capture.Capture) (profileName, path string, err error) {
	built, err := profile.FromCapture(name, measured)
	if err != nil {
		return "", "", err
	}
	built.Notes = fmt.Sprintf("captured %s from %s", now().UTC().Format(time.RFC3339), built.UserAgent)

	path = where
	if info, err := os.Stat(where); err == nil && info.IsDir() {
		// A directory per version holding one file per platform, so a machine
		// that measures Chrome 151 on two of them has one profile with two
		// spellings rather than two profiles.
		version, platform := profile.Split(built.Name)
		if platform == "" {
			platform = profile.HostPlatform()
		}
		if err := os.MkdirAll(filepath.Join(where, version), 0o755); err != nil {
			return "", "", err
		}
		built.Name = version + "_" + platform
		path = filepath.Join(where, version, platform+".json")
	}

	data, err := built.Save()
	if err == nil {
		err = atomicfile.Write(path, data, 0o644)
	}
	if err != nil {
		return "", "", err
	}
	return built.Name, path, nil
}

// mark is the star against a profile kept on this machine.
func mark(local bool) string {
	if local {
		return "*"
	}
	return " "
}

// line is one row of the listing, with no trailing space on the rows that carry
// no arrow.
func line(mark, name string, fallback bool) string {
	row := mark + " " + name
	if fallback {
		row += strings.Repeat(" ", max(1, 30-len(row))) + "<"
	}
	return row
}

// now is time.Now, named so a test can produce a byte-identical profile.
var now = time.Now

// profileNameFor derives a stable name from a user-agent, e.g. "chrome_151".
//
// The name matters more than it looks: a profile called "chrome" that was
// measured from Chrome 151 reads as current forever, and the mismatch between
// the name and the handshake is invisible in every log it appears in.
func profileNameFor(userAgent string) string {
	family, major := browserFrom(userAgent)
	switch {
	case family == "":
		return "captured"
	case major == "":
		return family
	}
	return family + "_" + major
}

// browserFrom reads the browser and its major version out of a user-agent,
// returning empty strings for one it does not know.
//
// Order matters. Every Chromium-based browser puts "Chrome/" in its user-agent,
// so the ones that add their own token have to be checked first or they all
// come out as chrome.
func browserFrom(userAgent string) (family, major string) {
	for _, known := range []struct{ token, name string }{
		{"Edg/", "edge"},
		{"OPR/", "opera"},
		{"Chrome/", "chrome"},
		{"Firefox/", "firefox"},
		{"Version/", "safari"},
	} {
		index := strings.Index(userAgent, known.token)
		if index < 0 {
			continue
		}
		major, _, _ = strings.Cut(userAgent[index+len(known.token):], ".")
		return known.name, major
	}
	return "", ""
}

func runServe(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("serve", out)
	addr := fs.StringP("addr", "a", "127.0.0.1:0", "listen address")
	host := fs.String("host", "localhost", "hostname used in the URL and certificate")
	// Long-only, like the other flags that are set once in a script and never
	// typed twice: a letter for each would be a letter nobody remembers.
	tickets := fs.Bool("session-tickets", false, "allow TLS session resumption")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}

	server, err := echo.Start(echo.WithAddr(*addr), echo.WithHost(*host), echo.WithSessionTickets(*tickets))
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()

	warnPublicListener("serve", server.Addr(), errOut)
	out.println(server.URL())
	out.println("  /          a page that measures the browser that opens it")
	out.println("  /api/all   this connection's fingerprint, as JSON")
	out.println()
	out.println("The certificate is self-signed and generated for this run, so clients")
	out.println("must be told to accept it (curl -k, tlsforge --insecure).")
	out.println("Ctrl-C to stop.")

	<-ctx.Done()
	return nil
}

func runProfiles(_ context.Context, args []string, out, _ *printer) error {
	fs := newFlagSet("profiles", out)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}

	// What a run lands on when nobody names a profile. Resolved rather than
	// printed as written, because "chrome" is two hops from a file and the
	// useful thing to know is which file. The same rule the commands use, or
	// the listing would point at a shipped profile while every run wore the
	// locally measured one.
	fallback := ""
	if p, err := profile.Get(defaultProfileName()); err == nil {
		fallback = p.Name
	}

	out.println("Measured from a real browser.")
	out.println("  * kept on this machine, and used ahead of anything shipped")
	out.println("  < what you get when no profile is named")
	out.println()

	measured := map[string]bool{}
	for _, group := range profile.Default.Measured() {
		p, err := profile.Get(group.Name)
		if err != nil {
			continue
		}
		measured[group.Name] = true
		// The mark goes on the file that is actually used, not on every name
		// that reaches it: a version and its platform both lead to one file, and
		// two arrows pointing at one thing say less than one.
		out.println(line(mark(group.Local), group.Name, len(group.Variants) == 0 &&
			p.Name == fallback))

		// Every line is a name that can be copied into --profile, rather than a
		// platform the reader has to work out how to spell.
		for _, variant := range group.Variants {
			full := group.Name + "_" + variant.Platform
			measured[full] = true
			out.println(line(mark(variant.Local)+"  ", full, full == fallback))
		}
	}

	// One lookup per name, and a name that cannot be resolved is listed with the
	// catalogue rather than silently dropped: a profile that exists but will not
	// load is exactly the thing a user needs to be told about.
	var catalogue []string
	for _, name := range profile.Names() {
		if measured[name] {
			continue
		}
		if p, err := profile.Get(name); err != nil || len(p.ClientHello) == 0 {
			catalogue = append(catalogue, name)
		}
	}

	out.println()
	out.println("From the tls-client catalogue, a handshake but no headers of its own:")
	out.println()
	for i, name := range catalogue {
		out.printf("  %-24s", name)
		if i%3 == 2 {
			out.println()
		}
	}
	out.println()
	out.println()
	out.println("Measure your own with:  tls-forge capture --install")
	if dir := profile.DefaultDir(); dir != "" {
		out.printf("Kept on this machine in: %s\n", dir)
	}
	return nil
}

func printJSON(out io.Writer, v any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
