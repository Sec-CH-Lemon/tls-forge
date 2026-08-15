package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func runCapture(ctx context.Context, args []string, out *printer) error {
	fs := newFlagSet("capture", out)
	browserName := fs.String("browser", "", "browser to measure: chrome, chromium, edge, brave, or a path")
	headless := fs.Bool("headless", false, "run the browser without a window")
	save := fs.String("save", "", "write a reusable profile to this path")
	name := fs.String("name", "", "profile name (default: derived from the browser's version)")
	asJSON := fs.Bool("json", false, "print the raw capture instead of a summary")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for the browser")
	if err := fs.Parse(args); err != nil {
		return err
	}

	out.println("opening a browser… (it will show the result; you can close it)")
	measured, err := tlsforge.MeasureBrowser(ctx, tlsforge.MeasureOptions{
		Browser:  *browserName,
		Headless: *headless,
		Timeout:  *timeout,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		return printJSON(out, measured)
	}
	printCapture(out, measured)

	if *save == "" {
		out.println("\nRe-run with -save <path> to write a reusable profile.")
		return nil
	}

	profileName := *name
	if profileName == "" {
		profileName = profileNameFor(measured.UserAgent())
	}
	saved, err := saveProfile(*save, profileName, measured)
	if err != nil {
		return err
	}
	out.printf("\nwrote profile %q to %s\n", saved, *save)
	return nil
}

// saveProfile turns a measurement into a committed profile and returns the name
// it was filed under.
func saveProfile(path, name string, measured *capture.Capture) (string, error) {
	built, err := profile.FromCapture(name, measured)
	if err != nil {
		return "", err
	}
	built.Notes = fmt.Sprintf("captured %s from %s", now().UTC().Format(time.RFC3339), built.UserAgent)

	data, err := built.Save()
	if err == nil {
		err = os.WriteFile(path, data, 0o644)
	}
	if err != nil {
		return "", err
	}
	return built.Name, nil
}

// now is time.Now, named so a test can produce a byte-identical profile.
var now = time.Now

// profileNameFor derives a stable name from a user-agent, e.g. "chrome_151".
//
// The name matters more than it looks: a profile called "chrome" that was
// measured from Chrome 151 reads as current forever, and the mismatch between
// the name and the handshake is invisible in every log it appears in.
func profileNameFor(userAgent string) string {
	// Order matters. Every Chromium-based browser puts "Chrome/" in its
	// user-agent, so the ones that add their own token have to be checked first
	// or they all come out named chrome.
	families := []struct{ token, name string }{
		{"Edg/", "edge"},
		{"OPR/", "opera"},
		{"Chrome/", "chrome"},
		{"Firefox/", "firefox"},
		{"Version/", "safari"},
	}
	for _, family := range families {
		index := strings.Index(userAgent, family.token)
		if index < 0 {
			continue
		}
		major, _, _ := strings.Cut(userAgent[index+len(family.token):], ".")
		if major != "" {
			return family.name + "_" + major
		}
		return family.name
	}
	return "captured"
}

func runServe(ctx context.Context, args []string, out *printer) error {
	fs := newFlagSet("serve", out)
	addr := fs.String("addr", "127.0.0.1:0", "listen address")
	host := fs.String("host", "localhost", "hostname used in the URL and certificate")
	tickets := fs.Bool("session-tickets", false, "allow TLS session resumption")
	if err := fs.Parse(args); err != nil {
		return err
	}

	server, err := echo.Start(echo.WithAddr(*addr), echo.WithHost(*host), echo.WithSessionTickets(*tickets))
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()

	out.println(server.URL())
	out.println("  /          a page that measures the browser that opens it")
	out.println("  /api/all   this connection's fingerprint, as JSON")
	out.println()
	out.println("The certificate is self-signed and generated for this run, so clients")
	out.println("must be told to accept it (curl -k, tlsforge -insecure).")
	out.println("Ctrl-C to stop.")

	<-ctx.Done()
	return nil
}

func runProfiles(_ context.Context, args []string, out *printer) error {
	fs := newFlagSet("profiles", out)
	if err := fs.Parse(args); err != nil {
		return err
	}

	out.println("Measured from a real browser and shipped with this library:")
	out.println()
	// One lookup per name, and a name that cannot be resolved is listed with the
	// catalogue rather than silently dropped: a profile that exists but will not
	// load is exactly the thing a user needs to be told about.
	var catalogue []string
	for _, name := range profile.Names() {
		p, err := profile.Get(name)
		if err != nil || len(p.ClientHello) == 0 {
			catalogue = append(catalogue, name)
			continue
		}
		out.printf("  %-24s %s\n", name, p.UserAgent)
	}

	out.println()
	out.println("From the tls-client catalogue — a handshake, but no headers of its own:")
	out.println()
	for i, name := range catalogue {
		out.printf("  %-24s", name)
		if i%3 == 2 {
			out.println()
		}
	}
	out.println()
	out.println()
	out.println("Measure your own with:  tls-forge capture -save my-chrome.json")
	return nil
}

func printJSON(out io.Writer, v any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
