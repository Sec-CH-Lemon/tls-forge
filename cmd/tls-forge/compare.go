package main

import (
	"context"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

func runCompare(ctx context.Context, args []string, out, _ *printer) error {
	fs := newFlagSet("compare", out)
	profileName := fs.StringP("profile", "p", tlsforge.DefaultProfile, "profile to check")
	browserName := fs.StringP("browser", "b", "", "browser to compare against")
	headless := fs.Bool("headless", false, "run the browser without a window")
	asJSON := fs.BoolP("json", "j", false, "print both captures and the diff as JSON")
	colour := fs.StringP("color", "c", "auto", "colourise the diff: auto, always or never")
	full := fs.BoolP("full", "f", false, "print matching values in full; differing ones always are")
	timeout := fs.DurationP("timeout", "t", 2*time.Minute, "how long to wait for the browser")
	if err := parse(fs, args); err != nil {
		return err
	}

	// Checked before the browser is launched: a bad flag should not cost anyone
	// two minutes of waiting first.
	pal, err := paletteFor(*colour, out)
	if err != nil {
		return err
	}

	out.println("measuring the browser…")
	result, err := tlsforge.CompareToBrowser(ctx,
		tlsforge.MeasureOptions{Browser: *browserName, Headless: *headless, Timeout: *timeout},
		tlsforge.WithProfile(*profileName),
	)
	if err != nil {
		return err
	}

	if *asJSON {
		if err := printJSON(out, result); err != nil {
			return err
		}
	} else {
		printComparison(out, result, pal, *full)
	}

	if !result.OK() {
		return errDiffers
	}
	return nil
}

func printComparison(out *printer, result *tlsforge.Comparison, pal palette, full bool) {
	browserHello, browserErr := result.Browser.Hello()
	clientHello, clientErr := result.Client.Hello()
	if browserErr != nil || clientErr != nil {
		// Compare already parsed both of these to build the report, so reaching
		// here means something changed underneath. Say so rather than printing
		// an empty diff that reads as agreement.
		out.println("the captures could not be re-read for display; use -json")
		return
	}

	out.printf("%s--- browser  %s%s\n", pal.differ, result.Browser.UserAgent(), pal.reset)
	out.printf("%s+++ client   profile %s%s\n\n", pal.match, result.Client.Profile, pal.reset)

	tlsWant, tlsGot := fingerprint.TLSFields(browserHello), fingerprint.TLSFields(clientHello)

	// Absent when the connection came out as HTTP/1.1, and then there is nothing
	// to compare rather than a difference to report.
	var h2Want, h2Got []fingerprint.Field
	if result.Browser.HTTP2 != nil && result.Client.HTTP2 != nil {
		h2Want = fingerprint.HTTP2Fields(result.Browser.HTTP2.Fingerprint())
		h2Got = fingerprint.HTTP2Fields(result.Client.HTTP2.Fingerprint())
	}

	// One width across both sections, or the eye loses the column between them.
	d := &diffPrinter{out: out, colour: pal, full: full, labelAt: widestLabel(tlsWant, h2Want)}
	d.section("TLS", tlsWant, tlsGot)
	if h2Want != nil {
		d.section("HTTP/2", h2Want, h2Got)
	}

	if result.OK() {
		out.printf("%severy field matches; the client is indistinguishable from the browser.%s\n",
			pal.match, pal.reset)
		out.println()
		out.println("JA3 is deliberately not compared: Chrome shuffles its extension order per")
		out.println("connection, so its own JA3 differs from request to request.")
		return
	}

	differing := len(result.TLS.Differences) + len(result.HTTP2.Differences)
	out.printf("%s%d field(s) differ.%s Fix by measuring this browser and using the profile\n",
		pal.differ, differing, pal.reset)
	out.println("it produces:")
	out.println("  tls-forge capture --save my-browser.json")
}

func printCapture(out *printer, measured *capture.Capture) {
	line := strings.Repeat("─", 72)
	out.println(line)
	field := func(label, value string) {
		if value != "" {
			out.printf("  %-16s %s\n", label, value)
		}
	}
	field("user-agent", measured.UserAgent())
	field("JA4", measured.TLS.JA4)
	field("JA3 hash", measured.TLS.JA3Hash)
	field("ALPN", strings.Join(measured.TLS.ALPN, ", "))
	if measured.TLS.Resumed {
		field("resumed", "yes — this hello carries pre_shared_key, so its JA4 is not "+
			"the one a server sees on first contact")
	}
	if measured.HTTP2 != nil {
		field("HTTP/2", measured.HTTP2.Akamai)
		field("header order", strings.Join(measured.HTTP2.HeaderOrder, ", "))
	}
	if nav := measured.Navigator; nav != nil {
		field("platform", strings.TrimSpace(nav.Platform+" "+nav.PlatformVersion))
		field("architecture", strings.TrimSpace(nav.Architecture+" "+nav.Bitness))
		field("languages", strings.Join(nav.Languages, ", "))
	}
	out.println(line)
}
