package main

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2"
	"github.com/Sec-CH-Lemon/tls-forge/v2/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v2/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

func runCompare(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("compare", out)
	profileName := fs.StringP("profile", "p", tlsforge.DefaultProfile, "profile to check")
	browserName := fs.StringP("browser", "b", "", "browser to compare against")
	headless := fs.Bool("headless", false, "run the browser without a window")
	asJSON := fs.BoolP("json", "j", false, "print both captures and the diff as JSON")
	colour := fs.StringP("color", "c", "auto", "colourise the diff: auto, always or never")
	full := fs.BoolP("full", "f", false, "print matching values in full; differing ones always are")
	timeout := fs.DurationP("timeout", "t", 2*time.Minute,
		"how long to wait for the browser; with --manual, ten minutes unless given")
	browserArgs := browserArgFlag(fs)
	visits := addVisitFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}
	if err := visits.check(fs); err != nil {
		return err
	}

	// Checked before the browser is launched: a bad flag should not cost anyone
	// two minutes of waiting first.
	pal, err := paletteFor(*colour, out)
	if err != nil {
		return err
	}

	var result *tlsforge.Comparison
	if *visits.manual {
		result, err = compareVisitor(ctx, visits, visits.waitFor(fs, *timeout), errOut,
			tlsforge.WithProfile(*profileName))
	} else {
		errOut.println("measuring the browser…")
		result, err = tlsforge.CompareToBrowser(ctx,
			tlsforge.MeasureOptions{Browser: *browserName, Headless: *headless, Timeout: *timeout,
				BrowserArgs: *browserArgs},
			tlsforge.WithProfile(*profileName),
		)
	}
	if err != nil {
		return err
	}

	if *asJSON {
		if err := printJSON(out, result); err != nil {
			return err
		}
	} else {
		printComparison(out, result, pal, *full)
		if *visits.manual && result.Browser.HTTP1 == nil {
			out.println("HTTP/1.1 was not measured from the browser you opened, and is not compared.")
		}
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
		out.println("the captures could not be re-read for display; use --json")
		return
	}

	out.printf("%s--- browser  %s%s\n", pal.differ, result.Browser.UserAgent(), pal.reset)
	measured := result.Measured
	if about := strings.Join(slices.DeleteFunc([]string{measured.Browser, measured.Platform, measured.Mode},
		func(s string) bool { return s == "" || s == result.Browser.UserAgent() }), ", "); about != "" {
		out.printf("%s             %s%s\n", pal.differ, about, pal.reset)
	}
	out.printf("%s+++ client   profile %s%s\n\n", pal.match, result.Client.Profile, pal.reset)
	if len(measured.Scenario) > 0 {
		out.printf("%smeasured%s\n", pal.dim, pal.reset)
		for _, what := range measured.Scenario {
			out.printf("  %s\n", what)
		}
		out.println()
	}

	tlsWant, tlsGot := fingerprint.TLSFields(browserHello), fingerprint.TLSFields(clientHello)
	var h1Want, h1Got []fingerprint.Field
	if result.Browser.HTTP1 != nil && result.Client.HTTP1 != nil {
		h1Want = fingerprint.HTTP1Fields(result.Browser.HTTP1.Fingerprint())
		h1Got = fingerprint.HTTP1Fields(result.Client.HTTP1.Fingerprint())
	}

	// Absent when the connection came out as HTTP/1.1, and then there is nothing
	// to compare rather than a difference to report.
	var h2Want, h2Got []fingerprint.Field
	if result.Browser.HTTP2 != nil && result.Client.HTTP2 != nil {
		h2Want = fingerprint.HTTP2Fields(result.Browser.HTTP2.Fingerprint())
		h2Got = fingerprint.HTTP2Fields(result.Client.HTTP2.Fingerprint())
	}

	// One width across both sections, or the eye loses the column between them.
	d := &diffPrinter{out: out, colour: pal, full: full, labelAt: widestLabel(tlsWant, h1Want, h2Want)}
	d.section("TLS", tlsWant, tlsGot)
	if h1Want != nil {
		d.section("HTTP/1.1", h1Want, h1Got)
	}
	if h2Want != nil {
		d.section("HTTP/2", h2Want, h2Got)
	}

	unchecked := slices.Concat(result.TLS.Unchecked, result.HTTP1.Unchecked, result.HTTP2.Unchecked)
	if len(unchecked) > 0 {
		d.unchecked(unchecked)
	}

	if result.OK() {
		out.printf("%severy field matches; the client is indistinguishable from the browser.%s\n",
			pal.match, pal.reset)
		out.println()
		out.println("JA3 is deliberately not compared: Chrome shuffles its extension order per")
		out.println("connection, so its own JA3 differs from request to request.")
		return
	}

	if differing := len(result.TLS.Differences) + len(result.HTTP1.Differences) + len(result.HTTP2.Differences); differing > 0 {
		out.printf("%s%d field(s) differ.%s Fix by measuring this browser and using the profile\n",
			pal.differ, differing, pal.reset)
		out.println("it produces:")
		out.println("  tls-forge capture --save my-browser.json")
	}
	if len(unchecked) > 0 {
		out.printf("%s%d could not be compared:%s nothing says whether they may differ, so the client\n",
			pal.warn, len(unchecked), pal.reset)
		out.println("is not shown to match the browser there.")
	}
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
	if measured.HTTP1 != nil {
		field("HTTP/1.1 order", strings.Join(measured.HTTP1.HeaderNames, ", "))
	}
	if nav := measured.Navigator; nav != nil {
		field("platform", strings.TrimSpace(nav.Platform+" "+nav.PlatformVersion))
		field("architecture", strings.TrimSpace(nav.Architecture+" "+nav.Bitness))
		field("languages", strings.Join(nav.Languages, ", "))
	}
	// What it sent its page, which asked for every client hint.
	if len(measured.ClientHints) > 0 {
		field("client hints", hintsSaid(measured.ClientHints))
	}
	// What a browser a person opened drew for each of the connections its page
	// opened, and how it resumed, which a profile cannot say all of.
	if len(measured.Connections) > 0 {
		drawn, err := profile.DrawnOf(measured)
		field("per connection", drawnSaid(drawn, err))
		if drawn != nil && len(drawn.Sometimes) > 0 {
			field("not every time", extensionsNamed(drawn.Sometimes)+
				": in some of its hellos only; the profile sends what the measured one did")
		}
		field("resumed", resumptionSaid(profile.ResumptionOf(measured)))
	}
	out.println(line)
}

// hintsSaid says how many of the client hints a server has to ask for a
// browser sent its page, which asked for every one.
func hintsSaid(sent []capture.HeaderField) string {
	asked := 0
	for _, h := range sent {
		if slices.Contains(profile.AskedClientHints(), h.Name) {
			asked++
		}
	}
	if asked == 0 {
		return "none of those a server asks for, though asked"
	}
	return fmt.Sprintf("%d of the %d a server asks for, sent when asked", asked, len(profile.AskedClientHints()))
}

// drawnSaid says what a browser drew for each connection, measured, or that
// it was not.
func drawnSaid(d *profile.Drawn, err error) string {
	switch {
	case err != nil:
		return "not measured: " + err.Error()
	case d == nil:
		return "not measured: too few connections"
	}
	said := "its extensions in one order"
	if d.Order {
		said = "the order of its extensions drawn for each"
	}
	lengths := make([]string, len(d.ECH))
	for i, length := range d.ECH {
		lengths[i] = strconv.Itoa(length)
	}
	switch len(lengths) {
	case 0:
	case 1:
		said += ", a GREASE ECH payload of " + lengths[0] + " bytes every time"
	default:
		said += ", a GREASE ECH payload of " + strings.Join(lengths, ", ") + " bytes"
	}
	return fmt.Sprintf("%s (%d hellos)", said, d.Hellos)
}

// resumptionSaid says how a browser resumed a session, against tls-forge.
func resumptionSaid(r profile.Resumption, err error) string {
	switch {
	case err != nil:
		return "not read: " + err.Error()
	case !r.Measured:
		return "it resumed none of the sessions it was given"
	case r.AsTLSForge():
		return "as tls-forge resumes: the hello it sent cold, and pre_shared_key last"
	}
	var otherwise []string
	if len(r.Added) > 0 {
		otherwise = append(otherwise, "adds "+extensionsNamed(r.Added))
	}
	if len(r.Missing) > 0 {
		otherwise = append(otherwise, "lacks "+extensionsNamed(r.Missing))
	}
	if r.NotLast {
		otherwise = append(otherwise, "pre_shared_key not last")
	}
	if r.Identities != 1 {
		otherwise = append(otherwise, fmt.Sprintf("offers %d tickets", r.Identities))
	}
	return "otherwise than tls-forge resumes: " + strings.Join(otherwise, ", ")
}

// extensionsNamed names extensions, as a ClientHello's are named.
func extensionsNamed(types []uint16) string {
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = fingerprint.ExtensionName(t)
	}
	return strings.Join(names, ", ")
}
