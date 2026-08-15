package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

func runCompare(ctx context.Context, args []string, out io.Writer) error {
	fs := newFlagSet("compare", out)
	profileName := fs.String("profile", tlsforge.DefaultProfile, "profile to check")
	browserName := fs.String("browser", "", "browser to compare against")
	headless := fs.Bool("headless", false, "run the browser without a window")
	asJSON := fs.Bool("json", false, "print both captures and the diff as JSON")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for the browser")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Fprintln(out, "measuring the browser…")
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
		printComparison(out, result)
	}

	if !result.OK() {
		return errDiffers
	}
	return nil
}

func printComparison(out io.Writer, result *tlsforge.Comparison) {
	line := strings.Repeat("─", 72)
	fmt.Fprintln(out, line)
	fmt.Fprintf(out, "  browser   %s\n", result.Browser.UserAgent())
	fmt.Fprintf(out, "  profile   %s\n", result.Client.Profile)
	fmt.Fprintln(out, line)

	row := func(label, browser, client string) {
		if browser == client {
			fmt.Fprintf(out, "  match   %-14s %s\n", label, browser)
			return
		}
		fmt.Fprintf(out, "  DIFFER  %-14s %s\n", label, browser)
		fmt.Fprintf(out, "  %6s  %-14s %s\n", "", "", client)
	}
	row("JA4", result.Browser.TLS.JA4, result.Client.TLS.JA4)
	if result.Browser.HTTP2 != nil && result.Client.HTTP2 != nil {
		row("HTTP/2", result.Browser.HTTP2.Akamai, result.Client.HTTP2.Akamai)
		row("header order",
			strings.Join(result.Browser.HTTP2.HeaderOrder, ","),
			strings.Join(result.Client.HTTP2.HeaderOrder, ","))
	}
	fmt.Fprintln(out, line)

	if result.OK() {
		fmt.Fprintln(out, "\nThe client is indistinguishable from the browser on every field compared.")
		fmt.Fprintln(out, "JA3 is deliberately not compared: Chrome shuffles its extension order per")
		fmt.Fprintln(out, "connection, so its own JA3 differs from request to request.")
		return
	}

	fmt.Fprintln(out)
	if !result.TLS.OK() {
		fmt.Fprintf(out, "TLS\n%s\n\n", result.TLS)
	}
	if !result.HTTP2.OK() {
		fmt.Fprintf(out, "HTTP/2\n%s\n\n", result.HTTP2)
	}
	fmt.Fprintln(out, "Fix by measuring this browser and using the profile it produces:")
	fmt.Fprintln(out, "  tls-forge capture -save my-browser.json")
}

func printCapture(out io.Writer, measured *capture.Capture) {
	line := strings.Repeat("─", 72)
	fmt.Fprintln(out, line)
	field := func(label, value string) {
		if value != "" {
			fmt.Fprintf(out, "  %-16s %s\n", label, value)
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
	fmt.Fprintln(out, line)
}
