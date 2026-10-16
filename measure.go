package tlsforge

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/browser"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// Measuring: what does a client actually send?
//
// Both halves — a real browser and this library — are pointed at one local echo
// server, which reports each connection back to whoever made it. Comparing the
// two answers is then comparing two values of one type produced by one
// instrument, rather than reconciling two services' idea of what a fingerprint
// is.
//
// Doing it locally also makes the check reproducible. Third-party fingerprint
// endpoints rate-limit, go down, and change their output; a verification step
// that depends on one fails for reasons that have nothing to do with the code.

// startEchoServer is echo.Start, named so a test can make it fail. Binding a
// port is the one thing every measurement does before anything else, and the
// branch that reports it failing is otherwise unreachable.
var startEchoServer = echo.Start

// MeasureOptions controls a browser measurement.
type MeasureOptions struct {
	// Browser names an installed browser ("chrome", "chromium", "edge",
	// "brave") or is a path to an executable. Empty searches for one.
	Browser string

	// Headless runs without a window.
	//
	// Chrome's modern headless was measured to send the identical handshake:
	// same JA4, same HTTP/2 fingerprint, same header order. It is still not the
	// default, because the browser being impersonated is a headed one, and
	// "identical when last measured" is a fact about the past.
	Headless bool

	// Timeout bounds the whole measurement. Zero means two minutes, which is
	// generous on purpose: it includes a cold browser start.
	Timeout time.Duration

	// BrowserArgs are extra flags for the browser, appended last so they win.
	//
	// For the machine rather than for the measurement. `--no-sandbox` is the one
	// a CI runner needs: Ubuntu 24.04 restricts the unprivileged user namespaces
	// Chrome's sandbox is built on, and a Windows runner denies the sandbox
	// access to the executable in its tool cache. In both, Chrome starts, never
	// loads the page, and the measurement times out having launched a browser
	// that was never going to answer. Process isolation is not TLS, so the
	// capture is the same capture — but nothing here checks that, and a flag
	// that did change what goes on the wire would quietly make this a
	// measurement of something else.
	BrowserArgs []string
}

// MeasureBrowser launches a browser, points it at a local server and returns
// what it sent.
//
// The window that opens shows the result and can be closed; the browser runs
// with a throwaway profile directory, so nothing touches the user's own.
func MeasureBrowser(ctx context.Context, opts MeasureOptions) (*capture.Capture, error) {
	server, err := startEchoServer()
	if err != nil {
		return nil, err
	}
	defer func() { _ = server.Close() }()
	return MeasureBrowserAt(ctx, server, opts)
}

// MeasureBrowserAt measures a browser against a server the caller already has,
// which is how a comparison puts both sides on one instrument.
func MeasureBrowserAt(ctx context.Context, server *echo.Server, opts MeasureOptions) (*capture.Capture, error) {
	if server == nil {
		return nil, fmt.Errorf("tlsforge: browser measurement needs an echo server")
	}
	found, err := browser.Find(opts.Browser)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	browserOptions := browser.Options{Headless: opts.Headless, Args: opts.BrowserArgs}
	// Each protocol gets its own fresh browser profile and direct top-level
	// navigation. The old single-process flow reached the HTTP/1.1 listener with
	// location.replace() from the HTTP/2 page. Chrome correctly labelled that
	// request same-site and omitted Sec-Fetch-User, so replaying the result made
	// the measuring instrument visible on every forced-H1 request.
	http1, err := measureBrowserNavigation(ctx, found, server,
		server.CaptureURL()+"/?http1=cold", browserOptions)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: HTTP/1.1 browser measurement: %w", err)
	}
	if err := validateColdHTTP1(http1.HTTP1); err != nil {
		return nil, err
	}
	measured, err := measureBrowserNavigation(ctx, found, server,
		server.URL()+"/?http1=done", browserOptions)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: HTTP/2 browser measurement: %w", err)
	}
	measured.HTTP1 = http1.HTTP1
	return measured, nil
}

func measureBrowserNavigation(ctx context.Context, found *browser.Browser, server *echo.Server,
	url string, opts browser.Options) (*capture.Capture, error) {
	closeBrowser, err := found.Open(ctx, url, opts)
	if err != nil {
		return nil, err
	}
	defer closeBrowser()

	session, err := server.Await(ctx)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: no capture from %s: %w", found.Path, err)
	}
	return session.Capture(capture.SourceBrowser), nil
}

func validateColdHTTP1(measured *capture.HTTP1) error {
	values := make(map[string]string)
	if measured != nil {
		for _, header := range measured.Headers {
			values[strings.ToLower(header.Name)] = header.Value
		}
	}
	for _, field := range []struct{ name, want string }{
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
	} {
		if got := values[field.name]; got != field.want {
			return fmt.Errorf("tlsforge: HTTP/1.1 capture is not a cold top-level navigation: %s = %q, want %q",
				field.name, got, field.want)
		}
	}
	return nil
}

// MeasureVisitorAt waits for a browser a person opens a server's page in, and
// returns what it sent: Firefox, Safari, a phone's, none of which this library
// can launch. The server is one started with echo.WithManual(true), whose page
// walks the person through the visit that is measured; the browser is measured
// over HTTP/2 alone.
func MeasureVisitorAt(ctx context.Context, server *echo.Server) (*capture.Capture, error) {
	if server == nil {
		return nil, fmt.Errorf("tlsforge: measuring a visiting browser needs an echo server")
	}
	session, err := server.Await(ctx)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: no browser came to %s: %w", server.URL(), err)
	}
	return session.Capture(capture.SourceBrowser), nil
}

// MeasureSelf returns what THIS library sends, measured the same way.
func MeasureSelf(ctx context.Context, opts ...Option) (*capture.Capture, error) {
	server, err := startEchoServer()
	if err != nil {
		return nil, err
	}
	defer func() { _ = server.Close() }()
	return MeasureSelfAt(ctx, server, opts...)
}

var doMeasurementRequest = func(client *Client, req *Request) (*Response, error) {
	return client.Do(req)
}

// MeasureSelfAt measures this library against a server the caller already has.
func MeasureSelfAt(ctx context.Context, server *echo.Server, opts ...Option) (*capture.Capture, error) {
	if server == nil {
		return nil, fmt.Errorf("tlsforge: self measurement needs an echo server")
	}
	// The echo server's certificate is generated per run and signs nothing but
	// itself, so verification is turned off — for this one loopback address,
	// inside this process, carrying nothing secret.
	measurementOpts := append([]Option(nil), opts...)
	measurementOpts = append(measurementOpts, WithInsecureSkipVerify())
	client, err := New(measurementOpts...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	http1Response, err := doMeasurementRequest(client, &Request{Context: ctx, URL: server.CaptureURL() + "/api/all"})
	if err != nil {
		return nil, err
	}
	http1, err := readMeasurement(http1Response, client.Profile().Name)
	if err != nil {
		return nil, err
	}

	res, err := doMeasurementRequest(client, &Request{Context: ctx, URL: server.URL() + "/api/all"})
	if err != nil {
		return nil, err
	}
	measured, err := readMeasurement(res, client.Profile().Name)
	if err != nil {
		return nil, err
	}
	measured.HTTP1 = http1.HTTP1
	return measured, nil
}

// readMeasurement turns the echo server's answer into a capture.
//
// Split out from the request so the failure cases have a name and a test. They
// are not hypothetical: the answer is JSON from a server, and "the server
// replied with something else" is the failure that otherwise surfaces as an
// unmarshalling error about a character in a 404 page.
func readMeasurement(res *Response, profileName string) (*capture.Capture, error) {
	if !res.OK() {
		return nil, fmt.Errorf("tlsforge: echo server returned %d: %s",
			res.Status, strings.TrimSpace(res.Text()))
	}
	var measured capture.Capture
	if err := json.Unmarshal(res.Body, &measured); err != nil {
		return nil, fmt.Errorf("tlsforge: reading measurement: %w", err)
	}
	measured.Source = capture.SourceTLSFetch
	measured.Profile = profileName
	return &measured, nil
}

// Comparison is the result of measuring both sides.
type Comparison struct {
	Browser *capture.Capture `json:"browser"`
	Client  *capture.Capture `json:"client"`
	TLS     fingerprint.Report
	HTTP1   fingerprint.Report
	HTTP2   fingerprint.Report

	// Measured is what the comparison was made of, and Manifest the rule each
	// field was compared by: together, what a match covers.
	Measured Measurement        `json:"measured"`
	Manifest []fingerprint.Rule `json:"manifest"`
}

// Measurement is what a comparison was made of: the browser, as it says it
// is, how it was run, and which of its requests were compared. The captures
// beside it hold what was sent, as it went.
type Measurement struct {
	// Browser is the browser's build, as navigator.userAgentData says it, or
	// its user agent when that says nothing.
	Browser string `json:"browser,omitempty"`
	// Platform is its operating system and machine, as navigator says them.
	Platform string `json:"platform,omitempty"`
	// Mode is how it was run: headless, with a window, or opened by a person;
	// empty for captures compared after the fact.
	Mode string `json:"mode,omitempty"`
	// Scenario is what was compared, protocol by protocol.
	Scenario []string `json:"scenario"`
}

// How a browser was run, for Measurement.Mode.
const (
	ModeHeadless = "headless"
	ModeWindow   = "with a window"
	ModeManual   = "opened by a person"
)

// measurementOf is what a capture of a browser says of it, and of the requests
// the comparison holds the client to.
func measurementOf(browser *capture.Capture) Measurement {
	out := Measurement{Browser: browser.UserAgent()}
	if nav := browser.Navigator; nav != nil {
		if brand, ok := browserBrand(nav.FullVersionList); ok {
			out.Browser = brand
		}
		out.Platform = strings.Join(slices.DeleteFunc([]string{
			strings.TrimSpace(nav.Platform + " " + nav.PlatformVersion),
			strings.TrimSpace(nav.Architecture + " " + nav.Bitness),
		}, func(s string) bool { return s == "" }), ", ")
	}
	out.Scenario = append(out.Scenario, "TLS: "+map[bool]string{
		false: "first contact", true: "resuming a session"}[browser.TLS.Resumed])
	if http1 := browser.HTTP1; http1 != nil {
		fields := map[string]string{}
		for _, field := range http1.Headers {
			fields[strings.ToLower(field.Name)] = field.Value
		}
		out.Scenario = append(out.Scenario, "HTTP/1.1: "+http1.Method+", "+requestKind(fields))
	}
	if http2 := browser.HTTP2; http2 != nil {
		fields := map[string]string{}
		for _, field := range http2.Headers {
			fields[field.Name] = field.Value
		}
		out.Scenario = append(out.Scenario, "HTTP/2: "+fields[":method"]+", "+requestKind(fields)+
			", the first request of its connection")
	}
	return out
}

// browserBrand is the brand a browser names itself by in its full version
// list: not the GREASE one, and not Chromium when there is another.
func browserBrand(brands []capture.Brand) (string, bool) {
	var chromium string
	for _, brand := range brands {
		switch {
		case strings.Contains(brand.Brand, "Not") && strings.Contains(brand.Brand, "Brand"):
		case brand.Brand == "Chromium":
			chromium = brand.Brand + " " + brand.Version
		default:
			return brand.Brand + " " + brand.Version, true
		}
	}
	return chromium, chromium != ""
}

// requestKind is what a request was, as its Sec-Fetch fields say.
func requestKind(fields map[string]string) string {
	if fields["sec-fetch-mode"] == "navigate" && fields["sec-fetch-dest"] == "document" &&
		fields["sec-fetch-site"] == "none" {
		return "a page opened from the address bar"
	}
	return fmt.Sprintf("Sec-Fetch-Mode %q, Sec-Fetch-Dest %q, Sec-Fetch-Site %q",
		fields["sec-fetch-mode"], fields["sec-fetch-dest"], fields["sec-fetch-site"])
}

// OK reports a client indistinguishable from the browser on every field
// compared, with nothing left that could not be compared.
func (c *Comparison) OK() bool { return c.TLS.OK() && c.HTTP1.OK() && c.HTTP2.OK() }

func (c *Comparison) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "browser  %s\n", c.Browser.TLS.JA4)
	fmt.Fprintf(&b, "client   %s  (profile %s)\n", c.Client.TLS.JA4, c.Client.Profile)
	if c.OK() {
		b.WriteString("\nidentical on every field compared.\n")
		return b.String()
	}
	b.WriteString("\n")
	if !c.TLS.OK() {
		fmt.Fprintf(&b, "TLS\n%s\n", c.TLS)
	}
	if !c.HTTP1.OK() {
		fmt.Fprintf(&b, "HTTP/1.1\n%s\n", c.HTTP1)
	}
	if !c.HTTP2.OK() {
		fmt.Fprintf(&b, "HTTP/2\n%s\n", c.HTTP2)
	}
	return b.String()
}

// CompareToBrowser measures a browser and this library on one server and diffs
// them.
//
// This is the function behind `tls-forge compare`, and the answer to "is the
// impersonation still good?" after a browser update — which is when it silently
// stops being true.
func CompareToBrowser(ctx context.Context, measure MeasureOptions, opts ...Option) (*Comparison, error) {
	server, err := startEchoServer()
	if err != nil {
		return nil, err
	}
	defer func() { _ = server.Close() }()

	browserCapture, err := MeasureBrowserAt(ctx, server, measure)
	if err != nil {
		return nil, err
	}
	clientCapture, err := MeasureSelfAt(ctx, server, opts...)
	if err != nil {
		return nil, err
	}
	mode := ModeWindow
	if measure.Headless {
		mode = ModeHeadless
	}
	return compared(browserCapture, clientCapture, mode)
}

// compared is what Compare makes of two captures, of a browser run as mode
// says.
func compared(browserCapture, clientCapture *capture.Capture, mode string) (*Comparison, error) {
	out, err := Compare(browserCapture, clientCapture)
	if out != nil {
		out.Measured.Mode = mode
	}
	return out, err
}

// CompareVisitorAt measures a visiting browser and this library on one server
// and diffs them, over TLS and HTTP/2: the browser is not measured over
// HTTP/1.1, so this library's HTTP/1.1 has nothing to be held to, and is left
// out rather than reported as a difference.
func CompareVisitorAt(ctx context.Context, server *echo.Server, opts ...Option) (*Comparison, error) {
	browserCapture, err := MeasureVisitorAt(ctx, server)
	if err != nil {
		return nil, err
	}
	clientCapture, err := MeasureSelfAt(ctx, server, opts...)
	if err != nil {
		return nil, err
	}
	clientCapture.HTTP1 = nil
	return compared(browserCapture, clientCapture, ModeManual)
}

// Compare diffs two measurements that were taken earlier, which is how a
// capture saved to disk is checked against today's client.
func Compare(browserCapture, clientCapture *capture.Capture) (*Comparison, error) {
	if browserCapture == nil {
		return nil, fmt.Errorf("tlsforge: browser capture is nil")
	}
	if clientCapture == nil {
		return nil, fmt.Errorf("tlsforge: client capture is nil")
	}
	browserHello, err := browserCapture.Hello()
	if err != nil {
		return nil, fmt.Errorf("tlsforge: browser capture: %w", err)
	}
	clientHello, err := clientCapture.Hello()
	if err != nil {
		return nil, fmt.Errorf("tlsforge: client capture: %w", err)
	}

	out := &Comparison{
		Browser:  browserCapture,
		Client:   clientCapture,
		TLS:      fingerprint.CompareTLS(browserHello, clientHello),
		Measured: measurementOf(browserCapture),
		Manifest: fingerprint.Manifest(),
	}
	switch {
	case browserCapture.HTTP2 != nil && clientCapture.HTTP2 != nil:
		out.HTTP2 = fingerprint.CompareHTTP2(
			browserCapture.HTTP2.Fingerprint(), clientCapture.HTTP2.Fingerprint())
	case browserCapture.HTTP2 != nil || clientCapture.HTTP2 != nil:
		out.HTTP2.Differences = []fingerprint.Difference{{
			Field: "http_protocol", Reference: negotiatedProtocol(browserCapture),
			Candidate: negotiatedProtocol(clientCapture),
		}}
	}
	switch {
	case browserCapture.HTTP1 != nil && clientCapture.HTTP1 != nil:
		out.HTTP1 = fingerprint.CompareHTTP1(
			browserCapture.HTTP1.Fingerprint(), clientCapture.HTTP1.Fingerprint())
	case browserCapture.HTTP1 != nil || clientCapture.HTTP1 != nil:
		out.HTTP1.Differences = []fingerprint.Difference{{
			Field: "http1_capture", Reference: recordedHTTP1(browserCapture),
			Candidate: recordedHTTP1(clientCapture),
		}}
	}
	return out, nil
}

func recordedHTTP1(c *capture.Capture) string {
	if c.HTTP1 == nil {
		return "(not recorded)"
	}
	return c.HTTP1.Proto
}

func negotiatedProtocol(c *capture.Capture) string {
	if c.Negotiated != "" {
		return c.Negotiated
	}
	if c.HTTP2 != nil {
		return "h2"
	}
	if c.HTTP1 != nil {
		return c.HTTP1.Proto
	}
	return "(not recorded)"
}
