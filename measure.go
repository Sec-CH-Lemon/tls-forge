package tlsforge

import (
	"context"
	"encoding/json"
	"fmt"
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

	closeBrowser, err := found.Open(ctx, server.URL(),
		browser.Options{Headless: opts.Headless, Args: opts.BrowserArgs})
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

// MeasureSelf returns what THIS library sends, measured the same way.
func MeasureSelf(ctx context.Context, opts ...Option) (*capture.Capture, error) {
	server, err := startEchoServer()
	if err != nil {
		return nil, err
	}
	defer func() { _ = server.Close() }()
	return MeasureSelfAt(ctx, server, opts...)
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

	res, err := client.Do(&Request{Context: ctx, URL: server.URL() + "/api/all"})
	if err != nil {
		return nil, err
	}
	return readMeasurement(res, client.Profile().Name)
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
	HTTP2   fingerprint.Report
}

// OK reports a client indistinguishable from the browser on every field
// compared.
func (c *Comparison) OK() bool { return c.TLS.OK() && c.HTTP2.OK() }

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
	return Compare(browserCapture, clientCapture)
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
		Browser: browserCapture,
		Client:  clientCapture,
		TLS:     fingerprint.CompareTLS(browserHello, clientHello),
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
	return out, nil
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
