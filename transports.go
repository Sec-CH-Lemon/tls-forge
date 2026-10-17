package tlsforge

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
	http2 "github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// transports are how a client's requests reach the network: the transport a
// page's requests go out on, the one of fetch() and an XHR, made when one
// first does, and what each is built with. A client made Fresh has transports
// of its own, and shares its session (session).
type transports struct {
	page tls_client.HttpClient
	// build is what a transport is built with, for the log it writes to and
	// the client profile it wears: the client's options, but for how it
	// dials, which is each transport's own.
	build   func(log *slog.Logger, built profiles.ClientProfile) []tls_client.HttpClientOption
	profile profiles.ClientProfile
	// log is what the transport of fetch() and an XHR logs to, and proxy what
	// an error building fresh transports is cleaned of.
	log   *slog.Logger
	proxy string

	mu     sync.Mutex
	script tls_client.HttpClient
}

// newTransports builds the page's transport with build, wearing profile,
// logging to log.
func newTransports(build func(*slog.Logger, profiles.ClientProfile) []tls_client.HttpClientOption,
	profile profiles.ClientProfile, log *slog.Logger, proxy string) (*transports, error) {
	page, err := newInnerClient(tls_client.NewNoopLogger(), build(log, profile)...)
	if err != nil {
		// A proxy the transport cannot read is quoted back whole, password and
		// all, by url.Parse and by the transport alike.
		return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, proxy))
	}
	return &transports{page: page, build: build, profile: profile, log: log, proxy: proxy}, nil
}

// fresh are transports of their own, built as these were, logging to log.
func (t *transports) fresh(log *slog.Logger) (*transports, error) {
	return newTransports(t.build, t.profile, log, t.proxy)
}

// forScript is the transport a request of fetch() or an XHR goes out on,
// made when one first does: the page's, but for the priority on each
// request's HEADERS frame, which Chrome gives such a request (weight 220)
// where it gives a page its highest (256). The transport puts one priority on
// every request it sends, so these go out on connections of their own, with
// TLS sessions of their own.
func (t *transports) forScript() (tls_client.HttpClient, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.script == nil {
		built := withHeaderPriority(t.profile, scriptHeaderPriority)
		script, err := newInnerClient(tls_client.NewNoopLogger(), t.build(t.log, built)...)
		if err != nil {
			// Do takes the proxy's password out of the error it returns, and
			// the request's log out of what it writes.
			return nil, fmt.Errorf("tlsforge: %w", err)
		}
		t.script = script
	}
	return t.script, nil
}

// closeIdle closes the connections both hold open between requests.
func (t *transports) closeIdle() {
	t.page.CloseIdleConnections()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.script != nil {
		t.script.CloseIdleConnections()
	}
}

// withHeaderPriority is a client profile with another priority on the
// HEADERS frame of every request.
func withHeaderPriority(p profiles.ClientProfile, priority http2.PriorityParam) profiles.ClientProfile {
	return profiles.NewClientProfile(p.GetClientHelloId(), p.GetSettings(), p.GetSettingsOrder(),
		p.GetPseudoHeaderOrder(), p.GetConnectionFlow(), p.GetPriorities(), &priority, p.GetStreamID(),
		p.GetAllowHTTP(), p.GetHttp3Settings(), p.GetHttp3SettingsOrder(), p.GetHttp3PriorityParam(),
		p.GetHttp3PseudoHeaderOrder(), p.GetHttp3SendGreaseFrames())
}

// scriptHeaderPriority is the priority Chrome 155 puts on the HEADERS frame of
// fetch(), an XHR and a CORS preflight: exclusive, on no stream (on a
// connection of their own), weight 220 (219 on the wire), as measured in
// testdata/chrome155-requests.json, where a page's is 256.
var scriptHeaderPriority = http2.PriorityParam{Exclusive: true, Weight: 219}
