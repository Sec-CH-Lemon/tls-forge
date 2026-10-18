package tlsforge

import (
	"fmt"
	"log/slog"

	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
	http2 "github.com/igor-lemon/fhttp/http2"
	tls_client "github.com/igor-lemon/tls-client"
)

// transports are how a client's requests reach the network: the connections a
// request that carries credentials goes out on, a page's and a script's alike,
// the connections of one that carries none, each HEADERS frame with its own
// priority, and what both are built with. A client made Fresh has transports
// of its own, and shares its session (session).
type transports struct {
	inner tls_client.HttpClient
	// bare is where a request that carries no credentials goes out: a CORS
	// preflight, fetch() with credentials omitted, or one kept to its own
	// origin going to another. Chrome sends those on connections of their
	// own, which resume only TLS sessions of their own, as the Fetch
	// standard keys a connection by whether its request carries credentials
	// (testdata/chrome155-connections.json). Built as inner is, with the
	// same jar.
	bare tls_client.HttpClient
	// build is what transports are built with, for the log they write to: the
	// client's options, but for how they dial, which is each client's own.
	build func(log *slog.Logger) []tls_client.HttpClientOption
	// proxy is what an error building them is cleaned of.
	proxy string
}

// newTransports builds transports with build, logging to log.
func newTransports(build func(*slog.Logger) []tls_client.HttpClientOption, log *slog.Logger,
	proxy string) (*transports, error) {
	var built [2]tls_client.HttpClient
	for i := range built {
		inner, err := newInnerClient(tls_client.NewNoopLogger(), build(log)...)
		if err != nil {
			// A proxy the transport cannot read is quoted back whole, password
			// and all, by url.Parse and by the transport alike.
			return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, proxy))
		}
		built[i] = inner
	}
	return &transports{inner: built[0], bare: built[1], build: build, proxy: proxy}, nil
}

// fresh are transports of their own, built as these were, logging to log.
func (t *transports) fresh(log *slog.Logger) (*transports, error) {
	return newTransports(t.build, log, t.proxy)
}

// carrying is the transport of a request that carries credentials, or of one
// that carries none.
func (t *transports) carrying(credentials bool) tls_client.HttpClient {
	if credentials {
		return t.inner
	}
	return t.bare
}

// closeIdle closes the connections they hold open between requests.
func (t *transports) closeIdle() {
	t.inner.CloseIdleConnections()
	t.bare.CloseIdleConnections()
}

// scriptHeaderPriority is the priority Chrome 155 puts on the HEADERS frame of
// fetch(), an XHR and a CORS preflight: exclusive, on no stream, weight 220
// (219 on the wire), as measured in testdata/chrome155-requests.json, where a
// page's is 256. The transport puts the profile's on every other request.
var scriptHeaderPriority = http2.PriorityParam{Exclusive: true, Weight: 219}
