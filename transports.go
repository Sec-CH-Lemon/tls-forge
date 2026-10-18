package tlsforge

import (
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"sync"

	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
	http2 "github.com/igor-lemon/fhttp/http2"
	tls_client "github.com/igor-lemon/tls-client"
)

// transports are how a client's requests reach the network: for each
// top-level site, the connections a request that carries credentials goes out
// on, a page's and a script's alike, and the connections of one that carries
// none, each HTTP/2 HEADERS frame with its own priority; and what they are
// built with. A client made Fresh has transports of its own, and shares its
// session (session).
type transports struct {
	// build is what transports are built with, for the log they write to: the
	// client's options, but for how they dial, which is each client's own.
	build func(log *slog.Logger) []tls_client.HttpClientOption
	log   *slog.Logger
	// proxy is what an error building them is cleaned of.
	proxy string

	mu sync.Mutex
	// sites are the connections of each top-level site a request went to,
	// the one used longest ago first, maxSites at most. Chrome keys its
	// connections and their TLS sessions by the site of the page at the top
	// (its network anonymization key), as well as by whether a request
	// carries credentials (testdata/chrome155-connections.json): a page of
	// another site has connections of its own, as do the requests it makes.
	sites []*site
	// spare are the connections built with the transports, which the first
	// site to need some takes.
	spare *site
}

// site are the connections of one top-level site.
type site struct {
	name  string
	inner tls_client.HttpClient
	// bare is where a request that carries no credentials goes out: a CORS
	// preflight, fetch() with credentials omitted, or one kept to its own
	// origin going to another. Chrome sends those on connections of their
	// own, which resume only TLS sessions of their own, as the Fetch
	// standard keys a connection by whether its request carries credentials.
	// Built as inner is, with the same jar.
	bare tls_client.HttpClient
}

// maxSites is how many top-level sites a client keeps the connections and
// TLS sessions of: a request to one more drops the site used longest ago,
// whose idle connections are closed, and whose sessions are forgotten.
const maxSites = 64

// newTransports builds transports with build, logging to log.
func newTransports(build func(*slog.Logger) []tls_client.HttpClientOption, log *slog.Logger,
	proxy string) (*transports, error) {
	t := &transports{build: build, log: log, proxy: proxy}
	spare, err := t.newSite("")
	if err != nil {
		return nil, err
	}
	t.spare = spare
	return t, nil
}

// newSite builds the connections of the site named.
func (t *transports) newSite(name string) (*site, error) {
	var built [2]tls_client.HttpClient
	for i := range built {
		inner, err := newInnerClient(tls_client.NewNoopLogger(), t.build(t.log)...)
		if err != nil {
			// A proxy the transport cannot read is quoted back whole, password
			// and all, by url.Parse and by the transport alike.
			return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, t.proxy))
		}
		built[i] = inner
	}
	return &site{name: name, inner: built[0], bare: built[1]}, nil
}

// fresh are transports of their own, built as these were, logging to log.
func (t *transports) fresh(log *slog.Logger) (*transports, error) {
	return newTransports(t.build, log, t.proxy)
}

// siteOf are the connections of the top-level site named: a request to a page
// of it goes out on them, as does every request such a page makes.
func (t *transports) siteOf(name string) (*site, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	at := slices.IndexFunc(t.sites, func(s *site) bool { return s.name == name })
	var s *site
	switch {
	case at >= 0:
		s = t.sites[at]
		t.sites = slices.Delete(t.sites, at, at+1)
	case t.spare != nil:
		s, t.spare = t.spare, nil
		s.name = name
	default:
		built, err := t.newSite(name)
		if err != nil {
			return nil, err
		}
		s = built
	}
	if len(t.sites) == maxSites {
		t.sites[0].closeIdle()
		t.sites = slices.Delete(t.sites, 0, 1)
	}
	t.sites = append(t.sites, s)
	return s, nil
}

// carrying is the site's transport of a request that carries credentials, or
// of one that carries none.
func (s *site) carrying(credentials bool) tls_client.HttpClient {
	if credentials {
		return s.inner
	}
	return s.bare
}

// topSite is the site of the page at the top a request loads or is made by,
// which Chrome keys its connections by: a script's request, and its
// preflight, are its page's; a navigation's and a form's are the site of the
// page they load, and so are a request's with no browser context, which goes
// out as a navigation typed in. Each hop of a redirect goes out on the
// connections of the first hop's site, where Chrome sends a navigation's hop
// to another site on that site's.
func topSite(browser *browserRequest, target *url.URL) string {
	if browser != nil && browser.scripted() {
		return browser.from.site()
	}
	return originOf(target).site()
}

// closeIdle closes the connections they hold open between requests.
func (t *transports) closeIdle() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sites {
		s.closeIdle()
	}
	if t.spare != nil {
		t.spare.closeIdle()
	}
}

func (s *site) closeIdle() {
	s.inner.CloseIdleConnections()
	s.bare.CloseIdleConnections()
}

// scriptHeaderPriority is the priority Chrome 155 puts on the HEADERS frame of
// fetch(), an XHR and a CORS preflight: exclusive, on no stream, weight 220
// (219 on the wire), as measured in testdata/chrome155-requests.json, where a
// page's is 256. The transport puts the profile's on every other request.
var scriptHeaderPriority = http2.PriorityParam{Exclusive: true, Weight: 219}
