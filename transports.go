package tlsforge

import (
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"net/url"
	"slices"
	"sync"

	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
)

// transports are how a client's requests reach the network: for each
// top-level site, the connections a request that carries credentials goes out
// on, a page's and a script's alike, and the connections of one that carries
// none, each HTTP/2 HEADERS frame with its own priority; and what they are
// built with. A client made Fresh has transports of its own, and shares its
// session (session).
type transports struct {
	behavior behavior.Policy
	// build is what transports are built with: the client's options, with own
	// given before the caller's.
	build func(proxyPool *proxyH2Pool, own ...tls_client.HttpClientOption) []tls_client.HttpClientOption
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
	inner pool
	// bare is where a request that carries no credentials goes out: a CORS
	// preflight, fetch() with credentials omitted, or one kept to its own
	// origin going to another. Chrome sends those on connections of their
	// own, which resume only TLS sessions of their own, as the Fetch
	// standard keys a connection by whether its request carries credentials.
	// Built as inner is, with the same jar.
	bare pool
}

// pool is one kind of a site's connections: the client of the transport's they
// are, and the round tripper it built, which sends each hop of a redirect that
// goes out on them, whichever client follows it.
type pool struct {
	tls_client.HttpClient
	trip fhttp.RoundTripper
}

// hopper is how a client of the transport's sends a request, which is its own
// round tripper's but for the requests of a chain: each of those is sent by
// that of the pool its hop goes out on (chain.on), as Chrome sends a hop of a
// redirect on the connections of its own top-level site and credentials,
// whichever the hop before went out on. A preflight, of no chain, is sent by
// the client's own.
type hopper struct{ own fhttp.RoundTripper }

func (h hopper) RoundTrip(req *fhttp.Request) (*fhttp.Response, error) {
	if ch, ok := req.Context().Value(chainKey{}).(*chain); ok {
		return ch.client.session.cache.roundTrip(ch, req, ch.on.trip)
	}
	return h.own.RoundTrip(req)
}

// wrap is what the pool's client sends by (tls-client's
// WithTransportWrapper): trip, the round tripper it built, kept, in a hopper.
func (p *pool) wrap(trip fhttp.RoundTripper) fhttp.RoundTripper {
	p.trip = trip
	return hopper{trip}
}

// maxSites is how many top-level sites a client keeps the connections and
// TLS sessions of: a request to one more drops the site used longest ago,
// whose idle connections are closed, and whose sessions are forgotten.
var maxSites = legacyPolicy().Int("http.max_site_pools")

// newTransports builds transports with build.
func newTransports(build func(*proxyH2Pool, ...tls_client.HttpClientOption) []tls_client.HttpClientOption,
	proxy string, policies ...behavior.Policy) (*transports, error) {
	t := &transports{behavior: policyArgument(policies), build: build, proxy: proxy}
	spare, err := t.newSite("")
	if err != nil {
		return nil, err
	}
	t.spare = spare
	return t, nil
}

// newSite builds the connections of the site named.
func (t *transports) newSite(name string) (*site, error) {
	var built [2]pool
	proxyPool := newProxyH2Pool(t.behavior)
	for i := range built {
		p := &built[i]
		inner, err := newInnerClient(tls_client.NewNoopLogger(), t.build(proxyPool, tls_client.WithTransportWrapper(p.wrap))...)
		if err != nil {
			// A proxy the transport cannot read is quoted back whole, password
			// and all, by url.Parse and by the transport alike.
			return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, t.proxy))
		}
		p.HttpClient = inner
	}
	return &site{name: name, inner: built[0], bare: built[1]}, nil
}

// fresh are transports of their own, built as these were.
func (t *transports) fresh() (*transports, error) {
	return newTransports(t.build, t.proxy, t.behavior)
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
	if len(t.sites) >= t.behavior.Int("http.max_site_pools") {
		t.sites[0].closeIdle()
		t.sites = slices.Delete(t.sites, 0, 1)
	}
	t.sites = append(t.sites, s)
	return s, nil
}

// carrying is the site's pool of a request that carries credentials, or of one
// that carries none.
func (s *site) carrying(credentials bool) pool {
	if credentials {
		return s.inner
	}
	return s.bare
}

// topSite is the site of the page at the top a request loads or is made by,
// which Chrome keys its connections by: a script's request, and its
// preflight, are its page's; a navigation's and a form's are the site of the
// page they load, and so are a request's with no browser context, which goes
// out as a navigation typed in. So is each hop of a redirect: a navigation's
// hop to another site goes out on that site's, and one back on the first's.
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
var scriptHeaderPriority = priorityFrom(legacyPolicy(), "headers.script_priority")
