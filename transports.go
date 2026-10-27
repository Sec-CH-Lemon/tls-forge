package tlsforge

import (
	"context"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"maps"
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
	// given before the caller's, for the site whose name site says.
	build func(proxyPool *proxyH2Pool, site func() string, own ...tls_client.HttpClientOption) []tls_client.HttpClientOption
	// proxy is what an error building them is cleaned of.
	proxy string

	mu sync.Mutex
	// sites are the connections of each top-level site a request went to,
	// the one used longest ago first, maxSites at most. Chrome keys its
	// connections and their TLS sessions by the site of the page at the top
	// (its network anonymization key), as well as by whether a request
	// carries credentials (testdata/chrome155-connections.json): a page of
	// another site has connections of its own, as do the requests it makes.
	sites   []*site
	retired map[*site]bool
	closed  bool
	// spare are the connections built with the transports, which the first
	// site to need some takes.
	spare *site
	// ending is what its connections let go of answers in the background
	// for (leave), and draining those still at it, each until its channel
	// is closed: closeIdle ends them and waits for them, so that the next
	// request opens a connection of its own.
	ending   context.Context
	end      context.CancelFunc
	draining map[<-chan struct{}]bool
}

// site are the connections of one top-level site.
type site struct {
	name    string
	refs    int // chain and background-drain leases, under transports.mu
	retired bool
	inner   pool
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
		return ch.client.session.cache.roundTrip(ch, req, dnsUpgrade{ch.client.upgrades, ch.on.trip})
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
func newTransports(build func(*proxyH2Pool, func() string, ...tls_client.HttpClientOption) []tls_client.HttpClientOption,
	proxy string, policies ...behavior.Policy) (*transports, error) {
	t := &transports{behavior: policyArgument(policies), build: build, proxy: proxy}
	t.ending, t.end = context.WithCancel(context.Background())
	t.draining = map[<-chan struct{}]bool{}
	t.retired = map[*site]bool{}
	spare, err := t.newSite("")
	if err != nil {
		return nil, err
	}
	t.spare = spare
	return t, nil
}

// newSite builds the connections of the site named, which the spare is when
// the first site takes it.
func (t *transports) newSite(name string) (*site, error) {
	s := &site{name: name}
	proxyPool := newProxyH2Pool(t.behavior)
	for _, p := range []*pool{&s.inner, &s.bare} {
		inner, err := newInnerClient(tls_client.NewNoopLogger(), t.build(proxyPool, s.named, tls_client.WithTransportWrapper(p.wrap))...)
		if err != nil {
			// A proxy the transport cannot read is quoted back whole, password
			// and all, by url.Parse and by the transport alike.
			return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, t.proxy))
		}
		p.HttpClient = inner
	}
	return s, nil
}

// named is the site's name, asked of each request after siteOf handed the
// site out.
func (s *site) named() string { return s.name }

// fresh are transports of their own, built as these were.
func (t *transports) fresh() (*transports, error) {
	return newTransports(t.build, t.proxy, t.behavior)
}

// siteOf are the connections of the top-level site named: a request to a page
// of it goes out on them, as does every request such a page makes.
func (t *transports) siteOf(name string) (*site, error) {
	t.mu.Lock()
	var evicted *site
	defer func() {
		t.mu.Unlock()
		if evicted != nil {
			evicted.closeIdle()
		}
	}()
	if t.closed {
		return nil, fmt.Errorf("tlsforge: this client is closed; construct a new one")
	}
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
		evicted = t.sites[0]
		evicted.retired = true
		if evicted.refs > 0 {
			t.retired[evicted] = true
		}
		t.sites = slices.Delete(t.sites, 0, 1)
	}
	t.sites = append(t.sites, s)
	s.refs++
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

// closeIdle closes the connections they hold open between requests, those
// they let go of an answer on in the background (leave) too: it ends them and
// waits for them, so that none is put back to be used once it returns.
func (t *transports) closeIdle() { t.clearIdle(false) }
func (t *transports) close()     { t.clearIdle(true) }

// sitesLocked snapshots ownership, never transport I/O. Retired entries live
// only while a request or a detached drainer can still return a connection.
func (t *transports) sitesLocked() []*site {
	sites := append([]*site(nil), t.sites...)
	for s := range t.retired {
		sites = append(sites, s)
	}
	if t.spare != nil {
		sites = append(sites, t.spare)
	}
	return sites
}

func (t *transports) clearIdle(permanent bool) {
	t.mu.Lock()
	var sites []*site
	if permanent {
		t.closed = true
		sites = t.sitesLocked()
		for _, s := range sites {
			s.retired = true
			if s.refs > 0 {
				t.retired[s] = true
			}
		}
		t.sites = nil
		t.spare = nil
	}
	end, draining := t.end, slices.Collect(maps.Keys(t.draining))
	if !t.closed {
		t.ending, t.end = context.WithCancel(context.Background())
	}
	t.mu.Unlock()
	end()
	for _, done := range draining {
		<-done
	}
	if !permanent {
		t.mu.Lock()
		sites = t.sitesLocked()
		t.mu.Unlock()
	}
	for _, s := range sites {
		s.closeIdle()
	}
}

// releaseSite closes a retired pool after the last user has finished with its
// response. Final bodies keep their chain's lease until Client.do returns.
func (t *transports) releaseSite(s *site) {
	t.mu.Lock()
	s.refs--
	close := s.retired && s.refs == 0
	if close {
		delete(t.retired, s)
	}
	t.mu.Unlock()
	if close {
		s.closeIdle()
	}
}

// Register before starting the drain: CloseIdleConnections must also wait for
// a drain still inside its synchronous grace period. Preserve its concrete
// response body for fhttp's buffered/detached/priority machinery.
func (t *transports) letGo(drain func(context.Context) <-chan struct{}, owners ...*site) {
	tracked := make(chan struct{})
	t.mu.Lock()
	ending := t.ending
	t.draining[tracked] = true
	for _, s := range owners {
		if s != nil {
			s.refs++
		}
	}
	t.mu.Unlock()
	done := drain(ending)
	finish := func() {
		for _, s := range owners {
			if s != nil {
				t.releaseSite(s)
			}
		}
		t.mu.Lock()
		delete(t.draining, tracked)
		t.mu.Unlock()
		close(tracked)
	}
	select {
	case <-done:
		finish()
		return
	default:
	}
	go func() { <-done; finish() }()
}

func (s *site) closeIdle() {
	s.inner.CloseIdleConnections()
	s.bare.CloseIdleConnections()
}

// reapIdle closes, in every pool of every site, the idle HTTP/1.1 connections
// an on-request idle timeout ("h1.idle_reap") finds too old, and the
// connections that lost a race to QUIC and wait past their time
// ("http.unused_idle_connection_timeout_ms") or that their servers closed,
// as Chromium's one socket pool cleans up the idle sockets of every host each
// time a socket is asked of it, and never on its own: but at but, the address
// of the request that asks, whose round trip cleans up there.
func (t *transports) reapIdle(but string) {
	t.mu.Lock()
	sites := t.sitesLocked()
	t.mu.Unlock()
	for _, s := range sites {
		s.reapIdle(but)
	}
}

func (s *site) reapIdle(but string) {
	for _, p := range []pool{s.inner, s.bare} {
		if r, ok := p.HttpClient.(interface{ ReapIdleConnectionsBut(string) }); ok {
			r.ReapIdleConnectionsBut(but)
		}
	}
}
