package tlsforge

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	tls_client "github.com/igor-lemon/tls-client"
)

// idler is a transport that counts the times its idle connections are
// closed, and does nothing else.
type idler struct {
	tls_client.HttpClient
	closed atomic.Int32
}

func (c *idler) CloseIdleConnections() { c.closed.Add(1) }

// idlers are transports whose every client is an idler, built through
// proxy, but for the n-th built when refuse says so: the clients built so
// far, in order, the two of each site.
func idlers(t *testing.T, proxy string, refuse func(n int) error) (*transports, func() []*idler) {
	t.Helper()
	original := newInnerClient
	t.Cleanup(func() { newInnerClient = original })
	var mu sync.Mutex
	var built []*idler
	tried := 0
	newInnerClient = func(tls_client.Logger, ...tls_client.HttpClientOption) (tls_client.HttpClient, error) {
		mu.Lock()
		defer mu.Unlock()
		tried++
		if err := refuse(tried); err != nil {
			return nil, err
		}
		c := &idler{}
		built = append(built, c)
		return c, nil
	}
	tr, err := newTransports(func(*slog.Logger) []tls_client.HttpClientOption { return nil }, nil, proxy)
	if err != nil {
		t.Fatalf("newTransports: %v", err)
	}
	return tr, func() []*idler {
		mu.Lock()
		defer mu.Unlock()
		return append([]*idler(nil), built...)
	}
}

func refuseNone(int) error { return nil }

// at is the site named's transport of requests that carry credentials or
// none, which a test needs.
func at(t *testing.T, tr *transports, name string, credentials bool) tls_client.HttpClient {
	t.Helper()
	s, err := tr.siteOf(name)
	if err != nil {
		t.Fatalf("site %s: %v", name, err)
	}
	return s.carrying(credentials)
}

func TestASiteKeepsItsConnectionsAndAnotherHasItsOwn(t *testing.T) {
	tr, built := idlers(t, "", refuseNone)
	// The transports a client is made with are the first site's.
	if n := len(built()); n != 2 {
		t.Fatalf("%d transports built with the client", n)
	}
	a, aBare := at(t, tr, "https://a.test", true), at(t, tr, "https://a.test", false)
	again := at(t, tr, "https://a.test", true)
	b, bBare := at(t, tr, "https://b.test", true), at(t, tr, "https://b.test", false)
	got := built()
	if len(got) != 4 || a != got[0] || aBare != got[1] || again != a || b != got[2] || bBare != got[3] {
		t.Errorf("a.test has %p and %p, then %p; b.test %p and %p; built %v", a, aBare, again, b, bBare, got)
	}
}

func TestOneSiteMoreDropsTheOneUsedLongestAgo(t *testing.T) {
	tr, built := idlers(t, "", refuseNone)
	name := func(i int) string { return fmt.Sprintf("https://s%d.test", i) }
	for i := range maxSites {
		at(t, tr, name(i), true)
	}
	// s0 again: s1 is now the one used longest ago, and goes.
	first := at(t, tr, name(0), false)
	at(t, tr, "https://one-more.test", true)
	got := built()
	for i, c := range got {
		want := int32(0)
		if i == 2 || i == 3 {
			want = 1
		}
		if c.closed.Load() != want {
			t.Errorf("transport %d closed its idle connections %d times", i, c.closed.Load())
		}
	}
	if len(tr.sites) != maxSites || first != got[1] {
		t.Errorf("%d sites kept; s0 has %p", len(tr.sites), first)
	}
	// Back, it is built anew, and s2 goes for it; s0 is kept as it was.
	if back := at(t, tr, name(1), true); back == got[2] || len(built()) != len(got)+2 {
		t.Errorf("s1 back with %p, built %d", back, len(built()))
	}
	if got[4].closed.Load() != 1 || at(t, tr, name(0), true) != got[0] {
		t.Error("s2 was not dropped, or s0 was")
	}
}

func TestASiteWhoseConnectionsCannotBeBuiltIsNotKept(t *testing.T) {
	const proxy = "http://alice:s3cr3t@proxy.test:8080"
	refused := errors.New("no transport through " + proxy)
	refusing := true
	tr, built := idlers(t, proxy, func(n int) error {
		// The client's own two, the first site's; then the next site's first,
		// or its second.
		if refusing && n > 2 && n != 4 {
			return refused
		}
		return nil
	})
	at(t, tr, "https://a.test", true)
	for _, which := range []string{"first", "second"} {
		_, err := tr.siteOf("https://b.test")
		if err == nil || !errors.Is(err, refused) || strings.Contains(err.Error(), "s3cr3t") ||
			!strings.HasPrefix(err.Error(), "tlsforge: ") {
			t.Errorf("b.test's %s transport refused: %v", which, err)
		}
		if len(tr.sites) != 1 {
			t.Errorf("%d sites kept", len(tr.sites))
		}
		refusing = which == "first"
	}
	// Asked again once it can be, it is built.
	if _, err := tr.siteOf("https://b.test"); err != nil || len(tr.sites) != 2 || len(built()) != 5 {
		t.Errorf("b.test again: %v, %d sites, %d built", err, len(tr.sites), len(built()))
	}
}

func TestIdleConnectionsCloseOnEverySite(t *testing.T) {
	tr, built := idlers(t, "", refuseNone)
	// Before any site took them, the client's own.
	tr.closeIdle()
	at(t, tr, "https://a.test", true)
	at(t, tr, "https://b.test", true)
	tr.closeIdle()
	for i, c := range built() {
		want := int32(1)
		if i < 2 {
			want = 2
		}
		if c.closed.Load() != want {
			t.Errorf("transport %d closed its idle connections %d times", i, c.closed.Load())
		}
	}
}

func TestSitesAtOnce(t *testing.T) {
	tr, built := idlers(t, "", refuseNone)
	var wg sync.WaitGroup
	for i := range 4 * maxSites {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := tr.siteOf(fmt.Sprintf("https://s%d.test", i%(2*maxSites)))
			if err != nil {
				t.Errorf("site: %v", err)
				return
			}
			_ = s.carrying(i%2 == 0)
			if i%7 == 0 {
				tr.closeIdle()
			}
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, s := range tr.sites {
		if seen[s.name] {
			t.Errorf("%s is kept twice", s.name)
		}
		seen[s.name] = true
	}
	if len(tr.sites) != maxSites || len(built())%2 != 0 {
		t.Errorf("%d sites kept, %d transports built", len(tr.sites), len(built()))
	}
}

func TestARequestGoesOutOnTheConnectionsOfThePageAtTheTop(t *testing.T) {
	page, err := url.Parse("https://www.example.com/page")
	if err != nil {
		t.Fatal(err)
	}
	from := originOf(page)
	for _, tc := range []struct {
		name    string
		browser *browserRequest
		target  string
		site    string
	}{
		{"no browser context", nil, "https://api.example.net/x", "https://example.net"},
		{"a navigation from the page", &browserRequest{kind: KindNavigation, from: from}, "https://api.example.net/x",
			"https://example.net"},
		{"a typed navigation", &browserRequest{kind: KindNavigation}, "https://api.example.net/x", "https://example.net"},
		{"a form", &browserRequest{kind: KindForm, from: from}, "https://api.example.net/x", "https://example.net"},
		{"fetch()", &browserRequest{kind: KindFetch, from: from}, "https://api.example.net/x", "https://example.com"},
		{"an XHR", &browserRequest{kind: KindXHR, from: from}, "http://localhost:8080/x", "https://example.com"},
		{"plain HTTP", nil, "http://www.example.net/x", "http://example.net"},
		{"an address", nil, "https://127.0.0.1:8443/x", "https://127.0.0.1"},
	} {
		target, err := url.Parse(tc.target)
		if err != nil {
			t.Fatal(err)
		}
		if got := topSite(tc.browser, target); got != tc.site {
			t.Errorf("%s to %s: on %s's connections, want %s's", tc.name, tc.target, got, tc.site)
		}
	}
}

func TestARequestToASiteWhoseConnectionsCannotBeBuiltFails(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := newTestClient(t, server.dialing())
	if _, err := client.Get("https://www.example.com/"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	original := newInnerClient
	t.Cleanup(func() { newInnerClient = original })
	newInnerClient = func(tls_client.Logger, ...tls_client.HttpClientOption) (tls_client.HttpClient, error) {
		return nil, errors.New("no transport")
	}
	if _, err := client.Get("https://www.example.net/"); err == nil || err.Error() != "tlsforge: no transport" {
		t.Errorf("another site: %v", err)
	}
	// Those of a site it has go on as they were: www.example.com's are
	// api.example.com's.
	if _, err := client.Get("https://api.example.com/"); err != nil {
		t.Errorf("the same site: %v", err)
	}
}
