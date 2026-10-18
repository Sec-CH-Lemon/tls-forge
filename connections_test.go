package tlsforge

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// script is the context of fetch() or an XHR of a scenario's run page, with
// the credentials and mode it was given; the page is filled in when it is
// sent.
func script(kind RequestKind, credentials, mode string) BrowserContext {
	return BrowserContext{Kind: kind, Credentials: credentials, Mode: mode}
}

// askedOnConnections are the requests each scenario of
// testdata/chrome155-connections.json had its run page ask for, by their
// place among the requests Chrome sent, each in its context: the rest after
// the run page, preflights, the hops of redirects and a request sent again
// for a 421, Chrome made itself, as the client makes them. A scenario whose
// requests had other places over HTTP/2 than over HTTP/1.1 is named with the
// protocol after a slash.
var askedOnConnections = map[string]map[int]BrowserContext{
	"conn-fetch":                                 {1: script(KindFetch, "", "")},
	"conn-fetch-omit":                            {1: script(KindFetch, credentialsNone, "")},
	"conn-fetch-include":                         {1: script(KindFetch, credentialsAll, "")},
	"conn-xhr":                                   {1: script(KindXHR, "", "")},
	"conn-xhr-credentials":                       {1: script(KindXHR, credentialsAll, "")},
	"conn-omit-and-not":                          {1: script(KindFetch, credentialsNone, ""), 2: script(KindFetch, "", ""), 3: script(KindFetch, credentialsNone, "")},
	"conn-nav-after-omit":                        {1: script(KindFetch, credentialsNone, ""), 2: {Kind: KindNavigation}},
	"conn-nav-same-site":                         {1: {Kind: KindNavigation}},
	"conn-nav-cross-site":                        {1: {Kind: KindNavigation}},
	"conn-nav-cross-site-after-include":          {1: script(KindFetch, credentialsAll, ""), 2: {Kind: KindNavigation}},
	"conn-nav-redirect-cross-site":               {1: {Kind: KindNavigation}},
	"conn-nav-redirect-cross-site-after-include": {1: script(KindFetch, credentialsAll, ""), 2: {Kind: KindNavigation}},
	"conn-fetch-same-site":                       {1: script(KindFetch, "", "")},
	"conn-fetch-same-site-include":               {1: script(KindFetch, credentialsAll, "")},
	"conn-fetch-same-site-no-cors":               {1: script(KindFetch, "", modeNoCORS)},
	"conn-fetch-cross-site":                      {1: script(KindFetch, "", "")},
	"conn-fetch-cross-site-include":              {1: script(KindFetch, credentialsAll, "")},
	"conn-fetch-cross-site-no-cors":              {1: script(KindFetch, "", modeNoCORS)},
	"conn-xhr-cross-site":                        {1: script(KindXHR, "", "")},
	"conn-xhr-cross-site-credentials":            {1: script(KindXHR, credentialsAll, "")},
	"conn-fetch-cross-site-both":                 {1: script(KindFetch, credentialsAll, ""), 2: script(KindFetch, "", ""), 3: script(KindFetch, "", modeNoCORS), 4: script(KindFetch, credentialsAll, "")},
	"conn-fetch-cross-site-then-same-site":       {1: script(KindFetch, "", ""), 2: script(KindFetch, "", "")},
	"conn-fetch-omit-then-cross-site":            {1: script(KindFetch, credentialsNone, ""), 2: script(KindFetch, "", "")},
	"conn-preflight":                             {2: script(KindFetch, "", "")},
	"conn-preflight-include":                     {2: script(KindFetch, credentialsAll, "")},
	"conn-preflight-include-after-cors":          {1: script(KindFetch, "", ""), 3: script(KindFetch, credentialsAll, "")},
	"conn-redirect-to-cross-site":                {1: script(KindFetch, "", ""), 2: script(KindFetch, "", "")},
	"conn-redirect-include-to-cross-site":        {1: script(KindFetch, "", ""), 2: script(KindFetch, credentialsAll, "")},
	"conn-resume":                                {1: script(KindFetch, "", ""), 2: script(KindFetch, "", ""), 3: script(KindFetch, credentialsNone, ""), 4: script(KindFetch, credentialsNone, "")},
	"conn-misdirected-pooled":                    {1: script(KindFetch, credentialsAll, "")},
	"conn-misdirected-pooled-again/h2":           {1: script(KindFetch, credentialsAll, ""), 3: script(KindFetch, credentialsAll, "")},
	"conn-misdirected-pooled-again/h1":           {1: script(KindFetch, credentialsAll, ""), 2: script(KindFetch, credentialsAll, "")},
	"conn-misdirected-first":                     {1: script(KindFetch, "", "")},
	"conn-misdirected-always":                    {1: script(KindFetch, "", ""), 3: script(KindFetch, "", "")},
	"conn-misdirected-post":                      {1: script(KindFetch, "", "")},
	"conn-misdirected-nav":                       {1: {Kind: KindNavigation}},
	"conn-misdirected-redirect":                  {1: script(KindFetch, credentialsAll, "")},
	"conn-misdirected-preflight/h2":              {1: script(KindFetch, credentialsNone, ""), 4: script(KindFetch, credentialsAll, "")},
	"conn-misdirected-preflight/h1":              {1: script(KindFetch, credentialsNone, ""), 3: script(KindFetch, credentialsAll, "")},
}

// apartFromChrome are the scenarios, by name and protocol, whose requests the
// client sends on other connections than Chrome did: the connections it sends
// them on, as onConnections says them, and why.
var apartFromChrome = map[string]struct{ sent, why string }{
	"conn-redirect-to-cross-site/h2":                {"1* 2 1* 1*", uncredentialed},
	"conn-redirect-to-cross-site/h1":                {"1* 2 1* 3", uncredentialed},
	"conn-nav-redirect-cross-site/h2":               {"1* 1* 1*", redirected},
	"conn-nav-redirect-cross-site-after-include/h2": {"1* 1* 1* 1*", redirected},
	"conn-nav-redirect-cross-site-after-include/h1": {"1* 2 1* 2", redirected},
}

// Why a client's requests go out on other connections than Chrome's.
const (
	uncredentialed = "Chrome follows a redirect that leaves a request without credentials on the connections of " +
		"requests that carry none; the client follows it on the connections the request went out on"
	redirected = "Chrome sends a navigation's redirect to another site on the connections of that site's, as it " +
		"keeps each top-level site's apart; the client follows a redirect on the connections of the first hop's site"
)

// onConnections says which connection each request came on, numbered from
// the first, in the order requests first came on them, and with a * where
// that connection resumed a TLS session.
func onConnections(conns []int64, resumed []bool) string {
	numbered := map[int64]int{}
	said := make([]string, len(conns))
	for i, conn := range conns {
		if numbered[conn] == 0 {
			numbered[conn] = len(numbered) + 1
		}
		said[i] = strconv.Itoa(numbered[conn])
		if resumed[i] {
			said[i] += "*"
		}
	}
	return strings.Join(said, " ")
}

func TestOnConnectionsNumbersThemByFirstUse(t *testing.T) {
	if got := onConnections([]int64{7, 9, 7, 3}, []bool{true, false, true, false}); got != "1* 2 1* 3" {
		t.Errorf("onConnections: %q", got)
	}
	if got := onConnections(nil, nil); got != "" {
		t.Errorf("onConnections of nothing: %q", got)
	}
}

func TestRequestsGoOutOnTheConnectionsChromeSentThemOn(t *testing.T) {
	fixture, err := harness.LoadRequests("testdata/chrome155-connections.json")
	if err != nil {
		t.Fatalf("LoadRequests: %v", err)
	}
	for _, id := range slices.Sorted(maps.Keys(fixture.Scenarios)) {
		for proto, want := range map[string][]harness.Request{"h2": fixture.Scenarios[id].H2, "h1": fixture.Scenarios[id].H1} {
			asked, ok := askedOnConnections[id+"/"+proto]
			if !ok {
				asked, ok = askedOnConnections[id]
			}
			if !ok {
				t.Errorf("%s over %s is measured, and not sent", id, proto)
				continue
			}
			t.Run(id+"/"+proto, func(t *testing.T) {
				got := sendOnConnections(t, proto, id, asked, want)
				var sentAs, chromeAs []string
				var conns []int64
				var resumed []bool
				for _, r := range got {
					sentAs = append(sentAs, r.method+" "+r.url)
					conns, resumed = append(conns, r.conn), append(resumed, r.resumed)
				}
				var chromeConns []int64
				var chromeResumed []bool
				for _, r := range want {
					chromeAs = append(chromeAs, r.Method+" "+r.URL)
					chromeConns, chromeResumed = append(chromeConns, int64(r.Conn)), append(chromeResumed, r.Resumed)
				}
				if !slices.Equal(sentAs, chromeAs) {
					t.Fatalf("sent\n  %q\nChrome\n  %q", sentAs, chromeAs)
				}
				sent, chrome := onConnections(conns, resumed), onConnections(chromeConns, chromeResumed)
				apart, known := apartFromChrome[id+"/"+proto]
				switch {
				case known && (sent != apart.sent || sent == chrome):
					t.Errorf("sent on %s, Chrome on %s; the client was to send them on %s: %s", sent, chrome, apart.sent, apart.why)
				case !known && sent != chrome:
					t.Errorf("sent on %s, Chrome on %s (%s)", sent, chrome, fixture.Scenarios[id].Note)
				}
			})
		}
	}
	for which := range askedOnConnections {
		id, proto, apart := strings.Cut(which, "/")
		if _, ok := fixture.Scenarios[id]; !ok || apart && proto != "h2" && proto != "h1" {
			t.Errorf("%s is sent, and not measured", which)
		}
	}
	for which := range apartFromChrome {
		id, proto, _ := strings.Cut(which, "/")
		if _, ok := fixture.Scenarios[id]; !ok || proto != "h2" && proto != "h1" {
			t.Errorf("%s is no scenario measured", which)
		}
	}
}

// sendOnConnections sends what the run page of scenario id asked for, each
// request in its context, to a recorder speaking proto, after the page it was
// opened from and Chrome's closing every idle connection, and is what the
// recorder kept from the run page on: preflights and redirects too.
func sendOnConnections(t *testing.T, proto, id string, asked map[int]BrowserContext, want []harness.Request) []*keptRequest {
	t.Helper()
	server := newRecorder(t, proto, answeringAsMeasured)
	client, err := New(WithProfile("chrome_155_macos"), server.trusting(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	lobby := "https://www.example.com/p/lobby?after=2&next=/run/" + id
	if _, err := client.Do(&Request{URL: lobby, Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
		t.Fatalf("Do %s: %v", lobby, err)
	}
	client.CloseIdleConnections()
	skip := len(server.requests())
	contexts := map[int]BrowserContext{0: {Kind: KindNavigation, Initiator: lobby}}
	maps.Copy(contexts, asked)
	for _, at := range slices.Sorted(maps.Keys(contexts)) {
		measured, browser := want[at], contexts[at]
		if at > 0 {
			browser.Initiator = run(id)
		}
		req := &Request{Method: measured.Method, URL: measured.URL, Body: []byte(measured.Body), Browser: &browser}
		for _, h := range measured.Headers {
			if strings.EqualFold(h[0], "content-type") {
				req.Header = append(req.Header, profile.Field{Name: "Content-Type", Value: h[1]})
			}
		}
		if _, err := client.Do(req); err != nil {
			t.Fatalf("Do %s: %v", measured.URL, err)
		}
		if strings.Contains(measured.URL, "close=1") {
			// Chrome's script waited for the connection to end; so does the
			// client's next request.
			sent := server.requests()
			server.waitClosed(t, sent[len(sent)-1].conn)
		}
	}
	return server.requests()[skip:]
}
