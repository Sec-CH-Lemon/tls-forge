package tlsforge

import (
	"context"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	tls_client "github.com/igor-lemon/tls-client"
)

// hpackAsk is a request a scenario's page made, as Chrome's network stack was
// given it: its kind, typed or from the run page, its method, its origin, A
// (www.example.com) or S (api.example.com), and path, and what the script gave
// fetch(). A preflight is none: the client makes it.
type hpackAsk struct {
	kind         RequestKind
	fromPage     bool
	method, path string
	origin       string
	body         string
	header       []profile.Field
}

// typed, page and fetched are a scenario's run page, typed, a navigation from
// it, and a fetch() of its origin.
func typed(path string) hpackAsk   { return hpackAsk{kind: KindNavigation, path: path} }
func fromRun(path string) hpackAsk { return hpackAsk{kind: KindNavigation, fromPage: true, path: path} }
func fetched(method, path string, header ...string) hpackAsk {
	ask := hpackAsk{kind: KindFetch, fromPage: true, method: method, path: path}
	for i := 0; i < len(header); i += 2 {
		ask.header = append(ask.header, profile.Field{Name: header[i], Value: header[i+1]})
	}
	return ask
}

// withBody is ask with a body, of a fetch() given a string or JSON.
func (ask hpackAsk) withBody(body string) hpackAsk { ask.body = body; return ask }

// of is ask of another origin.
func (ask hpackAsk) of(origin string) hpackAsk { ask.origin = origin; return ask }

// hpackAsked is what the page of each scenario of testdata/chrome155-hpack.json
// asked for, in order: as its script in internal/harness says.
var hpackAsked = map[string][]hpackAsk{
	"hpack-fetch":       {typed("/run/hpack-fetch"), fetched("GET", "/p/hpack-fetch"), fetched("GET", "/done/hpack-fetch")},
	"hpack-fetch-again": {typed("/run/hpack-fetch-again"), fetched("GET", "/p/hpack-a"), fetched("GET", "/p/hpack-b"), fetched("GET", "/p/hpack-a"), fetched("GET", "/done/hpack-fetch-again")},
	"hpack-navigation":  {typed("/run/hpack-navigation"), fromRun("/p/hpack-navigation?quiet")},
	"hpack-cookies":     {typed("/run/hpack-cookies?cookie=1"), fetched("GET", "/p/hpack-cookies-fetch"), fromRun("/p/hpack-cookies?quiet")},
	"hpack-methods": {typed("/run/hpack-methods"),
		fetched("PUT", "/p/hpack-put", "content-type", "text/plain;charset=UTF-8").withBody("x"),
		fetched("DELETE", "/p/hpack-delete"),
		fetched("PATCH", "/p/hpack-patch", "content-type", "text/plain;charset=UTF-8").withBody("y"),
		fetched("POST", "/p/hpack-post", "content-type", "application/json").withBody("{}"),
		fetched("GET", "/done/hpack-methods")},
	"hpack-preflight": {typed("/run/hpack-preflight"), fetched("GET", "/cors/hpack-simple").of("S"),
		fetched("GET", "/cors/hpack-preflighted?maxage=0", "x-foo", "bar").of("S"), fetched("GET", "/done/hpack-preflight")},
	"hpack-big-cookie": {typed("/run/hpack-big-cookie?big=4080"), fetched("GET", "/p/hpack-big-1"), fetched("GET", "/p/hpack-big-2"), fetched("GET", "/done/hpack-big-cookie")},
	"hpack-table-64k":  {typed("/run/hpack-table-64k"), fetched("GET", "/p/hpack-table-64k"), fetched("GET", "/done/hpack-table-64k")},
	"hpack-table-1k":   {typed("/run/hpack-table-1k"), fetched("GET", "/p/hpack-table-1k"), fetched("GET", "/done/hpack-table-1k")},
	"hpack-records-header": {typed("/run/hpack-records-header"),
		fetched("GET", "/p/hpack-records-header", "x-foo", strings.Repeat("a", 8000)), fetched("GET", "/done/hpack-records-header")},
	"hpack-records-post-1k": {typed("/run/hpack-records-post-1k"),
		fetched("POST", "/p/hpack-records-post-1k", "content-type", "text/plain;charset=UTF-8").withBody(strings.Repeat("a", 1000)),
		fetched("GET", "/done/hpack-records-post-1k")},
	"hpack-records-post-64k": {typed("/run/hpack-records-post-64k"),
		fetched("POST", "/p/hpack-records-post-64k", "content-type", "text/plain;charset=UTF-8").withBody(strings.Repeat("a", 65536)),
		fetched("GET", "/done/hpack-records-post-64k")},
	"hpack-records-long-url": {typed("/run/hpack-records-long-url"),
		fetched("GET", "/p/hpack-records-long-url?"+strings.Repeat("a", 8000)), fetched("GET", "/done/hpack-records-long-url")},
	"hpack-records-big-header": {typed("/run/hpack-records-big-header"),
		fetched("GET", "/p/hpack-records-big-header", "x-foo", strings.Repeat("a", 30000)), fetched("GET", "/done/hpack-records-big-header")},
	"hpack-records-cookie-2k": {typed("/run/hpack-records-cookie-2k?big=2044"),
		fetched("GET", "/p/hpack-records-cookie-2k"), fetched("GET", "/done/hpack-records-cookie-2k")},
	"hpack-records-cookie-4k": {typed("/run/hpack-records-cookie-4k?big=4092"),
		fetched("GET", "/p/hpack-records-cookie-4k"), fetched("GET", "/done/hpack-records-cookie-4k")},
	"hpack-records-cookie-16k": {typed("/run/hpack-records-cookie-16k?big=4091&bigs=4"),
		fetched("GET", "/p/hpack-records-cookie-16k"), fetched("GET", "/done/hpack-records-cookie-16k")},
	"hpack-records-post-16k": {typed("/run/hpack-records-post-16k"),
		fetched("POST", "/p/hpack-records-post-16k", "content-type", "text/plain;charset=UTF-8").withBody(strings.Repeat("a", 16376)),
		fetched("GET", "/done/hpack-records-post-16k")},
	"hpack-big-header": {typed("/run/hpack-big-header"),
		fetched("GET", "/p/hpack-big-header", "x-foo", strings.Repeat("a", 30000)), fetched("GET", "/done/hpack-big-header")},
	"hpack-bigger-header": {typed("/run/hpack-bigger-header"),
		fetched("GET", "/p/hpack-bigger-header", "x-foo", strings.Repeat("a", 60000)), fetched("GET", "/done/hpack-bigger-header")},
	"hpack-big-header-16k": {typed("/run/hpack-big-header-16k"),
		fetched("GET", "/p/hpack-big-header-16k", "x-foo", strings.Repeat("a", 30000)), fetched("GET", "/done/hpack-big-header-16k")},
	"hpack-bigger-header-16k": {typed("/run/hpack-bigger-header-16k"),
		fetched("GET", "/p/hpack-bigger-header-16k", "x-foo", strings.Repeat("a", 60000)),
		fetched("GET", "/done/hpack-bigger-header-16k")},
}

// hpackDiffers are the scenarios of testdata/chrome155-hpack.json tls-forge
// does not write as Chrome did, and why: none, kept for a difference measured
// later.
var hpackDiffers = map[string]string{}

// headlessChrome is the profile of the Chrome the HPACK fixture was measured
// on: chrome_155_macos, with the user agent HeadlessChrome said, so that each
// field is as long as Chrome's and the table empties as Chrome's did.
func headlessChrome(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	p = p.Clone()
	p.UserAgent = loadChromeRequests(t).Scenarios["nav-direct"].H2[0].header("user-agent")
	for i, h := range p.Headers {
		if h.Name == "user-agent" {
			p.Headers[i].Value = p.UserAgent
		}
	}
	return p
}

func TestEveryHPACKScenarioMeasuredIsSent(t *testing.T) {
	fixture, err := harness.LoadHPACK("testdata/chrome155-hpack.json")
	if err != nil {
		t.Fatalf("LoadHPACK: %v", err)
	}
	if got := slices.Sorted(maps.Keys(hpackAsked)); !slices.Equal(got, slices.Sorted(maps.Keys(fixture.Scenarios))) {
		t.Errorf("sent %v, measured %v", got, slices.Sorted(maps.Keys(fixture.Scenarios)))
	}
}

func TestLaterRequestsGoIntoHPACKAsChromeWroteThem(t *testing.T) {
	// Each scenario's page sent as Chrome's was asked to, to the bench's own
	// server, and read back as the bench read Chrome's: every header block of
	// every connection held to Chrome's against the dynamic table the ones
	// before it left, from a server allowing the table Chrome's allowed.
	fixture, err := harness.LoadHPACK("testdata/chrome155-hpack.json")
	if err != nil {
		t.Fatalf("LoadHPACK: %v", err)
	}
	server, err := harness.StartHPACKServer()
	if err != nil {
		t.Fatalf("StartHPACKServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	chrome := headlessChrome(t)
	for _, scenario := range slices.Sorted(maps.Keys(hpackAsked)) {
		want := fixture.Scenarios[scenario]
		t.Run(scenario, func(t *testing.T) {
			// The bench's ports have five digits, as Chrome's had, and as
			// every system's own ports have: each field naming one is as
			// long as Chrome's, so the table empties where Chrome's did.
			port := strconv.Itoa(server.PortFor(harness.H2Settings{Table: want.Table, Frame: want.Frame}))
			if len(port) != 5 {
				t.Fatalf("the bench listens on %s; Chrome was measured on ports of five digits", port)
			}
			server.Reset()
			opts := []Option{WithProfileValue(chrome), WithTransportOption(tls_client.WithDialContext(
				func(ctx context.Context, network, addr string) (net.Conn, error) {
					_, at, _ := net.SplitHostPort(addr)
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", at))
				}))}
			if hpackDiffers[scenario] != "" {
				// A request the server refuses is tried again until the
				// client gives up.
				opts = append(opts, WithTimeout(2*time.Second))
			}
			client := newTestClient(t, opts...)
			origin := map[string]string{"": "https://www.example.com:" + port, "S": "https://api.example.com:" + port}
			run := origin[""] + hpackAsked[scenario][0].path
			for _, ask := range hpackAsked[scenario] {
				browser := &BrowserContext{Kind: ask.kind}
				if ask.fromPage {
					browser.Initiator = run
				}
				req := &Request{Method: ask.method, URL: origin[ask.origin] + ask.path, Body: []byte(ask.body),
					Header: ask.header, Browser: browser}
				if _, err := client.Do(req); err != nil {
					if hpackDiffers[scenario] != "" {
						return
					}
					t.Fatalf("%s %s: %v", ask.method, req.URL, err)
				}
			}
			entries, err := server.Requests()
			if err != nil {
				t.Fatalf("Requests: %v", err)
			}
			got, err := server.Written(entries, want.Table, want.Records)
			if err != nil {
				t.Fatalf("Written: %v", err)
			}
			diffs := harness.DiffHPACK(want, harness.HPACKScenario{Connections: got})
			if why := hpackDiffers[scenario]; why != "" {
				if len(diffs) == 0 {
					t.Errorf("%s is written as Chrome wrote it: take it out of hpackDiffers (%s)", scenario, why)
				}
				return
			}
			for _, diff := range diffs {
				t.Errorf("%s (%s): %s", scenario, want.Note, diff)
			}
		})
	}
}
