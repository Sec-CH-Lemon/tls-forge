package tlsforge

import (
	"context"
	"maps"
	"net"
	"slices"
	"strconv"
	"testing"

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
}

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
			port := strconv.Itoa(server.PortFor(want.Table))
			if len(port) != 5 {
				t.Fatalf("the bench listens on %s; Chrome was measured on ports of five digits", port)
			}
			server.Reset()
			client := newTestClient(t, WithProfileValue(chrome), WithTransportOption(tls_client.WithDialContext(
				func(ctx context.Context, network, addr string) (net.Conn, error) {
					_, at, _ := net.SplitHostPort(addr)
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", at))
				})))
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
					t.Fatalf("%s %s: %v", ask.method, req.URL, err)
				}
			}
			entries, err := server.Requests()
			if err != nil {
				t.Fatalf("Requests: %v", err)
			}
			got, err := server.Written(entries, want.Table)
			if err != nil {
				t.Fatalf("Written: %v", err)
			}
			for _, diff := range harness.DiffHPACK(want, harness.HPACKScenario{Connections: got}) {
				t.Errorf("%s (%s): %s", scenario, want.Note, diff)
			}
		})
	}
}
