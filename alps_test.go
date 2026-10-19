package tlsforge

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	tls_client "github.com/igor-lemon/tls-client"
)

// alpsFixture is what Chrome made of the bench's ALPS server.
const alpsFixture = "testdata/chrome155-alps.json"

// alpsPage is what the page of a scenario of testdata/chrome155-alps.json
// asked for, in order, where it is not a page typed into the browser whose
// script fetches /done/ID (alpsAskedOf): the variant of what the bench's
// ALPS server gives, as internal/harness names it, and whether the run page,
// the first, was opened from the lobby, a page over plain HTTP.
type alpsPage struct {
	variant string
	lobby   bool
	asked   []hpackAsk
}

// alpsPages are the scenarios of two navigations.
var alpsPages = map[string]alpsPage{
	"alps-accept-ch-link": {"accept-ch", true,
		[]hpackAsk{typed("/run/alps-accept-ch-link"), fromRun("/p/alps-accept-ch-link?quiet")}},
	"alps-accept-ch-form": {"accept-ch", true,
		[]hpackAsk{typed("/run/alps-accept-ch-form"), formPosted("/p/alps-accept-ch-form?quiet", "a=1&b=x+y")}},
	"alps-accept-ch-redirect": {"accept-ch", true, []hpackAsk{typed("/run/alps-accept-ch-redirect"),
		fromRun("/r/302/alps-accept-ch-redirect?to=/p/alps-accept-ch-redirected%3Fquiet")}},
	"alps-accept-ch-asked": {"accept-ch", true, []hpackAsk{typed("/run/alps-accept-ch-asked?accept=sec-ch-ua-arch"),
		fromRun("/p/alps-accept-ch-asked?quiet")}},
}

// formPosted is a form a scenario's run page posted, its body as given.
func formPosted(path, body string) hpackAsk {
	return hpackAsk{kind: KindForm, fromPage: true, method: "POST", path: path, body: body}
}

// alpsAskedOf is what the page of scenario asked for: as alpsPages says, or
// the page typed, of the variant the scenario is named after, and its
// script's fetch() of /done/ID.
func alpsAskedOf(scenario string) alpsPage {
	if page, ok := alpsPages[scenario]; ok {
		return page
	}
	return alpsPage{variant: strings.TrimPrefix(scenario, "alps-"),
		asked: []hpackAsk{typed("/run/" + scenario), fetched("GET", "/done/"+scenario)}}
}

// alpsDiffer are the scenarios of testdata/chrome155-alps.json tls-forge does
// not make of the bench's ALPS server what Chrome did, and why, the flight of
// its handshake aside (flightApart), and those whose ALPS Chrome refused
// (differs).
var alpsDiffer = map[string]string{
	"alps-settings":                      alpsSettingsApart,
	"alps-settings-flags":                alpsSettingsApart,
	"alps-accept-ch":                     alpsHintsApart,
	"alps-accept-ch-link":                alpsHintsApart,
	"alps-accept-ch-form":                alpsHintsApart,
	"alps-accept-ch-redirect":            alpsHintsApart,
	"alps-accept-ch-asked":               alpsHintsApart,
	"alps-accept-ch-two-entries":         alpsHintsApart,
	"alps-accept-ch-other-origin":        alpsHintsApart,
	"alps-accept-ch-two-frames":          alpsHintsApart,
	"alps-accept-ch-malformed-then-good": alpsHintsApart,
	"alps-accept-ch-good-then-malformed": alpsHintsApart,
}

const (
	// alpsSettingsApart is why the first request of a connection whose ALPS
	// gave SETTINGS differs: the transport takes the server's SETTINGS from its
	// first SETTINGS frame, not from ALPS, and opens no block with a size
	// update.
	alpsSettingsApart = "the transport does not take ALPS's SETTINGS: no size update in the first request"
	// alpsHintsApart is why a page's request over a connection whose ALPS
	// asked for client hints differs: it does not carry them.
	alpsHintsApart = "the client hints ALPS asks for are not sent"
	// alpsRefused is why tls-forge answers what Chrome refuses: the transport
	// does not read ALPS, where Chrome ends the connection with GOAWAY and the
	// request fails.
	alpsRefused = "the transport does not read ALPS: it sends its request where Chrome says GOAWAY and the request fails"
)

// differs is why tls-forge does not make of scenario what Chrome did, want:
// as alpsDiffer says, and alpsRefused for one whose ALPS Chrome refused.
func differs(scenario string, want harness.ALPSScenario) string {
	if why := alpsDiffer[scenario]; why != "" {
		return why
	}
	if n := len(want.Handshakes); n > 0 && want.Handshakes[n-1].GoAway != "" {
		return alpsRefused
	}
	return ""
}

// flightApart is why the flight of every handshake that negotiated ALPS
// differs from Chrome's: utls writes the client's EncryptedExtensions and
// Finished in a record each, where Chrome's BoringSSL writes them in one.
const flightApart = "utls writes the client's EncryptedExtensions and Finished in a record each, where Chrome writes them in one"

// apart sets aside of got the flight flightApart says, after holding it to
// being Chrome's written apart: what each record carried, EE+F as EE and F.
// It counts the flights it set aside in set.
func apart(want, got harness.ALPSScenario, set *int) harness.ALPSScenario {
	for i := range min(len(got.Handshakes), len(want.Handshakes)) {
		split := []string{}
		for _, carried := range want.Handshakes[i].Flight {
			split = append(split, strings.Split(carried, "+")...)
		}
		if slices.Equal(got.Handshakes[i].Flight, split) && !slices.Equal(split, want.Handshakes[i].Flight) {
			got.Handshakes[i].Flight = want.Handshakes[i].Flight
			*set++
		}
	}
	return got
}

func TestALPSIsTakenAsChromeTookIt(t *testing.T) {
	fixture, err := harness.LoadALPS(alpsFixture)
	if err != nil {
		t.Fatalf("LoadALPS: %v", err)
	}
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if len(strconv.Itoa(server.Plain)) != 5 {
		t.Fatalf("the bench listens on %d; Chrome was measured on ports of five digits", server.Plain)
	}
	chrome := headlessChrome(t)
	setAside := 0
	t.Cleanup(func() {
		if setAside == 0 {
			t.Errorf("no flight was set aside: take flightApart out (%s)", flightApart)
		}
	})
	for _, scenario := range slices.Sorted(maps.Keys(fixture.Scenarios)) {
		want, page := fixture.Scenarios[scenario], alpsAskedOf(scenario)
		t.Run(scenario, func(t *testing.T) {
			port := strconv.Itoa(server.ALPS[page.variant])
			if len(port) != 5 {
				t.Fatalf("the bench listens on %s; Chrome was measured on ports of five digits", port)
			}
			server.Reset()
			client := newTestClient(t, WithProfileValue(chrome), WithTimeout(5*time.Second),
				WithTransportOption(tls_client.WithDialContext(
					func(ctx context.Context, network, addr string) (net.Conn, error) {
						_, at, _ := net.SplitHostPort(addr)
						return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", at))
					})))
			origin := "https://www.example.com:" + port
			run := origin + page.asked[0].path
			for i, ask := range page.asked {
				browser := &BrowserContext{Kind: ask.kind}
				switch {
				case i == 0 && page.lobby:
					browser.Initiator = "http://www.example.com:" + strconv.Itoa(server.Plain) + "/p/lobby?after=2&next=" + run
				case ask.fromPage:
					browser.Initiator = run
				}
				req := &Request{Method: ask.method, URL: origin + ask.path, Body: []byte(ask.body), Browser: browser}
				if _, err := client.Do(req); err != nil {
					if i == 0 {
						// The page did not load, and asked nothing.
						break
					}
					t.Fatalf("%s %s: %v", ask.method, req.URL, err)
				}
			}
			client.CloseIdleConnections()
			got := settledALPS(t, server, want.Note, page.variant)
			diffs := harness.DiffALPS(want, apart(want, got, &setAside))
			if why := differs(scenario, want); why != "" {
				if len(diffs) == 0 {
					t.Errorf("%s is taken as Chrome took it: take it out of alpsDiffer (%s)", scenario, why)
				}
				return
			}
			for _, diff := range diffs {
				t.Errorf("%s (%s): %s", scenario, want.Note, diff)
			}
		})
	}
}

// settledALPS is what the bench's ALPS server made of a client once it has
// taken all it was sent: the same for 100 ms on end, or what it was after two
// seconds. A client's handshake is done before the server has read its
// Finished, and its SETTINGS and GOAWAY are read after it is done.
func settledALPS(t *testing.T, server *harness.Server, note, variant string) harness.ALPSScenario {
	t.Helper()
	var got harness.ALPSScenario
	said, since := "", time.Now()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		entries, err := server.Requests()
		if err != nil {
			t.Fatalf("Requests: %v", err)
		}
		if got, err = server.ALPSOf(note, variant, entries); err != nil {
			t.Fatalf("ALPSOf: %v", err)
		}
		if now := fmt.Sprintf("%+v", got); now != said {
			said, since = now, time.Now()
		} else if time.Since(since) >= 100*time.Millisecond {
			break
		}
	}
	return got
}

func TestEveryALPSScenarioMeasuredIsSent(t *testing.T) {
	fixture, err := harness.LoadALPS(alpsFixture)
	if err != nil {
		t.Fatalf("LoadALPS: %v", err)
	}
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for scenario := range fixture.Scenarios {
		if server.ALPS[alpsAskedOf(scenario).variant] == 0 {
			t.Errorf("%s is sent to a variant the bench has not: %s", scenario, alpsAskedOf(scenario).variant)
		}
	}
	for scenario := range maps.Keys(alpsPages) {
		if _, ok := fixture.Scenarios[scenario]; !ok {
			t.Errorf("%s is sent, and was not measured", scenario)
		}
	}
	for scenario := range alpsDiffer {
		if _, ok := fixture.Scenarios[scenario]; !ok {
			t.Errorf("%s differs, and was not measured", scenario)
		}
	}
}
