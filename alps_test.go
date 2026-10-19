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
	tls_client "github.com/igor-lemon/tls-client"
)

// alpsFixture is what Chrome made of the bench's ALPS server.
const alpsFixture = "testdata/chrome155-alps.json"

// alpsAsked are the variant of what the bench's ALPS server gives in each
// scenario of testdata/chrome155-alps.json, as internal/harness names it:
// every scenario's page is typed, and its script fetches /done/ID.
var alpsAsked = map[string]string{
	"alps-none":                   "none",
	"alps-empty":                  "empty",
	"alps-settings":               "settings",
	"alps-accept-ch":              "accept-ch",
	"alps-unknown-frame":          "unknown-frame",
	"alps-malformed":              "malformed",
	"alps-settings-ack":           "settings-ack",
	"alps-data":                   "data",
	"alps-settings-stream":        "settings-stream",
	"alps-accept-ch-malformed":    "accept-ch-malformed",
	"alps-accept-ch-empty-origin": "accept-ch-empty-origin",
}

// alpsDiffer are the scenarios of testdata/chrome155-alps.json tls-forge does
// not make of the bench's ALPS server what Chrome did, and why, the flight of
// its handshake aside (flightApart).
var alpsDiffer = map[string]string{
	"alps-settings":        "the transport takes the server's SETTINGS from its first SETTINGS frame, not from ALPS: no size update in the first request",
	"alps-accept-ch":       "the client hints ALPS asks for are not sent on the navigation",
	"alps-data":            alpsTaken,
	"alps-malformed":       alpsTaken,
	"alps-settings-ack":    alpsTaken,
	"alps-settings-stream": alpsTaken,
}

const (
	// alpsTaken is why tls-forge answers what Chrome refuses: the transport
	// does not read ALPS, where Chrome ends the connection with GOAWAY,
	// tries once more on another and gives up.
	alpsTaken = "the transport does not read ALPS: it sends its requests where Chrome says GOAWAY and gives up"
	// flightApart is why the flight of every handshake that negotiated ALPS
	// differs from Chrome's: utls writes the client's EncryptedExtensions and
	// Finished in a record each, where Chrome's BoringSSL writes them in one.
	flightApart = "utls writes the client's EncryptedExtensions and Finished in a record each, where Chrome writes them in one"
)

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
	chrome := headlessChrome(t)
	setAside := 0
	t.Cleanup(func() {
		if setAside == 0 {
			t.Errorf("no flight was set aside: take flightApart out (%s)", flightApart)
		}
	})
	for _, scenario := range slices.Sorted(maps.Keys(alpsAsked)) {
		want := fixture.Scenarios[scenario]
		t.Run(scenario, func(t *testing.T) {
			port := strconv.Itoa(server.ALPS[alpsAsked[scenario]])
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
			run := origin + "/run/" + scenario
			// The page typed, and, when it came, its script's fetch().
			if _, err := client.Do(&Request{Method: "GET", URL: run, Browser: &BrowserContext{Kind: KindNavigation}}); err == nil {
				if _, err := client.Do(&Request{Method: "GET", URL: origin + "/done/" + scenario,
					Browser: &BrowserContext{Kind: KindFetch, Initiator: run}}); err != nil {
					t.Fatalf("fetch(): %v", err)
				}
			}
			entries, err := server.Requests()
			if err != nil {
				t.Fatalf("Requests: %v", err)
			}
			got, err := server.ALPSOf(want.Note, alpsAsked[scenario], entries)
			if err != nil {
				t.Fatalf("ALPSOf: %v", err)
			}
			diffs := harness.DiffALPS(want, apart(want, got, &setAside))
			if why := alpsDiffer[scenario]; why != "" {
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

func TestEveryALPSScenarioMeasuredIsSent(t *testing.T) {
	fixture, err := harness.LoadALPS(alpsFixture)
	if err != nil {
		t.Fatalf("LoadALPS: %v", err)
	}
	if got, want := slices.Sorted(maps.Keys(alpsAsked)), slices.Sorted(maps.Keys(fixture.Scenarios)); !slices.Equal(got, want) {
		t.Errorf("sent %q, measured %q", got, want)
	}
	for scenario := range alpsDiffer {
		if !strings.HasPrefix(scenario, "alps-") || alpsAsked[scenario] == "" {
			t.Errorf("%s differs, and is not sent", scenario)
		}
	}
}
