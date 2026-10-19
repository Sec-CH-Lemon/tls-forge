package tlsforge

import (
	"context"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	tls_client "github.com/igor-lemon/tls-client"
)

// recordsFixture is how Chrome's TLS records carried its requests over
// HTTP/1.1.
const recordsFixture = "testdata/chrome155-records.json"

// posted is a fetch() POST of n letters, as the page's script gave it.
func posted(path string, n int) hpackAsk {
	return fetched("POST", path, "content-type", "text/plain;charset=UTF-8").withBody(strings.Repeat("a", n))
}

// recordsAsked is what the page of each scenario of testdata/chrome155-records.json
// asked for, in order: as its script in internal/harness says.
var recordsAsked = map[string][]hpackAsk{
	"h1-records-header": {typed("/run/h1-records-header"),
		fetched("GET", "/p/h1-records-header", "x-foo", strings.Repeat("a", 8000)), fetched("GET", "/done/h1-records-header")},
	"h1-records-big-header": {typed("/run/h1-records-big-header"),
		fetched("GET", "/p/h1-records-big-header", "x-foo", strings.Repeat("a", 30000)), fetched("GET", "/done/h1-records-big-header")},
	"h1-records-bigger-header": {typed("/run/h1-records-bigger-header"),
		fetched("GET", "/p/h1-records-bigger-header", "x-foo", strings.Repeat("a", 60000)),
		fetched("GET", "/done/h1-records-bigger-header")},
	"h1-records-long-url": {typed("/run/h1-records-long-url"),
		fetched("GET", "/p/h1-records-long-url?"+strings.Repeat("a", 8000)), fetched("GET", "/done/h1-records-long-url")},
	"h1-records-cookie-2k": {typed("/run/h1-records-cookie-2k?big=2044"),
		fetched("GET", "/p/h1-records-cookie-2k"), fetched("GET", "/done/h1-records-cookie-2k")},
	"h1-records-cookie-4k": {typed("/run/h1-records-cookie-4k?big=4092"),
		fetched("GET", "/p/h1-records-cookie-4k"), fetched("GET", "/done/h1-records-cookie-4k")},
	"h1-records-cookie-16k": {typed("/run/h1-records-cookie-16k?big=4091&bigs=4"),
		fetched("GET", "/p/h1-records-cookie-16k"), fetched("GET", "/done/h1-records-cookie-16k")},
	"h1-records-post-100": {typed("/run/h1-records-post-100"), posted("/p/h1-records-post-100", 100),
		fetched("GET", "/done/h1-records-post-100")},
	"h1-records-post-1k": {typed("/run/h1-records-post-1k"), posted("/p/h1-records-post-1k", 1000),
		fetched("GET", "/done/h1-records-post-1k")},
	"h1-records-post-at-1400": {typed("/run/h1-records-post-at-1400"), posted("/p/h1-records-post-at-1400", 705),
		fetched("GET", "/done/h1-records-post-at-1400")},
	"h1-records-post-at-1401": {typed("/run/h1-records-post-at-1401"), posted("/p/h1-records-post-at-1401", 706),
		fetched("GET", "/done/h1-records-post-at-1401")},
	"h1-records-post-16k": {typed("/run/h1-records-post-16k"), posted("/p/h1-records-post-16k", 16385),
		fetched("GET", "/done/h1-records-post-16k")},
	"h1-records-post-64k": {typed("/run/h1-records-post-64k"), posted("/p/h1-records-post-64k", 65536),
		fetched("GET", "/done/h1-records-post-64k")},
	"h1-records-form": {typed("/run/h1-records-form"), {kind: KindForm, fromPage: true, method: "POST",
		path: "/p/h1-records-form?quiet", body: "a=1&b=x+y", header: []profile.Field{{Name: "Content-Type", Value: formEncoded}}}},
}

// recordsDiffer are the scenarios of testdata/chrome155-records.json whose
// requests tls-forge's records do not carry as Chrome's did, and why.
var recordsDiffer = map[string]string{
	"h1-records-header":        headInPieces,
	"h1-records-big-header":    headInPieces,
	"h1-records-bigger-header": headInPieces,
	"h1-records-long-url":      headInPieces,
	"h1-records-cookie-4k":     headInPieces,
	"h1-records-cookie-16k":    headInPieces,
	"h1-records-post-100":      bodyApart,
	"h1-records-post-at-1400":  bodyApart,
	"h1-records-form":          bodyApart,
}

const (
	headInPieces = "the transport writes a head larger than its 4 KiB buffer in pieces of the buffer's size, where Chrome writes it at once"
	bodyApart    = "the transport writes a body held in memory after its head, where Chrome writes the two at once up to 1,400 bytes"
)

func TestRequestsGoIntoTLSRecordsOverHTTP1AsChromeWroteThem(t *testing.T) {
	// Each scenario's page sent as Chrome's was asked to, to the bench's own
	// server over HTTP/1.1, and read back as the bench read Chrome's: how the
	// TLS records of each request carried its head and its body, held to
	// Chrome's record by record.
	fixture, err := harness.LoadRecords(recordsFixture)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	server, err := harness.StartRecordsServer()
	if err != nil {
		t.Fatalf("StartRecordsServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	// The bench's ports have five digits, as Chrome's had: each head naming
	// one is as long as Chrome's.
	port := strconv.Itoa(server.H1)
	if len(port) != 5 {
		t.Fatalf("the bench listens on %s; Chrome was measured on ports of five digits", port)
	}
	chrome := headlessChrome(t)
	for _, scenario := range slices.Sorted(maps.Keys(recordsAsked)) {
		want := fixture.Scenarios[scenario]
		t.Run(scenario, func(t *testing.T) {
			server.Reset()
			client := newTestClient(t, WithProfileValue(chrome), WithTransportOption(tls_client.WithDialContext(
				func(ctx context.Context, network, addr string) (net.Conn, error) {
					_, at, _ := net.SplitHostPort(addr)
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", at))
				})))
			origin := "https://www.example.com:" + port
			run := origin + recordsAsked[scenario][0].path
			for _, ask := range recordsAsked[scenario] {
				browser := &BrowserContext{Kind: ask.kind}
				if ask.fromPage {
					browser.Initiator = run
				}
				req := &Request{Method: ask.method, URL: origin + ask.path, Body: []byte(ask.body), Header: ask.header,
					Browser: browser}
				if _, err := client.Do(req); err != nil {
					t.Fatalf("%s %s: %v", ask.method, req.URL, err)
				}
			}
			entries, err := server.Requests()
			if err != nil {
				t.Fatalf("Requests: %v", err)
			}
			diffs := harness.DiffRecords(want, harness.RecordsScenario{Requests: server.Recorded(entries)})
			if why := recordsDiffer[scenario]; why != "" {
				if len(diffs) == 0 {
					t.Errorf("%s is carried as Chrome's records carried it: take it out of recordsDiffer (%s)", scenario, why)
				}
				return
			}
			for _, diff := range diffs {
				t.Errorf("%s (%s): %s", scenario, want.Note, diff)
			}
		})
	}
}

func TestEveryRecordsScenarioMeasuredIsSent(t *testing.T) {
	fixture, err := harness.LoadRecords(recordsFixture)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if got, want := slices.Sorted(maps.Keys(recordsAsked)), slices.Sorted(maps.Keys(fixture.Scenarios)); !slices.Equal(got, want) {
		t.Errorf("sent %q, measured %q", got, want)
	}
	for scenario := range recordsDiffer {
		if _, ok := recordsAsked[scenario]; !ok {
			t.Errorf("%s differs, and is not sent", scenario)
		}
	}
}
