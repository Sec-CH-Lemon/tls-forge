package tlsforge

import (
	"context"
	"maps"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
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
// requests tls-forge's records do not carry as Chrome's did, and why: none,
// kept for a difference measured later.
var recordsDiffer = map[string]string{}

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
	macOS := headlessChrome(t)
	onEveryPlatform(t, func(t *testing.T, p *profile.Profile) {
		carriedAsChromeCarriedThem(t, headless(p), macOS, server, fixture, port)
	})
}

// mergedHeadAndBody is how many bytes an HTTP/1.1 request's head and a body
// held in memory may be together for Chrome to write them at once:
// HttpStreamParser's kMaxMergedHeaderAndBodySize (h1-records-post-at-1400 and
// -1401).
const mergedHeadAndBody = 1400

// recordsWearing is a scenario of the records fixture as Chrome writes it
// wearing chrome, the fixture's Chrome being macOS: every head as much longer
// as chrome's user agent and platform are than macOS's (the last part of one
// a record cuts), and a body held in memory in its head's write when the two
// are no more than mergedHeadAndBody bytes together, as Chrome's rule says.
// For macOS it is the fixture.
func recordsWearing(want harness.RecordsScenario, chrome, macOS *profile.Profile) harness.RecordsScenario {
	delta := 0
	for _, name := range []string{"user-agent", "sec-ch-ua-platform"} {
		mine, _ := ownValue(chrome, name)
		theirs, _ := ownValue(macOS, name)
		delta += len(mine) - len(theirs)
	}
	out := harness.RecordsScenario{Note: want.Note}
	for _, r := range want.Requests {
		records := slices.Clone(r.Records)
		// The last part of the head: a head alone, or with its body.
		for i := len(records) - 1; i >= 0; i-- {
			head, rest, _ := strings.Cut(records[i], "+")
			if size, err := strconv.Atoi(head[1:]); err == nil && (head[0] == 'R' || head[0] == 'r') {
				records[i] = head[:1] + strconv.Itoa(size+delta)
				if rest != "" {
					records[i] += "+" + rest
				}
				break
			}
		}
		// A head and its body, together or apart, as their sum says.
		head, body := 0, 0
		switch {
		case len(records) == 1 && strings.Contains(records[0], "+B"):
			h, b, _ := strings.Cut(records[0], "+B")
			head, _ = strconv.Atoi(h[1:])
			body, _ = strconv.Atoi(b)
		case len(records) == 2 && records[0][0] == 'R' && records[1][0] == 'B':
			head, _ = strconv.Atoi(records[0][1:])
			body, _ = strconv.Atoi(records[1][1:])
		}
		switch {
		case body == 0:
		case head+body <= mergedHeadAndBody:
			records = []string{"R" + strconv.Itoa(head) + "+B" + strconv.Itoa(body)}
		default:
			records = []string{"R" + strconv.Itoa(head), "B" + strconv.Itoa(body)}
		}
		r.Records = records
		out.Requests = append(out.Requests, r)
	}
	return out
}

// carriedAsChromeCarriedThem sends every scenario of the records fixture
// wearing chrome, and holds every request's records to Chrome's as Chrome
// writes them wearing it (recordsWearing).
func carriedAsChromeCarriedThem(t *testing.T, chrome, macOS *profile.Profile, server *harness.Server,
	fixture *harness.RecordsFixture, port string) {
	for _, scenario := range slices.Sorted(maps.Keys(recordsAsked)) {
		want := recordsWearing(fixture.Scenarios[scenario], chrome, macOS)
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
			entries := readWhole(t, server, recordsAsked[scenario])
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

func TestRecordsWearingFollowsChromesRule(t *testing.T) {
	// As long as macOS's, a scenario is the fixture's; a head 10 bytes longer
	// takes a head and body across the 1,400 bytes they are merged up to, and
	// one 10 bytes shorter brings them back; a head cut into records grows in
	// its last part, and a body of more than a record never joins its head.
	macOS := &profile.Profile{EngineMajor: profile.Major(2), Headers: []profile.Field{{Name: "user-agent", Value: "UA"},
		{Name: "sec-ch-ua-platform", Value: `"macOS"`}}}
	longer := &profile.Profile{EngineMajor: profile.Major(2), Headers: []profile.Field{{Name: "user-agent", Value: "UA and more"},
		{Name: "sec-ch-ua-platform", Value: `"macOS!"`}}}
	scenario := func(records ...[]string) harness.RecordsScenario {
		out := harness.RecordsScenario{Note: "n"}
		for _, r := range records {
			out.Requests = append(out.Requests, harness.RecordedRequest{Method: "POST", URL: "u", Records: r})
		}
		return out
	}
	want := scenario([]string{"R700"}, []string{"R695+B705"}, []string{"R690", "B720"}, []string{"r16384", "r100"},
		[]string{"R689", "b16384", "b1"}, []string{"R686", "B1000"})
	if got := recordsWearing(want, macOS, macOS); !reflect.DeepEqual(got, want) {
		t.Errorf("as long as macOS's: %+v", got)
	}
	if got := recordsWearing(want, longer, macOS); !reflect.DeepEqual(got, scenario([]string{"R710"},
		[]string{"R705", "B705"}, []string{"R700", "B720"}, []string{"r16384", "r110"}, []string{"R699", "b16384", "b1"},
		[]string{"R696", "B1000"})) {
		t.Errorf("10 bytes longer: %+v", got)
	}
	if got := recordsWearing(want, macOS, longer); !reflect.DeepEqual(got.Requests[2].Records, []string{"R680+B720"}) ||
		!reflect.DeepEqual(got.Requests[1].Records, []string{"R685+B705"}) {
		t.Errorf("10 bytes shorter: %+v", got)
	}
}
