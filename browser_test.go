package tlsforge

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// chromeRequests is testdata/chrome155-requests.json: what Chrome 155 sent
// for each scenario, over HTTP/2 and over HTTP/1.1, as its "how" says.
type chromeRequests struct {
	Browser   string `json:"browser"`
	Scenarios map[string]struct {
		Note string          `json:"note"`
		H2   []chromeRequest `json:"h2"`
		H1   []chromeRequest `json:"h1"`
	} `json:"scenarios"`
}

type chromeRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Headers  [][2]string `json:"headers"`
	Priority []uint32    `json:"priority"`
	Body     string      `json:"body"`
}

func loadChromeRequests(t *testing.T) chromeRequests {
	t.Helper()
	raw, err := os.ReadFile("testdata/chrome155-requests.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var measured chromeRequests
	if err := json.Unmarshal(raw, &measured); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return measured
}

// header is the value of a measured request's header, by name in any case.
func (r chromeRequest) header(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// asSent is how a scenario of the fixture is sent in a browser context: its
// first request, made by the page the scenario ran in, with the cookies its
// pages had set.
type asSent struct {
	browser BrowserContext
	// script are the headers fetch() or an XHR was given, by name: the value
	// is the measured request's.
	script []string
	// form is a form's Content-Type, the measured request's.
	form    bool
	cookies []Cookie
}

// run is the page a scenario ran in.
func run(scenario string) string { return "https://www.example.com/run/" + scenario }

// setByRun and setOnEveryKind are the cookies the scenarios' pages set.
var (
	setByRun = []Cookie{
		{Name: "a", Value: "1", Domain: "www.example.com", HostOnly: true, Path: "/"},
		{Name: "b", Value: "2", Domain: "www.example.com", HostOnly: true, Path: "/", Secure: true, SameSite: "none"},
	}
	setOnEveryKind = func(host string) []Cookie {
		return []Cookie{
			{Name: "a", Value: "1", Domain: host, HostOnly: true, Path: "/"},
			{Name: "b", Value: "2", Domain: host, HostOnly: true, Path: "/", Secure: true, SameSite: "none"},
			{Name: "c", Value: "3", Domain: host, HostOnly: true, Path: "/", SameSite: "strict"},
			{Name: "d", Value: "4", Domain: host, HostOnly: true, Path: "/", SameSite: "lax"},
		}
	}
)

// sentInContexts are the scenarios a browser context sends as Chrome did:
// every one measured but those of CORS, redirects and the order of several
// headers a script set.
var sentInContexts = map[string]asSent{
	"nav-direct":              {browser: BrowserContext{Kind: KindNavigation}},
	"nav-direct-cookies":      {browser: BrowserContext{Kind: KindNavigation}, cookies: setByRun},
	"nav-same-origin":         {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-same-origin")}},
	"nav-same-origin-cookies": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-same-origin-cookies") + "?cookie=1"}, cookies: setByRun},
	"nav-same-site":           {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-same-site")}},
	"nav-cross-site":          {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-cross-site")}},
	"nav-downgrade":           {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-downgrade")}},
	"nav-ref-no-referrer": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-ref-no-referrer"),
		ReferrerPolicy: "no-referrer"}},
	"nav-ref-origin": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-ref-origin"),
		ReferrerPolicy: "origin"}},
	"nav-ref-unsafe-url-cross-site": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("nav-ref-unsafe-url-cross-site"), ReferrerPolicy: "unsafe-url"}},
	"nav-ref-same-origin-cross-site": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("nav-ref-same-origin-cross-site"), ReferrerPolicy: "same-origin"}},
	"nav-ref-strict-origin": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-ref-strict-origin"),
		ReferrerPolicy: "strict-origin"}},
	"nav-cross-site-samesite": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-cross-site-samesite")},
		cookies: setOnEveryKind("www.example.net")},
	"nav-same-site-samesite": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-same-site-samesite")},
		cookies: setOnEveryKind("api.example.com")},
	"form-post-same-origin": {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-same-origin")}, form: true},
	"form-post-same-origin-cookies": {browser: BrowserContext{Kind: KindForm,
		Initiator: run("form-post-same-origin-cookies") + "?cookie=1"}, form: true, cookies: setByRun},
	"form-post-same-site":  {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-same-site")}, form: true},
	"form-post-cross-site": {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-cross-site")}, form: true},
	"form-post-multipart":  {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-multipart")}, form: true},
	"form-post-text":       {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-text")}, form: true},
	"form-get-same-origin": {browser: BrowserContext{Kind: KindForm, Initiator: run("form-get-same-origin")}},
	"form-post-cross-site-samesite": {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-cross-site-samesite")},
		form: true, cookies: setOnEveryKind("www.example.net")},
	"fetch-get-same-origin": {browser: BrowserContext{Kind: KindFetch, Initiator: run("fetch-get-same-origin")}},
	"fetch-post-same-origin-json": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-post-same-origin-json")}, script: []string{"Content-Type"}},
	"fetch-post-same-origin-text": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-post-same-origin-text")}, script: []string{"Content-Type"}},
	"fetch-post-same-origin-form": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-post-same-origin-form")}, script: []string{"Content-Type"}},
	"fetch-get-same-origin-header": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-same-origin-header")}, script: []string{"X-Foo"}},
	"fetch-put-same-origin": {browser: BrowserContext{Kind: KindFetch, Initiator: run("fetch-put-same-origin")},
		script: []string{"Content-Type"}},
	"fetch-get-cross-site-no-cors": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-cross-site-no-cors"), Mode: "no-cors"}},
	"fetch-get-same-origin-cookies": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-same-origin-cookies") + "?cookie=1"}, cookies: setByRun},
	"xhr-get-same-origin":  {browser: BrowserContext{Kind: KindXHR, Initiator: run("xhr-get-same-origin")}},
	"xhr-post-same-origin": {browser: BrowserContext{Kind: KindXHR, Initiator: run("xhr-post-same-origin")}, script: []string{"Content-Type"}},
}

func TestABrowserContextSendsWhatChromeSent(t *testing.T) {
	measured := loadChromeRequests(t)
	for _, scenario := range slices.Sorted(maps.Keys(sentInContexts)) {
		how := sentInContexts[scenario]
		measuredBoth, ok := measured.Scenarios[scenario]
		if !ok {
			t.Fatalf("%s is not in the fixture", scenario)
		}
		for proto, want := range map[string]chromeRequest{"h2": measuredBoth.H2[0], "h1": measuredBoth.H1[0]} {
			t.Run(scenario+"/"+proto, func(t *testing.T) {
				got := sendAsMeasured(t, proto, how, want)
				if diff := diffRequest(want, got, proto); diff != "" {
					t.Errorf("%s over %s (%s):\n%s", scenario, proto, measuredBoth.Note, diff)
				}
			})
		}
	}
}

// sendAsMeasured sends a scenario's first request in its browser context to a
// recorder speaking proto, or plain HTTP when Chrome went over it, and is what
// the recorder kept.
func sendAsMeasured(t *testing.T, proto string, how asSent, want chromeRequest) *keptRequest {
	t.Helper()
	serving := proto
	if strings.HasPrefix(want.URL, "http:") {
		serving = "http"
	}
	server := newRecorder(t, serving, nil)
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	req := &Request{Method: want.Method, URL: want.URL, Body: []byte(want.Body), Browser: &how.browser,
		Cookies: how.cookies}
	for _, name := range how.script {
		req.Header = append(req.Header, profile.Field{Name: name, Value: want.header(name)})
	}
	if how.form {
		req.Header = append(req.Header, profile.Field{Name: "content-type", Value: want.header("content-type")})
	}
	if _, err := client.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	kept := server.requests()
	if len(kept) != 1 {
		t.Fatalf("the server was sent %d requests", len(kept))
	}
	return kept[0]
}

// diffRequest is how a request sent differs from what Chrome sent: nothing
// when they are the same but for the user agent, which is the profile's and
// was HeadlessChrome's.
func diffRequest(want chromeRequest, got *keptRequest, proto string) string {
	var diff []string
	if got.method != want.Method || got.url != want.URL {
		diff = append(diff, fmt.Sprintf("sent %s %s, Chrome %s %s", got.method, got.url, want.Method, want.URL))
	}
	if got.body != want.Body {
		diff = append(diff, fmt.Sprintf("body %q, Chrome's %q", got.body, want.Body))
	}
	if len(want.Priority) > 0 {
		if got.priority == nil || got.priority[0] != want.Priority[0] || got.priority[1] != 0 ||
			got.priority[2] != want.Priority[2] {
			diff = append(diff, fmt.Sprintf("priority %v, Chrome's %v", got.priority, want.Priority))
		}
	}
	names := func(headers [][2]string) []string {
		var out []string
		for _, h := range headers {
			out = append(out, h[0])
		}
		return out
	}
	if !slices.Equal(names(got.headers), names(want.Headers)) {
		diff = append(diff, fmt.Sprintf("headers\n  sent   %v\n  Chrome %v", names(got.headers), names(want.Headers)))
		return strings.Join(diff, "\n")
	}
	for i, h := range want.Headers {
		if strings.EqualFold(h[0], "user-agent") {
			continue
		}
		if got.headers[i][1] != h[1] {
			diff = append(diff, fmt.Sprintf("%s: %q, Chrome's %q", h[0], got.headers[i][1], h[1]))
		}
	}
	return strings.Join(diff, "\n")
}
