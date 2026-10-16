package tlsforge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
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
	// refused is what a scenario's page asked for that CORS refused: Chrome
	// sent its preflight alone.
	refused *chromeRequest
	// redirected is a scenario whose page asked once: every request after the
	// first is a redirect Chrome followed, or a preflight it made for one.
	redirected bool
	// fails is what the page's request failed with, said in its error.
	fails string
	// before is a URL got first, as the page the scenario ran in was, for the
	// cookies it set: what it is sent is no part of the scenario.
	before string
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
// every one measured but the order of several headers a script set.
var sentInContexts = map[string]asSent{
	"nav-direct":              {browser: BrowserContext{Kind: KindNavigation}},
	"nav-direct-cookies":      {browser: BrowserContext{Kind: KindNavigation}, cookies: setByRun},
	"nav-same-origin":         {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-same-origin")}},
	"nav-same-origin-cookies": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-same-origin-cookies") + "?cookie=1"}, cookies: setByRun},
	"nav-same-site":           {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-same-site")}},
	"nav-cross-site":          {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-cross-site")}},
	"nav-downgrade":           {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-downgrade")}},
	"nav-https-to-localhost":  {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-https-to-localhost")}},
	"nav-localhost-to-http": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: "http://localhost/run/nav-localhost-to-http"}},
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
	"fetch-get-same-origin-authorization": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-same-origin-authorization")}, script: []string{"Authorization"}},
	"xhr-get-same-origin-authorization": {browser: BrowserContext{Kind: KindXHR,
		Initiator: run("xhr-get-same-origin-authorization")}, script: []string{"Authorization"}},
	"fetch-put-same-origin": {browser: BrowserContext{Kind: KindFetch, Initiator: run("fetch-put-same-origin")},
		script: []string{"Content-Type"}},
	"fetch-get-cross-site-no-cors": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-cross-site-no-cors"), Mode: "no-cors"}},
	"fetch-get-same-origin-cookies": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-same-origin-cookies") + "?cookie=1"}, cookies: setByRun},
	"xhr-get-same-origin":  {browser: BrowserContext{Kind: KindXHR, Initiator: run("xhr-get-same-origin")}},
	"xhr-post-same-origin": {browser: BrowserContext{Kind: KindXHR, Initiator: run("xhr-post-same-origin")}, script: []string{"Content-Type"}},
	// CORS: what goes to another origin in cors mode, a preflight first where
	// one is asked for.
	"fetch-get-same-site":  {browser: BrowserContext{Kind: KindFetch, Initiator: run("fetch-get-same-site")}},
	"fetch-get-cross-site": {browser: BrowserContext{Kind: KindFetch, Initiator: run("fetch-get-cross-site")}},
	"fetch-post-cross-site-json": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-post-cross-site-json")}, script: []string{"Content-Type"}},
	"fetch-post-cross-site-json-denied": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-post-cross-site-json-denied")}, script: []string{"Content-Type"},
		refused: &chromeRequest{Method: "POST", URL: "https://www.example.net/cors/fetch-post-cross-site-json-denied?deny=1",
			Headers: [][2]string{{"Content-Type", "application/json"}}, Body: "{}"}},
	"fetch-post-cross-site-json-cached": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-post-cross-site-json-cached")}, script: []string{"Content-Type"}},
	"fetch-get-cross-site-header": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-cross-site-header")}, script: []string{"X-Foo"}},
	"fetch-get-cross-site-credentials": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-cross-site-credentials"), Credentials: "include"}},
	"fetch-get-cross-site-samesite": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("fetch-get-cross-site-samesite"), Credentials: "include"}, cookies: setOnEveryKind("www.example.net")},
	"xhr-get-cross-site": {browser: BrowserContext{Kind: KindXHR, Initiator: run("xhr-get-cross-site")}},
	"xhr-post-cross-site-json": {browser: BrowserContext{Kind: KindXHR, Initiator: run("xhr-post-cross-site-json")},
		script: []string{"Content-Type"}},
	// Redirects, of every status, typed and from a page, to the same origin,
	// another site and back, to plain HTTP, under a policy a redirect set, and
	// through CORS: the page asked once, and Chrome followed the rest.
	"redir-nav-direct-301":                  {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-302":                  {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-303":                  {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-307":                  {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-308":                  {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-cookie":               {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-cross-site":           {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-through-another-site": {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-chain": {browser: BrowserContext{Kind: KindNavigation}, redirected: true,
		fails: "the 20th redirect was not followed"},
	"redir-nav-same-origin": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("redir-nav-same-origin")},
		redirected: true},
	"redir-nav-there-and-back": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("redir-nav-there-and-back")}, redirected: true},
	"redir-nav-downgrade": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("redir-nav-downgrade")},
		redirected: true},
	"redir-nav-https-to-localhost": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("redir-nav-https-to-localhost")}, redirected: true},
	"redir-nav-localhost-to-http": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: "http://localhost/run/redir-nav-localhost-to-http"}, redirected: true},
	"redir-nav-location-credentials": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("redir-nav-location-credentials")}, redirected: true},
	"redir-nav-rp-no-referrer": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("redir-nav-rp-no-referrer")}, redirected: true},
	"redir-nav-rp-upper": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("redir-nav-rp-upper")},
		redirected: true},
	"redir-nav-rp-unsafe-url": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("redir-nav-rp-unsafe-url") + "?q=1"}, redirected: true},
	"redir-nav-rp-last-known": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("redir-nav-rp-last-known")}, redirected: true},
	"redir-form-301": {browser: BrowserContext{Kind: KindForm, Initiator: run("redir-form-301")}, form: true,
		redirected: true},
	"redir-form-302": {browser: BrowserContext{Kind: KindForm, Initiator: run("redir-form-302")}, form: true,
		redirected: true},
	"redir-form-303": {browser: BrowserContext{Kind: KindForm, Initiator: run("redir-form-303")}, form: true,
		redirected: true},
	"redir-form-307": {browser: BrowserContext{Kind: KindForm, Initiator: run("redir-form-307")}, form: true,
		redirected: true},
	"redir-form-308": {browser: BrowserContext{Kind: KindForm, Initiator: run("redir-form-308")}, form: true,
		redirected: true},
	"redir-form-307-cross-site": {browser: BrowserContext{Kind: KindForm, Initiator: run("redir-form-307-cross-site")},
		form: true, redirected: true},
	"redir-fetch-same-origin-302": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-same-origin-302")}, redirected: true},
	"redir-fetch-post-307": {browser: BrowserContext{Kind: KindFetch, Initiator: run("redir-fetch-post-307")},
		script: []string{"Content-Type"}, redirected: true},
	"redir-fetch-cross-site-302": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-cross-site-302")}, redirected: true},
	"redir-fetch-same-origin-to-cross": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-same-origin-to-cross")}, redirected: true},
	"redir-fetch-post-same-origin-to-cross": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-post-same-origin-to-cross")}, script: []string{"Content-Type"}, redirected: true},
	"redir-fetch-there-and-back": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-there-and-back")}, redirected: true},
	"redir-fetch-preflighted-307": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-preflighted-307")}, script: []string{"Content-Type"}, redirected: true},
	"redir-fetch-cors-post-302": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-cors-post-302")}, script: []string{"Content-Type"}, redirected: true},
	"redir-fetch-cors-post-303": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-cors-post-303")}, script: []string{"Content-Type"}, redirected: true},
	"redir-fetch-cors-put-301": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-cors-put-301")}, script: []string{"Content-Type"}, redirected: true},
	"redir-fetch-include-same-origin-to-cross": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-include-same-origin-to-cross"), Credentials: "include"}, redirected: true},
	"redir-xhr-same-origin-to-cross": {browser: BrowserContext{Kind: KindXHR,
		Initiator: run("redir-xhr-same-origin-to-cross")}, redirected: true},
	"redir-xhr-post-cross-303": {browser: BrowserContext{Kind: KindXHR, Initiator: run("redir-xhr-post-cross-303")},
		script: []string{"Content-Type"}, redirected: true},
	"redir-fetch-same-origin-to-cross-and-on": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-same-origin-to-cross-and-on")}, redirected: true},
	"redir-fetch-tainted-and-on": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-tainted-and-on")}, redirected: true},
	"redir-fetch-there-and-back-cookies": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-there-and-back-cookies") + "?cookie=1"}, redirected: true,
		before: run("redir-fetch-there-and-back-cookies") + "?cookie=1"},
	"redir-nav-narrowing": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("redir-nav-narrowing")},
		redirected: true},
	"redir-fetch-auth-cross-origin": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-auth-cross-origin")}, script: []string{"Authorization"}, redirected: true},
	"redir-fetch-rp-unsafe-url": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-rp-unsafe-url")}, redirected: true},
	"redir-fetch-cors-redirect-refused": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-cors-redirect-refused")}, redirected: true,
		fails: "CORS: the redirect of GET https://www.example.net/r/302/redir-fetch-cors-redirect-refused?noacao=1&to=https://www.example.net/cors/after-refused to https://www.example.net/cors/after-refused did not allow https://www.example.com"},
	"redir-fetch-location-credentials": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-location-credentials")}, redirected: true,
		fails: "CORS: fetch() follows no redirect to a URL with credentials in it: https://u@www.example.net/cors/after-credentials"},
	"redir-fetch-same-origin-location-credentials": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-same-origin-location-credentials")}, redirected: true,
		fails: "CORS: fetch() follows no redirect to a URL with credentials in it"},
	"redir-fetch-same-origin-mode-away": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-same-origin-mode-away"), Mode: "same-origin"}, redirected: true,
		fails: "CORS: fetch() in same-origin mode follows no redirect to another origin: https://www.example.net/cors/after-som"},
	"redir-xhr-same-origin-location-credentials": {browser: BrowserContext{Kind: KindXHR,
		Initiator: run("redir-xhr-same-origin-location-credentials")}, redirected: true},
	"redir-xhr-location-credentials": {browser: BrowserContext{Kind: KindXHR,
		Initiator: run("redir-xhr-location-credentials")}, redirected: true,
		fails: "CORS: an XHR follows no redirect to a URL with credentials in it across origins"},
}

// sentAfter are scenarios whose page made a first fetch() of another kind,
// to set cookies, before the one measured: the context of each call.
var sentAfter = map[string][]BrowserContext{
	"fetch-get-cross-site-omit": {
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-omit"), Credentials: "include"},
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-omit"), Credentials: "omit"},
	},
	"fetch-get-cross-site-same-origin-creds": {
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-same-origin-creds"), Credentials: "include"},
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-same-origin-creds")},
	},
}

func TestABrowserContextSendsWhatChromeSent(t *testing.T) {
	measured := loadChromeRequests(t)
	scenarios := slices.Sorted(maps.Keys(sentInContexts))
	scenarios = append(scenarios, slices.Sorted(maps.Keys(sentAfter))...)
	for _, scenario := range scenarios {
		how := sentInContexts[scenario]
		measuredBoth, ok := measured.Scenarios[scenario]
		if !ok {
			t.Fatalf("%s is not in the fixture", scenario)
		}
		for proto, want := range map[string][]chromeRequest{"h2": measuredBoth.H2, "h1": measuredBoth.H1} {
			t.Run(scenario+"/"+proto, func(t *testing.T) {
				got := sendAsMeasured(t, proto, how, sentAfter[scenario], want)
				if len(got) != len(want) {
					t.Fatalf("%s over %s: sent %d requests, Chrome %d", scenario, proto, len(got), len(want))
				}
				for i := range want {
					if diff := diffRequest(want[i], got[i], proto); diff != "" {
						t.Errorf("%s over %s (%s), request %d:\n%s", scenario, proto, measuredBoth.Note, i+1, diff)
					}
				}
			})
		}
	}
}

// answeringAsMeasured answers as the server the scenarios were measured
// against did: a page CORS allows; under /cors/ an answer CORS allows, a
// preflight allowed but for ?deny, kept as long as ?maxage says; under
// /r/STATUS/ a redirect of that status to ?to, which CORS allows but for
// ?noacao, saying Referrer-Policy as ?rp does, and a preflight of it allowed
// and kept for none; under /chain/N a redirect to /chain/N+1; and cookies,
// two for ?cookie=1 and one of each SameSite for ?cookie=2.
func answeringAsMeasured(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	allow := func() {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
	if set := q.Get("cookie"); set != "" && r.Method != http.MethodOptions {
		cookies := []string{"a=1; Max-Age=3600; Path=/", "b=2; Max-Age=3600; Path=/; SameSite=None; Secure",
			"c=3; Max-Age=3600; Path=/; SameSite=Strict", "d=4; Max-Age=3600; Path=/; SameSite=Lax"}
		if set != "2" {
			cookies = cookies[:2]
		}
		for _, cookie := range cookies {
			w.Header().Add("Set-Cookie", cookie)
		}
	}
	switch path := r.URL.Path; {
	case strings.HasPrefix(path, "/r/"):
		if r.Method == http.MethodOptions {
			allow()
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
			if asked := r.Header.Get("Access-Control-Request-Headers"); asked != "" {
				w.Header().Set("Access-Control-Allow-Headers", asked)
			}
			w.Header().Set("Access-Control-Max-Age", "0")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if q.Get("noacao") == "" {
			allow()
		}
		if policy := q.Get("rp"); policy != "" {
			w.Header().Set("Referrer-Policy", policy)
		}
		status, _ := strconv.Atoi(strings.Split(path, "/")[2])
		w.Header().Set("Location", q.Get("to"))
		w.WriteHeader(status)
		return
	case strings.HasPrefix(path, "/chain/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(path, "/chain/"))
		w.Header().Set("Location", "/chain/"+strconv.Itoa(n+1))
		w.WriteHeader(http.StatusFound)
		return
	case !strings.HasPrefix(path, "/cors/"):
		allow()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>page</title>")
		return
	}
	if q.Get("deny") == "" {
		allow()
	}
	if r.Method == http.MethodOptions {
		if q.Get("deny") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		if asked := r.Header.Get("Access-Control-Request-Headers"); asked != "" {
			w.Header().Set("Access-Control-Allow-Headers", asked)
		}
		w.Header().Set("Access-Control-Max-Age", q.Get("maxage"))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

// sendAsMeasured sends what a scenario's page asked for, each request but the
// preflights Chrome made itself, in its browser context, to a recorder
// speaking proto, or plain HTTP when Chrome went over it, and is what the
// recorder kept: preflights and all.
func sendAsMeasured(t *testing.T, proto string, how asSent, contexts []BrowserContext, want []chromeRequest) []*keptRequest {
	t.Helper()
	server := newRecorder(t, proto, answeringAsMeasured)
	plain := newRecorder(t, "http", answeringAsMeasured)
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialingWith(plain))
	skip := 0
	if how.before != "" {
		if _, err := client.Get(how.before); err != nil {
			t.Fatalf("Get %s: %v", how.before, err)
		}
		skip = 1
	}
	var asked []chromeRequest
	for _, req := range want {
		if req.Method != http.MethodOptions {
			asked = append(asked, req)
		}
	}
	if how.redirected {
		asked = asked[:1]
	}
	if how.refused != nil {
		asked = append(asked, *how.refused)
	}
	for i, measured := range asked {
		browser := how.browser
		if contexts != nil {
			browser = contexts[i]
		}
		req := &Request{Method: measured.Method, URL: measured.URL, Body: []byte(measured.Body), Browser: &browser}
		if i == 0 {
			req.Cookies = how.cookies
		}
		for _, name := range how.script {
			req.Header = append(req.Header, profile.Field{Name: name, Value: measured.header(name)})
		}
		if how.form {
			req.Header = append(req.Header, profile.Field{Name: "content-type", Value: measured.header("content-type")})
		}
		_, err := client.Do(req)
		switch {
		case how.refused != nil && i == len(asked)-1:
			if !errors.Is(err, ErrCORS) {
				t.Fatalf("CORS let it through: %v", err)
			}
		case how.fails != "":
			if err == nil || !strings.Contains(err.Error(), how.fails) {
				t.Fatalf("Do: %v, want it to fail with %q", err, how.fails)
			}
		case err != nil:
			t.Fatalf("Do: %v", err)
		}
	}
	return server.requests()[skip:]
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
