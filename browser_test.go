package tlsforge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
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
	// first is one Chrome made itself, a redirect it followed, a preflight it
	// made for one, or the navigation started again for its client hints.
	redirected bool
	// fails is what the page's request failed with, said in its error.
	fails string
	// corsRefused are the requests a page asked for, by their place among
	// those it asked, whose answers CORS refused once they came.
	corsRefused []int
	// before is a URL navigated to first, typed, as the page the scenario ran
	// in was, for the cookies it set and the client hints it asked for: what
	// it is sent is no part of the scenario.
	before string
	// each is the context of each request the page asked, where they differ:
	// a page another led to by a refresh.
	each []BrowserContext
	// pages are the requests of a scenario that its pages asked for, by their
	// place among Chrome's, where Chrome made others itself between them: a
	// challenge it answered, a redirect it followed, a request it sent again
	// for a 421. The first is sent in browser, and each after it as a
	// navigation from the URL Chrome's requests before it ended on, unless
	// each says otherwise. credentials are what each page's URL carried,
	// which no request shows.
	pages       []int
	credentials []string
}

// notSent are the scenarios measured that a browser context does not send as
// Chrome did, and why.
var notSent = map[string]string{
	"fetch-post-same-origin-headers": "the order of several headers a script set follows the renderer's hash table",
	"ch-fetch-three":                 "the order of several client hints of a script's request follows the renderer's hash table",
	"ch-fetch-all":                   "the order of several client hints of a script's request follows the renderer's hash table",
	"auth-digest-ntlm":               "Chrome answers NTLM, which it prefers to Digest and Basic, and tls-forge answers neither instead",
}

// asked is the URL of a scenario's page with its query.
const allHints = "sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-full-version,sec-ch-ua-full-version-list,sec-ch-ua-model,sec-ch-ua-platform-version,sec-ch-ua-wow64,sec-ch-ua-form-factors,sec-ch-dpr,sec-ch-viewport-width,sec-ch-viewport-height,sec-ch-device-memory,sec-ch-prefers-color-scheme,sec-ch-prefers-reduced-motion,sec-ch-prefers-reduced-transparency,dpr,viewport-width,device-memory,rtt,downlink,ect,save-data"

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
	// Typed to plain http, and to http on the machine itself, which is
	// potentially trustworthy as https is.
	"nav-direct-plain":         {browser: BrowserContext{Kind: KindNavigation}},
	"nav-direct-localhost":     {browser: BrowserContext{Kind: KindNavigation}},
	"nav-direct-dot-localhost": {browser: BrowserContext{Kind: KindNavigation}},
	"nav-direct-ipv4":          {browser: BrowserContext{Kind: KindNavigation}},
	"nav-direct-ipv6":          {browser: BrowserContext{Kind: KindNavigation}},

	"form-post-same-origin": {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-same-origin")}, form: true},
	"form-post-same-origin-cookies": {browser: BrowserContext{Kind: KindForm,
		Initiator: run("form-post-same-origin-cookies") + "?cookie=1"}, form: true, cookies: setByRun},
	"form-post-same-site":  {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-same-site")}, form: true},
	"form-post-cross-site": {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-cross-site")}, form: true},
	"form-post-multipart":  {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-multipart")}, form: true},
	"form-post-text":       {browser: BrowserContext{Kind: KindForm, Initiator: run("form-post-text")}, form: true},
	"form-get-same-origin": {browser: BrowserContext{Kind: KindForm, Initiator: run("form-get-same-origin")}},
	"form-get-same-origin-cookies": {browser: BrowserContext{Kind: KindForm,
		Initiator: run("form-get-same-origin-cookies") + "?cookie=1"}, cookies: setByRun},
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
	"xhr-get-same-origin": {browser: BrowserContext{Kind: KindXHR, Initiator: run("xhr-get-same-origin")}},
	"xhr-get-same-origin-cookies": {browser: BrowserContext{Kind: KindXHR,
		Initiator: run("xhr-get-same-origin-cookies") + "?cookie=1"}, cookies: setByRun},
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
	"redir-nav-direct-downgrade":            {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-upgrade":              {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-to-localhost":         {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"redir-nav-direct-plain-to-localhost":   {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
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
	"redir-fetch-same-origin-302-cookies": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-same-origin-302-cookies") + "?cookie=1"}, cookies: setByRun, redirected: true},
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
	// Client hints an origin asked for with Accept-CH.
	"ch-nav-all": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("ch-nav-all") + "?accept=" + allHints},
		before: run("ch-nav-all") + "?accept=" + allHints},
	"ch-nav-some": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("ch-nav-some") + "?accept=Sec-CH-UA-Arch,%20Sec-CH-UA-Bitness,%20Sec-CH-UA-Model"},
		before: run("ch-nav-some") + "?accept=Sec-CH-UA-Arch,%20Sec-CH-UA-Bitness,%20Sec-CH-UA-Model"},
	"ch-nav-cross-site": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("ch-nav-cross-site") + "?accept=sec-ch-ua-arch"}, before: run("ch-nav-cross-site") + "?accept=sec-ch-ua-arch"},
	"ch-nav-same-site": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("ch-nav-same-site") + "?accept=sec-ch-ua-arch"}, before: run("ch-nav-same-site") + "?accept=sec-ch-ua-arch"},
	"ch-nav-cleared": {before: run("ch-nav-cleared") + "?accept=sec-ch-ua-arch", each: []BrowserContext{
		{Kind: KindNavigation, Initiator: run("ch-nav-cleared") + "?accept=sec-ch-ua-arch"},
		{Kind: KindNavigation, Initiator: "https://www.example.com/p/ch-clear?accept=&next=/p/ch-cleared-end"}}},
	"ch-nav-replaced": {before: run("ch-nav-replaced") + "?accept=sec-ch-ua-arch", each: []BrowserContext{
		{Kind: KindNavigation, Initiator: run("ch-nav-replaced") + "?accept=sec-ch-ua-arch"},
		{Kind: KindNavigation,
			Initiator: "https://www.example.com/p/ch-replace?accept=sec-ch-ua-bitness&next=/p/ch-replaced-end"}}},
	"ch-nav-unasked": {before: run("ch-nav-unasked") + "?accept=sec-ch-ua-arch", each: []BrowserContext{
		{Kind: KindNavigation, Initiator: run("ch-nav-unasked") + "?accept=sec-ch-ua-arch"},
		{Kind: KindNavigation, Initiator: "https://www.example.com/p/ch-unasked?next=/p/ch-unasked-end"}}},
	"ch-redirect-accept": {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-nav-all-redirect": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("ch-nav-all-redirect") + "?accept=" + allHints}, before: run("ch-nav-all-redirect") + "?accept=" + allHints,
		redirected: true},
	"ch-redirect-to-asker": {browser: BrowserContext{Kind: KindNavigation,
		Initiator: run("ch-redirect-to-asker") + "?accept=sec-ch-ua-arch"},
		before: run("ch-redirect-to-asker") + "?accept=sec-ch-ua-arch", redirected: true},
	"ch-nav-from-other-site": {before: run("ch-nav-from-other-site") + "?accept=sec-ch-ua-arch", each: []BrowserContext{
		{Kind: KindNavigation, Initiator: run("ch-nav-from-other-site") + "?accept=sec-ch-ua-arch"},
		{Kind: KindNavigation, Initiator: "https://www.example.net/p/ch-away?next=https://www.example.com/p/ch-back"}}},
	"ch-persist": {browser: BrowserContext{Kind: KindNavigation}, before: "https://www.example.com/p/ch-persist-set?accept=sec-ch-ua-arch"},
	// And Critical-CH: a navigation started again, once, where it began.
	"ch-critical-typed":          {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-critical-unasked":        {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-critical-low":            {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-critical-redirect":       {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-critical-all":            {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-critical-cookie":         {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-critical-after-redirect": {browser: BrowserContext{Kind: KindNavigation}, redirected: true},
	"ch-critical-from-page": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("ch-critical-from-page")},
		redirected: true},
	"ch-critical-form-post": {browser: BrowserContext{Kind: KindForm, Initiator: run("ch-critical-form-post")}, form: true,
		redirected: true},
	"ch-fetch-critical": {each: []BrowserContext{{Kind: KindFetch, Initiator: run("ch-fetch-critical")},
		{Kind: KindFetch, Initiator: run("ch-fetch-critical")}}},
	"ch-form-post": {browser: BrowserContext{Kind: KindForm, Initiator: run("ch-form-post") + "?accept=sec-ch-ua-arch"}, form: true, before: run("ch-form-post") + "?accept=sec-ch-ua-arch"},
	"ch-form-get":  {browser: BrowserContext{Kind: KindForm, Initiator: run("ch-form-get") + "?accept=sec-ch-ua-arch"}, before: run("ch-form-get") + "?accept=sec-ch-ua-arch"},
	"ch-form-post-asks": {form: true, each: []BrowserContext{{Kind: KindForm, Initiator: run("ch-form-post-asks")},
		{Kind: KindNavigation,
			Initiator: "https://www.example.com/p/ch-form-post-asks?accept=sec-ch-ua-arch&next=/p/ch-form-post-asks-end"}}},
	"ch-plain-asks": {each: []BrowserContext{{Kind: KindNavigation},
		{Kind: KindNavigation, Initiator: "http://www.example.com/p/ch-plain-asks?accept=sec-ch-ua-arch&next=/p/ch-plain-asks-end"}}},
	"ch-fetch-same-origin": {browser: BrowserContext{Kind: KindFetch, Initiator: run("ch-fetch-same-origin") + "?accept=sec-ch-ua-arch"}, before: run("ch-fetch-same-origin") + "?accept=sec-ch-ua-arch"},
	"ch-fetch-cross-site":  {browser: BrowserContext{Kind: KindFetch, Initiator: run("ch-fetch-cross-site") + "?accept=sec-ch-ua-arch"}, before: run("ch-fetch-cross-site") + "?accept=sec-ch-ua-arch"},
	"ch-fetch-post-json": {browser: BrowserContext{Kind: KindFetch, Initiator: run("ch-fetch-post-json") + "?accept=sec-ch-ua-arch"},
		before: run("ch-fetch-post-json") + "?accept=sec-ch-ua-arch", script: []string{"Content-Type"}},
	"ch-xhr-same-origin": {browser: BrowserContext{Kind: KindXHR, Initiator: run("ch-xhr-same-origin") + "?accept=sec-ch-ua-arch"}, before: run("ch-xhr-same-origin") + "?accept=sec-ch-ua-arch"},
	"ch-fetch-asks": {each: []BrowserContext{{Kind: KindFetch, Initiator: run("ch-fetch-asks")},
		{Kind: KindNavigation, Initiator: run("ch-fetch-asks")}}},
	"ch-fetch-from-other-site": {browser: BrowserContext{Kind: KindFetch, Initiator: "https://www.example.net/run/ch-fetch-from-other-site"},
		before: "https://www.example.com/p/ch-third-set?accept=sec-ch-ua-arch"},
	"redir-fetch-same-origin-to-cross-and-on": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-same-origin-to-cross-and-on")}, redirected: true},
	"redir-fetch-tainted-and-on": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-tainted-and-on")}, redirected: true},
	"redir-fetch-there-and-back-cookies": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-there-and-back-cookies") + "?cookie=1"}, redirected: true,
		before: run("redir-fetch-there-and-back-cookies") + "?cookie=1"},
	"redir-fetch-no-cors-back-cookies": {browser: BrowserContext{Kind: KindFetch,
		Initiator: run("redir-fetch-no-cors-back-cookies") + "?cookie=1", Mode: modeNoCORS}, redirected: true,
		before: run("redir-fetch-no-cors-back-cookies") + "?cookie=1"},
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

// The scenarios of HTTP authentication: what each page asked for, the URL it
// asked with and the credentials in it, a page led on by the last one.
func init() {
	typed := BrowserContext{Kind: KindNavigation}
	for scenario, how := range map[string]asSent{
		"auth-nav-typed":                   {browser: typed, pages: []int{0, 2, 4}, credentials: []string{"u:p", "u:p", "u:p"}},
		"auth-nav-typed-other-dir":         {browser: typed, pages: []int{0, 2, 4}, credentials: []string{"u:p", "u:p", "u:p"}},
		"auth-nav-wrong":                   {browser: typed, pages: []int{0}, credentials: []string{"u:x"}},
		"auth-nav-from-page":               {browser: BrowserContext{Kind: KindNavigation, Initiator: run("auth-nav-from-page")}, pages: []int{0, 2}, credentials: []string{"u:p", "u:p"}},
		"auth-nav-redirect-to-credentials": {browser: typed, pages: []int{0, 3}, credentials: []string{"", "u:p"}},
		"auth-nav-redirect-after":          {browser: typed, pages: []int{0, 4}, credentials: []string{"u:p", "u:p"}},
		"auth-form-post":                   {browser: BrowserContext{Kind: KindForm, Initiator: run("auth-form-post")}, form: true, pages: []int{0, 2}, credentials: []string{"u:p", "u:p"}},
		"auth-xhr":                         {browser: BrowserContext{Kind: KindXHR, Initiator: run("auth-xhr")}, pages: []int{0}, credentials: []string{"u:p"}},
		"auth-nav-later-same-dir":          {browser: typed, pages: []int{0, 2, 3}, credentials: []string{"u:p", "", ""}},
		"auth-nav-later-other-dir":         {browser: typed, pages: []int{0, 2, 4}, credentials: []string{"u:p", "", ""}},
		"auth-nav-digest":                  {browser: typed, pages: []int{0}, credentials: []string{"u:p"}},
		"auth-digest":                      {browser: typed, pages: []int{0, 2, 3, 4}, credentials: []string{"u:p", "", "", ""}},
		"auth-digest-stale":                {browser: typed, pages: []int{0, 3, 4}, credentials: []string{"u:p", "", ""}},
		"auth-digest-stale-later":          {browser: typed, pages: []int{0, 2, 4, 5}, credentials: []string{"u:p", "", "", ""}},
		"auth-digest-other-dir":            {browser: typed, pages: []int{0, 2, 4, 5}, credentials: []string{"u:p", "", "", ""}},
		"auth-digest-form-post": {browser: BrowserContext{Kind: KindForm, Initiator: run("auth-digest-form-post")}, form: true,
			pages: []int{0, 2}, credentials: []string{"u:p", ""}},
		"auth-digest-redirect":   {browser: typed, pages: []int{0, 3}, credentials: []string{"u:p", ""}},
		"auth-digest-basic-kept": {browser: typed, pages: []int{0, 2}, credentials: []string{"u:p", ""}},
		"auth-digest-stale-forever": {browser: typed, pages: []int{0}, credentials: []string{"u:p"},
			fails: "asked for authentication again after 31 answers"},
		"auth-nav-cross-site-samesite":    {browser: BrowserContext{Kind: KindNavigation, Initiator: run("auth-nav-cross-site-samesite")}, pages: []int{0, 2}, credentials: []string{"u:p", "u:p"}, cookies: setOnEveryKind("www.example.net")},
		"nav-misdirected-401-misdirected": {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-misdirected-401-misdirected")}, pages: []int{0}, credentials: []string{"u:p"}},
		"nav-401-misdirected":             {browser: BrowserContext{Kind: KindNavigation, Initiator: run("nav-401-misdirected")}, pages: []int{0}, credentials: []string{"u:p"}},
		"set-cookie-samesite-fetch-cross-site": {each: []BrowserContext{
			{Kind: KindFetch, Initiator: run("set-cookie-samesite-fetch-cross-site"), Credentials: "include"},
			{Kind: KindNavigation, Initiator: run("set-cookie-samesite-fetch-cross-site")},
			{Kind: KindNavigation, Initiator: "https://www.example.net/p/set-cookie-samesite-fetch-cross-site-land?after=0&" +
				"next=https://www.example.net/p/set-cookie-samesite-fetch-cross-site-after"}}},
		"set-cookie-samesite-nav-cross-site": {browser: BrowserContext{Kind: KindNavigation,
			Initiator: run("set-cookie-samesite-nav-cross-site")}, pages: []int{0, 1}, credentials: []string{"", ""}},
		"set-cookie-samesite-form-cross-site": {browser: BrowserContext{Kind: KindForm,
			Initiator: run("set-cookie-samesite-form-cross-site")}, form: true, pages: []int{0, 1}, credentials: []string{"", ""}},
		"set-cookie-samesite-fetch-redirect-back": {pages: []int{0, 2}, credentials: []string{"", ""}, each: []BrowserContext{
			{Kind: KindFetch, Initiator: run("set-cookie-samesite-fetch-redirect-back"), Credentials: "include"},
			{Kind: KindFetch, Initiator: run("set-cookie-samesite-fetch-redirect-back")}}},
		"set-cookie-samesite-nav-redirect-back": {browser: BrowserContext{Kind: KindNavigation,
			Initiator: run("set-cookie-samesite-nav-redirect-back")}, pages: []int{0, 2}, credentials: []string{"", ""}},
		"set-cookie-preflight": {script: []string{"Content-Type", "X-Foo"}, each: []BrowserContext{
			{Kind: KindFetch, Initiator: run("set-cookie-preflight"), Credentials: "include"},
			{Kind: KindFetch, Initiator: run("set-cookie-preflight"), Credentials: "include"},
			{Kind: KindFetch, Initiator: run("set-cookie-preflight"), Credentials: "include"}}},
		"set-cookie-fetch-cors-refused": {corsRefused: []int{0}, each: []BrowserContext{
			{Kind: KindFetch, Initiator: run("set-cookie-fetch-cors-refused"), Credentials: "include"},
			{Kind: KindFetch, Initiator: run("set-cookie-fetch-cors-refused"), Credentials: "include"}}},
		"set-cookie-redir-across-same-origin-creds": {pages: []int{0, 2, 3}, credentials: []string{"", "", ""},
			each: []BrowserContext{
				{Kind: KindFetch, Initiator: run("set-cookie-redir-across-same-origin-creds")},
				{Kind: KindFetch, Initiator: run("set-cookie-redir-across-same-origin-creds")},
				{Kind: KindFetch, Initiator: run("set-cookie-redir-across-same-origin-creds"), Credentials: "include"}}},
		"fetch-misdirected-cookie": {each: []BrowserContext{{Kind: KindFetch, Initiator: run("fetch-misdirected-cookie")},
			{Kind: KindFetch, Initiator: run("fetch-misdirected-cookie")}}, pages: []int{0, 2}, credentials: []string{"", ""}},
	} {
		sentInContexts[scenario] = how
	}
	// A page of each offer, answered, then one of its directory, sent unasked
	// what was kept, then a page of no realm.
	for _, offer := range []string{"md5", "md5-sess", "sha256", "sha256-sess", "no-qop", "auth-int", "qop-list", "opaque",
		"userhash", "no-realm", "unknown-algorithm", "no-nonce", "empty-value", "after-basic", "md5-first",
		"sha256-first", "negotiate", "quoting", "unquoted"} {
		sentInContexts["auth-digest-"+offer] = asSent{browser: typed, pages: []int{0, 2, 3}, credentials: []string{"u:p", "", ""}}
	}
}

// sentAfter are scenarios whose page made a first fetch() of another kind,
// to set cookies, before the one measured: the context of each call.
var sentAfter = map[string][]BrowserContext{
	"set-cookie-samesite-fetch-same-site": {
		{Kind: KindFetch, Initiator: run("set-cookie-samesite-fetch-same-site"), Credentials: "include"},
		{Kind: KindFetch, Initiator: run("set-cookie-samesite-fetch-same-site"), Credentials: "include"},
	},
	"set-cookie-fetch-omit": {
		{Kind: KindFetch, Initiator: run("set-cookie-fetch-omit"), Credentials: "omit"},
		{Kind: KindFetch, Initiator: run("set-cookie-fetch-omit")},
	},
	"set-cookie-fetch-across-same-origin-creds": {
		{Kind: KindFetch, Initiator: run("set-cookie-fetch-across-same-origin-creds")},
		{Kind: KindFetch, Initiator: run("set-cookie-fetch-across-same-origin-creds"), Credentials: "include"},
	},
	"fetch-get-cross-site-omit": {
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-omit"), Credentials: "include"},
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-omit"), Credentials: "omit"},
	},
	"fetch-get-cross-site-same-origin-creds": {
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-same-origin-creds"), Credentials: "include"},
		{Kind: KindFetch, Initiator: run("fetch-get-cross-site-same-origin-creds")},
	},
}

func TestEveryScenarioMeasuredIsSentOrSaysWhyNot(t *testing.T) {
	for scenario := range loadChromeRequests(t).Scenarios {
		_, sent := sentInContexts[scenario]
		_, after := sentAfter[scenario]
		_, why := notSent[scenario]
		if sent == why && after == why || sent && after {
			t.Errorf("%s: sent %v, after %v, not sent %v", scenario, sent, after, why)
		}
	}
	for scenario := range notSent {
		if _, ok := loadChromeRequests(t).Scenarios[scenario]; !ok {
			t.Errorf("%s is not in the fixture", scenario)
		}
	}
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
				contexts := sentAfter[scenario]
				if how.each != nil {
					contexts = how.each
				}
				if how.pages != nil && how.each == nil {
					contexts = []BrowserContext{how.browser}
					for _, at := range how.pages[1:] {
						contexts = append(contexts, BrowserContext{Kind: KindNavigation, Initiator: want[at-1].URL})
					}
				}
				got := sendAsMeasured(t, proto, how, contexts, want)
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
// and kept for none; under /chain/N a redirect to /chain/N+1; under /auth/ a
// 401 with a Basic challenge, after a Digest one for ?offer=digest, until the
// request says u:p, then a redirect to ?to or a page; under /digest/ what the
// bench answers (harness.DigestPage); under /misdirected/ what the bench
// answers (harness.Misdirection), and otherwise what /cors/ answers, CORS
// refusing it for ?noacao; cookies, two for ?cookie=1 and one of each SameSite
// for ?cookie=2, one named by ?keep on any answer but a preflight's and one
// named by ?pfkeep on a preflight's; and for ?close,
// the connection ended once answered, as Connection: close says (GOAWAY over
// HTTP/2).
func answeringAsMeasured(w http.ResponseWriter, r *http.Request) {
	// The whole request is read before it is answered. Go's HTTP/2 client
	// stops sending a body once an answer above 299 comes, and over loopback
	// a 401 could come between a POST's HEADERS and its DATA, which no answer
	// over a network outruns: the body was sent, and recorded, or not, as the
	// machine was loaded.
	_, _ = io.Copy(io.Discard, r.Body)
	q := r.URL.Query()
	if q.Has("accept") {
		w.Header().Set("Accept-CH", q.Get("accept"))
	}
	if q.Has("critical") {
		w.Header().Set("Critical-CH", q.Get("critical"))
	}
	if q.Has("close") {
		w.Header().Set("Connection", "close")
	}
	allow := func() {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
	keep := q.Get("keep")
	if r.Method == http.MethodOptions {
		keep = q.Get("pfkeep")
	}
	if keep != "" {
		w.Header().Add("Set-Cookie", keep+"=1; Max-Age=3600; Path=/; SameSite=None; Secure")
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
	misdirect := strings.HasPrefix(r.URL.Path, "/misdirected/")
	if misdirect && misdirected(w, r) {
		return
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
	case strings.HasPrefix(path, "/auth/") && r.Header.Get("Authorization") != "Basic dTpw":
		if q.Get("offer") == "digest" {
			w.Header().Add("WWW-Authenticate", `Digest realm="bench", nonce="b3ec7d4c", qop="auth"`)
		}
		w.Header().Add("WWW-Authenticate", `Basic realm="bench"`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "<!doctype html><title>401</title><p>401</p>")
		return
	case strings.HasPrefix(path, "/digest/"):
		harness.DigestPage(w, r)
		return
	case strings.HasPrefix(path, "/auth/") && q.Get("to") != "":
		w.Header().Set("Location", q.Get("to"))
		w.WriteHeader(http.StatusFound)
		return
	case !strings.HasPrefix(path, "/cors/") && !misdirect:
		allow()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>page</title>")
		return
	}
	if q.Get("deny") == "" && q.Get("noacao") == "" {
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

// chromeCnonce is the client nonce of a Digest answer of Chrome's: 16
// hexadecimal digits in lower case.
var chromeCnonce = regexp.MustCompile(`, cnonce="([0-9a-f]{16})"`)

// sendAsMeasured sends what a scenario's page asked for, each request but the
// preflights Chrome made itself, in its browser context, to a recorder
// speaking proto, or plain HTTP when Chrome went over it, and is what the
// recorder kept: preflights and all.
func sendAsMeasured(t *testing.T, proto string, how asSent, contexts []BrowserContext, want []chromeRequest) []*keptRequest {
	t.Helper()
	server := newRecorder(t, proto, answeringAsMeasured)
	plain := newRecorder(t, "http", answeringAsMeasured)
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialingWith(plain))
	// The client nonces of Chrome's Digest answers, drawn again in the order
	// it drew them: what an answer says, its response too, has to be Chrome's.
	var drawn []string
	for _, req := range want {
		if found := chromeCnonce.FindStringSubmatch(req.header("authorization")); found != nil {
			drawn = append(drawn, found[1])
		}
	}
	client.session.auth.draw = func() string {
		if len(drawn) == 0 {
			t.Error("a client nonce was drawn that Chrome did not draw")
			return ""
		}
		next := drawn[0]
		drawn = drawn[1:]
		return next
	}
	skip := 0
	if how.before != "" {
		if _, err := client.Do(&Request{URL: how.before, Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
			t.Fatalf("Do %s: %v", how.before, err)
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
	if how.pages != nil {
		asked = nil
		for i, at := range how.pages {
			req := want[at]
			if how.credentials[i] != "" {
				req.URL = strings.Replace(req.URL, "://", "://"+how.credentials[i]+"@", 1)
			}
			asked = append(asked, req)
		}
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
			if value := measured.header(name); value != "" {
				req.Header = append(req.Header, profile.Field{Name: name, Value: value})
			}
		}
		if how.form && measured.header("content-type") != "" {
			req.Header = append(req.Header, profile.Field{Name: "content-type", Value: measured.header("content-type")})
		}
		_, err := client.Do(req)
		switch {
		case slices.Contains(how.corsRefused, i):
			if !errors.Is(err, ErrCORS) {
				t.Fatalf("request %d: CORS let it through: %v", i+1, err)
			}
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
// was HeadlessChrome's, and the network's client hints.
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
		if slices.ContainsFunc([]string{"user-agent", "rtt", "downlink"}, func(name string) bool {
			return strings.EqualFold(h[0], name)
		}) {
			// The user agent is the profile's, and was HeadlessChrome's;
			// round-trip time and downlink are Chrome's estimates of the
			// network, made anew all the time.
			continue
		}
		if got.headers[i][1] != h[1] {
			diff = append(diff, fmt.Sprintf("%s: %q, Chrome's %q", h[0], got.headers[i][1], h[1]))
		}
	}
	return strings.Join(diff, "\n")
}
