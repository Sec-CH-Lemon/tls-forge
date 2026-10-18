package tlsforge

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
)

// header is the value of a kept request's header, by name in any case, and
// whether it has one.
func (r *keptRequest) header(name string) (string, bool) {
	for _, h := range r.headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

// sent is what a recorder answering as the scenarios' server was sent for one
// request, followed through its redirects.
func sent(t *testing.T, req *Request, opts ...Option) ([]*keptRequest, error) {
	t.Helper()
	server := newRecorder(t, "h2", answeringAsMeasured)
	plain := newRecorder(t, "http", answeringAsMeasured)
	client := newTestClient(t, append([]Option{WithProfile("chrome_155_macos"), server.dialingWith(plain)}, opts...)...)
	_, err := client.Do(req)
	return server.requests(), err
}

func TestARedirectPolicyGivenAsATransportOptionReplacesChromes(t *testing.T) {
	// Given after tls-forge's own, it is the one the transport keeps: the
	// redirect is answered, not followed, as WithoutRedirects would have it.
	got, err := sent(t, &Request{URL: "https://www.example.com/r/302/x?to=/p/y"},
		WithTransportOption(tls_client.WithNotFollowRedirects()))
	if err != nil || len(got) != 1 {
		t.Fatalf("sent %d requests, %v", len(got), err)
	}
}

func TestARedirectLeavesTheMethodAsTheFetchStandardDoes(t *testing.T) {
	// The transport made a GET of every method but GET and HEAD on 301, 302
	// and 303, and dropped its body; Chrome does that to a POST alone on 301
	// and 302, and to all but HEAD on 303.
	for _, tc := range []struct {
		method string
		status string
		want   string
		body   bool
	}{
		{"PUT", "301", "PUT", true}, {"PUT", "302", "PUT", true}, {"PATCH", "302", "PATCH", true},
		{"DELETE", "301", "DELETE", true},
		{"POST", "301", "GET", false}, {"POST", "302", "GET", false}, {"POST", "303", "GET", false},
		{"PUT", "303", "GET", false}, {"DELETE", "303", "GET", false},
		{"HEAD", "303", "HEAD", false}, {"GET", "303", "GET", false}, {"HEAD", "301", "HEAD", false},
		{"POST", "307", "POST", true}, {"PUT", "308", "PUT", true},
	} {
		t.Run(tc.method+"/"+tc.status, func(t *testing.T) {
			body := "a=1"
			if tc.method == "HEAD" || tc.method == "GET" {
				body = ""
			}
			got, err := sent(t, &Request{Method: tc.method, URL: "https://www.example.com/r/" + tc.status + "/x?to=/p/y",
				Body: []byte(body), Header: NewHeader("Content-Type", "text/plain", "Content-Language", "de",
					"Origin", "https://www.example.com")})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("sent %d requests", len(got))
			}
			hop := got[1]
			if hop.method != tc.want || hop.url != "https://www.example.com/p/y" {
				t.Errorf("the hop is %s %s, want %s", hop.method, hop.url, tc.want)
			}
			_, typed := hop.header("content-type")
			_, language := hop.header("content-language")
			origin, _ := hop.header("origin")
			kept := tc.body || tc.method == tc.want
			if (hop.body != "") != tc.body || typed != kept || language != kept || (origin != "") != kept {
				t.Errorf("the hop sent body %q, Content-Type %v, Content-Language %v, Origin %q", hop.body, typed,
					language, origin)
			}
		})
	}
}

func TestABodyARedirectDroppedStaysDropped(t *testing.T) {
	// The transport sends the first request's body again after a 307, and its
	// headers on every hop, even once a 302 dropped both.
	got, err := sent(t, &Request{Method: "POST", URL: "https://www.example.com/r/302/x?to=/r/307/y?to=/p/z",
		Body: []byte("a=1"), Header: NewHeader("Content-Type", "text/plain", "Origin", "https://www.example.com")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("sent %d requests", len(got))
	}
	for _, hop := range got[1:] {
		_, typed := hop.header("content-type")
		_, origin := hop.header("origin")
		if hop.method != "GET" || hop.body != "" || typed || origin {
			t.Errorf("%s %s sent body %q, Content-Type %v, Origin %v", hop.method, hop.url, hop.body, typed, origin)
		}
	}
	// A form keeps its Cache-Control.
	got, err = sent(t, &Request{Method: "POST", URL: "https://www.example.com/r/302/x?to=/r/307/y?to=/p/z",
		Body: []byte("a=1"), Browser: &BrowserContext{Kind: KindForm, Initiator: "https://www.example.com/page"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	for _, hop := range got[1:] {
		_, typed := hop.header("content-type")
		cache, _ := hop.header("cache-control")
		if hop.method != "GET" || hop.body != "" || typed || cache != "max-age=0" {
			t.Errorf("the form's %s %s sent body %q, Content-Type %v, Cache-Control %q", hop.method, hop.url,
				hop.body, typed, cache)
		}
	}
}

func TestARedirectSendsOnlyTheRefererARequestWasGiven(t *testing.T) {
	// The transport sent the redirecting URL, query and all, to wherever it
	// redirected: here a token, to another site.
	got, err := sent(t, &Request{URL: "https://www.example.com/r/302/x?token=secret&to=https://www.example.net/p/y"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if referer, ok := got[1].header("referer"); ok {
		t.Errorf("the hop said Referer: %s", referer)
	}
	if origin, ok := got[1].header("origin"); ok {
		t.Errorf("the hop said Origin: %s", origin)
	}
	for _, h := range got[1].headers {
		if strings.Contains(h[1], "secret") {
			t.Errorf("the hop said %s: %s", h[0], h[1])
		}
	}
	got, err = sent(t, &Request{URL: "https://www.example.com/r/302/x?to=https://www.example.net/p/y",
		Header: NewHeader("Referer", "https://shop.example/a", "Referer", "https://shop.example/b")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	var referers []string
	for _, h := range got[1].headers {
		if strings.EqualFold(h[0], "referer") {
			referers = append(referers, h[1])
		}
	}
	if strings.Join(referers, " ") != "https://shop.example/a https://shop.example/b" {
		t.Errorf("the hop said Referer %v", referers)
	}
}

func TestARedirectAcrossOriginsDropsAuthorizationForGood(t *testing.T) {
	given := NewHeader("Authorization", "Bearer x", "Origin", "https://www.example.com")
	// To another origin of the same site, which the transport counts as its
	// own, and on within it: the transport copies the first request's headers
	// onto every hop.
	got, err := sent(t, &Request{Method: "PUT", URL: "https://www.example.com/r/307/x?to=" +
		"https://api.example.com/r/307/y?to=/p/z", Header: given, Body: []byte("a")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("sent %d requests", len(got))
	}
	for i, hop := range got[1:] {
		_, authorized := hop.header("authorization")
		if origin, _ := hop.header("origin"); authorized || origin != "null" {
			t.Errorf("hop %d sent Authorization %v, Origin %q", i+1, authorized, origin)
		}
	}
	// Within its origin it keeps both.
	got, err = sent(t, &Request{Method: "PUT", URL: "https://www.example.com/r/307/x?to=/p/z", Header: given,
		Body: []byte("a")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	authorization, _ := got[1].header("authorization")
	if origin, _ := got[1].header("origin"); authorization != "Bearer x" || origin != "https://www.example.com" {
		t.Errorf("the hop sent Authorization %q, Origin %q", authorization, origin)
	}
}

func TestALocationWithCredentialsIsFollowedWithoutThem(t *testing.T) {
	// Chrome sends credentials a Location names only when the server asks;
	// the transport sent them at once, as Basic.
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := newTestClient(t, server.dialing())
	res, err := client.Get("https://www.example.com/r/302/x?to=https://u:p@www.example.com/p/y")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got := server.requests()
	if authorization, ok := got[1].header("authorization"); ok {
		t.Errorf("the hop sent Authorization: %s", authorization)
	}
	if res.URL != "https://www.example.com/p/y" {
		t.Errorf("the answer is of %s", res.URL)
	}
}

func TestAPreflightARedirectNeedsCanRefuseIt(t *testing.T) {
	// A POST of JSON to the page's own origin goes without a preflight; its
	// redirect to another site asks there, and goes no further when refused.
	got, err := sent(t, &Request{Method: "POST", URL: "https://www.example.com/r/307/x?to=" +
		"https://www.example.net/cors/after?deny=1", Body: []byte("{}"), Header: NewHeader("Content-Type", "application/json"),
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}})
	if !errors.Is(err, ErrCORS) || !strings.Contains(err.Error(),
		"the preflight of POST https://www.example.net/cors/after?deny=1 from https://www.example.com refused it") {
		t.Errorf("error = %v", err)
	}
	var asked []string
	for _, req := range got {
		asked = append(asked, req.method+" "+req.url)
	}
	if strings.Join(asked, ", ") != "POST https://www.example.com/r/307/x?to=https://www.example.net/cors/after?deny=1, "+
		"OPTIONS https://www.example.net/cors/after?deny=1" {
		t.Errorf("sent %v", asked)
	}
}

func TestTheRedirectsPreflightGoesOutWithoutCredentials(t *testing.T) {
	// The page has a connection with credentials to www.example.net, from a
	// fetch() that carried them; the preflight its redirect there needs goes
	// out on one of the connections of requests that carry none, as every
	// preflight does.
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	page := "https://www.example.com/page"
	if _, err := client.Do(&Request{URL: "https://www.example.net/cors/first", Browser: &BrowserContext{Kind: KindFetch,
		Initiator: page, Credentials: credentialsAll}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if _, err := client.Do(&Request{Method: "POST", URL: "https://www.example.com/r/307/x?to=https://www.example.net/cors/after",
		Body: []byte("{}"), Header: NewHeader("Content-Type", "application/json"),
		Browser: &BrowserContext{Kind: KindFetch, Initiator: page}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 4 || got[2].method != "OPTIONS" || got[2].conn == got[0].conn || got[2].conn == got[1].conn {
		var sent []string
		for _, req := range got {
			sent = append(sent, fmt.Sprintf("%s %s on %d", req.method, req.url, req.conn))
		}
		t.Errorf("sent %q", sent)
	}
}

func TestCredentialsInALocationAPageMayFollow(t *testing.T) {
	// fetch() follows none, but to the page's own origin with the page's own
	// credentials; and nothing in cors mode does once CORS answers for it, or
	// to another origin than the page's.
	for _, tc := range []struct {
		name    string
		browser BrowserContext
		url     string
		says    string
	}{
		{"fetch() with the page's credentials", BrowserContext{Kind: KindFetch,
			Initiator: "https://u:p@www.example.com/page"}, "https://www.example.com/r/302/x?to=https://u:p@www.example.com/p/y",
			""},
		{"fetch() in no-cors mode with them", BrowserContext{Kind: KindFetch, Mode: "no-cors",
			Initiator: "https://u:p@www.example.com/page"}, "https://www.example.com/r/302/x?to=https://u:p@www.example.com/p/y",
			""},
		{"fetch() in no-cors mode back from another origin", BrowserContext{Kind: KindFetch, Mode: "no-cors",
			Initiator: "https://u:p@www.example.com/page"}, "https://www.example.com/r/302/x?to=" +
			"https://www.example.net/r/302/y?to=https://u:p@www.example.com/p/y", ""},
		{"fetch() with another password", BrowserContext{Kind: KindFetch,
			Initiator: "https://u:q@www.example.com/page"}, "https://www.example.com/r/302/x?to=https://u:p@www.example.com/p/y",
			"fetch() follows no redirect to a URL with credentials in it"},
		{"fetch() with another user", BrowserContext{Kind: KindFetch,
			Initiator: "https://v:p@www.example.com/page"}, "https://www.example.com/r/302/x?to=https://u:p@www.example.com/p/y",
			"fetch() follows no redirect to a URL with credentials in it"},
		{"fetch() to another origin", BrowserContext{Kind: KindFetch, Mode: "no-cors",
			Initiator: "https://u:p@www.example.com/page"}, "https://www.example.com/r/302/x?to=https://u:p@api.example.com/p/y",
			"fetch() follows no redirect to a URL with credentials in it"},
		{"fetch() back from another origin", BrowserContext{Kind: KindFetch,
			Initiator: "https://u:p@www.example.com/page"}, "https://www.example.net/r/302/x?to=https://u:p@www.example.com/p/y",
			"fetch() follows no redirect to a URL with credentials in it across origins"},
		{"an XHR to another origin", BrowserContext{Kind: KindXHR, Initiator: "https://www.example.com/page"},
			"https://www.example.com/r/302/x?to=https://u:p@www.example.net/p/y",
			"an XHR follows no redirect to a URL with credentials in it across origins"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			browser := tc.browser
			got, err := sent(t, &Request{URL: tc.url, Browser: &browser})
			switch {
			case tc.says == "" && err != nil:
				t.Fatalf("Do: %v", err)
			case tc.says != "" && (!errors.Is(err, ErrCORS) || !strings.Contains(err.Error(), tc.says)):
				t.Fatalf("error = %v, want %q", err, tc.says)
			case tc.says != "" && len(got) != 1:
				t.Errorf("sent %d requests", len(got))
			case tc.says == "":
				last := got[len(got)-1]
				if authorization, ok := last.header("authorization"); ok || last.url != "https://www.example.com/p/y" {
					t.Errorf("the last hop went to %s with Authorization %q", last.url, authorization)
				}
			}
		})
	}
}

func TestAFormsOriginStaysNullAcrossOrigins(t *testing.T) {
	// Chrome's network stack says "null" on a hop to another origin, and
	// leaves it so: back on one origin, the form's own does not come back.
	got, err := sent(t, &Request{Method: "POST", URL: "https://www.example.com/r/307/x?to=" +
		"https://www.example.net/r/307/y?to=/p/z", Body: []byte("a=1"),
		Browser: &BrowserContext{Kind: KindForm, Initiator: "https://www.example.com/page"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	var origins []string
	for _, req := range got {
		origin, _ := req.header("origin")
		origins = append(origins, origin)
	}
	if strings.Join(origins, " ") != "https://www.example.com null null" {
		t.Errorf("Origin %v", origins)
	}
}

func TestAReferrerOnceGoneStaysGone(t *testing.T) {
	// Each hop's Referer comes from the one before: down to plain HTTP it is
	// none, and back on HTTPS still none.
	got, err := sent(t, &Request{URL: "https://www.example.com/r/302/x?to=http://www.example.com/r/302/y?to=" +
		"https://www.example.com/p/z", Browser: &BrowserContext{Kind: KindNavigation,
		Initiator: "https://www.example.com/page"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("sent %d requests", len(got))
	}
	for i, req := range got[1:] {
		if referer, ok := req.header("referer"); ok {
			t.Errorf("hop %d said Referer: %s", i+1, referer)
		}
	}
}

func TestThePagesReferrerPolicyHoldsThroughARedirect(t *testing.T) {
	got, err := sent(t, &Request{URL: "https://www.example.com/r/302/x?to=https://www.example.net/p/z",
		Browser: &BrowserContext{Kind: KindNavigation, Initiator: "https://www.example.com/page?q=1",
			ReferrerPolicy: "unsafe-url"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if referer, _ := got[1].header("referer"); referer != "https://www.example.com/page?q=1" {
		t.Errorf("the hop said Referer: %s", referer)
	}
}

func TestAHopCarriesTheCookiesItsOwnRuleLets(t *testing.T) {
	// fetch() keeps its cookies to its own origin unless it includes them: a
	// hop to another site carries none, or, included, those SameSite=None.
	for credentials, want := range map[string]string{"": "", "include": "b=2"} {
		server := newRecorder(t, "h2", answeringAsMeasured)
		client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
		// The other site sets one cookie of each SameSite.
		if _, err := client.Get("https://www.example.net/p/set?cookie=2"); err != nil {
			t.Fatalf("Get: %v", err)
		}
		_, err := client.Do(&Request{URL: "https://www.example.com/r/302/x?to=https://www.example.net/cors/z",
			Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page",
				Credentials: credentials}})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		got := server.requests()
		if cookie, _ := got[2].header("cookie"); cookie != want || got[2].url != "https://www.example.net/cors/z" {
			t.Errorf("credentials %q: %s sent Cookie %q, want %q", credentials, got[2].url, cookie, want)
		}
	}
}

func TestTheAnswerARedirectLedToIsCORSChecked(t *testing.T) {
	// A fetch() of its own origin needs no CORS; redirected to another, its
	// answer there does.
	_, err := sent(t, &Request{URL: "https://www.example.com/r/302/x?to=https://www.example.net/cors/after?deny=1",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}})
	if !errors.Is(err, ErrCORS) || !strings.Contains(err.Error(),
		"the answer of GET https://www.example.net/cors/after?deny=1 did not allow https://www.example.com") {
		t.Errorf("error = %v", err)
	}
}

func TestSecFetchSiteGoesByEveryURLOfAChain(t *testing.T) {
	got, err := sent(t, &Request{URL: "https://www.example.com/r/302/x?to=https://api.example.com/r/302/y?to=" +
		"https://www.example.com/p/z", Browser: &BrowserContext{Kind: KindNavigation,
		Initiator: "https://www.example.com/page"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	var sites []string
	for _, req := range got {
		site, _ := req.header("sec-fetch-site")
		sites = append(sites, site)
	}
	if strings.Join(sites, " ") != "same-origin same-site same-site" {
		t.Errorf("Sec-Fetch-Site %v", sites)
	}
}

func TestTheReferrerPolicyARedirectSets(t *testing.T) {
	for _, tc := range []struct {
		fields []string
		want   string
	}{
		{nil, ""},
		{[]string{""}, ""},
		{[]string{"no-referrer"}, "no-referrer"},
		{[]string{"NO-REFERRER"}, "no-referrer"},
		{[]string{"Strict-Origin-When-Cross-Origin"}, "strict-origin-when-cross-origin"},
		{[]string{"unsafe-url, nonsense"}, "unsafe-url"},
		{[]string{"nonsense"}, ""},
		{[]string{" origin \t"}, "origin"},
		{[]string{"origin,,"}, "origin"},
		{[]string{"origin", "unsafe-url, bogus"}, "unsafe-url"},
		{[]string{"same-origin", "bogus"}, "same-origin"},
		{[]string{"\vno-referrer-when-downgrade\f"}, "no-referrer-when-downgrade"},
		// Chrome lowers ASCII alone: a long s is no s, a Turkish capital
		// dotted I no i.
		{[]string{"ſtrict-origin"}, ""},
		{[]string{"STRİCT-ORIGIN"}, ""},
		{[]string{"origin-when-cross-origin"}, "origin-when-cross-origin"},
		{[]string{"strict-origin"}, "strict-origin"},
	} {
		header := fhttp.Header{}
		for _, field := range tc.fields {
			header.Add("Referrer-Policy", field)
		}
		if got := redirectPolicy(header); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.fields, got, tc.want)
		}
	}
}

func TestTheClientHintsGoAfterSecFetchDest(t *testing.T) {
	for _, tc := range []struct{ order, want string }{
		{"sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform user-agent sec-fetch-dest referer",
			"user-agent sec-fetch-dest sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform referer"},
		{"Sec-CH-UA user-agent Sec-Fetch-Dest", "user-agent Sec-Fetch-Dest Sec-CH-UA"},
		{"user-agent sec-fetch-dest sec-ch-ua", "user-agent sec-fetch-dest sec-ch-ua"},
		{"sec-ch-ua user-agent", "sec-ch-ua user-agent"},
		{"sec-ch-ua-arch user-agent sec-fetch-dest", "sec-ch-ua-arch user-agent sec-fetch-dest"},
		{"", ""},
	} {
		if got := strings.Join(hintsAfterDest(strings.Fields(tc.order)), " "); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.order, got, tc.want)
		}
	}
}

func TestAHeaderWithoutSomeNames(t *testing.T) {
	h := Header{{Name: "A", Value: "1"}, {Name: "b", Value: "2"}, {Name: "a", Value: "3"}, {Name: "C", Value: "4"}}
	before := slices.Clone(h)
	if got := h.without("a", "c"); !slices.Equal(got, Header{{Name: "b", Value: "2"}}) {
		t.Errorf("%v", got)
	}
	if !slices.Equal(h, before) {
		t.Errorf("the header changed: %v", h)
	}
	if got := Header(nil).without("a"); got != nil {
		t.Errorf("%v", got)
	}
}

func TestAPageRequestIsCalledByItsKind(t *testing.T) {
	if (&browserRequest{kind: KindXHR}).kindName() != "an XHR" || (&browserRequest{kind: KindFetch}).kindName() != "fetch()" {
		t.Error("misnamed")
	}
	if !(&browserRequest{kind: KindXHR}).scripted() || (&browserRequest{kind: KindForm}).scripted() {
		t.Error("misread")
	}
}
