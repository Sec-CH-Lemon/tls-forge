package tlsforge

import (
	"errors"
	"strings"
	"testing"
)

func TestAPageOverHTTPSAsksNothingOfPlainHTTPAsChromeDoes(t *testing.T) {
	client := newTestClient(t, WithProfile("chrome_155_macos"))
	page := "https://www.example.com/page"
	fetch := BrowserContext{Kind: KindFetch, Initiator: page}
	form := BrowserContext{Kind: KindForm, Initiator: page}
	const sent = "is not sent to"
	const submitted = "a form of a page over https is not submitted to"
	for _, tc := range []struct {
		name    string
		req     Request
		browser BrowserContext
		says    string
	}{
		{"fetch() of an http site", Request{URL: "http://www.example.com/x"}, fetch,
			"fetch() from a page over https " + sent + " http://www.example.com/x, which is not potentially trustworthy"},
		{"its name in capitals", Request{URL: "http://WWW.EXAMPLE.COM/x"}, fetch, sent + " http://www.example.com/x"},
		{"no-cors", Request{URL: "http://www.example.com/x"},
			BrowserContext{Kind: KindFetch, Initiator: page, Mode: "no-cors"}, sent},
		{"credentials omitted", Request{URL: "http://www.example.com/x"},
			BrowserContext{Kind: KindFetch, Initiator: page, Credentials: "omit"}, sent},
		{"a POST", Request{Method: "POST", URL: "http://www.example.com/x", Body: []byte("x")}, fetch, sent},
		{"an XHR", Request{URL: "http://www.example.com/x"}, BrowserContext{Kind: KindXHR, Initiator: page},
			"an XHR from a page over https " + sent},
		{"a name that only begins with localhost", Request{URL: "http://localhost.example.com/"}, fetch, sent},
		{"a name that only ends in localhost", Request{URL: "http://notlocalhost/"}, fetch, sent},
		{"an address of the network, not the machine", Request{URL: "http://10.0.0.1/"}, fetch, sent},
		{"a form's GET", Request{URL: "http://www.example.com/x?a=1"}, form,
			submitted + " http://www.example.com/x?a=1, which is not potentially trustworthy, until the person using Chrome says to go on"},
		{"a form's POST", Request{Method: "POST", URL: "http://www.example.com/x", Body: []byte("a=1")}, form, submitted},
		{"a page whose URL has credentials", Request{URL: "http://www.example.com/x"},
			BrowserContext{Kind: KindFetch, Initiator: "https://u:p@www.example.com/page"}, sent},
		{"fetch() of https", Request{URL: "https://www.example.net/"}, fetch, ""},
		{"fetch() of localhost", Request{URL: "http://localhost:8080/"}, fetch, ""},
		{"of LOCALHOST", Request{URL: "http://LOCALHOST/"}, fetch, ""},
		{"of localhost with its dot", Request{URL: "http://localhost./"}, fetch, ""},
		{"of a name under .localhost", Request{URL: "http://app.localhost/"}, fetch, ""},
		{"of one under it with its dot", Request{URL: "http://a.b.localhost./"}, fetch, ""},
		{"of 127.0.0.1", Request{URL: "http://127.0.0.1/"}, fetch, ""},
		{"of another loopback address", Request{URL: "http://127.255.0.9/"}, fetch, ""},
		{"of [::1]", Request{URL: "http://[::1]:8080/"}, fetch, ""},
		{"a form posted to localhost", Request{Method: "POST", URL: "http://localhost/x", Body: []byte("a=1")}, form, ""},
		{"a navigation from the page", Request{URL: "http://www.example.com/"},
			BrowserContext{Kind: KindNavigation, Initiator: page}, ""},
		{"a navigation typed", Request{URL: "http://www.example.com/"}, BrowserContext{Kind: KindNavigation}, ""},
		{"fetch() from a page of localhost", Request{URL: "http://www.example.com/"},
			BrowserContext{Kind: KindFetch, Initiator: "http://localhost/page"}, ""},
		{"from a page over plain http", Request{URL: "http://www.example.net/"},
			BrowserContext{Kind: KindFetch, Initiator: "http://www.example.com/page"}, ""},
		{"a form of a page of localhost", Request{Method: "POST", URL: "http://www.example.com/", Body: []byte("a=1")},
			BrowserContext{Kind: KindForm, Initiator: "http://localhost/page"}, ""},
	} {
		req := tc.req
		req.Browser = &tc.browser
		err := client.Validate(&req)
		switch {
		case tc.says == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.says != "" && (!errors.Is(err, ErrMixedContent) || !strings.HasPrefix(err.Error(), "tlsforge: mixed content: ") ||
			!strings.Contains(err.Error(), tc.says)):
			t.Errorf("%s: %v, want mixed content saying %q", tc.name, err, tc.says)
		}
	}
}

func TestAURLsPasswordIsNotSaidByMixedContent(t *testing.T) {
	client := newTestClient(t, WithProfile("chrome_155_macos"))
	err := client.Validate(&Request{URL: "http://alice:secret@www.example.com/x",
		Browser: &BrowserContext{Kind: KindXHR, Initiator: "https://www.example.com/page"}})
	if !errors.Is(err, ErrMixedContent) || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "alice") {
		t.Errorf("error = %v", err)
	}
}

func TestAContextsOwnTroubleIsSaidBeforeMixedContent(t *testing.T) {
	// fetch() in same-origin mode of another origin over plain http: what
	// is wrong with the request itself first.
	client := newTestClient(t, WithProfile("chrome_155_macos"))
	err := client.Validate(&Request{URL: "http://www.example.com/x", Browser: &BrowserContext{Kind: KindFetch,
		Initiator: "https://www.example.com/page", Mode: "same-origin"}})
	if err == nil || errors.Is(err, ErrMixedContent) || !strings.Contains(err.Error(), "same-origin mode") {
		t.Errorf("error = %v", err)
	}
}

func TestNothingIsSentOfARequestMixedContentStops(t *testing.T) {
	got, err := sent(t, &Request{URL: "http://www.example.com/cors/x",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}})
	if !errors.Is(err, ErrMixedContent) || len(got) != 0 {
		t.Errorf("sent %d requests, %v", len(got), err)
	}
}

func TestARedirectToPlainHTTPIsFollowedAsChromeFollowsIt(t *testing.T) {
	page := "https://www.example.com/page"
	fetch := BrowserContext{Kind: KindFetch, Initiator: page}
	form := BrowserContext{Kind: KindForm, Initiator: page}
	const to = "http://www.example.com/p/y"
	for _, tc := range []struct {
		name    string
		method  string
		target  string
		browser BrowserContext
		// asked are the requests that went, by method and URL; says is the
		// mixed content error, none when empty.
		asked []string
		says  string
	}{
		{"fetch()", "GET", "https://www.example.com/r/302/x?to=" + to, fetch,
			[]string{"GET https://www.example.com/r/302/x?to=" + to},
			"fetch() from a page over https follows no redirect to http://www.example.com/p/y, which is not potentially trustworthy"},
		{"an XHR", "GET", "https://www.example.com/r/307/x?to=" + to, BrowserContext{Kind: KindXHR, Initiator: page},
			[]string{"GET https://www.example.com/r/307/x?to=" + to}, "an XHR from a page over https follows no redirect to"},
		{"fetch() of localhost, sent on", "GET", "http://localhost/r/302/x?to=" + to, fetch,
			[]string{"GET http://localhost/r/302/x?to=" + to}, "follows no redirect to http://www.example.com/p/y"},
		{"fetch(), a hop to localhost", "GET", "https://www.example.com/r/302/x?to=http://localhost/cors/y", fetch,
			[]string{"GET https://www.example.com/r/302/x?to=http://localhost/cors/y", "GET http://localhost/cors/y"}, ""},
		{"fetch() from a page of localhost", "GET", "https://www.example.com/r/302/x?to=" + to,
			BrowserContext{Kind: KindFetch, Initiator: "http://localhost/page"},
			[]string{"GET https://www.example.com/r/302/x?to=" + to, "GET " + to}, ""},
		{"a form posted again after a 307", "POST", "https://www.example.com/r/307/x?to=" + to, form,
			[]string{"POST https://www.example.com/r/307/x?to=" + to},
			"a form of a page over https is not posted again to http://www.example.com/p/y, which is not potentially " +
				"trustworthy, until the person using Chrome says to go on"},
		{"after a 308", "POST", "https://www.example.com/r/308/x?to=" + to, form,
			[]string{"POST https://www.example.com/r/308/x?to=" + to}, "is not posted again to"},
		{"a form's POST after a 302, a GET", "POST", "https://www.example.com/r/302/x?to=" + to, form,
			[]string{"POST https://www.example.com/r/302/x?to=" + to, "GET " + to}, ""},
		{"after a 303", "POST", "https://www.example.com/r/303/x?to=" + to, form,
			[]string{"POST https://www.example.com/r/303/x?to=" + to, "GET " + to}, ""},
		{"a form's GET after a 307", "GET", "https://www.example.com/r/307/x?to=" + to, form,
			[]string{"GET https://www.example.com/r/307/x?to=" + to, "GET " + to}, ""},
		{"posted on to another site, then to plain http", "POST",
			"https://www.example.com/r/307/x?to=https://www.example.net/r/307/y?to=" + to, form,
			[]string{"POST https://www.example.com/r/307/x?to=https://www.example.net/r/307/y?to=" + to,
				"POST https://www.example.net/r/307/y?to=" + to}, "is not posted again to"},
		{"a GET since a 302, then a 307 to plain http", "POST",
			"https://www.example.com/r/302/x?to=https://www.example.net/r/307/y?to=" + to, form,
			[]string{"POST https://www.example.com/r/302/x?to=https://www.example.net/r/307/y?to=" + to,
				"GET https://www.example.net/r/307/y?to=" + to, "GET " + to}, ""},
		{"a navigation", "GET", "https://www.example.com/r/302/x?to=" + to,
			BrowserContext{Kind: KindNavigation, Initiator: page},
			[]string{"GET https://www.example.com/r/302/x?to=" + to, "GET " + to}, ""},
	} {
		req := &Request{Method: tc.method, URL: tc.target, Browser: &tc.browser}
		if tc.method == "POST" {
			req.Body = []byte("a=1")
		}
		got, err := sent(t, req)
		var asked []string
		for _, r := range got {
			asked = append(asked, r.method+" "+r.url)
		}
		switch {
		case strings.Join(asked, ", ") != strings.Join(tc.asked, ", "):
			t.Errorf("%s: sent %v, want %v (%v)", tc.name, asked, tc.asked, err)
		case tc.says == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.says != "" && (!errors.Is(err, ErrMixedContent) || !strings.Contains(err.Error(), tc.says)):
			t.Errorf("%s: %v, want mixed content saying %q", tc.name, err, tc.says)
		}
	}
}

func TestCORSIsAskedAboutARedirectBeforeMixedContent(t *testing.T) {
	// Chrome's network stack checks the redirect itself before its page
	// checks where it goes: a redirect to plain http that CORS does not allow
	// is CORS's, and so is one in same-origin mode.
	page := "https://www.example.com/page"
	for _, tc := range []struct {
		target string
		mode   string
	}{
		{"https://www.example.net/r/302/x?noacao=1&to=http://www.example.net/p/y", ""},
		{"https://www.example.com/r/302/x?to=http://www.example.net/p/y", "same-origin"},
	} {
		got, err := sent(t, &Request{URL: tc.target, Browser: &BrowserContext{Kind: KindFetch, Initiator: page, Mode: tc.mode}})
		if !errors.Is(err, ErrCORS) || errors.Is(err, ErrMixedContent) || len(got) != 1 {
			t.Errorf("%s: sent %d requests, %v", tc.target, len(got), err)
		}
	}
}

func TestAHopMixedContentStopsAsksNoPreflight(t *testing.T) {
	// A POST of JSON to the page's own origin needs no preflight; its 307 to
	// another origin over plain http would, and neither goes.
	got, err := sent(t, &Request{Method: "POST", URL: "https://www.example.com/r/307/x?to=http://www.example.net/cors/y",
		Body: []byte("{}"), Header: NewHeader("Content-Type", "application/json"),
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}})
	if !errors.Is(err, ErrMixedContent) || len(got) != 1 || got[0].method != "POST" {
		t.Errorf("sent %d requests, %v", len(got), err)
	}
}
