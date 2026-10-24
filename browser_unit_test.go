package tlsforge

import (
	"context"
	"github.com/igor-lemon/utls/behavior"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// contextClient is a client of the profile Chrome was measured as, every
// connection of which reaches server.
func contextClient(t *testing.T, server *recorder, opts ...Option) *Client {
	t.Helper()
	return newTestClient(t, append([]Option{WithProfile("chrome_155_macos"), server.dialing()}, opts...)...)
}

func TestABrowserContextIsRefusedBeforeAnythingIsSent(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	page := "https://www.example.com/page"
	other := "https://www.example.net/x"
	for _, tc := range []struct {
		name    string
		browser BrowserContext
		method  string
		url     string
		header  Header
		body    string
		says    string
	}{
		{"no kind", BrowserContext{}, "", page, nil, "", `kind "" is not navigation, form, fetch or xhr`},
		{"an unknown kind", BrowserContext{Kind: "iframe"}, "", page, nil, "", `kind "iframe"`},
		{"an unknown policy", BrowserContext{Kind: KindNavigation, ReferrerPolicy: "never"}, "", page, nil, "",
			`referrer policy "never" is not one of no-referrer`},
		{"an initiator that is not a URL", BrowserContext{Kind: KindNavigation, Initiator: "%zz"}, "", page, nil, "",
			`initiator "%zz" is not a URL: it names no scheme`},
		{"an initiator Chrome sends as it is and tls-forge cannot", BrowserContext{Kind: KindNavigation,
			Initiator: "https://www.example.com/a%zz"}, "", page, nil, "", `initiator "https://www.example.com/a%zz" has "%zz" in its path`},
		{"an initiator of another scheme", BrowserContext{Kind: KindNavigation, Initiator: "ftp://x/"}, "", page, nil, "",
			`initiator "ftp://x/"`},
		{"a file as initiator", BrowserContext{Kind: KindNavigation, Initiator: "file://localhost/page"}, "", page, nil, "",
			`initiator "file://localhost/page"`},
		{"a websocket as initiator", BrowserContext{Kind: KindNavigation, Initiator: "wss://www.example.com/"}, "", page,
			nil, "", `initiator "wss://www.example.com/"`},
		{"a relative initiator", BrowserContext{Kind: KindNavigation, Initiator: "/page"}, "", page, nil, "",
			`initiator "/page"`},
		{"an initiator with no host", BrowserContext{Kind: KindNavigation, Initiator: "https:///"}, "", page, nil, "",
			`initiator "https:///" names no host`},
		{"a navigation that posts", BrowserContext{Kind: KindNavigation}, "POST", page, nil, "",
			"a navigation is a GET, not a POST: a form posts"},
		{"a navigation with a body", BrowserContext{Kind: KindNavigation}, "GET", page, nil, "x",
			"a navigation sends no body"},
		{"a navigation with a mode", BrowserContext{Kind: KindNavigation, Mode: "cors"}, "", page, nil, "",
			"a navigation has no mode: only fetch() has one"},
		{"a navigation with credentials", BrowserContext{Kind: KindNavigation, Credentials: "include"}, "", page, nil, "",
			"a navigation has no credentials mode"},
		{"a navigation with a header", BrowserContext{Kind: KindNavigation}, "", page, NewHeader("X-Foo", "1"), "",
			"a navigation sends the headers the browser gives it, not x-foo"},
		// A Referer is the browser's to work out, from the page and its
		// policy, whatever the kind.
		{"a navigation given a Referer", BrowserContext{Kind: KindNavigation, Initiator: other}, "", page,
			NewHeader("Referer", other), "", "a navigation sends the headers the browser gives it, not referer"},
		{"a form given a Referer", BrowserContext{Kind: KindForm, Initiator: page}, "POST", page,
			NewHeader("Content-Type", formEncoded, "Referer", other), "a=1", "a form sends the headers the browser gives it, not referer"},
		{"fetch() given a Referer", BrowserContext{Kind: KindFetch, Initiator: page}, "", page, NewHeader("Referer", other), "",
			"fetch() cannot set referer: the browser sets it"},
		{"an XHR given a Referer", BrowserContext{Kind: KindXHR, Initiator: page}, "", page, NewHeader("Referer", other), "",
			"an XHR cannot set referer: the browser sets it"},
		{"a form from no page", BrowserContext{Kind: KindForm}, "POST", page, nil, "a=1",
			"a form is submitted from a page: name it as the initiator"},
		{"a form put", BrowserContext{Kind: KindForm, Initiator: page}, "PUT", page, nil, "",
			"a form is sent by GET or POST, not PUT"},
		{"a form got with a body", BrowserContext{Kind: KindForm, Initiator: page}, "GET", page, nil, "a=1",
			"a form sent by GET has its fields in the URL"},
		{"a form got with a type", BrowserContext{Kind: KindForm, Initiator: page}, "GET", page,
			NewHeader("Content-Type", formEncoded), "", "a form sent by GET has its fields in the URL"},
		{"a form of JSON", BrowserContext{Kind: KindForm, Initiator: page}, "POST", page,
			NewHeader("Content-Type", "application/json"), "{}", `not "application/json"`},
		{"a multipart form with no boundary", BrowserContext{Kind: KindForm, Initiator: page}, "POST", page,
			NewHeader("Content-Type", "multipart/form-data"), "", "with its boundary"},
		{"a multipart form with an empty boundary", BrowserContext{Kind: KindForm, Initiator: page}, "POST", page,
			NewHeader("Content-Type", "multipart/form-data; boundary="), "", "with its boundary"},
		{"a multipart form with a quoted boundary", BrowserContext{Kind: KindForm, Initiator: page}, "POST", page,
			NewHeader("Content-Type", `multipart/form-data; boundary="b"`), "", "with its boundary"},
		{"a form with another header", BrowserContext{Kind: KindForm, Initiator: page}, "POST", page,
			NewHeader("Content-Type", formEncoded, "X-Foo", "1"), "", "a form sends the headers the browser gives it"},
		{"a form with a mode", BrowserContext{Kind: KindForm, Initiator: page, Mode: "cors"}, "POST", page, nil, "",
			"a form has no mode"},
		{"fetch() from no page", BrowserContext{Kind: KindFetch}, "", page, nil, "",
			"fetch() is sent by a page's script: name the page as the initiator"},
		{"an XHR from no page", BrowserContext{Kind: KindXHR}, "", page, nil, "", "an XHR is sent by a page's script"},
		{"an XHR with a mode", BrowserContext{Kind: KindXHR, Initiator: page, Mode: "cors"}, "", page, nil, "",
			"an XHR has no mode"},
		{"an XHR that omits credentials", BrowserContext{Kind: KindXHR, Initiator: page, Credentials: "omit"}, "", page,
			nil, "", `an XHR's credentials are same-origin or include, which is withCredentials, not "omit"`},
		{"an unknown mode", BrowserContext{Kind: KindFetch, Initiator: page, Mode: "navigate"}, "", page, nil, "",
			`mode "navigate" is not cors, no-cors or same-origin`},
		{"unknown credentials", BrowserContext{Kind: KindFetch, Initiator: page, Credentials: "all"}, "", page, nil, "",
			`credentials "all" is not same-origin, include or omit`},
		{"a CONNECT", BrowserContext{Kind: KindFetch, Initiator: page}, "CONNECT", page, nil, "", "fetch() cannot send CONNECT"},
		{"a TRACE", BrowserContext{Kind: KindXHR, Initiator: page}, "TRACE", page, nil, "", "an XHR cannot send TRACE"},
		{"a track in lower case", BrowserContext{Kind: KindFetch, Initiator: page}, "track", page, nil, "", "cannot send track"},
		{"a GET with a body", BrowserContext{Kind: KindFetch, Initiator: page}, "GET", page, nil, "x",
			"fetch() sends no body with GET"},
		{"a HEAD with a body", BrowserContext{Kind: KindFetch, Initiator: page}, "HEAD", page, nil, "x",
			"sends no body with HEAD"},
		{"a cookie set by script", BrowserContext{Kind: KindFetch, Initiator: page}, "", page, NewHeader("Cookie", "a=1"), "",
			"fetch() cannot set cookie: the browser sets it"},
		{"a Sec- header", BrowserContext{Kind: KindFetch, Initiator: page}, "", page, NewHeader("Sec-Foo", "1"), "",
			"cannot set sec-foo"},
		{"a Proxy- header", BrowserContext{Kind: KindFetch, Initiator: page}, "", page,
			NewHeader("Proxy-Authorization", "x"), "", "cannot set proxy-authorization"},
		{"a user agent", BrowserContext{Kind: KindXHR, Initiator: page}, "", page, NewHeader("User-Agent", "x"), "",
			"an XHR cannot set user-agent"},
		{"same-origin mode to another origin", BrowserContext{Kind: KindFetch, Initiator: page, Mode: "same-origin"}, "",
			other, nil, "", "fetch() in same-origin mode cannot go to another origin"},
		{"no-cors mode that puts", BrowserContext{Kind: KindFetch, Initiator: page, Mode: "no-cors"}, "PUT", other, nil, "",
			"fetch() in no-cors mode sends GET, HEAD or POST"},
		{"no-cors mode with a header CORS asks about", BrowserContext{Kind: KindFetch, Initiator: page, Mode: "no-cors"},
			"", other, NewHeader("X-Foo", "1"), "", "with only the headers CORS lets through"},
		{"no-cors mode with JSON", BrowserContext{Kind: KindFetch, Initiator: page, Mode: "no-cors"}, "POST", other,
			NewHeader("Content-Type", "application/json"), "{}", "with only the headers CORS lets through"},
		{"a URL with credentials", BrowserContext{Kind: KindFetch, Initiator: page}, "",
			"https://u:p@www.example.com/x", nil, "", "fetch() is given no URL with credentials in it"},
		{"fetch() clicked", BrowserContext{Kind: KindFetch, Initiator: page, Clicked: true}, "", page, nil, "",
			"fetch() is no navigation: a click says nothing of it"},
		{"an XHR clicked", BrowserContext{Kind: KindXHR, Initiator: page, Clicked: true}, "", page, nil, "",
			"an XHR is no navigation: a click says nothing of it"},
		{"a typed navigation clicked", BrowserContext{Kind: KindNavigation, Clicked: true}, "", page, nil, "",
			"a navigation typed into the address bar is the person's already: only one from a page is clicked"},
		{"a browser's request clicked", BrowserContext{Kind: KindNavigation, Initiator: page, Sent: true, Clicked: true},
			"", page, nil, "", "a request a browser sent says itself whether a click sent it"},
	} {
		browser := tc.browser
		var payload []byte
		if tc.body != "" {
			payload = []byte(tc.body)
		}
		_, err := client.Do(&Request{Method: tc.method, URL: tc.url, Header: tc.header, Body: payload,
			Browser: &browser})
		if err == nil || !strings.HasPrefix(err.Error(), "tlsforge: browser context: ") ||
			!strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.says)
		}
	}
	if got := server.requests(); len(got) != 0 {
		t.Errorf("%d requests were sent", len(got))
	}
}

func TestABrowserContextNeedsAChromiumProfileWithHeaders(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	firefox, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	firefox.Name, firefox.UserAgent = "firefox_148", "Mozilla/5.0 (Macintosh; rv:148.0) Gecko/20100101 Firefox/148.0"
	firefox.Behavior = behavior.Generic() // This fixture changes policy explicitly; renaming is metadata only.
	firefox.PerConnection = nil
	firefox.Headers = []profile.Field{{Name: "user-agent", Value: firefox.UserAgent}}
	for _, tc := range []struct {
		option Option
		says   string
	}{
		{WithProfileValue(firefox), `browser context: profile "firefox_148" does not enable browser_context`},
		{WithProfile("chrome_133"), `browser context: needs the profile's headers, and profile "chrome_133" has none to send`},
	} {
		client := newTestClient(t, tc.option, server.dialing())
		_, err := client.Do(&Request{URL: "https://www.example.com/", Browser: &BrowserContext{Kind: KindNavigation}})
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%v, want %q", err, tc.says)
		}
	}
	if got := server.requests(); len(got) != 0 {
		t.Errorf("%d requests were sent", len(got))
	}
}

func TestTheHeadersOfARequestInAContext(t *testing.T) {
	base := Header(nil)
	prof, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	base = append(base, prof.Headers...)
	page := mustURL(t, "https://www.example.com/page?q=1")
	for _, tc := range []struct {
		name    string
		request browserRequest
		target  string
		want    map[string]string
		absent  []string
	}{
		{"a form posted from https to http", browserRequest{kind: KindForm, method: "POST", posted: true, initiator: page,
			from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, contentType: formEncoded},
			"http://www.example.com/form",
			map[string]string{"origin": "null", "accept-encoding": "gzip, deflate", "cache-control": "max-age=0"},
			[]string{"sec-fetch-site", "sec-ch-ua", "referer"}},
		{"a form posted to the machine itself", browserRequest{kind: KindForm, method: "POST", posted: true, initiator: page,
			from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, contentType: formEncoded},
			"http://localhost:8080/form",
			map[string]string{"origin": "null", "sec-fetch-site": "cross-site",
				"accept-encoding": "gzip, deflate, br, zstd"},
			[]string{"referer"}},
		{"a form posted under no-referrer", browserRequest{kind: KindForm, method: "POST", posted: true, initiator: page,
			from: originOf(page), policy: policyNoReferrer, contentType: formEncoded},
			"https://www.example.com/form", map[string]string{"origin": "null"}, []string{"referer"}},
		{"a form posted under same-origin to another site", browserRequest{kind: KindForm, method: "POST", posted: true,
			initiator: page, from: originOf(page), policy: policySameOrigin, contentType: formEncoded},
			"https://www.example.net/form", map[string]string{"origin": "null"}, []string{"referer"}},
		{"a form posted under same-origin to its own origin", browserRequest{kind: KindForm, method: "POST", posted: true,
			initiator: page, from: originOf(page), policy: policySameOrigin, contentType: formEncoded},
			"https://www.example.com/form", map[string]string{"origin": "https://www.example.com"}, nil},
		{"a form posted under unsafe-url to http", browserRequest{kind: KindForm, method: "POST", posted: true, initiator: page,
			from: originOf(page), policy: policyUnsafeURL, contentType: formEncoded},
			"http://www.example.com/form",
			map[string]string{"origin": "https://www.example.com", "referer": "https://www.example.com/page?q=1"}, nil},
		{"fetch() posted to its own origin", browserRequest{kind: KindFetch, method: "POST", initiator: page,
			from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, mode: modeCORS, credentials: credentialsSame},
			"https://www.example.com/api", map[string]string{"origin": "https://www.example.com", "accept": "*/*",
				"priority": "u=1, i"}, []string{"upgrade-insecure-requests"}},
		{"fetch() HEAD of its own origin", browserRequest{kind: KindFetch, method: "HEAD", initiator: page,
			from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, mode: modeCORS, credentials: credentialsSame},
			"https://www.example.com/api", nil, []string{"origin"}},
		{"no-cors fetch() posted under no-referrer", browserRequest{kind: KindFetch, method: "POST", initiator: page,
			from: originOf(page), policy: policyNoReferrer, mode: modeNoCORS, credentials: credentialsSame},
			"https://www.example.net/api", map[string]string{"origin": "null", "sec-fetch-mode": "no-cors"}, nil},
		{"no-cors fetch() of another site with credentials", browserRequest{kind: KindFetch, method: "GET",
			initiator: page, from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, mode: modeNoCORS,
			credentials: credentialsAll},
			"https://www.example.net/x", map[string]string{"sec-fetch-storage-access": "active"}, []string{"origin"}},
		{"no-cors fetch() of the same site with credentials", browserRequest{kind: KindFetch, method: "GET",
			initiator: page, from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, mode: modeNoCORS,
			credentials: credentialsAll},
			"https://api.example.com/x", map[string]string{"sec-fetch-site": "same-site"},
			[]string{"sec-fetch-storage-access"}},
		{"cors fetch() of another origin", browserRequest{kind: KindFetch, method: "GET", initiator: page,
			from: originOf(page), policy: policyNoReferrer, mode: modeCORS, credentials: credentialsSame, cors: true},
			"https://api.example.com/x", map[string]string{"origin": "https://www.example.com", "sec-fetch-mode": "cors"},
			[]string{"referer"}},
		{"fetch() with an Accept of its own", browserRequest{kind: KindFetch, method: "GET", initiator: page,
			from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, mode: modeCORS, credentials: credentialsSame,
			script: NewHeader("Accept", "application/json")},
			"https://www.example.com/api", map[string]string{"accept": "application/json"}, nil},
	} {
		got := tc.request.header(tc.request.first(mustURL(t, tc.target)), base)
		for name, want := range tc.want {
			if value := got.Get(name); value != want || !got.Has(name) {
				t.Errorf("%s: %s is %q, want %q", tc.name, name, value, want)
			}
		}
		for _, name := range tc.absent {
			if got.Has(name) {
				t.Errorf("%s: has %s: %q", tc.name, name, got.Get(name))
			}
		}
		if names := got.Names(); len(names) != len(uniqueNames(names)) {
			t.Errorf("%s: a header twice: %v", tc.name, names)
		}
	}
}

func TestNoEncodingIsOfferedThatTheProfileDoesNotOffer(t *testing.T) {
	r := browserRequest{kind: KindNavigation, method: "GET"}
	got := r.header(r.first(mustURL(t, "http://www.example.com/")), NewHeader("User-Agent", "x"))
	if got.Has("accept-encoding") {
		t.Errorf("Accept-Encoding: %q", got.Get("accept-encoding"))
	}
}

func TestScriptHeadersRetainTheirSpellingInRendererOrder(t *testing.T) {
	page := mustURL(t, "https://www.example.com/page")
	base := NewHeader("User-Agent", "UA", "sec-ch-ua", "CH", "sec-ch-ua-platform", "P")
	for _, tc := range []struct {
		script Header
		want   string
	}{
		{Header{{Name: "authorization", Value: "x"}}, "sec-ch-ua-platform authorization user-agent sec-ch-ua"},
		{Header{{Name: "AUTHORIZATION", Value: "x"}}, "sec-ch-ua-platform AUTHORIZATION user-agent sec-ch-ua"},
		{Header{{Name: "X-Foo", Value: "1"}}, "sec-ch-ua-platform user-agent sec-ch-ua X-Foo"},
		{Header{{Name: "Authorization", Value: "x"}, {Name: "X-Foo", Value: "1"}},
			"sec-ch-ua-platform Authorization user-agent sec-ch-ua X-Foo"},
	} {
		for _, kind := range []RequestKind{KindFetch, KindXHR} {
			r := browserRequest{kind: kind, method: "GET", initiator: page, from: originOf(page),
				policy: policyStrictOriginWhenCrossOrigin, mode: modeCORS, credentials: credentialsSame, script: tc.script}
			got := r.header(r.first(page), base).Names()
			if names := strings.Join(got[:min(len(got), len(strings.Fields(tc.want)))], " "); names != tc.want {
				t.Errorf("%s with %v: %v, want %s first", kind, tc.script, got, tc.want)
			}
		}
	}
}

func uniqueNames(names []string) map[string]bool {
	out := map[string]bool{}
	for _, name := range names {
		out[strings.ToLower(name)] = true
	}
	return out
}

func TestAFormPostedWithoutATypeIsURLEncoded(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	page := "https://www.example.com/page"
	if _, err := client.Do(&Request{Method: "POST", URL: page, Body: []byte("a=1"),
		Browser: &BrowserContext{Kind: KindForm, Initiator: page}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 1 {
		t.Fatalf("%d requests", len(got))
	}
	var contentType string
	for _, h := range got[0].headers {
		if h[0] == "content-type" {
			contentType = h[1]
		}
	}
	if contentType != formEncoded || got[0].body != "a=1" {
		t.Errorf("sent %q, %q", contentType, got[0].body)
	}
}

func TestWithoutCodings(t *testing.T) {
	for value, want := range map[string]string{
		"gzip, deflate, br, zstd": "gzip, deflate",
		"br;q=1.0, gzip;q=0.8":    "gzip;q=0.8",
		"gzip,br":                 "gzip",
		" zstd , identity ":       "identity",
		"br":                      "",
		"":                        "",
		"gzip, , deflate":         "gzip, deflate",
	} {
		if got := withoutCodings(value, "br", "zstd"); got != want {
			t.Errorf("%q: %q, want %q", value, got, want)
		}
	}
}

func TestWhatCORSLetsThrough(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"Accept", "application/json", true},
		{"accept", "text/html, */*;q=0.8", true},
		{"Accept", "a(b)", false},
		{"Accept", "a\x01", false},
		{"Accept", "a\tb", true},
		{"Accept-Language", "en-US,en;q=0.9", true},
		{"Accept-Language", "en_US", false},
		{"Content-Language", "de-DE", true},
		{"Content-Type", "text/plain;charset=UTF-8", true},
		{"Content-Type", formEncoded, true},
		{"Content-Type", "multipart/form-data; boundary=x", true},
		{"Content-Type", "application/json", false},
		{"Content-Type", "text/plain; x=\"y\"", false},
		{"Content-Type", "TEXT/PLAIN", true},
		{"X-Foo", "1", false},
		{"Accept", strings.Repeat("a", 129), false},
		{"Accept", strings.Repeat("a", 128), true},
	} {
		if got := corsSafelisted(tc.name, tc.value); got != tc.want {
			t.Errorf("%s: %q: %v", tc.name, tc.value, got)
		}
	}
	if !noCORSSafe("HEAD", NewHeader("Accept", "*/*")) || noCORSSafe("DELETE", nil) {
		t.Error("noCORSSafe")
	}
}

func TestWhatAScriptCannotSet(t *testing.T) {
	for _, name := range []string{"Accept-Charset", "accept-encoding", "Access-Control-Request-Headers",
		"Access-Control-Request-Method", "Connection", "Content-Length", "Cookie", "Cookie2", "Date", "DNT",
		"Expect", "Host", "Keep-Alive", "Origin", "Referer", "Set-Cookie", "TE", "Trailer", "Transfer-Encoding",
		"Upgrade", "Via", "User-Agent", "X-HTTP-Method", "X-HTTP-Method-Override", "X-Method-Override",
		"Proxy-Anything", "Sec-Anything", "sec-ch-ua"} {
		if !forbiddenHeader(name) {
			t.Errorf("%s may be set", name)
		}
	}
	for _, name := range []string{"Accept", "Content-Type", "X-Foo", "Authorization", "Cache-Control", "Priority"} {
		if forbiddenHeader(name) {
			t.Errorf("%s may not be set", name)
		}
	}
	for contentType, want := range map[string]bool{formEncoded: true, formText: true,
		"multipart/form-data; boundary=----WebKitFormBoundaryabc": true, "multipart/form-data; boundary=a b": false,
		"multipart/form-data; boundary=a;b": false, "multipart/form-data": false, "text/plain;charset=UTF-8": false} {
		if got := formEncoding(contentType); got != want {
			t.Errorf("%q: %v", contentType, got)
		}
	}
	for method, want := range map[string]bool{"CONNECT": true, "trace": true, "Track": true, "GET": false, "PATCH": false} {
		if got := forbiddenMethod(method); got != want {
			t.Errorf("%s: %v", method, got)
		}
	}
}

func TestAContextSpellsHTTP1AsChromeDoes(t *testing.T) {
	h := Header{{Name: "user-agent", Value: "UA"}, {Name: "sec-ch-ua", Value: "CH"}, {Name: "content-type", Value: "a/b"},
		{Name: "X-Mixed", Value: "1"}, {Name: "x-lower", Value: "2"}, {Name: "accept", Value: "*/*"},
		{Name: "priority", Value: "u=1, i"}}
	script := Header{{Name: "X-Mixed", Value: "1"}, {Name: "x-lower", Value: "2"}}
	order := []string{"user-agent", "sec-ch-ua", "content-type", "x-mixed", "x-lower", "accept", "priority"}
	measured := &profile.HTTP1{HeaderOrder: []string{"Host", "Connection", "User-Agent", "Accept"}}
	for _, tc := range []struct {
		name     string
		measured *profile.HTTP1
		http1    Header
		want     []string
	}{
		{"as measured", measured, NewHeader("connection", "close"),
			[]string{"Host", "Connection", "User-Agent", "sec-ch-ua", "Content-Type", "X-Mixed", "x-lower", "Accept"}},
		{"with nothing measured", nil, nil,
			[]string{"Host", "Connection", "User-Agent", "sec-ch-ua", "Content-Type", "X-Mixed", "x-lower", "Accept"}},
	} {
		layout := browserHTTP1Layout(h, script, nil, order, tc.measured, tc.http1, "www.example.com")
		var names []string
		for name := range layout {
			if name != fhttp.HeaderOrderKey {
				names = append(names, name)
			}
		}
		for _, want := range tc.want {
			if _, ok := layout[want]; !ok {
				t.Errorf("%s: no %s in %v", tc.name, want, names)
			}
		}
		if len(names) != len(tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, names, tc.want)
		}
		if got := layout[fhttp.HeaderOrderKey]; strings.Join(got, ",") != "host,connection,user-agent,sec-ch-ua,content-type,x-mixed,x-lower,accept" {
			t.Errorf("%s: order %v", tc.name, got)
		}
		connection := "keep-alive"
		if tc.http1 != nil {
			connection = "close"
		}
		if got := layout["Connection"]; len(got) != 1 || got[0] != connection {
			t.Errorf("%s: Connection %v", tc.name, got)
		}
	}
}

func TestTheCookiesARequestInAContextCarries(t *testing.T) {
	now := time.Now()
	fresh, old := now.Add(-time.Minute), now.Add(-3*time.Minute)
	type cookie struct {
		facts cookieFacts
		known bool
	}
	none := cookie{cookieFacts{sameSite: fhttp.SameSiteNoneMode}, true}
	strict := cookie{cookieFacts{sameSite: fhttp.SameSiteStrictMode}, true}
	lax := cookie{cookieFacts{sameSite: fhttp.SameSiteLaxMode}, true}
	defaulted := cookie{cookieFacts{created: fresh}, true}
	defaultedOld := cookie{cookieFacts{created: old}, true}
	defaultedEmpty := cookie{cookieFacts{sameSite: fhttp.SameSiteDefaultMode, created: fresh}, true}
	unknown := cookie{cookieFacts{}, false}
	all := []cookie{none, strict, lax, defaulted, defaultedOld, defaultedEmpty, unknown}
	for _, tc := range []struct {
		name string
		rule sendRule
		want []bool
	}{
		{"none at all", sendRule{none: true}, []bool{false, false, false, false, false, false, false}},
		{"to its own site", sendRule{crossSite: false}, []bool{true, true, true, true, true, true, true}},
		{"a page got from another site", sendRule{crossSite: true, topLevel: true, safe: true},
			[]bool{true, false, true, true, true, true, true}},
		{"a page posted to from another site", sendRule{crossSite: true, topLevel: true},
			[]bool{true, false, false, true, false, true, false}},
		{"a script's request to another site", sendRule{crossSite: true, safe: true},
			[]bool{true, false, false, false, false, false, false}},
	} {
		for i, c := range all {
			if got := tc.rule.allows(c.facts, c.known, now); got != tc.want[i] {
				t.Errorf("%s: cookie %d: %v", tc.name, i, got)
			}
		}
	}
	page := mustURL(t, "https://www.example.com/page")
	for _, tc := range []struct {
		name    string
		request browserRequest
		target  string
		want    sendRule
	}{
		{"a typed navigation", browserRequest{kind: KindNavigation, method: "GET"}, "https://www.example.net/",
			sendRule{topLevel: true, safe: true}},
		{"a form posted to another site", browserRequest{kind: KindForm, method: "POST", posted: true, initiator: page,
			from: originOf(page)}, "https://www.example.net/", sendRule{crossSite: true, topLevel: true}},
		{"fetch() omitting credentials", browserRequest{kind: KindFetch, method: "GET", initiator: page,
			from: originOf(page), credentials: credentialsNone}, "https://www.example.com/", sendRule{none: true, safe: true}},
		{"fetch() keeping them to its origin, to another", browserRequest{kind: KindFetch, method: "HEAD",
			initiator: page, from: originOf(page), credentials: credentialsSame}, "https://api.example.com/",
			sendRule{none: true, safe: true}},
		{"fetch() keeping them to its origin, to it", browserRequest{kind: KindFetch, method: "POST",
			initiator: page, from: originOf(page), credentials: credentialsSame}, "https://www.example.com/",
			sendRule{}},
		{"fetch() including them, to another site", browserRequest{kind: KindFetch, method: "GET",
			initiator: page, from: originOf(page), credentials: credentialsAll}, "https://www.example.net/",
			sendRule{crossSite: true, safe: true}},
	} {
		if got := tc.request.cookies(tc.request.first(mustURL(t, tc.target))); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// A hop of a chain that has left the page's origin, back at it.
	noCORS := browserRequest{kind: KindFetch, method: "GET", initiator: page, from: originOf(page),
		credentials: credentialsSame, mode: modeNoCORS}
	back := hop{to: originOf(page), site: "cross-site", method: "GET", redirected: true}
	within := back
	within.site = "same-origin"
	included := noCORS
	included.credentials = credentialsAll
	for _, tc := range []struct {
		name    string
		request browserRequest
		hop     hop
		want    sendRule
	}{
		{"fetch() in no-cors mode keeping them to its origin, back at it", noCORS, back, sendRule{none: true, safe: true}},
		{"the same, redirected within its origin", noCORS, within, sendRule{safe: true}},
		{"fetch() in no-cors mode including them, back at its origin", included, back, sendRule{safe: true}},
	} {
		if got := tc.request.cookies(tc.hop); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestACookieSetAgainKeepsWhenItWasFirstSet(t *testing.T) {
	jar := newTestJar()
	u := mustURL(t, "https://www.example.com/")
	jar.SetCookies(u, []*fhttp.Cookie{{Name: "a", Value: "1"}})
	first := jar.kept[cookieKey{"a", "www.example.com", "/"}].created
	time.Sleep(2 * time.Millisecond)
	jar.SetCookies(u, []*fhttp.Cookie{{Name: "a", Value: "2", SameSite: fhttp.SameSiteLaxMode}})
	again := jar.kept[cookieKey{"a", "www.example.com", "/"}]
	if first.IsZero() || !again.created.Equal(first) || again.sameSite != fhttp.SameSiteLaxMode {
		t.Errorf("first set %v, set again %+v", first, again)
	}
	// What the transport asks about other URLs is the jar's own answer.
	jar.restrict(mustURL(t, "https://www.example.com/"), sendRule{none: true})
	if got := jar.Cookies(u); len(got) != 1 {
		t.Errorf("another URL's rule held back %v", got)
	}
	jar.restrict(u, sendRule{none: true})
	if got := jar.Cookies(u); len(got) != 0 {
		t.Errorf("the rule let through %v", got)
	}
	jar.release(u)
	if got := jar.Cookies(u); len(got) != 1 {
		t.Errorf("released, the jar answered %v", got)
	}
}

func TestCredentialsSayWhichCookiesFetchSends(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	set := []Cookie{
		{Name: "lax", Value: "1", Domain: "www.example.com", HostOnly: true, Path: "/"},
		{Name: "anywhere", Value: "2", Domain: "www.example.net", HostOnly: true, Path: "/", Secure: true, SameSite: "none"},
		{Name: "lax", Value: "3", Domain: "www.example.net", HostOnly: true, Path: "/", SameSite: "lax"},
	}
	page := "https://www.example.com/page"
	for _, tc := range []struct {
		name    string
		browser BrowserContext
		url     string
		want    []string
	}{
		{"omitted, to its own origin", BrowserContext{Kind: KindFetch, Initiator: page, Credentials: "omit"},
			"https://www.example.com/api", nil},
		{"same-origin, to its own origin", BrowserContext{Kind: KindFetch, Initiator: page},
			"https://www.example.com/api", []string{"lax=1"}},
		{"same-origin, to another site", BrowserContext{Kind: KindFetch, Initiator: page, Mode: "no-cors"},
			"https://www.example.net/x", nil},
		{"included, to another site", BrowserContext{Kind: KindFetch, Initiator: page, Mode: "no-cors",
			Credentials: "include"}, "https://www.example.net/x", []string{"anywhere=2"}},
		{"withCredentials, to its own origin", BrowserContext{Kind: KindXHR, Initiator: page, Credentials: "include"},
			"https://www.example.com/api", []string{"lax=1"}},
	} {
		before := len(server.requests())
		if _, err := client.Do(&Request{URL: tc.url, Browser: &tc.browser, Cookies: set}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var got []string
		for _, h := range server.requests()[before].headers {
			if h[0] == "cookie" {
				got = append(got, h[1])
			}
		}
		if strings.Join(got, "; ") != strings.Join(tc.want, "; ") {
			t.Errorf("%s: sent %v, want %v", tc.name, got, tc.want)
		}
	}
	// A request without a context sends what the jar holds, as it always has.
	before := len(server.requests())
	if _, err := client.Do(&Request{URL: "https://www.example.net/x"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	var cookies []string
	for _, h := range server.requests()[before].headers {
		if h[0] == "cookie" {
			cookies = append(cookies, h[1])
		}
	}
	if strings.Join(cookies, "; ") != "anywhere=2; lax=3" {
		t.Errorf("without a context: %v", cookies)
	}
}

func TestScriptsGoOutOnThePagesConnectionsWithAPriorityOfTheirOwn(t *testing.T) {
	// Chrome sends a page's requests and its scripts' on one connection, each
	// HEADERS frame with its own priority, and so does a client, at once too.
	const held = 8
	var arrived atomic.Int32
	all := make(chan struct{})
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/held" {
			// Every request held is in flight on the connection at once.
			if arrived.Add(1) == held {
				close(all)
			}
			select {
			case <-all:
			case <-time.After(5 * time.Second):
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
	var dials atomic.Int32
	client := newTestClient(t, WithProfile("chrome_155_macos"),
		WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, server.addr)
		})))
	page := "https://www.example.com/page"
	fetch := &Request{URL: page, Browser: &BrowserContext{Kind: KindFetch, Initiator: page}}
	for _, req := range []*Request{
		{URL: page, Browser: &BrowserContext{Kind: KindNavigation}},
		fetch,
		{URL: page, Browser: &BrowserContext{Kind: KindXHR, Initiator: page}},
		{URL: page},
	} {
		if _, err := client.Do(req); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	errs := make(chan error, held)
	for i := range held {
		kind := KindNavigation
		if i%2 == 0 {
			kind = KindFetch
		}
		go func() {
			_, err := client.Do(&Request{URL: "https://www.example.com/held",
				Browser: &BrowserContext{Kind: kind, Initiator: page}})
			errs <- err
		}()
	}
	for range held {
		if err := <-errs; err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	got := server.requests()
	if len(got) != 4+held || dials.Load() != 1 {
		t.Fatalf("%d requests over %d connections", len(got), dials.Load())
	}
	scripts := 0
	for i, r := range got {
		want := uint32(255)
		if mode, _ := r.header("sec-fetch-mode"); mode == "cors" {
			want = 219
			scripts++
		}
		if r.priority == nil || r.priority[2] != want {
			t.Errorf("request %d, %s: priority %v, want weight %d", i, r.url, r.priority, want)
		}
	}
	if scripts != 2+held/2 {
		t.Errorf("%d requests of scripts", scripts)
	}

	// Closing idle connections closes the scripts' with the page's, and the
	// next request opens one; a fresh client opens its own.
	client.CloseIdleConnections()
	if _, err := client.Do(fetch); err != nil || dials.Load() != 2 {
		t.Errorf("after closing: %v, %d connections", err, dials.Load())
	}
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if _, err := fresh.Do(fetch); err != nil || dials.Load() != 3 {
		t.Errorf("a fresh client: %v, %d connections", err, dials.Load())
	}
}

func TestARequestThatCarriesNoCredentialsGoesOutOnConnectionsOfItsOwn(t *testing.T) {
	// As Chrome sends one (testdata/chrome155-connections.json, held request
	// for request by TestRequestsGoOutOnTheConnectionsChromeSentThemOn), with
	// a script's priority still; closing idle connections closes these too,
	// and a fresh client has its own.
	server := newRecorder(t, "h2", nil)
	var dials atomic.Int32
	client := newTestClient(t, WithProfile("chrome_155_macos"),
		WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, server.addr)
		})))
	page := "https://www.example.com/page"
	omit := &Request{URL: page, Browser: &BrowserContext{Kind: KindFetch, Initiator: page, Credentials: "omit"}}
	same := &Request{URL: page, Browser: &BrowserContext{Kind: KindFetch, Initiator: page}}
	for _, req := range []*Request{{URL: page}, omit, same, omit} {
		if _, err := client.Do(req); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	got := server.requests()
	if dials.Load() != 2 || len(got) != 4 || got[0].conn != got[2].conn || got[1].conn != got[3].conn || got[0].conn == got[1].conn {
		t.Fatalf("%d connections: %+v", dials.Load(), got)
	}
	for _, r := range got[1:] {
		if r.priority == nil || r.priority[2] != 219 {
			t.Errorf("%s: priority %v", r.url, r.priority)
		}
	}
	client.CloseIdleConnections()
	for i, req := range []*Request{omit, same} {
		if _, err := client.Do(req); err != nil || dials.Load() != int32(3+i) {
			t.Errorf("after closing: %v, %d connections", err, dials.Load())
		}
	}
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if _, err := fresh.Do(omit); err != nil || dials.Load() != 5 {
		t.Errorf("a fresh client: %v, %d connections", err, dials.Load())
	}
}

func TestValidateRefusesWhatDoRefusesAndSendsNothing(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	page := "https://www.example.com/page"
	for _, tc := range []struct {
		name string
		req  *Request
		says string
	}{
		{"no request", nil, "tlsforge: request needs a URL"},
		{"no URL", &Request{}, "tlsforge: request needs a URL"},
		{"a URL Chrome cannot read", &Request{URL: "https://[::1"}, `tlsforge: "https://[::1" is not a URL`},
		{"a port Chrome sends nothing to", &Request{URL: "http://www.example.com:6000/"},
			`tlsforge: "http://www.example.com:6000/" is on port 6000`},
		{"a path Chrome sends as it is", &Request{URL: "https://www.example.com/a%zz"},
			`tlsforge: "https://www.example.com/a%zz" has "%zz" in its path`},
		{"a host the transport cannot read", &Request{URL: "https://a{b.example/"}, "tlsforge: parse"},
		{"a method that is not one", &Request{Method: "GE T", URL: page}, "tlsforge: net/http: invalid method"},
		{"a context a page could not be in", &Request{URL: page, Browser: &BrowserContext{Kind: KindForm}},
			"tlsforge: browser context: a form is submitted from a page"},
		{"a form posted in lower case", &Request{Method: "post", URL: page, Body: []byte("a=1"),
			Browser: &BrowserContext{Kind: KindForm, Initiator: page}}, ""},
		{"a request without a context", &Request{URL: page, Header: NewHeader("X-Foo", "1")}, ""},
		{"a request without a context by another method", &Request{Method: "DELETE", URL: page},
			"tlsforge: DELETE https://www.example.com/page needs a browser context"},
		{"a GET without a context with a body", &Request{URL: page, Body: []byte{}},
			"tlsforge: GET https://www.example.com/page with a body needs a browser context"},
	} {
		err := client.Validate(tc.req)
		if tc.says == "" && err != nil || tc.says != "" && (err == nil || !strings.HasPrefix(err.Error(), tc.says)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.says)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A closed client still says what it would have refused.
	if err := client.Validate(&Request{URL: page, Browser: &BrowserContext{Kind: KindFetch}}); err == nil {
		t.Error("a closed client let a script with no page through")
	}
	if got := server.requests(); len(got) != 0 {
		t.Errorf("Validate sent %d requests", len(got))
	}
}

func TestAnInitiatorIsThePagesURLAsChromeMadeIt(t *testing.T) {
	// The page's URL, which its Origin and its Referer come from, is read as
	// Chrome reads the URL of a page it is on.
	target, _ := url.Parse("https://api.example.com/x")
	r, err := (&BrowserContext{Kind: KindFetch, Initiator: " HTTPS://WWW.Example.COM:443/a/./b/../pa ge?q#f"}).
		resolve(fhttp.MethodGet, target, nil, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.initiator.String() != "https://www.example.com/a/pa%20ge?q" || r.from.String() != "https://www.example.com" {
		t.Errorf("the page is %s, of %s", r.initiator, r.from)
	}
}
