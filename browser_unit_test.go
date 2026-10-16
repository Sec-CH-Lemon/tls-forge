package tlsforge

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

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
			`initiator "%zz" is not an http or https URL`},
		{"an initiator of another scheme", BrowserContext{Kind: KindNavigation, Initiator: "ftp://x/"}, "", page, nil, "",
			`initiator "ftp://x/"`},
		{"a file as initiator", BrowserContext{Kind: KindNavigation, Initiator: "file://localhost/page"}, "", page, nil, "",
			`initiator "file://localhost/page"`},
		{"a websocket as initiator", BrowserContext{Kind: KindNavigation, Initiator: "wss://www.example.com/"}, "", page,
			nil, "", `initiator "wss://www.example.com/"`},
		{"a relative initiator", BrowserContext{Kind: KindNavigation, Initiator: "/page"}, "", page, nil, "",
			`initiator "/page"`},
		{"an initiator with no host", BrowserContext{Kind: KindNavigation, Initiator: "https:///page"}, "", page, nil, "",
			`initiator "https:///page"`},
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
	} {
		browser := tc.browser
		_, err := client.Do(&Request{Method: tc.method, URL: tc.url, Header: tc.header, Body: []byte(tc.body),
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
	firefox.PerConnection = nil
	firefox.Headers = []profile.Field{{Name: "user-agent", Value: firefox.UserAgent}}
	for _, tc := range []struct {
		option Option
		says   string
	}{
		{WithProfileValue(firefox), `browser context: is measured on Chrome; profile "firefox_148" is not of a Chromium browser`},
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
		{"a form posted from https to http", browserRequest{kind: KindForm, method: "POST", initiator: page,
			from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, contentType: formEncoded},
			"http://www.example.com/form",
			map[string]string{"origin": "null", "accept-encoding": "gzip, deflate", "cache-control": "max-age=0"},
			[]string{"sec-fetch-site", "sec-ch-ua", "referer"}},
		{"a form posted to the machine itself", browserRequest{kind: KindForm, method: "POST", initiator: page,
			from: originOf(page), policy: policyStrictOriginWhenCrossOrigin, contentType: formEncoded},
			"http://localhost:8080/form",
			map[string]string{"origin": "null", "sec-fetch-site": "cross-site", "accept-encoding": "gzip, deflate",
				"referer": "https://www.example.com/"},
			nil},
		{"a form posted under no-referrer", browserRequest{kind: KindForm, method: "POST", initiator: page,
			from: originOf(page), policy: policyNoReferrer, contentType: formEncoded},
			"https://www.example.com/form", map[string]string{"origin": "null"}, []string{"referer"}},
		{"a form posted under same-origin to another site", browserRequest{kind: KindForm, method: "POST",
			initiator: page, from: originOf(page), policy: policySameOrigin, contentType: formEncoded},
			"https://www.example.net/form", map[string]string{"origin": "null"}, []string{"referer"}},
		{"a form posted under same-origin to its own origin", browserRequest{kind: KindForm, method: "POST",
			initiator: page, from: originOf(page), policy: policySameOrigin, contentType: formEncoded},
			"https://www.example.com/form", map[string]string{"origin": "https://www.example.com"}, nil},
		{"a form posted under unsafe-url to http", browserRequest{kind: KindForm, method: "POST", initiator: page,
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
		got := tc.request.header(mustURL(t, tc.target), base)
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
			[]string{"Host", "Connection", "User-Agent", "sec-ch-ua", "Content-Type", "X-Mixed", "X-Lower", "Accept"}},
		{"with nothing measured", nil, nil,
			[]string{"Host", "Connection", "User-Agent", "sec-ch-ua", "Content-Type", "X-Mixed", "X-Lower", "Accept"}},
	} {
		layout := browserHTTP1Layout(h, script, order, tc.measured, tc.http1, "www.example.com")
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
		{"a form posted to another site", browserRequest{kind: KindForm, method: "POST", initiator: page,
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
		if got := tc.request.cookies(originOf(mustURL(t, tc.target))); got != tc.want {
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

func TestScriptsGoOutOnATransportOfTheirOwn(t *testing.T) {
	var count atomic.Int32
	server := newRecorder(t, "h2", func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		_, _ = w.Write([]byte("ok"))
	})
	client := contextClient(t, server)
	page := "https://www.example.com/page"
	fetch := &Request{URL: page, Browser: &BrowserContext{Kind: KindFetch, Initiator: page}}
	navigation := &Request{URL: page, Browser: &BrowserContext{Kind: KindNavigation}}
	for _, req := range []*Request{fetch, navigation, fetch, {URL: page}} {
		if _, err := client.Do(req); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	got := server.requests()
	if len(got) != 4 || got[0].priority[2] != 219 || got[1].priority[2] != 255 || got[2].priority[2] != 219 ||
		got[3].priority[2] != 255 {
		t.Fatalf("priorities: %+v", got)
	}
	script := client.script
	if _, err := client.Do(fetch); err != nil || client.script != script {
		t.Errorf("a second transport for scripts: %v", err)
	}
	client.CloseIdleConnections()
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if fresh.script != nil {
		t.Error("a fresh client shares the transport for scripts")
	}
	if _, err := fresh.Do(fetch); err != nil || fresh.script == nil || fresh.script == client.script {
		t.Errorf("the fresh client's own: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// A transport that cannot be made is said, and nothing is sent.
	other := contextClient(t, server)
	original := newInnerClient
	t.Cleanup(func() { newInnerClient = original })
	newInnerClient = func(tls_client.Logger, ...tls_client.HttpClientOption) (tls_client.HttpClient, error) {
		return nil, errors.New("no transport")
	}
	before := count.Load()
	if _, err := other.Do(fetch); err == nil || err.Error() != "tlsforge: no transport" || count.Load() != before {
		t.Errorf("%v, %d requests", err, count.Load()-before)
	}
	// Closing a client that never made one is closing it.
	if err := other.Close(); err != nil || other.script != nil {
		t.Errorf("Close: %v", err)
	}
}
