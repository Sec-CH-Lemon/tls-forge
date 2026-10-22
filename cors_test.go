package tlsforge

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
)

// corsRequest is fetch() from a page of www.example.com in cors mode, with
// credentials as given, sending method and header to another site.
func corsRequest(method, credentials string, header Header) *browserRequest {
	page := mustURLOf("https://www.example.com/page")
	return &browserRequest{kind: KindFetch, method: method, initiator: page, from: originOf(page),
		policy: policyStrictOriginWhenCrossOrigin, mode: modeCORS, credentials: credentials, script: header, cors: true}
}

func mustURLOf(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// repeated is a header of n fields of one name and value, and the rest.
func repeated(n int, name, value string, rest ...string) Header {
	var out Header
	for range n {
		out.Add(name, value)
	}
	return append(out, NewHeader(rest...)...)
}

func TestWhatAPreflightAsksAbout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header Header
		want   string
	}{
		{"nothing", nil, ""},
		{"only what CORS lets through", NewHeader("Accept", "*/*", "Content-Type", "text/plain"), ""},
		{"what it does not, sorted, once each, in lower case",
			Header{{Name: "X-B", Value: "1"}, {Name: "Content-Type", Value: "application/json"}, {Name: "x-b", Value: "2"},
				{Name: "X-A", Value: "3"}}, "content-type,x-a,x-b"},
		{"every one, past 1024 bytes of what it lets through", repeated(9, "Accept", strings.Repeat("a", 120),
			"Content-Language", "de"), "accept,content-language"},
		{"none, at 1024 bytes", repeated(8, "Accept", strings.Repeat("a", 128)), ""},
	} {
		if got := strings.Join(unsafeHeaderNames(tc.header), ","); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		request *browserRequest
		want    bool
	}{
		{corsRequest("GET", credentialsSame, nil), false},
		{corsRequest("POST", credentialsSame, NewHeader("Content-Type", formEncoded)), false},
		{corsRequest("PUT", credentialsSame, nil), true},
		{corsRequest("GET", credentialsSame, NewHeader("X-Foo", "1")), true},
		{&browserRequest{method: "PUT"}, false},
	} {
		if got := tc.request.needsPreflight(tc.request.first(mustURLOf("https://www.example.net/api"))); got != tc.want {
			t.Errorf("%s %v: %v", tc.request.method, tc.request.script, got)
		}
	}
}

func TestTheCORSCheck(t *testing.T) {
	origin := "https://www.example.com"
	for _, tc := range []struct {
		name        string
		credentials string
		header      fhttp.Header
		says        string
	}{
		{"the page's origin", credentialsSame, fhttp.Header{"Access-Control-Allow-Origin": {origin}}, ""},
		{"any origin", credentialsSame, fhttp.Header{"Access-Control-Allow-Origin": {"*"}}, ""},
		{"no origin", credentialsSame, fhttp.Header{}, "Access-Control-Allow-Origin is said 0 times, not once"},
		{"two", credentialsSame, fhttp.Header{"Access-Control-Allow-Origin": {origin, origin}}, "said 2 times"},
		{"another origin", credentialsSame, fhttp.Header{"Access-Control-Allow-Origin": {"https://www.example.net"}},
			`Access-Control-Allow-Origin is "https://www.example.net", not "https://www.example.com"`},
		{"a list", credentialsSame, fhttp.Header{"Access-Control-Allow-Origin": {origin + ", *"}}, "is \""},
		{"any origin with credentials", credentialsAll, fhttp.Header{"Access-Control-Allow-Origin": {"*"}},
			`Access-Control-Allow-Origin is "*"`},
		{"credentials not allowed", credentialsAll, fhttp.Header{"Access-Control-Allow-Origin": {origin}},
			`Access-Control-Allow-Credentials is not "true"`},
		{"credentials allowed in capitals", credentialsAll, fhttp.Header{"Access-Control-Allow-Origin": {origin},
			"Access-Control-Allow-Credentials": {"TRUE"}}, `Access-Control-Allow-Credentials is not "true"`},
		{"credentials allowed", credentialsAll, fhttp.Header{"Access-Control-Allow-Origin": {origin},
			"Access-Control-Allow-Credentials": {"true"}}, ""},
		{"credentials allowed, none sent", credentialsNone, fhttp.Header{"Access-Control-Allow-Origin": {"*"},
			"Access-Control-Allow-Credentials": {"true"}}, ""},
	} {
		err := corsRequest("GET", tc.credentials, nil).corsCheck(tc.header, origin)
		if tc.says == "" && err != nil || tc.says != "" && (err == nil || !strings.Contains(err.Error(), tc.says)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.says)
		}
	}
}

func TestWhatAPreflightAllows(t *testing.T) {
	allowed := func(more fhttp.Header) *fhttp.Response {
		header := fhttp.Header{"Access-Control-Allow-Origin": {"https://www.example.com"},
			"Access-Control-Allow-Credentials": {"true"}}
		for name, values := range more {
			header[name] = values
		}
		return &fhttp.Response{StatusCode: 204, Header: header}
	}
	json := NewHeader("Content-Type", "application/json")
	for _, tc := range []struct {
		name    string
		request *browserRequest
		answer  *fhttp.Response
		says    string
		maxAge  time.Duration
	}{
		{"a refusal", corsRequest("PUT", credentialsSame, nil), &fhttp.Response{StatusCode: 403, Header: fhttp.Header{}},
			"it was answered 403", 0},
		{"a redirect", corsRequest("PUT", credentialsSame, nil), &fhttp.Response{StatusCode: 302, Header: fhttp.Header{}},
			"it was answered 302", 0},
		{"a 200", corsRequest("PUT", credentialsSame, nil), &fhttp.Response{StatusCode: 200,
			Header: fhttp.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Methods": {"PUT"}}}, "", 5 * time.Second},
		{"no origin", corsRequest("PUT", credentialsSame, nil), &fhttp.Response{StatusCode: 204, Header: fhttp.Header{}},
			"Access-Control-Allow-Origin is said 0 times", 0},
		{"a method allowed", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"GET, PUT"}}), "", 5 * time.Second},
		{"a method of two fields", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"GET", " ,PUT "}}), "", 5 * time.Second},
		{"a method not allowed", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"GET, put"}}),
			"Access-Control-Allow-Methods does not allow PUT", 0},
		{"any method", corsRequest("PATCH", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"*"}}), "", 5 * time.Second},
		{"any method, credentials sent", corsRequest("PATCH", credentialsAll, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"*"}}), "does not allow PATCH", 0},
		{"a method that is not a token", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"PUT, P(T"}}),
			`Access-Control-Allow-Methods lists "P(T", which is not a token`, 0},
		{"a header allowed in any case", corsRequest("POST", credentialsSame, json),
			allowed(fhttp.Header{"Access-Control-Allow-Headers": {"Content-Type"}}), "", 5 * time.Second},
		{"a header not allowed", corsRequest("POST", credentialsSame, json),
			allowed(fhttp.Header{"Access-Control-Allow-Headers": {"x-foo"}}),
			"Access-Control-Allow-Headers does not allow content-type", 0},
		{"a header that is not a token", corsRequest("POST", credentialsSame, json),
			allowed(fhttp.Header{"Access-Control-Allow-Headers": {"content-type, a b"}}), "which is not a token", 0},
		{"any header", corsRequest("POST", credentialsSame, json),
			allowed(fhttp.Header{"Access-Control-Allow-Headers": {"*"}}), "", 5 * time.Second},
		{"any header, credentials sent", corsRequest("POST", credentialsAll, json),
			allowed(fhttp.Header{"Access-Control-Allow-Headers": {"*"}}), "does not allow content-type", 0},
		{"any header, and Authorization", corsRequest("GET", credentialsSame, NewHeader("Authorization", "x")),
			allowed(fhttp.Header{"Access-Control-Allow-Headers": {"*"}}), "does not allow authorization", 0},
		{"Authorization named", corsRequest("GET", credentialsSame, NewHeader("Authorization", "x")),
			allowed(fhttp.Header{"Access-Control-Allow-Headers": {"*, authorization"}}), "", 5 * time.Second},
		{"kept for ten minutes", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"PUT"}, "Access-Control-Max-Age": {"600"}}), "", 10 * time.Minute},
		{"kept for none", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"PUT"}, "Access-Control-Max-Age": {"0"}}), "", 0},
		{"kept for a day, which Chrome cuts to two hours", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"PUT"}, "Access-Control-Max-Age": {"86400"}}), "", 2 * time.Hour},
		{"kept for ever", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"PUT"}, "Access-Control-Max-Age": {"99999999999999999999"}}),
			"", 5 * time.Second},
		{"kept for a negative while", corsRequest("PUT", credentialsSame, nil),
			allowed(fhttp.Header{"Access-Control-Allow-Methods": {"PUT"}, "Access-Control-Max-Age": {"-1"}}), "", 5 * time.Second},
	} {
		got, err := tc.request.checkPreflight(tc.answer, tc.request.first(mustURLOf("https://www.example.net/api")))
		if tc.says == "" && (err != nil || got.maxAge != tc.maxAge) ||
			tc.says != "" && (err == nil || !strings.Contains(err.Error(), tc.says)) {
			t.Errorf("%s: %+v, %v; want %q, %v", tc.name, got, err, tc.says, tc.maxAge)
		}
	}
}

func TestThePreflightCache(t *testing.T) {
	cache := newPreflightCache()
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	const target = "https://www.example.net/api"
	allows := func(r *browserRequest, target string) bool {
		return cache.allows(r, r.first(mustURLOf(target)), target)
	}
	keep := func(r *browserRequest, target string, a allowance) {
		cache.keep(r, r.first(mustURLOf(target)), target, a)
	}
	put := corsRequest("PUT", credentialsSame, nil)
	json := corsRequest("POST", credentialsSame, NewHeader("Content-Type", "application/json"))
	if allows(put, target) || allows(json, target) {
		t.Fatal("an empty cache allows")
	}
	keep(put, target, allowance{methods: []string{"PUT"}, maxAge: time.Minute})
	if !allows(put, target) || allows(json, target) {
		t.Error("first grant does not allow exactly its requested permission")
	}
	keep(json, target, allowance{headers: []string{"Content-Type"}, maxAge: time.Minute})
	if allows(put, target) || !allows(json, target) {
		t.Error("replacement grant inherited an old permission or lost its own")
	}
	for name, other := range map[string]*browserRequest{
		"another method":      corsRequest("DELETE", credentialsSame, nil),
		"another header":      corsRequest("GET", credentialsSame, NewHeader("X-Foo", "1")),
		"with credentials":    corsRequest("PUT", credentialsAll, nil),
		"from another origin": {method: "PUT", from: originOf(mustURL(t, "https://api.example.com/")), credentials: credentialsSame, cors: true},
	} {
		if allows(other, target) {
			t.Errorf("%s is allowed", name)
		}
	}
	if allows(put, target+"?other") {
		t.Error("another URL is allowed")
	}
	now = now.Add(time.Minute)
	if allows(json, target) {
		t.Error("an expired allowance holds")
	}
	// A wildcard stands for what a request without credentials sends, but
	// for Authorization.
	keep(put, target, allowance{methods: []string{"*"}, headers: []string{"*"}, maxAge: time.Minute})
	if !allows(corsRequest("PATCH", credentialsSame, NewHeader("X-Foo", "1")), target) {
		t.Error("the wildcards allow nothing")
	}
	if allows(corsRequest("GET", credentialsSame, NewHeader("Authorization", "x")), target) {
		t.Error("the wildcard allows Authorization")
	}
	include := corsRequest("PATCH", credentialsAll, nil)
	keep(include, target, allowance{methods: []string{"*"}, headers: []string{"*"}, maxAge: time.Minute})
	if allows(include, target) || allows(corsRequest("GET", credentialsAll, NewHeader("X-Foo", "1")), target) {
		t.Error("a wildcard allows a request with credentials")
	}
}

func TestAPreflightRefusedSendsNothingMore(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  func(w http.ResponseWriter, r *http.Request)
		methods []string
		says    string
	}{
		{"a redirect", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/elsewhere")
			w.Header().Set("Access-Control-Allow-Origin", "https://www.example.com")
			w.WriteHeader(http.StatusFound)
		}, []string{"OPTIONS"}, "it was answered 302"},
		{"a method it does not list", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://www.example.com")
			w.Header().Set("Access-Control-Allow-Methods", "GET")
			w.WriteHeader(http.StatusNoContent)
		}, []string{"OPTIONS"}, "Access-Control-Allow-Methods does not allow PUT"},
		{"an answer that does not allow the page", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://www.example.com")
			w.Header().Set("Access-Control-Allow-Methods", "PUT")
			if r.Method == http.MethodPut {
				w.Header().Set("Access-Control-Allow-Origin", "https://evil.example")
			}
			w.WriteHeader(http.StatusNoContent)
		}, []string{"OPTIONS", "PUT"}, `the answer of PUT https://www.example.net/api did not allow https://www.example.com: ` +
			`Access-Control-Allow-Origin is "https://evil.example"`},
	} {
		server := newRecorder(t, "h2", tc.answer)
		book, logger := newLogBook(slog.LevelInfo)
		client := contextClient(t, server, WithLogger(logger))
		res, err := client.Do(&Request{Method: "put", URL: "https://www.example.net/api",
			Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"},
			Cookies: []Cookie{{Name: "a", Value: "1", Domain: "www.example.net", HostOnly: true, Path: "/",
				Secure: true, SameSite: "none"}}})
		if res != nil || !errors.Is(err, ErrCORS) || !strings.Contains(err.Error(), tc.says) ||
			!strings.HasPrefix(err.Error(), "tlsforge: CORS: ") {
			t.Errorf("%s: %v, %v", tc.name, res, err)
		}
		var methods []string
		for _, got := range server.requests() {
			methods = append(methods, got.method)
			for _, h := range got.headers {
				if h[0] == "cookie" && got.method == "OPTIONS" {
					t.Errorf("%s: the preflight carried a cookie", tc.name)
				}
			}
		}
		if strings.Join(methods, ",") != strings.Join(tc.methods, ",") {
			t.Errorf("%s: sent %v", tc.name, methods)
		}
		if tc.methods[len(tc.methods)-1] == "OPTIONS" {
			if refused := book.one(t, "preflight refused"); !strings.Contains(refused.get("why"), strings.TrimPrefix(tc.says, "it ")) {
				t.Errorf("%s: logged %v", tc.name, refused)
			}
		} else {
			book.one(t, "preflight", "status", "204")
		}
	}
}

func TestAPreflightThatCannotBeSent(t *testing.T) {
	// Nothing listens: the preflight's connection fails, and is said.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	dead := &recorder{addr: ln.Addr().String()}
	_ = ln.Close()
	client := newTestClient(t, WithProfile("chrome_155_macos"), dead.dialing(), WithoutCookieJar())
	_, err = client.Do(&Request{Method: "DELETE", URL: "https://www.example.net/api",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}})
	if err == nil || errors.Is(err, ErrCORS) || !strings.HasPrefix(err.Error(), "tlsforge: ") {
		t.Errorf("%v", err)
	}
}

func TestACachedPreflightIsTheSessions(t *testing.T) {
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://www.example.com")
		w.Header().Set("Access-Control-Allow-Methods", "DELETE")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		_, _ = io.WriteString(w, "")
	})
	client := contextClient(t, server, WithoutCookieJar())
	send := func(c *Client) {
		t.Helper()
		if _, err := c.Do(&Request{Method: "DELETE", URL: "https://www.example.net/api",
			Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	send(client)
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	send(fresh)
	another := contextClient(t, server, WithoutCookieJar())
	send(another)
	var methods []string
	for _, got := range server.requests() {
		methods = append(methods, got.method)
	}
	if strings.Join(methods, ",") != "OPTIONS,DELETE,DELETE,OPTIONS,DELETE" {
		t.Errorf("sent %v", methods)
	}
}

func TestAMethodIsNormalizedAsFetchNormalizesIt(t *testing.T) {
	for given, want := range map[string]string{"post": "POST", "Delete": "DELETE", "get": "GET", "head": "HEAD",
		"options": "OPTIONS", "put": "PUT", "patch": "patch", "PROPFIND": "PROPFIND"} {
		if got := normalizedMethod(given); got != want {
			t.Errorf("%s: %s", given, got)
		}
	}
}

func TestATokenList(t *testing.T) {
	got, err := tokenList(fhttp.Header{"X": {"a, b", ",, c ,", "\td"}}, "X")
	if err != nil || strings.Join(got, "|") != "a|b|c|d" {
		t.Errorf("%v, %v", got, err)
	}
	if got, err := tokenList(fhttp.Header{}, "X"); err != nil || got != nil {
		t.Errorf("%v, %v", got, err)
	}
}

func TestAPreflightAsksForEveryHeaderOnOneLine(t *testing.T) {
	base := NewHeader("user-agent", "UA")
	request := corsRequest("POST", credentialsSame, Header{{Name: "X-Foo", Value: "1"}, {Name: "Content-Type",
		Value: "application/json"}})
	got := request.preflightHeader(request.first(mustURL(t, "https://www.example.net/api")), base)
	if asked := got.Get("access-control-request-headers"); asked != "content-type,x-foo" {
		t.Errorf("asks for %q", asked)
	}
	if got.Has("sec-ch-ua") || got.Has("cookie") || got.Get("access-control-request-method") != "POST" {
		t.Errorf("%v", got)
	}
}

func TestAResponseSaysEveryCookieTheJarHolds(t *testing.T) {
	// Whatever the request carried, the response lists what the jar holds
	// for its URL, as it always has.
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	res, err := client.Do(&Request{URL: "https://www.example.com/api",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page", Credentials: "omit"},
		Cookies: []Cookie{{Name: "a", Value: "1", Domain: "www.example.com", HostOnly: true, Path: "/"}}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	for _, h := range server.requests()[0].headers {
		if h[0] == "cookie" {
			t.Errorf("credentials omitted, and a cookie went: %v", h)
		}
	}
	if strings.Join(res.Cookies, ";") != "a=1" {
		t.Errorf("the response lists %v", res.Cookies)
	}
}
