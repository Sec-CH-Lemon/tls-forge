package tlsforge

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	fhttp "github.com/igor-lemon/fhttp"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestTheCookieSlotIsRightAfterAcceptLanguage(t *testing.T) {
	for _, c := range []struct {
		name        string
		order, want []string
	}{
		{"Chrome's HTTP/2 navigation", []string{"host", "user-agent", "accept-encoding", "accept-language", "priority"},
			[]string{"host", "user-agent", "accept-encoding", "accept-language", "cookie", "priority"}},
		{"its HTTP/1.1, where Accept-Language is last", []string{"host", "connection", "accept-language"},
			[]string{"host", "connection", "accept-language", "cookie"}},
		{"headers the request was given go after it", []string{"host", "accept-language", "priority", "x-foo"},
			[]string{"host", "accept-language", "cookie", "priority", "x-foo"}},
		{"a Cookie the request was given moves there", []string{"host", "accept-language", "priority", "cookie", "x-foo"},
			[]string{"host", "accept-language", "cookie", "priority", "x-foo"}},
		{"from the front too", []string{"cookie", "host", "accept-language"},
			[]string{"host", "accept-language", "cookie"}},
		{"twice is once", []string{"Cookie", "accept-language", "cookie"}, []string{"accept-language", "cookie"}},
		{"in any case", []string{"host", "Accept-Language", "priority"}, []string{"host", "Accept-Language", "cookie", "priority"}},
		{"Accept-Language first", []string{"accept-language", "priority"}, []string{"accept-language", "cookie", "priority"}},
		{"without Accept-Language, last", []string{"host", "user-agent", "priority"}, []string{"host", "user-agent", "priority", "cookie"}},
		{"an order of nothing", nil, []string{"cookie"}},
	} {
		block := fhttp.Header{"Accept-Language": {"en"}, fhttp.HeaderOrderKey: c.order}
		cookieSlot(block)
		if got := block[fhttp.HeaderOrderKey]; !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		// The slot is a name in the order: no field is made, none changed.
		if len(block) != 2 || block.Get("Accept-Language") != "en" {
			t.Errorf("%s: the block's fields changed: %v", c.name, block)
		}
	}
	// A request the same over both protocols has no HTTP/1.1 block.
	cookieSlot(nil)
}

func TestEveryKindOfRequestHasTheCookieWhereChromeWritesIt(t *testing.T) {
	// Right after Accept-Language and right before Priority, as every
	// request Chrome sent cookies with was measured: over HTTP/1.1, which has
	// no Priority, last.
	orders := map[string][]string{"navigation": navigationOrder, "form": formOrder, "restarted": restartedOrder,
		"redirected": redirectedOrder, "script": scriptOrder(hop{}),
		"script with a lone Authorization": scriptOrder(hop{script: NewHeader("authorization", "Bearer x")}),
		"script given its Origin late":     scriptOrder(hop{lateOrigin: true})}
	for name, order := range orders {
		at := slices.Index(order, "cookie")
		if at < 1 || order[at-1] != "accept-language" || at+1 >= len(order) || order[at+1] != "priority" {
			t.Errorf("%s: %v", name, order)
		}
		h1 := browserHTTP1Layout(nil, nil, order, nil, nil, "h")[fhttp.HeaderOrderKey]
		if h1[len(h1)-1] != "cookie" || h1[len(h1)-2] != "accept-language" {
			t.Errorf("%s over HTTP/1.1: %v", name, h1)
		}
	}
}

func TestARequestWithoutAContextNamesTheCookieWhereChromeWritesIt(t *testing.T) {
	given := NewHeader("x-foo", "bar")
	slot := func(t *testing.T, block fhttp.Header, want ...string) {
		t.Helper()
		order := block[fhttp.HeaderOrderKey]
		at := slices.Index(order, "cookie")
		if at < 1 || !slices.Equal(order[at-1:min(at-1+len(want), len(order))], want) {
			t.Errorf("order %v, want the cookie in %v", order, want)
		}
	}
	t.Run("measured over both", func(t *testing.T) {
		client := newTestClient(t, WithProfile("chrome_155_macos"))
		l := client.layoutsAsGiven(client.headers.Merge(given), given, "h")
		slot(t, l.http2, "accept-language", "cookie", "priority", "x-foo")
		slot(t, l.http1, "accept-language", "cookie", "x-foo")
		if l.managed["cookie"] {
			t.Error("the jar's Cookie is taken off what the HTTP/1.1 block is laid over")
		}
		// An answer to a 401 keeps it there.
		again := l.authorized("Basic x")
		slot(t, again.http2, "accept-language", "cookie", "priority", "x-foo")
		slot(t, again.http1, "accept-language", "cookie", "x-foo")
	})
	t.Run("the same over both", func(t *testing.T) {
		client := newTestClient(t, WithProfile("chrome_151_linux"))
		l := client.layoutsAsGiven(client.headers.Merge(given), given, "h")
		slot(t, l.http2, "accept-language", "cookie", "priority", "x-foo")
		if l.http1 != nil {
			t.Errorf("a profile that measured no HTTP/1.1 has a block of it: %v", l.http1)
		}
	})
	t.Run("no user agent, no Accept-Language", func(t *testing.T) {
		// A Chromium profile of the transport's catalogue has no headers: the
		// Cookie goes last, as the transport would put it anyway.
		client := newTestClient(t, WithProfile("chrome_131"))
		l := client.layoutsAsGiven(client.headers.Merge(given), given, "h")
		for _, block := range []fhttp.Header{l.http2, l.http1} {
			if order := block[fhttp.HeaderOrderKey]; !slices.Equal(order, []string{"host", "x-foo", "cookie"}) {
				t.Errorf("order %v", order)
			}
		}
	})
	t.Run("another browser", func(t *testing.T) {
		// Only Chromium was measured: Firefox's Cookie stays where the
		// transport puts a name the order lacks, last.
		p, err := profile.Get("chrome_155_macos")
		if err != nil {
			t.Fatalf("profile: %v", err)
		}
		p.Name, p.UserAgent = "firefox_test", "Mozilla/5.0 (Macintosh; rv:148.0) Gecko/20100101 Firefox/148.0"
		p.Headers = []profile.Field{{Name: "user-agent", Value: p.UserAgent}, {Name: "accept-language", Value: "en"},
			{Name: "priority", Value: "u=0, i"}}
		client := newTestClient(t, WithProfileValue(p))
		l := client.layoutsAsGiven(client.headers.Merge(given), given, "h")
		for _, block := range []fhttp.Header{l.http2, l.http1} {
			if order := block[fhttp.HeaderOrderKey]; slices.Contains(order, "cookie") {
				t.Errorf("a Firefox profile names the Cookie: %v", order)
			}
		}
	})
}

func TestARedirectLeavesTheCookieToTheClientInItsSlot(t *testing.T) {
	// A request's HTTP/1.1 block carries no Cookie (newLayouts), nor does a
	// hop's made from it: whether fhttp sends the Cookie the request was given
	// on to the hop's host as it was, without a cookie the redirect set, or
	// not at all to another host, the slot stays where it was, for the Cookie
	// fhttp's client leaves on the hop, over HTTP/1.1 as over HTTP/2, where
	// the order fhttp copies keeps it.
	first := fhttp.Header{"Host": {"a.test"}, "Accept-Language": {"en"}, "X-Foo": {"bar"},
		fhttp.HeaderOrderKey: {"host", "accept-language", "cookie", "x-foo"}}
	original := fhttp.Header{"Host": {"a.test"}, "Accept-Language": {"en"}, "Cookie": {"x=9; y=8"}, "X-Foo": {"bar"},
		fhttp.HeaderOrderKey: {"host", "accept-language", "cookie", "priority", "x-foo"}}
	for _, c := range []struct {
		name   string
		cookie []string
	}{
		{"sent on as it was", []string{"x=9; y=8"}},
		{"without the cookie the redirect set", []string{"y=8"}},
		{"not sent to another host", nil},
	} {
		hop := fhttp.Header{"Accept-Language": {"en"}, "X-Foo": {"bar"},
			fhttp.HeaderOrderKey: {"host", "accept-language", "cookie", "priority", "x-foo"}}
		if c.cookie != nil {
			hop["Cookie"] = c.cookie
		}
		got := redirectHTTP1Layout(first, original, hop, "b.test")
		if order := got[fhttp.HeaderOrderKey]; !slices.Equal(order, []string{"host", "accept-language", "cookie", "x-foo"}) {
			t.Errorf("%s: order %v", c.name, order)
		}
		if _, ok := got["Cookie"]; ok {
			t.Errorf("%s: the hop's HTTP/1.1 block carries a Cookie: %v", c.name, got)
		}
	}
}

func TestARequestsOwnCookieIsOneField(t *testing.T) {
	// fhttp's client adds the jar's cookies to the first field of a Cookie
	// and drops the rest: every pair given goes in that one, as a browser
	// writes its cookies.
	for _, c := range []struct {
		name        string
		given, want []string
	}{
		{"one cookie", []string{"x=9"}, []string{"x=9"}},
		{"several in a field", []string{"x=9; y=8"}, []string{"x=9; y=8"}},
		{"several fields, in their order", []string{"x=9", "y=8; z=7"}, []string{"x=9; y=8; z=7"}},
		{"the spaces around each pair", []string{" \tx=9 ;y=8\t", "  z=7"}, []string{"x=9; y=8; z=7"}},
		{"only the spaces HTTP has", []string{" x=9 "}, []string{" x=9 "}},
		{"a stray separator", []string{";x=9;; y=8;"}, []string{"x=9; y=8"}},
		{"an empty field among them", []string{"", "x=9", " ; "}, []string{"x=9"}},
		{"what a pair says is its own", []string{"x=a=b; y=; z"}, []string{"x=a=b; y=; z"}},
		{"nothing in it", []string{"", " ;\t;"}, nil},
		{"none", nil, nil},
	} {
		block := fhttp.Header{"Accept-Language": {"en"}, fhttp.HeaderOrderKey: {"accept-language", "cookie"}}
		if c.given != nil {
			block["Cookie"] = c.given
		}
		ownCookie(block)
		if got, ok := block["Cookie"]; !slices.Equal(got, c.want) || ok != (c.want != nil) {
			t.Errorf("%s: %q (%v), want %q", c.name, got, ok, c.want)
		}
		// Its slot stays, for the jar's when it is none, and nothing else changes.
		if order := block[fhttp.HeaderOrderKey]; !slices.Equal(order, []string{"accept-language", "cookie"}) ||
			block.Get("Accept-Language") != "en" {
			t.Errorf("%s: the block changed: %v", c.name, block)
		}
	}
}

func TestBothProtocolsWriteTheCookieTheClientLeaves(t *testing.T) {
	// The HTTP/1.1 block names the Cookie's slot and carries none, and the
	// change takes none away: over HTTP/1.1 as over HTTP/2 a request is
	// written with the Cookie fhttp's client left on it, the request's own
	// with the jar's after it, whatever the block was made with.
	order1 := []string{"host", "connection", "user-agent", "accept-language", "cookie"}
	l := newLayouts(fhttp.Header{"Host": {"h"}, "User-Agent": {"ua"}, "Accept-Language": {"en"}, "Cookie": {"x=9"},
		fhttp.HeaderOrderKey: {"host", "user-agent", "accept-language", "cookie", "priority"}},
		fhttp.Header{"Host": {"h"}, "Connection": {"keep-alive"}, "User-Agent": {"ua"}, "Accept-Language": {"en"},
			"Cookie": {"x=9"}, fhttp.HeaderOrderKey: slices.Clone(order1)})
	if _, ok := l.http1["Cookie"]; ok || l.managed["cookie"] {
		t.Errorf("the HTTP/1.1 block has the Cookie: %v, managed %v", l.http1, l.managed)
	}
	if order := l.http1[fhttp.HeaderOrderKey]; !slices.Equal(order, order1) {
		t.Errorf("the HTTP/1.1 order %v, want %v", order, order1)
	}
	if got := l.http2["Cookie"]; !slices.Equal(got, []string{"x=9"}) {
		t.Errorf("the HTTP/2 block's Cookie %q, want the request's own", got)
	}
	req, err := fhttp.NewRequest(fhttp.MethodGet, "https://h/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req = l.wear(req)
	for _, cookie := range [][]string{{"x=9; a=1"}, {"a=1"}, nil} {
		// As the client leaves it: the jar's added to the request's own, or
		// none at all.
		delete(req.Header, "Cookie")
		if cookie != nil {
			req.Header["Cookie"] = cookie
		}
		h1, h2 := req.WrittenHeader(fhttp.ProtocolHTTP1), req.WrittenHeader(fhttp.ProtocolHTTP2)
		if got, ok := h1["Cookie"]; !slices.Equal(got, cookie) || ok != (cookie != nil) {
			t.Errorf("over HTTP/1.1, Cookie %q (%v), want %q", got, ok, cookie)
		}
		if got := h2["Cookie"]; !slices.Equal(got, cookie) {
			t.Errorf("over HTTP/2, Cookie %q, want %q", got, cookie)
		}
		if order := h1[fhttp.HeaderOrderKey]; !slices.Equal(order, order1) || h1.Get("Connection") != "keep-alive" {
			t.Errorf("over HTTP/1.1, not its block: %v", h1)
		}
	}
}

func TestARequestWithoutAContextSendsItsCookiesAsChromeDid(t *testing.T) {
	// A request without a browser context is a navigation typed into the
	// address bar: with the jar's cookies, or with a Cookie of its own, it is
	// what Chrome sent, each crumb in its slot; and so is the redirect that
	// set them, and the hop that carried them.
	measured := loadChromeRequests(t)
	cases := []struct {
		scenario, how string
		req           Request
	}{
		{"nav-direct-cookies", "the jar's", Request{Cookies: setByRun}},
		{"nav-direct-cookies", "its own", Request{Header: NewHeader("cookie", "a=1; b=2")}},
		{"redir-nav-direct-cookie", "set by the redirect", Request{}},
	}
	for _, c := range cases {
		both := measured.Scenarios[c.scenario]
		for proto, want := range map[string][]chromeRequest{"h2": both.H2, "h1": both.H1} {
			t.Run(fmt.Sprintf("%s/%s/%s", c.scenario, c.how, proto), func(t *testing.T) {
				server := newRecorder(t, proto, answeringAsMeasured)
				client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
				req := c.req
				req.URL = want[0].URL
				if _, err := client.Do(&req); err != nil {
					t.Fatalf("Do: %v", err)
				}
				got := server.requests()
				if len(got) != len(want) {
					t.Fatalf("sent %d requests, Chrome %d", len(got), len(want))
				}
				for i := range want {
					if diff := diffRequest(want[i], got[i], proto); diff != "" {
						t.Errorf("request %d:\n%s", i+1, diff)
					}
				}
			})
		}
	}
}

func TestARedirectToAnotherHostSendsTheJarsCookieInTheSlot(t *testing.T) {
	// A Cookie given for www.example.com, which fhttp does not send on to
	// api.example.com, and the jar's for the domain, which it does: the hop's
	// Cookie goes right after Accept-Language, before what the request was
	// given, over both protocols.
	for _, proto := range []string{"h2", "h1"} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "www.example.com" {
					http.Redirect(w, r, "https://api.example.com/landed", http.StatusFound)
				}
			})
			client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
			// Given after X-Foo: the Cookie goes back to its slot.
			if _, err := client.Do(&Request{URL: "https://www.example.com/away", Header: NewHeader("x-foo", "bar", "cookie", "given=1"),
				Cookies: []Cookie{{Name: "d", Value: "4", Domain: "example.com", Path: "/"}}}); err != nil {
				t.Fatalf("Do: %v", err)
			}
			got := server.requests()
			if len(got) != 2 {
				t.Fatalf("sent %d requests", len(got))
			}
			var names []string
			for _, h := range got[1].headers {
				names = append(names, h[0])
			}
			want := []string{"Accept-Language", "Cookie", "X-Foo"}
			if proto == "h2" {
				want = []string{"accept-language", "cookie", "priority", "x-foo"}
			}
			at := slices.Index(names, want[1])
			if at < 1 || !slices.Equal(names[at-1:min(at-1+len(want), len(names))], want) {
				t.Fatalf("hop's headers %v, want %v", names, want)
			}
			if cookie := got[1].headers[at][1]; cookie != "d=4" {
				t.Errorf("hop's Cookie %q, want the jar's alone", cookie)
			}
		})
	}
}

func TestARequestsOwnCookieGoesBeforeTheJarsOverBothProtocols(t *testing.T) {
	// A request's own Cookie and the cookies the jar holds for its URL go
	// together, its own first, as net/http adds a jar's: the same over
	// HTTP/1.1, one line, and HTTP/2, a field for each cookie, right after
	// Accept-Language where the profile is Chromium's (cookieSlot). So on the
	// answer to a 401, and on a redirect's hop, to which fhttp sends the
	// request's own on its host alone.
	jar := []Cookie{{Name: "a", Value: "1", Domain: "example.com", Path: "/"}, {Name: "b", Value: "2"}}
	firefox, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	firefox.Name, firefox.UserAgent = "firefox_test", "Mozilla/5.0 (Macintosh; rv:148.0) Gecko/20100101 Firefox/148.0"
	firefox.Headers = []profile.Field{{Name: "user-agent", Value: firefox.UserAgent}, {Name: "accept-language", Value: "en"},
		{Name: "priority", Value: "u=0, i"}}
	own := NewHeader("cookie", "x=9")
	nav := &BrowserContext{Kind: KindNavigation}
	const www, api = "https://www.example.com", "https://api.example.com"
	type sent struct {
		url     string
		cookies []string
	}
	all := []string{"x=9", "a=1", "b=2"}
	for _, c := range []struct {
		name string
		opts []Option
		req  Request
		// last is a profile that names no slot: the Cookie goes after every
		// header it names.
		last bool
		want []sent
	}{
		{name: "the jar's after the request's own", req: Request{URL: www + "/", Header: own, Cookies: jar},
			want: []sent{{www + "/", all}}},
		{name: "every pair given, in one", req: Request{URL: www + "/", Cookies: jar,
			Header: NewHeader("cookie", " x=9 ;; ", "cookie", "", "cookie", "y=8;")},
			want: []sent{{www + "/", []string{"x=9", "y=8", "a=1", "b=2"}}}},
		{name: "a Cookie with nothing in it is none", req: Request{URL: www + "/", Header: NewHeader("cookie", " ; ")},
			want: []sent{{www + "/", nil}}},
		{name: "the client's own", opts: []Option{WithHeaders(NewHeader("cookie", "w=0"))},
			req: Request{URL: www + "/", Cookies: jar}, want: []sent{{www + "/", []string{"w=0", "a=1", "b=2"}}}},
		{name: "without a jar", opts: []Option{WithoutCookieJar()},
			req:  Request{URL: www + "/", Header: NewHeader("cookie", "x=9", "cookie", "y=8")},
			want: []sent{{www + "/", []string{"x=9", "y=8"}}}},
		{name: "redirected on its host", req: Request{URL: www + "/same", Header: own, Cookies: jar},
			want: []sent{{www + "/same", all}, {www + "/landed", all}}},
		{name: "redirected to another host", req: Request{URL: www + "/other", Header: own, Cookies: jar},
			want: []sent{{www + "/other", all}, {api + "/landed", []string{"a=1"}}}},
		{name: "redirected to a host under its own", req: Request{URL: "https://example.com/under", Header: own, Cookies: jar},
			want: []sent{{"https://example.com/under", all}, {www + "/landed", []string{"x=9", "a=1"}}}},
		{name: "redirected by an answer setting a cookie it was given",
			req:  Request{URL: www + "/set", Header: NewHeader("cookie", "x=9; y=8"), Cookies: jar},
			want: []sent{{www + "/set", []string{"x=9", "y=8", "a=1", "b=2"}}, {www + "/landed", []string{"y=8", "a=1", "b=2", "x=new"}}}},
		{name: "answered after a 401", req: Request{URL: "https://u:p@www.example.com/auth", Header: own, Cookies: jar},
			want: []sent{{www + "/auth", all}, {www + "/auth", all}}},
		{name: "a profile the same over both protocols", opts: []Option{WithProfile("chrome_151_linux")},
			req: Request{URL: www + "/same", Header: own, Cookies: jar}, want: []sent{{www + "/same", all}, {www + "/landed", all}}},
		{name: "a profile of the transport's catalogue", opts: []Option{WithProfile("chrome_131")}, last: true,
			req: Request{URL: www + "/same", Header: own, Cookies: jar}, want: []sent{{www + "/same", all}, {www + "/landed", all}}},
		{name: "another browser's profile", opts: []Option{WithProfileValue(firefox)}, last: true,
			req: Request{URL: www + "/same", Header: own, Cookies: jar}, want: []sent{{www + "/same", all}, {www + "/landed", all}}},
		{name: "a navigation in a context", req: Request{URL: www + "/same", Cookies: jar, Browser: nav},
			want: []sent{{www + "/same", []string{"a=1", "b=2"}}, {www + "/landed", []string{"a=1", "b=2"}}}},
		{name: "a navigation in a context to another host", req: Request{URL: www + "/other", Cookies: jar, Browser: nav},
			want: []sent{{www + "/other", []string{"a=1", "b=2"}}, {api + "/landed", []string{"a=1"}}}},
	} {
		for _, proto := range []string{"h2", "h1"} {
			t.Run(c.name+"/"+proto, func(t *testing.T) {
				server := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/same":
						http.Redirect(w, r, "/landed", http.StatusFound)
					case "/other":
						http.Redirect(w, r, api+"/landed", http.StatusFound)
					case "/under":
						http.Redirect(w, r, www+"/landed", http.StatusFound)
					case "/set":
						http.SetCookie(w, &http.Cookie{Name: "x", Value: "new", Path: "/"})
						http.Redirect(w, r, "/landed", http.StatusFound)
					case "/auth":
						if r.Header.Get("Authorization") == "" {
							w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
							w.WriteHeader(http.StatusUnauthorized)
						}
					}
				})
				client := newTestClient(t, append([]Option{WithProfile("chrome_155_macos"), server.dialing()}, c.opts...)...)
				req := c.req
				if _, err := client.Do(&req); err != nil {
					t.Fatalf("Do: %v", err)
				}
				got := server.requests()
				if len(got) != len(c.want) {
					t.Fatalf("sent %d requests, want %d", len(got), len(c.want))
				}
				for i, want := range c.want {
					cookies, names, at := cookiesSent(t, got[i], proto)
					if got[i].url != want.url || !slices.Equal(cookies, want.cookies) {
						t.Errorf("request %d to %s: cookies %q, want %q to %s", i+1, got[i].url, cookies, want.cookies, want.url)
					}
					end := at + 1
					if proto == "h2" {
						end = at + len(cookies)
					}
					switch {
					case at < 0:
					case c.last && end != len(names):
						t.Errorf("request %d: the Cookie is not last: %v", i+1, names)
					case !c.last && (at < 1 || names[at-1] != "accept-language"):
						t.Errorf("request %d: the Cookie is not right after Accept-Language: %v", i+1, names)
					}
				}
			})
		}
	}
}

// cookiesSent are the cookies k carried, in order: each HTTP/2 field one, the
// HTTP/1.1 line split at "; "; with the lower-case names of k's headers, and
// where its first Cookie field is, -1 for none. A second Cookie line over
// HTTP/1.1 fails t, and so does a field between two over HTTP/2.
func cookiesSent(t *testing.T, k *keptRequest, proto string) (cookies, names []string, at int) {
	t.Helper()
	at = -1
	for i, h := range k.headers {
		name := strings.ToLower(h[0])
		names = append(names, name)
		if name != "cookie" {
			continue
		}
		switch {
		case at < 0:
			at = i
		case proto == "h1":
			t.Errorf("%s: a second Cookie line %q", k.url, h[1])
		case names[i-1] != "cookie":
			t.Errorf("%s: cookie fields apart: %v", k.url, names)
		}
		if proto == "h1" {
			cookies = append(cookies, strings.Split(h[1], "; ")...)
		} else {
			cookies = append(cookies, h[1])
		}
	}
	return cookies, names, at
}

func TestACookieAPageCannotSetIsRefusedOverBothProtocols(t *testing.T) {
	// A page's script cannot set Cookie, and its navigation or form sends no
	// header of its own: refused before anything is sent, to a server of
	// either protocol.
	const page = "https://www.example.com/page"
	for _, proto := range []string{"h2", "h1"} {
		server := newRecorder(t, proto, nil)
		client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
		for _, c := range []struct {
			browser BrowserContext
			want    string
		}{
			{BrowserContext{Kind: KindFetch, Initiator: page}, "fetch() cannot set cookie: the browser sets it"},
			{BrowserContext{Kind: KindXHR, Initiator: page}, "an XHR cannot set cookie: the browser sets it"},
			{BrowserContext{Kind: KindNavigation, Initiator: page}, "a navigation sends the headers the browser gives it, not cookie"},
			{BrowserContext{Kind: KindForm, Initiator: page}, "a form sends the headers the browser gives it, not cookie"},
		} {
			_, err := client.Do(&Request{URL: "https://www.example.com/", Header: NewHeader("cookie", "x=9"), Browser: &c.browser,
				Cookies: []Cookie{{Name: "a", Value: "1"}}})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s %s: %v, want %q", proto, c.browser.Kind, err, c.want)
			}
		}
		if got := server.requests(); len(got) != 0 {
			t.Errorf("%s: %d requests sent", proto, len(got))
		}
	}
}
