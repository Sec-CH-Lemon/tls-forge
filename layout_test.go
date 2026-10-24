package tlsforge

import (
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"net/http"
	"net/url"
	"reflect"
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
		h1 := browserHTTP1Layout(nil, nil, nil, order, nil, nil, "h")[fhttp.HeaderOrderKey]
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
		p.Behavior = behavior.Generic() // This fixture changes policy explicitly; renaming is metadata only.
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
	onEveryPlatform(t, func(t *testing.T, p *profile.Profile) {
		for _, c := range cases {
			both := measured.Scenarios[c.scenario]
			for proto, want := range map[string][]chromeRequest{"h2": both.H2, "h1": both.H1} {
				t.Run(fmt.Sprintf("%s/%s/%s", c.scenario, c.how, proto), func(t *testing.T) {
					server := newRecorder(t, proto, answeringAsMeasured)
					client := newTestClient(t, WithProfileValue(p), server.dialing())
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
						if diff := diffRequest(want[i], got[i], proto, p); diff != "" {
							t.Errorf("request %d:\n%s", i+1, diff)
						}
					}
				})
			}
		}
	})
}

func TestARequestWithoutAContextGoesToEachURLAsChromeTypedIt(t *testing.T) {
	// A navigation typed into the address bar goes to https, and to http on
	// the machine itself (localhost, a name under .localhost, 127.0.0.1 and
	// [::1]), with every header the profile has; to any other http URL
	// without the client hints and Sec-Fetch-*, offering neither Brotli nor
	// zstd; and each hop of its redirects as its own URL is, what was withheld
	// from one going back on at the next.
	measured := loadChromeRequests(t)
	onEveryPlatform(t, func(t *testing.T, shipped *profile.Profile) {
		// As the profile ships, a typed navigation (typed.go), and as a
		// profile that says it goes as given lays the profile's headers out.
		for way, p := range map[string]*profile.Profile{"typed": shipped, "as given": asGiven(t, shipped)} {
			for _, scenario := range []string{"nav-direct", "nav-direct-plain", "nav-direct-localhost", "nav-direct-dot-localhost",
				"nav-direct-ipv4", "nav-direct-ipv6", "redir-nav-direct-301", "redir-nav-direct-302", "redir-nav-direct-303",
				"redir-nav-direct-307", "redir-nav-direct-308", "redir-nav-direct-cross-site", "redir-nav-direct-downgrade",
				"redir-nav-direct-upgrade", "redir-nav-direct-to-localhost", "redir-nav-direct-plain-to-localhost"} {
				both := measured.Scenarios[scenario]
				for proto, want := range map[string][]chromeRequest{"h2": both.H2, "h1": both.H1} {
					t.Run(way+"/"+scenario+"/"+proto, func(t *testing.T) {
						if len(want) == 0 {
							t.Fatal("not in the fixture")
						}
						server := newRecorder(t, proto, answeringAsMeasured)
						plain := newRecorder(t, "http", answeringAsMeasured)
						client := newTestClient(t, WithProfileValue(p), server.dialingWith(plain))
						if _, err := client.Do(&Request{URL: want[0].URL}); err != nil {
							t.Fatalf("Do: %v", err)
						}
						got := server.requests()
						if len(got) != len(want) {
							t.Fatalf("sent %d requests, Chrome %d", len(got), len(want))
						}
						for i := range want {
							if diff := diffRequest(want[i], got[i], proto, p); diff != "" {
								t.Errorf("request %d:\n%s", i+1, diff)
							}
						}
					})
				}
			}
		}
	})
}

func TestARedirectToAnotherHostSendsTheJarsCookieInTheSlot(t *testing.T) {
	// A Cookie given, which no hop after the first sends, as Chrome rebuilds
	// a hop's from the jar (headers.given_redirect_drops), and the jar's for
	// the domain, which the hop to api.example.com sends: its Cookie goes
	// right after Accept-Language, and what the request was given after
	// User-Agent, over both protocols.
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
			want, given := []string{"Accept-Language", "Cookie"}, []string{"User-Agent", "x-foo", "Accept"}
			if proto == "h2" {
				want, given = []string{"accept-language", "cookie", "priority"}, []string{"user-agent", "x-foo", "accept"}
			}
			at := slices.Index(names, want[1])
			if at < 1 || !slices.Equal(names[at-1:min(at-1+len(want), len(names))], want) {
				t.Fatalf("hop's headers %v, want %v", names, want)
			}
			if cookie := got[1].headers[at][1]; cookie != "d=4" {
				t.Errorf("hop's Cookie %q, want the jar's alone", cookie)
			}
			if at := slices.Index(names, given[1]); at < 1 || !slices.Equal(names[at-1:min(at+2, len(names))], given) {
				t.Errorf("hop's headers %v, want %v", names, given)
			}
		})
	}
}

func TestARequestsOwnCookieGoesBeforeTheJarsOverBothProtocols(t *testing.T) {
	// A request's own Cookie and the cookies the jar holds for its URL go
	// together, its own first, as net/http adds a jar's: the same over
	// HTTP/1.1, one line, and HTTP/2, a field for each cookie, right after
	// Accept-Language where the profile is Chromium's (cookieSlot). So on the
	// answer to a 401; a redirect's hop goes with the jar's alone, as Chrome
	// rebuilds a hop's Cookie from its jar (headers.given_redirect_drops), but
	// for a request sent as given, to which fhttp sends the request's own on
	// its host alone.
	jar := []Cookie{{Name: "a", Value: "1", Domain: "example.com", Path: "/"}, {Name: "b", Value: "2"}}
	firefox, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	firefox.Name, firefox.UserAgent = "firefox_test", "Mozilla/5.0 (Macintosh; rv:148.0) Gecko/20100101 Firefox/148.0"
	firefox.Behavior = behavior.Generic() // This fixture changes policy explicitly; renaming is metadata only.
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
			want: []sent{{www + "/same", all}, {www + "/landed", []string{"a=1", "b=2"}}}},
		{name: "sent as given, redirected on its host", opts: []Option{WithProfileValue(asGivenProfile(t, "chrome_155_macos"))},
			req: Request{URL: www + "/same", Header: own, Cookies: jar}, want: []sent{{www + "/same", all}, {www + "/landed", all}}},
		{name: "redirected to another host", req: Request{URL: www + "/other", Header: own, Cookies: jar},
			want: []sent{{www + "/other", all}, {api + "/landed", []string{"a=1"}}}},
		{name: "redirected to a host under its own", req: Request{URL: "https://example.com/under", Header: own, Cookies: jar},
			want: []sent{{"https://example.com/under", all}, {www + "/landed", []string{"a=1"}}}},
		{name: "sent as given, redirected to a host under its own", opts: []Option{WithProfileValue(asGivenProfile(t, "chrome_155_macos"))},
			req:  Request{URL: "https://example.com/under", Header: own, Cookies: jar},
			want: []sent{{"https://example.com/under", all}, {www + "/landed", []string{"x=9", "a=1"}}}},
		{name: "redirected by an answer setting a cookie it was given",
			req:  Request{URL: www + "/set", Header: NewHeader("cookie", "x=9; y=8"), Cookies: jar},
			want: []sent{{www + "/set", []string{"x=9", "y=8", "a=1", "b=2"}}, {www + "/landed", []string{"a=1", "b=2", "x=new"}}}},
		{name: "answered after a 401", req: Request{URL: "https://u:p@www.example.com/auth", Header: own, Cookies: jar},
			want: []sent{{www + "/auth", all}, {www + "/auth", all}}},
		{name: "a profile the same over both protocols", opts: []Option{WithProfile("chrome_151_linux")},
			req:  Request{URL: www + "/same", Header: own, Cookies: jar},
			want: []sent{{www + "/same", all}, {www + "/landed", []string{"a=1", "b=2"}}}},
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

// trustedOnly are the headers chrome_155_macos sends only to a URL that is
// potentially trustworthy.
var trustedOnly = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site", "sec-fetch-mode",
	"sec-fetch-user", "sec-fetch-dest"}

func TestAProfileWithholdsItsClientHintsSecFetchAndBrotliFromAURLThatIsNotTrustworthy(t *testing.T) {
	chrome, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	w := withheldOf(chrome, nil)
	if w == nil || !slices.Equal(w.names, trustedOnly) || !w.encoding {
		t.Fatalf("withheldOf(chrome_155_macos) = %+v", w)
	}
	// What the client was given is its own, in any case.
	if got := withheldOf(chrome, NewHeader("Sec-CH-UA", "x", "Accept-Encoding", "gzip")); got == nil ||
		!slices.Equal(got.names, trustedOnly[1:]) || got.encoding {
		t.Errorf("the client given sec-ch-ua and accept-encoding: %+v", got)
	}
	// And so is what a request was given.
	if got := w.without(NewHeader("sec-fetch-site", "cross-site")); got == nil ||
		!slices.Equal(got.names, slices.Delete(slices.Clone(trustedOnly), 3, 4)) || !got.encoding {
		t.Errorf("a request given sec-fetch-site: %+v", got)
	}
	if got := w.without(NewHeader("accept-encoding", "br")); got == nil || !slices.Equal(got.names, trustedOnly) ||
		got.encoding {
		t.Errorf("a request given accept-encoding: %+v", got)
	}
	// Everything given leaves nothing withheld, and nothing given changes
	// nothing.
	everything := NewHeader("accept-encoding", "br")
	for _, name := range trustedOnly {
		everything.Add(name, "x")
	}
	if got := w.without(everything); got != nil {
		t.Errorf("a request given everything: %+v", got)
	}
	if got := withheldOf(chrome, everything); got != nil {
		t.Errorf("a client given everything: %+v", got)
	}
	if w.without(nil) != w {
		t.Error("a request given nothing made a copy")
	}
	if got := (*withholding)(nil).without(NewHeader("x-foo", "1")); got != nil {
		t.Errorf("nothing withheld: %+v", got)
	}

	// What only the HTTP/1.1 capture has counts too, once.
	http1 := chrome.Clone()
	http1.Headers = []profile.Field{{Name: "user-agent", Value: chrome.UserAgent}}
	http1.HTTP1 = &profile.HTTP1{Headers: []profile.Field{{Name: "Sec-Fetch-Dest", Value: "document"},
		{Name: "sec-fetch-dest", Value: "document"}}}
	if got := withheldOf(http1, nil); got == nil || !slices.Equal(got.names, []string{"sec-fetch-dest"}) || got.encoding {
		t.Errorf("Sec-Fetch-Dest in the HTTP/1.1 capture alone: %+v", got)
	}
	// A profile with none of them withholds nothing; another browser's was
	// not measured.
	if got := withheldOf(&profile.Profile{EngineMajor: profile.Major(1), Name: "chrome_133", Base: "chrome_133"}, nil); got != nil {
		t.Errorf("a catalogue profile: %+v", got)
	}
	firefox := chrome.Clone()
	firefox.Name, firefox.UserAgent = "firefox_148", "Mozilla/5.0 (Macintosh; rv:148.0) Gecko/20100101 Firefox/148.0"
	firefox.Behavior = behavior.Generic() // This fixture changes policy explicitly; renaming is metadata only.
	firefox.PerConnection = nil
	if got := withheldOf(firefox, nil); got != nil {
		t.Errorf("another browser's profile: %+v", got)
	}
}

func TestWhatIsWithheldIsTakenOutOfABlockItsSlotsLeft(t *testing.T) {
	order := []string{"host", "sec-ch-ua", "user-agent", "Sec-Fetch-Site", "accept-encoding"}
	block := fhttp.Header{"Host": {"h"}, "sec-ch-ua": {"a"}, "User-Agent": {"u"}, "Sec-Fetch-Site": {"none"},
		"Accept-Encoding": {"gzip, deflate, br, zstd"}, fhttp.HeaderOrderKey: order}
	(&withholding{names: []string{"sec-ch-ua", "sec-fetch-site"}, encoding: true}).from(block)
	want := fhttp.Header{"Host": {"h"}, "User-Agent": {"u"}, "Accept-Encoding": {"gzip, deflate"},
		fhttp.HeaderOrderKey: order}
	if !reflect.DeepEqual(block, want) {
		t.Errorf("block %v, want %v", block, want)
	}
	for _, c := range []struct {
		offered, want []string
	}{
		{[]string{"gzip, br", "zstd;q=0.5, deflate;q=0.1"}, []string{"gzip, deflate;q=0.1"}},
		{[]string{"identity"}, []string{"identity"}},
		// Nothing else offered is no Accept-Encoding, not an empty one.
		{[]string{"br, zstd"}, nil},
	} {
		block := fhttp.Header{"accept-encoding": c.offered}
		(&withholding{encoding: true}).from(block)
		if got, ok := block["accept-encoding"]; !slices.Equal(got, c.want) || ok != (c.want != nil) {
			t.Errorf("%q: %q (%v), want %q", c.offered, got, ok, c.want)
		}
	}
	// Without the encoding, Accept-Encoding is as it was.
	kept := fhttp.Header{"Accept-Encoding": {"br"}, "Sec-Ch-Ua": {"a"}}
	(&withholding{names: []string{"sec-ch-ua"}}).from(kept)
	if !reflect.DeepEqual(kept, fhttp.Header{"Accept-Encoding": {"br"}}) {
		t.Errorf("kept %v", kept)
	}
}

func TestARequestToAURLThatIsNotTrustworthyIsWrittenWithoutWhatIsWithheld(t *testing.T) {
	http2 := fhttp.Header{"Sec-Ch-Ua": {"a"}, "Accept-Encoding": {"gzip, br"}, "User-Agent": {"u"},
		fhttp.HeaderOrderKey: {"sec-ch-ua", "user-agent", "accept-encoding"}}
	withheld := &withholding{names: []string{"sec-ch-ua"}, encoding: true}
	plain, _ := url.Parse("http://www.example.com/")
	for _, c := range []struct {
		name  string
		http1 fhttp.Header
	}{
		{"the same over both", nil},
		{"with an HTTP/1.1 block", fhttp.Header{"Connection": {"keep-alive"}, "sec-ch-ua": {"a"}, "Accept-Encoding": {"gzip, br"},
			"User-Agent": {"u"}, fhttp.HeaderOrderKey: {"connection", "sec-ch-ua", "user-agent", "accept-encoding"}}},
	} {
		l := newLayouts(cloneHeaderLayout(http2), cloneHeaderLayout(c.http1))
		if c.http1 == nil {
			l = newLayouts(cloneHeaderLayout(http2), nil)
		}
		l.withheld = withheld
		req := l.wear(&fhttp.Request{URL: plain, Header: fhttp.Header{}})
		// What it wears stays whole, for a redirect's request to be made
		// from: a hop to a URL that is trustworthy gets it all.
		if req.Header.Get("Sec-Ch-Ua") != "a" || req.Header.Get("Accept-Encoding") != "gzip, br" {
			t.Errorf("%s: wears %v", c.name, req.Header)
		}
		for _, protocol := range []string{fhttp.ProtocolHTTP1, fhttp.ProtocolHTTP2} {
			written := req.WrittenHeader(protocol)
			if _, ok := fieldOf(written, "sec-ch-ua"); ok || written.Get("Accept-Encoding") != "gzip" ||
				written.Get("User-Agent") != "u" {
				t.Errorf("%s: written over %s as %v", c.name, protocol, written)
			}
		}
		if written := req.WrittenHeader(fhttp.ProtocolHTTP1); (written.Get("Connection") != "") != (c.http1 != nil) {
			t.Errorf("%s: over HTTP/1.1, not its block: %v", c.name, written)
		}
		// The layouts go on the context only for an HTTP/1.1 block of their
		// own to be made from; the chain says what is withheld.
		if (layoutsOn(req) != nil) != (c.http1 != nil) {
			t.Errorf("%s: layouts on the context: %v", c.name, layoutsOn(req))
		}
		// To a URL that is potentially trustworthy nothing is withheld.
		for _, raw := range []string{"https://www.example.com/", "http://localhost/", "http://127.0.0.1:8080/", "http://[::1]/",
			"http://app.localhost/"} {
			u, _ := url.Parse(raw)
			req := l.wear(&fhttp.Request{URL: u, Header: fhttp.Header{}})
			if c.http1 == nil && req.HeaderFor != nil {
				t.Errorf("%s: %s wears more than its block", c.name, raw)
			}
			written := req.WrittenHeader(fhttp.ProtocolHTTP1)
			if hints, _ := fieldOf(written, "sec-ch-ua"); !slices.Equal(hints, []string{"a"}) ||
				written.Get("Accept-Encoding") != "gzip, br" {
				t.Errorf("%s: %s written as %v", c.name, raw, written)
			}
		}
	}
}

func TestWhatTheClientOrTheRequestWasGivenGoesToPlainHTTPAsGiven(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	plain := newRecorder(t, "http", nil)
	client := newTestClient(t, WithProfile("chrome_155_macos"), WithHeaders(NewHeader("sec-ch-ua", `"Mine";v="1"`)),
		server.dialingWith(plain))
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	for _, c := range []*Client{client, fresh} {
		if _, err := c.Do(&Request{URL: "http://www.example.com/",
			Header: NewHeader("Sec-Fetch-Site", "cross-site", "Accept-Encoding", "br")}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	got := server.requests()
	if len(got) != 2 {
		t.Fatalf("sent %d requests", len(got))
	}
	for i, r := range got {
		for name, want := range map[string]string{"sec-ch-ua": `"Mine";v="1"`, "sec-fetch-site": "cross-site", "accept-encoding": "br"} {
			if value, ok := r.header(name); !ok || value != want {
				t.Errorf("request %d: %s %q (%v), want it as given, %q", i+1, name, value, ok, want)
			}
		}
		for _, name := range []string{"sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest"} {
			if value, ok := r.header(name); ok {
				t.Errorf("request %d: the profile's %s went to plain HTTP: %q", i+1, name, value)
			}
		}
	}
}

func TestAProfileThatMeasuredNoHTTP11WithholdsOnEveryHopAsItsURLIs(t *testing.T) {
	// chrome_151 on Linux measured no HTTP/1.1: its requests go the same over
	// both protocols, and the chain says what of them is withheld.
	linux, err := profile.Get("chrome_151_linux")
	if err != nil || linux.HTTP1 != nil {
		t.Fatalf("chrome_151_linux: %v, HTTP/1.1 measured: %v", err, linux.HTTP1 != nil)
	}
	server := newRecorder(t, "h2", nil)
	plain := newRecorder(t, "http", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com/up", http.StatusFound)
	})
	client := newTestClient(t, WithProfile("chrome_151_linux"), server.dialingWith(plain))
	if _, err := client.Do(&Request{URL: "http://www.example.com/plain"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 2 {
		t.Fatalf("sent %d requests", len(got))
	}
	assertTrusted(t, got[0], false)
	assertTrusted(t, got[1], true)
}

func TestEachHopOfARedirectIsWrittenWithWhatIsWithheldOrWithoutAsItsURLIs(t *testing.T) {
	// https, then plain http, then https again: the hop in the middle without
	// the client hints, Sec-Fetch-* and Brotli, the last with them, the client
	// hints after Sec-Fetch-Dest as Chrome writes a hop's.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.Redirect(w, r, "http://www.example.com/middle", http.StatusFound)
		}
	})
	plain := newRecorder(t, "http", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com/last", http.StatusFound)
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialingWith(plain))
	if _, err := client.Do(&Request{URL: "https://www.example.com/first"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 3 {
		t.Fatalf("sent %d requests", len(got))
	}
	assertTrusted(t, got[0], true)
	assertTrusted(t, got[1], false)
	assertTrusted(t, got[2], true)
	upgraded := loadChromeRequests(t).Scenarios["redir-nav-direct-upgrade"].H2[1]
	var names, want []string
	for _, h := range got[2].headers {
		names = append(names, h[0])
	}
	for _, h := range upgraded.Headers {
		want = append(want, h[0])
	}
	if !slices.Equal(names, want) {
		t.Errorf("the last hop's headers %v, Chrome's after an upgrade %v", names, want)
	}
}

func TestAnAnswerToA401FromPlainHTTPIsWrittenWithoutWhatIsWithheld(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	plain := newRecorder(t, "http", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialingWith(plain))
	if _, err := client.Do(&Request{URL: "http://u:p@www.example.com/a"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 2 {
		t.Fatalf("sent %d requests", len(got))
	}
	for _, r := range got {
		assertTrusted(t, r, false)
	}
	if value, _ := got[1].header("authorization"); value != "Basic dTpw" {
		t.Errorf("the answer's Authorization %q", value)
	}
}

// fieldOf is the values of the field name in block, in whatever case it is
// spelt there, and whether it is there.
func fieldOf(block fhttp.Header, name string) ([]string, bool) {
	for key, values := range block {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}
	return nil, false
}

// assertTrusted holds r to what chrome_155_macos sends a URL that is
// potentially trustworthy, or to what it sends any other.
func assertTrusted(t *testing.T, r *keptRequest, trusted bool) {
	t.Helper()
	for _, name := range trustedOnly {
		if _, ok := r.header(name); ok != trusted {
			t.Errorf("%s: %s there: %v", r.url, name, ok)
		}
	}
	encoding := "gzip, deflate"
	if trusted {
		encoding = "gzip, deflate, br, zstd"
	}
	if value, _ := r.header("accept-encoding"); value != encoding {
		t.Errorf("%s: Accept-Encoding %q, want %q", r.url, value, encoding)
	}
}

func TestARefererGivenWithoutAContextGoesAsGivenBesideATypedNavigation(t *testing.T) {
	// A request without a browser context is a navigation typed in, and a
	// header given is the caller's: a Referer goes as given, though Chrome
	// sends none with Sec-Fetch-Site: none. A navigation from a page is a
	// browser context with its Initiator, which refuses a Referer given.
	server := newRecorder(t, "h2", nil)
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	if _, err := client.Do(&Request{URL: "https://www.example.com/", Header: NewHeader("Referer", "https://www.example.net/page")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 1 {
		t.Fatalf("sent %d requests", len(got))
	}
	for name, want := range map[string]string{"referer": "https://www.example.net/page", "sec-fetch-site": "none", "sec-fetch-user": "?1"} {
		if value, _ := got[0].header(name); value != want {
			t.Errorf("%s %q, want %q", name, value, want)
		}
	}
}
