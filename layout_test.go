package tlsforge

import (
	"fmt"
	"net/http"
	"slices"
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

func TestARedirectKeepsTheCookieSlotOfACookieItDrops(t *testing.T) {
	// fhttp sends a Cookie a request was given to no other host; the hop
	// carries the jar's for it, in the slot the request's was in, over
	// HTTP/1.1 as over HTTP/2, where the order fhttp copies keeps it.
	first := fhttp.Header{"Host": {"a.test"}, "Accept-Language": {"en"}, "Cookie": {"given=1"}, "X-Foo": {"bar"},
		fhttp.HeaderOrderKey: {"host", "accept-language", "cookie", "x-foo"}}
	original := fhttp.Header{"Host": {"a.test"}, "Accept-Language": {"en"}, "Cookie": {"given=1"}, "X-Foo": {"bar"},
		fhttp.HeaderOrderKey: {"host", "accept-language", "cookie", "priority", "x-foo"}}
	hop := fhttp.Header{"Accept-Language": {"en"}, "X-Foo": {"bar"},
		fhttp.HeaderOrderKey: {"host", "accept-language", "cookie", "priority", "x-foo"}}
	got := redirectHTTP1Layout(first, original, hop, "b.test")
	if order := got[fhttp.HeaderOrderKey]; !slices.Equal(order, []string{"host", "accept-language", "cookie", "x-foo"}) {
		t.Errorf("order %v", order)
	}
	if _, ok := got["Cookie"]; ok {
		t.Errorf("the Cookie given for a.test goes to b.test: %v", got)
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
