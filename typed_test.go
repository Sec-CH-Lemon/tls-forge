package tlsforge

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	tls_client "github.com/igor-lemon/tls-client"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// asGiven is a copy of p saying that a request without a browser context goes
// as given (headers.without_context): the profile's headers with the
// request's own over them, by any method and with any body, as every profile
// that does not say otherwise sends one.
func asGiven(t testing.TB, p *profile.Profile) *profile.Profile {
	t.Helper()
	out := workflowProfile(p)
	out.Behavior["headers.without_context"] = json.RawMessage(`"as-given"`)
	return out
}

// asGivenProfile is the profile of that name as given (asGiven).
func asGivenProfile(t testing.TB, name string) *profile.Profile {
	t.Helper()
	return asGiven(t, shippedProfile(t, name))
}

// shippedProfile is the profile of that name, as tls-forge ships it.
func shippedProfile(t testing.TB, name string) *profile.Profile {
	t.Helper()
	p, err := profile.Get(name)
	if err != nil {
		t.Fatalf("profile %s: %v", name, err)
	}
	return p
}

// regular are the names of the fields k came with, but the pseudo-headers,
// as they were written.
func regular(k *keptRequest) []string {
	var out []string
	for _, h := range k.headers {
		if !strings.HasPrefix(h[0], ":") {
			out = append(out, h[0])
		}
	}
	return out
}

// typedOrder is the order of the fields of a navigation typed into the address
// bar without a context, over the protocol given, its own fields given: lower
// case over HTTP/2, as Chrome spells them over HTTP/1.1.
func typedOrder(proto string, given ...string) []string {
	if proto == "h2" {
		return slices.Concat([]string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
			"user-agent"}, given, []string{"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"accept-encoding", "accept-language", "priority"})
	}
	return slices.Concat([]string{"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"Upgrade-Insecure-Requests", "User-Agent"}, given, []string{"Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
		"Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"})
}

func TestTheFieldsARequestIsGivenGoWhereChromeWritesThem(t *testing.T) {
	// Each in the slot Chrome writes that field in, in place of Chrome's own;
	// one Chrome has no slot for after User-Agent, by the bytes of its name as
	// given, as Chrome over DevTools writes the extra headers it is given
	// (testdata/chrome155-given.json), and over HTTP/1.1 spelt as given.
	for _, proto := range []string{"h2", "h1"} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, nil)
			client := contextClient(t, server, WithHeaders(NewHeader("X-Client", "c", "Accept-Language", "de",
				"X-Request", "the client's")))
			if _, err := client.Do(&Request{URL: "https://www.example.com/p", Header: NewHeader(
				"X-Zed", "1", "x-alpha", "2", "X-MiDdle", "3", "Origin", "https://shop.example",
				"Accept", "application/json", "sec-ch-ua-platform", `"Windows"`, "Referer", "https://shop.example/a",
				"x-zed", "4", "X-Request", "the request's")}); err != nil {
				t.Fatalf("Do: %v", err)
			}
			got := server.requests()[0]
			// The client's own, which WithHeaders keeps in lower case, among
			// them.
			// Each name as first spelt; the request's own in place of the
			// client's of the same name.
			block := []string{"Origin", "X-MiDdle", "X-Request", "X-Zed", "X-Zed", "x-alpha", "x-client"}
			want := typedOrder(proto, block...)
			// The Referer it was given, in Chrome's slot for it.
			want = slices.Insert(want, slices.Index(want, map[string]string{"h2": "accept-encoding", "h1": "Accept-Encoding"}[proto]),
				map[string]string{"h2": "referer", "h1": "Referer"}[proto])
			if proto == "h2" {
				for i := range want {
					want[i] = strings.ToLower(want[i])
				}
			}
			if names := regular(got); !slices.Equal(names, want) {
				t.Errorf("fields %v\nwant   %v", names, want)
			}
			for name, value := range map[string]string{"accept": "application/json", "sec-ch-ua-platform": `"Windows"`,
				"accept-language": "de", "x-client": "c", "origin": "https://shop.example", "referer": "https://shop.example/a",
				"sec-fetch-site": "none", "x-request": "the request's"} {
				if got, _ := got.header(name); got != value {
					t.Errorf("%s: %q, want %q", name, got, value)
				}
			}
			var zeds []string
			for _, h := range got.headers {
				if strings.EqualFold(h[0], "x-zed") {
					zeds = append(zeds, h[1])
				}
			}
			if !slices.Equal(zeds, []string{"1", "4"}) {
				t.Errorf("X-Zed %v, want both, in turn", zeds)
			}
		})
	}
}

func TestTheFieldsChromeAddsItselfGoInItsSlotsWhenARequestIsGivenThem(t *testing.T) {
	// Where Chrome's network stack writes them when they are its own
	// (testdata/chrome155-given.json): a reload's Pragma and Cache-Control and
	// what its cache knows of the realm's Authorization before the client
	// hints, a revalidation's validators after the cookies, and the Cookie
	// right after Accept-Language, the request's own before the jar's, over
	// HTTP/2 a field for each.
	for _, proto := range []string{"h2", "h1"} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, nil)
			client := contextClient(t, server)
			if _, err := client.Do(&Request{URL: "https://www.example.com/p", Header: NewHeader(
				"If-Modified-Since", "Wed, 21 Oct 2026 07:28:00 GMT", "Cookie", "given=1", "Authorization", "Bearer t",
				"Cache-Control", "no-cache", "If-None-Match", `"v1"`, "Pragma", "no-cache", "Priority", "u=1"),
				Cookies: []Cookie{{Name: "jar", Value: "1"}}}); err != nil {
				t.Fatalf("Do: %v", err)
			}
			got := server.requests()[0]
			want := []string{"pragma", "cache-control", "authorization", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
				"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
				"sec-fetch-dest", "accept-encoding", "accept-language", "cookie", "cookie", "if-none-match", "if-modified-since",
				"priority"}
			if proto == "h1" {
				// Chrome's spelling, and the Priority it was given too.
				want = []string{"Host", "Connection", "Pragma", "Cache-Control", "Authorization", "sec-ch-ua", "sec-ch-ua-mobile",
					"sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
					"Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language", "Cookie", "If-None-Match",
					"If-Modified-Since", "Priority"}
			}
			if names := regular(got); !slices.Equal(names, want) {
				t.Errorf("fields %v\nwant   %v", names, want)
			}
			cookies, _, _ := cookiesSent(t, got, proto)
			if !slices.Equal(cookies, []string{"given=1", "jar=1"}) {
				t.Errorf("cookies %q, want the request's own, then the jar's", cookies)
			}
			if priority, _ := got.header("priority"); priority != "u=1" {
				t.Errorf("priority %q", priority)
			}
		})
	}
}

func TestTheFieldsARequestIsGivenGoInTheirOrderWhereTheProfileSaysSo(t *testing.T) {
	// headers.given_order "as-given": the fields Chrome has no slot for in
	// the order they were given.
	server := newRecorder(t, "h2", nil)
	p := shippedProfile(t, "chrome_155_macos")
	p.Behavior["headers.given_order"] = json.RawMessage(`"as-given"`)
	client := contextClient(t, server, WithProfileValue(p))
	if _, err := client.Do(&Request{URL: "https://www.example.com/p", Header: NewHeader("X-Zed", "1", "X-Alpha", "2")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if names := regular(server.requests()[0]); !slices.Equal(names, typedOrder("h2", "x-zed", "x-alpha")) {
		t.Errorf("fields %v", names)
	}
}

func TestARequestWithoutAContextToAnUntrustworthyURLKeepsWhatItWasGiven(t *testing.T) {
	// Chrome tells a URL that is not potentially trustworthy neither its client
	// hints nor where its requests come from, and offers it neither Brotli nor
	// zstd; what the request was given goes as given.
	server := newRecorder(t, "http", nil)
	client := contextClient(t, server, WithTransportOption(tls_client.WithDialContext(
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.addr)
		})))
	if _, err := client.Do(&Request{URL: "http://www.example.com/p", Header: NewHeader("Sec-Fetch-Site", "cross-site")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()[0]
	want := []string{"Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
		"Accept-Encoding", "Accept-Language"}
	if names := regular(got); !slices.Equal(names, want) {
		t.Errorf("fields %v\nwant   %v", names, want)
	}
	if site, _ := got.header("sec-fetch-site"); site != "cross-site" {
		t.Errorf("Sec-Fetch-Site %q", site)
	}
	if codings, _ := got.header("accept-encoding"); codings != "gzip, deflate" {
		t.Errorf("Accept-Encoding %q", codings)
	}
}

func TestARequestWithoutAContextIsGivenTheHostItNames(t *testing.T) {
	// A Host it was given names the origin its first request, and those to the
	// same origin, go to; the last of several.
	server := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r":
			http.Redirect(w, r, "/landed", http.StatusFound)
		case "/landed":
			http.Redirect(w, r, "https://api.example.com/elsewhere", http.StatusFound)
		}
	})
	client := contextClient(t, server)
	if _, err := client.Do(&Request{URL: "https://www.example.com/r", Header: NewHeader("host", "first.example",
		"Host", "chosen.example")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	var hosts []string
	for _, k := range server.requests() {
		host, _ := k.header("host")
		hosts = append(hosts, host)
	}
	if want := []string{"chosen.example", "chosen.example", "api.example.com"}; !slices.Equal(hosts, want) {
		t.Errorf("hosts %v, want %v", hosts, want)
	}
}

func TestARequestWithoutAContextIsSentAgainForTheHintsALPSAsksForWithItsOwnFields(t *testing.T) {
	// A typed navigation is started again with the client hints the ALPS of
	// its connection asks for, after Accept, as Chrome's is
	// (testdata/chrome155-alps.json); its own fields where they were, and its
	// own Cookie with the jar's after it.
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, origin := alpsBench(t, server, "accept-ch")
	for _, req := range []*Request{{URL: origin + "/p/set?cookie=1"},
		{URL: origin + "/p/after", Header: NewHeader("Cookie", "given=1", "X-Foo", "1")}} {
		if _, err := client.Do(req); err != nil {
			t.Fatalf("%s: %v", req.URL, err)
		}
	}
	client.CloseIdleConnections()
	var sent []harness.WrittenRequest
	for _, c := range sentToALPS(t, server, "accept-ch") {
		sent = append(sent, c...)
	}
	if len(sent) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	names := fieldNames(sent[1])
	if !askedAfterAccept(names) || slices.Index(names, "x-foo") != slices.Index(names, "user-agent")+1 ||
		slices.Index(names, "cookie") != slices.Index(names, "accept-language")+1 ||
		strings.Count(strings.Join(names, " "), "cookie") != 3 {
		t.Errorf("the page after the cookies were set: %q", names)
	}
}

func TestARedirectTakesFromARequestWithoutAContextWhatChromeTakes(t *testing.T) {
	// Each hop keeps the fields the request was given, where they go after a
	// redirect, but its Cookie, which Chrome makes again of the jar's for each
	// (testdata/chrome155-given.json); across origins its Origin is said as
	// "null", as Chrome says it, and its Authorization goes for good, which
	// Chrome sends on.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r":
			http.Redirect(w, r, "/across", http.StatusFound)
		case "/across":
			http.Redirect(w, r, "https://api.example.com/back", http.StatusFound)
		case "/back":
			http.Redirect(w, r, "https://www.example.com/landed", http.StatusFound)
		}
	})
	client := contextClient(t, server)
	if _, err := client.Do(&Request{URL: "https://www.example.com/r", Header: NewHeader("Cookie", "given=1",
		"X-Foo", "1", "Authorization", "Bearer t", "Origin", "https://shop.example"),
		Cookies: []Cookie{{Name: "jar", Value: "1", Domain: "example.com", Path: "/"}}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 4 {
		t.Fatalf("sent %d requests", len(got))
	}
	for i, k := range got {
		cookies, _, _ := cookiesSent(t, k, "h2")
		authorization, _ := k.header("authorization")
		origin, _ := k.header("origin")
		want := []string{"jar=1"}
		wantAuthorization, wantOrigin := "", "null"
		switch i {
		case 0:
			want, wantAuthorization, wantOrigin = []string{"given=1", "jar=1"}, "Bearer t", "https://shop.example"
		case 1:
			wantAuthorization, wantOrigin = "Bearer t", "https://shop.example"
		}
		if !slices.Equal(cookies, want) || authorization != wantAuthorization || origin != wantOrigin {
			t.Errorf("hop %d: cookies %q, Authorization %q, Origin %q", i, cookies, authorization, origin)
		}
		// The Origin it was given after User-Agent, among what Chrome has no
		// slot of its own for in a navigation, and in its slot after a
		// redirect, where what else it was given follows.
		names := regular(k)
		if at := slices.Index(names, "origin"); at != slices.Index(names, "user-agent")+1 || names[at+1] != "x-foo" {
			t.Errorf("hop %d: %v", i, names)
		}
	}
}

func TestACriticalHintRestartsARequestWithoutAContextWithItsOwnFields(t *testing.T) {
	// Chrome starts the typed navigation again for its critical hints, with
	// the fields it was given, its Cookie too, where they were, and the hints
	// after Accept (testdata/chrome155-given.json).
	server := newRecorder(t, "h2", criticalPage)
	client := contextClient(t, server)
	if _, err := client.Do(&Request{URL: "https://www.example.com/p", Header: NewHeader("Cookie", "given=1", "X-Foo", "1")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()
	if len(got) != 2 {
		t.Fatalf("sent %d requests", len(got))
	}
	names := regular(got[1])
	if slices.Index(names, "x-foo") != slices.Index(names, "user-agent")+1 ||
		slices.Index(names, "sec-ch-ua") != slices.Index(names, "accept")+1 {
		t.Errorf("started again with %v", names)
	}
	if cookies, _, _ := cookiesSent(t, got[1], "h2"); !slices.Equal(cookies, []string{"given=1"}) {
		t.Errorf("started again with cookies %q", cookies)
	}
}

func TestARequestWithoutAContextThatIsNoTypedNavigationIsRefusedAndNothingIsSent(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	for _, req := range []*Request{
		{Method: "POST", URL: "https://www.example.com/p", Body: []byte("a=1")},
		{Method: "POST", URL: "https://www.example.com/p"},
		{Method: "PUT", URL: "https://www.example.com/p"},
		{Method: "HEAD", URL: "https://www.example.com/p"},
		{Method: "OPTIONS", URL: "https://www.example.com/p"},
		{URL: "https://www.example.com/p", Body: []byte{}},
		{Method: "get", URL: "https://u:secret@www.example.com/p", Body: []byte("x")},
	} {
		_, err := client.Do(req)
		if !errors.Is(err, ErrNeedsContext) || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s %s: %v", req.Method, req.URL, err)
		}
		if err := client.Validate(req); !errors.Is(err, ErrNeedsContext) {
			t.Errorf("Validate %s %s: %v", req.Method, req.URL, err)
		}
	}
	if got := server.requests(); len(got) != 0 {
		t.Errorf("sent %d requests", len(got))
	}
	// A GET in lower case is one.
	if _, err := client.Do(&Request{Method: "get", URL: "https://www.example.com/p"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := server.requests(); len(got) != 1 || got[0].method != "GET" {
		t.Errorf("sent %+v", got)
	}
}

func TestARequestWithoutAContextGoesAsGivenWhereTheProfileSaysSo(t *testing.T) {
	// The profile's headers with the request's own over them, a field it does
	// not have after the last of them, by any method: a profile that does not
	// say a request without a context is a typed navigation, as a catalogue's
	// or a capture's.
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server, WithProfileValue(asGivenProfile(t, "chrome_155_macos")))
	if _, err := client.Do(&Request{Method: "POST", URL: "https://www.example.com/p", Body: []byte("a"),
		Header: NewHeader("X-Foo", "1", "Accept-Language", "de")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	names := regular(server.requests()[0])
	if names[len(names)-2] != "x-foo" || slices.Index(names, "accept-language") != slices.Index(names, "accept-encoding")+1 {
		t.Errorf("fields %v", names)
	}
}

func TestAGivenAuthorizationIsTheRequestsOwnToAnswerFor(t *testing.T) {
	// A request without a context with an Authorization of its own is not
	// answered for by tls-forge: its 401 is the answer.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := contextClient(t, server)
	res, err := client.Do(&Request{URL: "https://u:p@www.example.com/p", Header: NewHeader("Authorization", "Bearer t")})
	if err != nil || res.Status != http.StatusUnauthorized {
		t.Fatalf("Do: %v, %+v", err, res)
	}
	if got := server.requests(); len(got) != 1 {
		t.Errorf("sent %d requests", len(got))
	}
}

func TestARequestWithoutAContextIsRefusedWhereTheProfileSaysNoPolicyThereIs(t *testing.T) {
	// A typed navigation is worked out under the profile's own referrer
	// policy, which has to be one.
	server := newRecorder(t, "h2", nil)
	p := shippedProfile(t, "chrome_155_macos")
	p.Behavior["headers.default_referrer_policy"] = json.RawMessage(`"bogus"`)
	client := contextClient(t, server, WithProfileValue(p))
	if _, err := client.Do(&Request{URL: "https://www.example.com/p"}); err == nil ||
		!strings.Contains(err.Error(), "browser context: referrer policy") {
		t.Errorf("Do: %v", err)
	}
	if got := server.requests(); len(got) != 0 {
		t.Errorf("sent %d requests", len(got))
	}
}

func TestTheSlotsAnOrderNames(t *testing.T) {
	// What stands for several headers in an order of the profile's.
	got := slotList([]string{"@hints", "@alps-hints", "@given", "accept"})
	if want := []string{slotHints, slotALPSHints, slotGiven, "accept"}; !slices.Equal(got, want) {
		t.Errorf("slots %q, want %q", got, want)
	}
}

func TestARequestWithoutAContextGoesAsGivenWhereTheProfileHasNoHeaders(t *testing.T) {
	// A profile that says a typed navigation and has no headers to send one
	// with sends a request without a context as given.
	server := newRecorder(t, "h2", nil)
	p := shippedProfile(t, "chrome_155_macos")
	p.Headers, p.HTTP1 = nil, nil
	client := contextClient(t, server, WithProfileValue(p))
	if _, err := client.Do(&Request{Method: "POST", URL: "https://www.example.com/p", Body: []byte("a"),
		Header: NewHeader("X-Foo", "1")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if names := regular(server.requests()[0]); !slices.Equal(names, []string{"x-foo", "content-length"}) {
		t.Errorf("fields %v", names)
	}
}

func TestATypedNavigationIsAnsweredAsARequestWithoutAContext(t *testing.T) {
	// No cache, and the fields of a body that was decoded taken off.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte("page"))
		_ = zw.Close()
	})
	client := contextClient(t, server)
	for range 2 {
		res, err := client.Get("https://www.example.com/cached")
		if err != nil || string(res.Body) != "page" || res.Header["content-encoding"] != nil || res.Encoding != "gzip" {
			t.Fatalf("Get: %v, %+v", err, res)
		}
	}
	if got := server.requests(); len(got) != 2 {
		t.Errorf("sent %d requests", len(got))
	}
}
