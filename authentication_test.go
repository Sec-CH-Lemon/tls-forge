package tlsforge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

func TestABasicChallengeIsReadAsChromiumReadsIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
		realm  string
		ok     bool
	}{
		{"a realm", []string{`Basic realm="bench"`}, "bench", true},
		{"a scheme in any case, a token for a value", []string{`bASIC realm=bench`}, "bench", true},
		{"no parameters", []string{`Basic`}, "", true},
		{"a tab after the scheme, spaces before it", []string{"  Basic\trealm=\"x\""}, "x", true},
		{"escapes, and a parameter of no matter", []string{`Basic realm="a\"b\\", charset="UTF-8"`}, `a"b\`, true},
		{"the last realm", []string{`Basic realm="x", REALM="y"`}, "y", true},
		{"a comma in quotes, and empty parts", []string{`Basic realm="a,b",, ,`}, "a,b", true},
		{"Latin-1", []string{"Basic realm=\"\xe9t\xe9\""}, "été", true},
		{"a parameter with no value", []string{`Basic realm`}, "", false},
		{"no name", []string{`Basic ="x"`}, "", false},
		{"a quote that does not end", []string{`Basic realm="x`}, "", false},
		{"an escape at the end", []string{`Basic realm="x\"`}, "", false},
		{"more after the quote", []string{`Basic realm="x"y`}, "", false},
		{"the first that can be read", []string{`Basic realm`, `Basic realm="b"`, `Basic realm="c"`}, "b", true},
		{"a scheme tls-forge does not know, then Basic", []string{`Bearer realm="api"`, `Basic realm="x"`}, "x", true},
		{"only a scheme tls-forge does not know", []string{`Bearer realm="api"`}, "", false},
		{"Digest, which Chrome prefers", []string{`Basic realm="x"`, `Digest realm="x", nonce="n"`}, "", false},
		{"NTLM", []string{`NTLM`, `Basic realm="x"`}, "", false},
		{"Negotiate", []string{`negotiate`, `Basic realm="x"`}, "", false},
		{"no challenge", nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if realm, ok := basicChallenge(tc.fields); realm != tc.realm || ok != tc.ok {
				t.Errorf("basicChallenge(%q) = %q, %v; want %q, %v", tc.fields, realm, ok, tc.realm, tc.ok)
			}
		})
	}
}

func TestCredentialsAreAUsernameAndItsPassword(t *testing.T) {
	for _, tc := range []struct {
		user *url.Userinfo
		want credentials
		ok   bool
	}{
		{nil, credentials{}, false},
		{url.User(""), credentials{}, false},
		{url.UserPassword("", "p"), credentials{}, false},
		{url.User("u"), credentials{"u", ""}, true},
		{url.UserPassword("u", "p"), credentials{"u", "p"}, true},
	} {
		if got, ok := credentialsOf(tc.user); got != tc.want || ok != tc.ok {
			t.Errorf("credentialsOf(%v) = %v, %v", tc.user, got, ok)
		}
	}
	for cred, want := range map[credentials]string{
		{"u", "p"}: "Basic dTpw",
		{"u", ""}:  "Basic dTo=",
		{"ü", "π"}: "Basic w7w6z4A=",
	} {
		if got := cred.basic(); got != want {
			t.Errorf("%v.basic() = %q, want %q", cred, got, want)
		}
	}
}

func TestALocationIsRelativeWhenItNamesNoSchemeAndNoHost(t *testing.T) {
	for location, want := range map[string]bool{"/a": true, "a": true, "?q": true,
		"//h/a": false, "https://h/a": false, "https:/a": false, "%zz": false} {
		if got := relativeLocation(location); got != want {
			t.Errorf("relativeLocation(%q) = %v", location, got)
		}
	}
}

func TestAuthorizationGoesWhereChromesNetworkStackAddsIt(t *testing.T) {
	h1 := fhttp.Header{"Host": {"h"}, "Connection": {"keep-alive"}, "Content-Length": {"3"}, "Cache-Control": {"no-cache"},
		"X-A": {"1"}, fhttp.HeaderOrderKey: {"host", "connection", "content-length", "cache-control", "x-a"}}
	h2 := fhttp.Header{"Host": {"h"}, "X-A": {"1"}, fhttp.HeaderOrderKey: {"host", "x-a"}}
	l := newLayouts(h2, h1).authorized("Basic one")
	if got := l.http1[fhttp.HeaderOrderKey]; fmt.Sprint(got) != "[host connection content-length cache-control authorization x-a]" {
		t.Errorf("HTTP/1.1 order %v", got)
	}
	// One given before is replaced, and the blocks it was made from are left
	// as they were.
	again := l.authorized("Basic two")
	if got := again.http2[fhttp.HeaderOrderKey]; fmt.Sprint(got) != "[host authorization x-a]" ||
		fmt.Sprint(again.http2["Authorization"]) != "[Basic two]" || fmt.Sprint(l.http2["Authorization"]) != "[Basic one]" {
		t.Errorf("HTTP/2 block %v, the one before %v", again.http2, l.http2)
	}
	if _, ok := h2["Authorization"]; ok {
		t.Error("the block authorized is changed")
	}
	if one := newLayouts(fhttp.Header{}, nil).authorized("Basic x"); one.http1 != nil || one.managed != nil {
		t.Errorf("a request the same over both has %v", one.http1)
	}
	// In every kind's order Authorization follows the Content-Length and
	// Cache-Control Chrome's network stack adds, and comes before the rest.
	for name, order := range map[string][]string{"navigation": navigationOrder, "form": formOrder,
		"restarted": restartedOrder, "redirected": redirectedOrder, "script": scriptOrder(hop{})} {
		at := slices.Index(order, "authorization")
		for _, before := range order[:at] {
			if before != "content-length" && before != "cache-control" {
				t.Errorf("%s: %s before Authorization", name, before)
			}
		}
		if at < 0 {
			t.Errorf("%s has no Authorization", name)
		}
	}
}

func TestAProtectionSpaceBeginsAtADirectory(t *testing.T) {
	for path, want := range map[string]string{"/a/b": "/a/", "/a/": "/a/", "/": "/", "": "/", "a": "/"} {
		if got := parentDirectory(path); got != want {
			t.Errorf("parentDirectory(%q) = %q, want %q", path, got, want)
		}
	}
	for raw, want := range map[string]string{"https://h": "/", "https://h/a%20b/c?q": "/a%20b/c"} {
		u, _ := url.Parse(raw)
		if got := requestPath(u); got != want {
			t.Errorf("requestPath(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestTheCacheKeepsWhatChromiumKeeps(t *testing.T) {
	a := origin{"https", "a.test", "443"}
	b := origin{"https", "b.test", "443"}
	right, wrong := credentials{"u", "p"}, credentials{"u", "x"}
	var c authCache
	if _, _, ok := c.forPath(a, "/x"); ok {
		t.Fatal("an empty cache sends something")
	}
	c.keep(a, "r", right, "/d/e/page")
	for path, ok := range map[string]bool{"/d/e/other": true, "/d/e/f/g": true, "/d/e": false, "/d/x": false} {
		if realm, cred, got := c.forPath(a, path); got != ok || got && (realm != "r" || cred != right) {
			t.Errorf("forPath(%s) = %q, %v, %v", path, realm, cred, got)
		}
	}
	if _, _, ok := c.forPath(b, "/d/e/x"); ok {
		t.Error("sent to another origin")
	}
	// A directory above the one kept takes its place; one under it is in it
	// already.
	c.keep(a, "r", right, "/d/page")
	c.keep(a, "r", right, "/d/e/f/page")
	if paths := c.entries[0].paths; len(paths) != 1 || paths[0] != "/d/" {
		t.Errorf("paths %v", paths)
	}
	// The closest directory above a path decides, and keeping replaces the
	// credentials.
	c.keep(a, "inner", wrong, "/d/e/page")
	if realm, cred, _ := c.forPath(a, "/d/e/x"); realm != "inner" || cred != wrong {
		t.Errorf("the closest is %q, %v", realm, cred)
	}
	c.keep(a, "inner", right, "/d/e/page")
	if cred, ok := c.forRealm(a, "inner"); !ok || cred != right {
		t.Errorf("forRealm = %v, %v", cred, ok)
	}
	if _, ok := c.forRealm(a, "none"); ok {
		t.Error("a realm never answered")
	}
	// Only the credentials turned down are forgotten.
	c.drop(a, "inner", wrong)
	c.drop(a, "nowhere", right)
	if _, ok := c.forRealm(a, "inner"); !ok {
		t.Error("newer credentials were forgotten")
	}
	c.drop(a, "inner", right)
	if _, ok := c.forRealm(a, "inner"); ok {
		t.Error("credentials turned down are kept")
	}
}

func TestTheCacheForgetsWhatChromiumForgets(t *testing.T) {
	at := origin{"https", "a.test", "443"}
	cred := credentials{"u", "p"}
	var c authCache
	for i := range maxAuthPaths + 1 {
		c.keep(at, "r", cred, "/"+strconv.Itoa(i)+"/page")
	}
	if paths := c.entries[0].paths; len(paths) != maxAuthPaths || paths[0] != "/10/" || paths[len(paths)-1] != "/1/" {
		t.Errorf("paths %v", paths)
	}
	// The least recently used realm goes: asking for one uses it.
	c = authCache{}
	for i := range maxAuthEntries {
		c.keep(at, strconv.Itoa(i), cred, "/"+strconv.Itoa(i)+"/page")
	}
	c.forRealm(at, "0")
	c.forPath(at, "/1/x")
	c.keep(at, "new", cred, "/new/page")
	if len(c.entries) != maxAuthEntries {
		t.Fatalf("%d entries", len(c.entries))
	}
	for realm, kept := range map[string]bool{"0": true, "1": true, "2": false, "new": true} {
		if _, ok := c.forRealm(at, realm); ok != kept {
			t.Errorf("realm %s kept %v", realm, ok)
		}
	}
}

func TestTheCacheIsAskedAtOnce(t *testing.T) {
	at := origin{"https", "a.test", "443"}
	var c authCache
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			realm := strconv.Itoa(i % 3)
			for range 50 {
				c.keep(at, realm, credentials{"u", realm}, "/"+realm+"/page")
				c.forPath(at, "/"+realm+"/x")
				c.forRealm(at, realm)
				c.drop(at, realm, credentials{"u", "?"})
			}
		}()
	}
	wg.Wait()
	if len(c.entries) != 3 {
		t.Errorf("%d entries", len(c.entries))
	}
}

// authURL is a URL of the recorder's under /auth/, which answers 401 until it
// is sent u:p, with credentials when said.
func authURL(credentials, rest string) string {
	if credentials != "" {
		credentials += "@"
	}
	return "https://" + credentials + "www.example.com/auth/" + rest
}

// authorizations are the Authorization each request kept had, empty for none.
func authorizations(kept []*keptRequest) []string {
	var out []string
	for _, k := range kept {
		value := ""
		for _, h := range k.headers {
			if strings.EqualFold(h[0], "authorization") {
				value = h[1]
			}
		}
		out = append(out, value)
	}
	return out
}

func TestAURLsCredentialsGoOnlyWhereA401AsksForThem(t *testing.T) {
	// A request without a browser context, typed into the address bar as the
	// profile's headers say, is what Chrome sent for one: the challenge
	// answered with the request sent again, Authorization in its place.
	measured := loadChromeRequests(t).Scenarios["auth-nav-typed"]
	for proto, want := range map[string][]chromeRequest{"h2": measured.H2[:2], "h1": measured.H1[:2]} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, answeringAsMeasured)
			client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
			res, err := client.Get(authURL("u:p", "auth-nav-typed/a?next=/auth/auth-nav-typed/b%3Fnext%3D/p/auth-nav-typed-end"))
			if err != nil || res.Status != http.StatusOK || strings.Contains(res.URL, "u:p") {
				t.Fatalf("Get: %v, %+v", err, res)
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

func TestWhatTheSessionKeepsIsSentWhereChromeSendsIt(t *testing.T) {
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	get := func(url string) {
		t.Helper()
		if res, err := client.Get(url); err != nil || res.Status != http.StatusOK {
			t.Fatalf("Get %s: %v, %+v", url, err, res)
		}
	}
	get(authURL("u:p", "d/a"))
	// Unasked to the directory answered in, and from a client made Fresh, as
	// one of the session; asked elsewhere in the realm, and answered with
	// what was kept; not at all outside it.
	get(authURL("", "d/b"))
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if res, err := fresh.Get(authURL("", "d/c/x")); err != nil || res.Status != http.StatusOK {
		t.Fatalf("fresh Get: %v, %+v", err, res)
	}
	get(authURL("", "e/a"))
	get("https://www.example.com/p/elsewhere")
	// A URL with credentials is sent nothing unasked, even where they are
	// kept.
	get(authURL("u:p", "d/again"))
	want := []string{"", "Basic dTpw", "Basic dTpw", "Basic dTpw", "", "Basic dTpw", "", "", "Basic dTpw"}
	if got := authorizations(server.requests()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Authorization sent %q,\nwant %q", got, want)
	}
}

func TestCredentialsTurnedDownAreTriedOnceAndForgotten(t *testing.T) {
	password := "p"
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != (credentials{"u", password}).basic() {
			w.Header().Set("WWW-Authenticate", `Basic realm="bench"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	status := func(url string) int {
		t.Helper()
		res, err := client.Get(url)
		if err != nil {
			t.Fatalf("Get %s: %v", url, err)
		}
		return res.Status
	}
	// Wrong in the URL: tried once, and nothing kept for the directory.
	if got := status(authURL("u:x", "d/a")); got != http.StatusUnauthorized {
		t.Errorf("status %d", got)
	}
	if got := status(authURL("", "d/b")); got != http.StatusUnauthorized {
		t.Errorf("status %d", got)
	}
	// Right, then changed on the server: what was kept is sent unasked,
	// turned down, and forgotten, with nothing else to try.
	if got := status(authURL("u:p", "d/c")); got != http.StatusOK {
		t.Errorf("status %d", got)
	}
	password = "q"
	if got := status(authURL("", "d/d")); got != http.StatusUnauthorized {
		t.Errorf("status %d", got)
	}
	if got := status(authURL("", "d/e")); got != http.StatusUnauthorized {
		t.Errorf("status %d", got)
	}
	want := []string{"", "Basic dTp4", "", "", "Basic dTpw", "Basic dTpw", ""}
	if got := authorizations(server.requests()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Authorization sent %q,\nwant %q", got, want)
	}
}

func TestA401ChromeWouldNotAnswerWithBasicIsLeftAsItIs(t *testing.T) {
	for name, tc := range map[string]struct {
		challenges []string
		status     int
		header     Header
	}{
		"Digest offered too":             {[]string{`Digest realm="r", nonce="n"`, `Basic realm="r"`}, http.StatusUnauthorized, nil},
		"NTLM offered too":               {[]string{`NTLM`, `Basic realm="r"`}, http.StatusUnauthorized, nil},
		"no challenge":                   {nil, http.StatusUnauthorized, nil},
		"a challenge that is no 401":     {[]string{`Basic realm="r"`}, http.StatusForbidden, nil},
		"an Authorization of the caller": {[]string{`Basic realm="r"`}, http.StatusUnauthorized, NewHeader("Authorization", "Bearer mine")},
	} {
		t.Run(name, func(t *testing.T) {
			server := newRecorder(t, "h2", func(w http.ResponseWriter, _ *http.Request) {
				for _, c := range tc.challenges {
					w.Header().Add("WWW-Authenticate", c)
				}
				w.WriteHeader(tc.status)
			})
			client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
			res, err := client.Do(&Request{URL: authURL("u:p", "x"), Header: tc.header})
			if err != nil || res.Status != tc.status {
				t.Fatalf("Do: %v, %+v", err, res)
			}
			// Sent once, and never with the URL's credentials.
			if got := authorizations(server.requests()); len(got) != 1 || strings.HasPrefix(got[0], "Basic") {
				t.Errorf("Authorization sent %q", got)
			}
		})
	}
}

func TestTheBodyIsSentAgainWithTheAnswer(t *testing.T) {
	server := newRecorder(t, "h1", answeringAsMeasured)
	var dials atomic.Int32
	client := newTestClient(t, WithProfile("chrome_155_macos"),
		WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, server.addr)
		})))
	res, err := client.Do(&Request{Method: http.MethodPost, URL: authURL("u:p", "post"), Body: []byte("a=1")})
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("Do: %v, %+v", err, res)
	}
	got := server.requests()
	if len(got) != 2 || got[0].body != "a=1" || got[1].body != "a=1" || got[1].method != http.MethodPost {
		t.Fatalf("sent %d requests: %+v", len(got), got)
	}
	// Over HTTP/1.1 Authorization follows Host and Connection; and the 401
	// was read to its end, so the answer went on its connection.
	if names := headerNames(got[1]); len(names) < 3 || names[0] != "Host" || names[1] != "Connection" || names[2] != "Authorization" {
		t.Errorf("headers %v", names)
	}
	if dials.Load() != 1 {
		t.Errorf("%d connections", dials.Load())
	}
}

// headerNames are the names of a request's headers, in order.
func headerNames(k *keptRequest) []string {
	var out []string
	for _, h := range k.headers {
		out = append(out, h[0])
	}
	return out
}

func TestARedirectsCredentialsAreItsLocationsOrThoseItIsRelativeTo(t *testing.T) {
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	get := func(url string, status int) {
		t.Helper()
		if res, err := client.Get(url); err != nil || res.Status != status || strings.Contains(res.URL, "@") {
			t.Fatalf("Get %s: %v, %+v", url, err, res)
		}
	}
	// A Location with credentials, and one relative to a URL with them.
	get("https://www.example.com/r/302/x?to="+url.QueryEscape(authURL("u:p", "one/a")), http.StatusOK)
	get(authURL("u:p", "two/a?to=/auth/two/b"), http.StatusOK)
	// An absolute Location without credentials gets none of the URL before.
	get(authURL("u:p", "three/a?to="+url.QueryEscape(authURL("", "elsewhere/b"))), http.StatusOK)
	// tls-forge's Authorization goes with no hop it was not given to: one
	// sent unasked to where it is kept, then a redirect out of it; and a
	// redirect into it is sent what is kept.
	get(authURL("", "one/b?to=/p/out"), http.StatusOK)
	get("https://www.example.com/r/302/y?to=/auth/one/c", http.StatusOK)
	want := []string{
		"", "", "Basic dTpw", // the redirect, the 401, the answer
		"", "Basic dTpw", "", "Basic dTpw", // the 401 and the answer, and again after the relative redirect
		"", "Basic dTpw", "", "Basic dTpw", // the same; the realm answers the absolute Location's 401
		"Basic dTpw", "", // unasked, and not on the way out
		"", "Basic dTpw", // nothing to the redirect, unasked into the directory
	}
	got := server.requests()
	if strings.Join(authorizations(got), ",") != strings.Join(want, ",") {
		t.Errorf("Authorization sent %q,\nwant %q", authorizations(got), want)
	}
	// The answer is the hop it answers, as the redirect left it, and not the
	// request the transport made it from.
	if hop, answer := headerNames(got[1]), headerNames(got[2]); fmt.Sprint(answer) !=
		fmt.Sprint(slices.Insert(slices.Clone(hop), 4, "authorization")) {
		t.Errorf("the answer's headers %v,\nthe hop's %v", answer, hop)
	}
}

func TestEachHopIsAnsweredWithTheCredentialsOfItsOwnURL(t *testing.T) {
	// /x asks for one realm and redirects, relatively, to /y, which asks for
	// another: each answered with the URL's credentials, those of /y being
	// the ones /x had, as resolving a relative Location keeps them.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		realm := map[string]string{"/x": "one", "/y": "two", "/x/again": "one", "/r": ""}[r.URL.Path]
		switch {
		case realm != "" && r.Header.Get("Authorization") != "Basic dTpw":
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/x" || r.URL.Path == "/r":
			w.Header().Set("Location", "/y")
			w.WriteHeader(http.StatusFound)
		}
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	for _, u := range []string{"https://u:p@www.example.com/x", "https://www.example.com/x/again"} {
		if res, err := client.Get(u); err != nil || res.Status != http.StatusOK {
			t.Fatalf("Get %s: %v, %+v", u, err, res)
		}
	}
	// A relative redirect of a URL with credentials, where nothing was asked
	// before it.
	other := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	if res, err := other.Get("https://u:p@www.example.com/r"); err != nil || res.Status != http.StatusOK {
		t.Fatalf("Get: %v, %+v", err, res)
	}
	want := []string{"", "Basic dTpw", "", "Basic dTpw", "Basic dTpw", "", "", "Basic dTpw"}
	if got := authorizations(server.requests()); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Authorization sent %q,\nwant %q", got, want)
	}
}

func TestARedirectIntoWhereCredentialsAreKeptCarriesThem(t *testing.T) {
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := contextClient(t, server)
	navigate := &BrowserContext{Kind: KindNavigation}
	for _, u := range []string{authURL("u:p", "d/a"), "https://www.example.com/r/302/x?to=/auth/d/b"} {
		if res, err := client.Do(&Request{URL: u, Browser: navigate}); err != nil || res.Status != http.StatusOK {
			t.Fatalf("Do %s: %v, %+v", u, err, res)
		}
	}
	got := server.requests()
	if fmt.Sprint(authorizations(got)) != fmt.Sprint([]string{"", "Basic dTpw", "", "Basic dTpw"}) {
		t.Fatalf("Authorization sent %q", authorizations(got))
	}
	// In the slot of a navigation after a redirect.
	if names := headerNames(got[3]); len(names) < 6 || names[4] != "authorization" || names[5] != "upgrade-insecure-requests" {
		t.Errorf("headers %v", names)
	}
}

func TestTheRedirectCountGoesOnAcrossAChallengeAnswered(t *testing.T) {
	// /c/10 asks for credentials; every other link redirects to the next.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/c/"))
		if n == 10 && r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="chain"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Location", "/c/"+strconv.Itoa(n+1))
		w.WriteHeader(http.StatusFound)
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	_, err := client.Get("https://u:p@www.example.com/c/0")
	if err == nil || !strings.Contains(err.Error(), "the 20th redirect was not followed") {
		t.Fatalf("Get: %v", err)
	}
	// Ten redirects, the 401 and its answer, then nine more: the twentieth is
	// not followed, as for a chain with no challenge in it.
	if got := len(server.requests()); got != 21 {
		t.Errorf("%d requests, want 21", got)
	}
}

func TestAChallengeAnsweredIsLoggedWithoutItsCredentials(t *testing.T) {
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != (credentials{"u", "secret5"}).basic() {
			w.Header().Set("WWW-Authenticate", `Basic realm="bench"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithProfile("chrome_155_macos"), WithLogger(log), server.dialing())
	for _, u := range []string{authURL("u:secret5", "d/a"), authURL("", "d/b"), authURL("", "e/a")} {
		if res, err := client.Get(u); err != nil || res.Status != http.StatusOK {
			t.Fatalf("Get %s: %v, %+v", u, err, res)
		}
	}
	answered := book.with(t, "challenge answered")
	if len(answered) != 2 || answered[0].get("credentials") != "url" || answered[1].get("credentials") != "realm" ||
		answered[0].get("realm") != "bench" || answered[0].get("url") != authURL("", "d/a") {
		t.Errorf("answered %v", answered)
	}
	if sent := book.one(t, "authorization sent"); sent.get("url") != authURL("", "d/b") || sent.get("realm") != "bench" {
		t.Errorf("sent %v", sent)
	}
	// Each answer's headers are written down: the 401's, then the 200's.
	if got := len(book.with(t, "response headers")); got != 5 {
		t.Errorf("%d answers written down, want 5", got)
	}
	if text := book.text(); strings.Contains(text, "secret5") || strings.Contains(text, "dTpzZWNyZXQ1") {
		t.Errorf("the credentials were logged: %s", text)
	}
}

func TestAScriptsRequestIsAuthenticatedOnlyWithCredentialsOfItsOwnOrigin(t *testing.T) {
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := contextClient(t, server)
	page := "https://www.example.com/run/x"
	// Kept for /auth/d/ by a navigation.
	if _, err := client.Do(&Request{URL: authURL("u:p", "d/a"), Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	for _, tc := range []struct {
		name string
		req  *Request
	}{
		{"fetch() that omits credentials", &Request{URL: authURL("", "d/b"),
			Browser: &BrowserContext{Kind: KindFetch, Initiator: page, Credentials: "omit"}}},
		{"fetch() with an Authorization of its own", &Request{URL: authURL("", "d/c"), Header: NewHeader("Authorization", "Bearer x"),
			Browser: &BrowserContext{Kind: KindFetch, Initiator: page}}},
		{"an XHR to another site", &Request{URL: "https://u:p@www.example.net/auth/d/d",
			Browser: &BrowserContext{Kind: KindXHR, Initiator: page}}},
		{"an XHR to another site with credentials", &Request{URL: "https://u:p@www.example.net/auth/d/e",
			Browser: &BrowserContext{Kind: KindXHR, Initiator: page, Credentials: "include"}}},
	} {
		res, err := client.Do(tc.req)
		if err == nil && res.Status != http.StatusUnauthorized {
			t.Errorf("%s: %+v", tc.name, res)
		}
	}
	// None of them touched what the session keeps.
	if res, err := client.Do(&Request{URL: authURL("", "d/z"), Browser: &BrowserContext{Kind: KindNavigation}}); err != nil ||
		res.Status != http.StatusOK {
		t.Fatalf("Do: %v, %+v", err, res)
	}
	want := []string{"", "Basic dTpw", "", "Bearer x", "", "", "Basic dTpw"}
	if got := authorizations(server.requests()); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Authorization sent %q,\nwant %q", got, want)
	}
}

func TestAURLsCredentialsLeaveHTTP1ItsLayout(t *testing.T) {
	// The transport added Basic to a URL's credentials on a copy of the
	// headers it took, and an HTTP/1.1 connection went out in the HTTP/2
	// layout, an empty User-Agent and all for a profile with none.
	for name, opts := range map[string][]Option{
		"measured":  {WithProfileValue(profileWithMeasuredHTTP1(t))},
		"catalogue": {WithProfile("firefox_148")},
	} {
		t.Run(name, func(t *testing.T) {
			url, recorded := recordingHTTP1Server(t)
			client := newTestClient(t, opts...)
			if _, err := client.Get(strings.Replace(url, "https://", "https://u:p@", 1)); err != nil {
				t.Fatalf("Get: %v", err)
			}
			for _, line := range <-recorded {
				if strings.HasPrefix(line, "Authorization") || line == "User-Agent: " || strings.HasPrefix(line, "Priority") {
					t.Errorf("sent %q", line)
				}
			}
		})
	}
}
