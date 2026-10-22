package tlsforge

import (
	"context"
	"fmt"
	"io"
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

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"

	"github.com/Sec-CH-Lemon/tls-forge/v5/profile"
)

func TestAChallengeIsReadAsChromiumReadsIt(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		windows     bool
		scheme      string
		realm       string
		ok          bool
	}{
		{"a realm", `Basic realm="bench"`, false, "basic", "bench", true},
		{"a scheme in any case, a token for a value", `bASIC realm=bench`, false, "basic", "bench", true},
		{"no parameters", `Basic`, false, "basic", "", true},
		{"a tab after the scheme, spaces before it", "  Basic\trealm=\"x\"", false, "basic", "x", true},
		{"a tab before it", "\t Basic realm=x", false, "basic", "x", true},
		{"escapes, and a parameter of no matter", `Basic realm="a\"b\\", charset="UTF-8"`, false, "basic", `a"b\`, true},
		{"the last realm", `Basic realm="x", REALM="y"`, false, "basic", "y", true},
		{"a comma in quotes, and empty parts", `Basic realm="a,b",, ,`, false, "basic", "a,b", true},
		{"Latin-1", "Basic realm=\"\xe9t\xe9\"", false, "basic", "été", true},
		{"a quote that does not end, read without it", `Basic realm="x`, false, "basic", "x", true},
		{"an escape at the end, dropped", `Basic realm="x\"`, false, "basic", "x", true},
		{"more after the quote, read as it is", `Basic realm="x"y`, false, "basic", `x"y`, true},
		{"a quote alone", `Basic realm="`, false, "basic", "", true},
		{"a parameter with no value", `Basic realm`, false, "basic", "", false},
		{"a parameter with nothing after its =", `Basic realm=`, false, "basic", "", false},
		{"no name", `Basic ="x"`, false, "basic", "", false},
		{"a quote in a name", `Basic "realm"=x`, false, "basic", "", false},
		{"Digest", `Digest realm="r", nonce="n"`, false, "digest", "r", true},
		{"Digest it cannot read", `Digest realm="r"`, false, "digest", "r", false},
		{"NTLM, a first challenge", `NTLM`, false, "ntlm", "", true},
		{"NTLM with a token, which no first challenge has", `NTLM TlRMTVNTUAACAAAA`, false, "ntlm", "", false},
		{"NTLM with padding alone", `ntlm ===`, false, "ntlm", "", true},
		{"NTLM with spaces and tabs after it", "NTLM \t ", false, "ntlm", "", true},
		{"NTLM with padding that is a token", `NTLM ====`, false, "ntlm", "", false},
		{"Negotiate on Windows", `Negotiate`, true, "negotiate", "", true},
		{"Negotiate with a token", `Negotiate YIIG`, true, "negotiate", "", false},
		{"Negotiate elsewhere", `Negotiate`, false, "negotiate", "", false},
		{"a scheme Chrome does not answer", `Bearer realm="api"`, true, "bearer", "", false},
		{"nothing", ` `, true, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := readChallenge(tc.field, tc.windows)
			if c.scheme != tc.scheme || ok != tc.ok || ok && (c.realm != tc.realm || c.field != tc.field) {
				t.Errorf("readChallenge(%q) = %+v, %v", tc.field, c, ok)
			}
		})
	}
}

func TestAChallengesParametersAreReadAsChromiumReadsThem(t *testing.T) {
	for _, tc := range []struct {
		text     string
		want     []authParam
		readable bool
	}{
		{"", nil, true},
		{` a = 1 ,	b="x,y" `, []authParam{{"a", "1"}, {"b", "x,y"}}, true},
		{`a="1",, ,b=2`, []authParam{{"a", "1"}, {"b", "2"}}, true},
		{`a b=1=2, c=d e`, []authParam{{"a b", "1=2"}, {"c", "d e"}}, true},
		{`A=""`, []authParam{{"A", ""}}, true},
		{`a="a\\b\"c"`, []authParam{{"a", `a\b"c`}}, true},
		{`a="x\"`, []authParam{{"a", "x"}}, true},
		{`a="x`, []authParam{{"a", "x"}}, true},
		{`a="x"y`, []authParam{{"a", `x"y`}}, true},
		{`a="x\", b=1`, []authParam{{"a", `x\", b=1`}}, true},
		{`a="`, []authParam{{"a", ""}}, true},
		{`a=1, b, c=2`, []authParam{{"a", "1"}}, false},
		{`a=1, b=`, []authParam{{"a", "1"}}, false},
		{`=1`, nil, false},
		{`"a"=1`, nil, false},
	} {
		got, readable := authParams(tc.text)
		if !slices.Equal(got, tc.want) || readable != tc.readable {
			t.Errorf("authParams(%q) = %q, %v; want %q, %v", tc.text, got, readable, tc.want, tc.readable)
		}
	}
}

func TestTheBestChallengeIsTheOneChromePrefers(t *testing.T) {
	mac := newTestClient(t, WithProfile("chrome_155_macos"))
	windows := newTestClient(t, WithProfile("chrome_155_windows"))
	digest := `Digest realm="r", nonce="n"`
	for _, tc := range []struct {
		name    string
		fields  []string
		mac     string
		windows string
	}{
		{"Digest before Basic, wherever it is", []string{`Basic realm="r"`, digest}, digest, digest},
		{"the first of equals", []string{digest + `, algorithm=MD5`, digest + `, algorithm=SHA-256`},
			digest + `, algorithm=MD5`, digest + `, algorithm=MD5`},
		{"Basic when Digest cannot be read", []string{`Digest realm="r"`, `Basic realm="r"`}, `Basic realm="r"`, `Basic realm="r"`},
		{"NTLM before Digest", []string{digest, `NTLM`, `Basic realm="r"`}, `NTLM`, `NTLM`},
		{"Negotiate before NTLM on Windows alone", []string{`NTLM`, `Negotiate`, digest}, `NTLM`, `Negotiate`},
		{"Negotiate passed over elsewhere", []string{`Negotiate`, digest}, digest, `Negotiate`},
		{"none Chrome answers", []string{`Bearer`, `Basic realm`}, "", ""},
		{"no challenge", nil, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for client, want := range map[*Client]string{mac: tc.mac, windows: tc.windows} {
				if best, ok := client.bestChallenge(tc.fields); ok != (want != "") || best.field != want {
					t.Errorf("%s: %+v, %v; want %q", client.profile.Name, best, ok, want)
				}
			}
		})
	}
}

func TestWhatA401SaysOfAnAnswerIsReadAsChromiumReadsIt(t *testing.T) {
	basic := keptBasic("r")
	digest, _ := readChallenge(`Digest realm="r", nonce="1"`, false)
	latin, _ := readChallenge("Digest realm=\"\xe9\", nonce=\"1\"", false)
	for _, tc := range []struct {
		name   string
		sent   challenge
		fields []string
		said   verdict
		field  string
	}{
		{"Basic again", basic, []string{`Basic realm="r"`}, turnedDown, `Basic realm="r"`},
		{"Basic of another realm", basic, []string{`Basic realm="s"`}, otherRealm, `Basic realm="s"`},
		{"the first Basic it can read", basic, []string{`Basic realm`, `Basic realm="s"`, `Basic realm="r"`}, otherRealm, `Basic realm="s"`},
		{"no Basic it can read", basic, []string{`Basic realm`}, turnedDown, ""},
		{"no challenge of the scheme", basic, []string{`Digest realm="r", nonce="2", stale=true`}, turnedDown, ""},
		{"no challenge", digest, nil, turnedDown, ""},
		{"Digest again", digest, []string{`Digest realm="r", nonce="2"`}, turnedDown, `Digest realm="r", nonce="2"`},
		{"a nonce out of date", digest, []string{`Basic realm="r"`, `Digest realm="r", nonce="2", stale=true`}, outOfDate,
			`Digest realm="r", nonce="2", stale=true`},
		{"in any case, before the realm is looked at", digest, []string{`Digest stale=TRUE, realm="s"`}, outOfDate, `Digest stale=TRUE, realm="s"`},
		{"not out of date", digest, []string{`Digest realm="r", stale=false`}, turnedDown, `Digest realm="r", stale=false`},
		{"another realm", digest, []string{`Digest realm="s", nonce="2"`}, otherRealm, `Digest realm="s", nonce="2"`},
		{"no realm", digest, []string{`Digest nonce="2"`}, otherRealm, `Digest nonce="2"`},
		{"read up to what it cannot read", digest, []string{`Digest realm="r", x, stale=true`}, turnedDown, `Digest realm="r", x, stale=true`},
		{"a realm in Latin-1", latin, []string{"Digest realm=\"\xe9\""}, turnedDown, "Digest realm=\"\xe9\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if said, field := tc.sent.respond(tc.fields); said != tc.said || field != tc.field {
				t.Errorf("respond(%q) = %s, %q; want %s, %q", tc.fields, says[said], field, says[tc.said], tc.field)
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

func TestALocationIsRelativeWhenItNamesNoAuthority(t *testing.T) {
	// As Chrome reads one after an https URL: no scheme, or https, and no two
	// slashes, either way round, after it.
	for location, want := range map[string]bool{"/a": true, "a": true, "?q": true, "": true, "%zz": true,
		`\a`: true, "  /a": true, "https:/a": true, "HTTPS:a": true, "https:": true,
		"//h/a": false, `\\h\a`: false, `/\h`: false, `\/h`: false, "https://h/a": false, `https:\\h`: false,
		"http:/a": false, "http://h/a": false, "mailto:x": false, " //h": false} {
		if got := relativeLocation(location, "https"); got != want {
			t.Errorf("relativeLocation(%q, https) = %v", location, got)
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

// keptBasic is a Basic challenge of realm, as the cache keeps one.
func keptBasic(realm string) challenge {
	return challenge{scheme: "basic", field: `Basic realm="` + realm + `"`, realm: realm}
}

func TestTheCacheKeepsWhatChromiumKeeps(t *testing.T) {
	a := origin{"https", "a.test", "443"}
	b := origin{"https", "b.test", "443"}
	right, wrong := credentials{"u", "p"}, credentials{"u", "x"}
	var c authCache
	if _, ok := c.forPath(a, "/x"); ok {
		t.Fatal("an empty cache sends something")
	}
	c.keep(a, keptBasic("r"), right, "/d/e/page")
	for path, ok := range map[string]bool{"/d/e/other": true, "/d/e/f/g": true, "/d/e": false, "/d/x": false} {
		if k, got := c.forPath(a, path); got != ok || got && (k.field != `Basic realm="r"` || k.credentials != right) {
			t.Errorf("forPath(%s) = %+v, %v", path, k, got)
		}
	}
	if _, ok := c.forPath(b, "/d/e/x"); ok {
		t.Error("sent to another origin")
	}
	// A directory above the one kept takes its place; one under it is in it
	// already.
	c.keep(a, keptBasic("r"), right, "/d/page")
	c.keep(a, keptBasic("r"), right, "/d/e/f/page")
	if paths := c.entries[0].paths; len(paths) != 1 || paths[0] != "/d/" {
		t.Errorf("paths %v", paths)
	}
	// The closest directory above a path decides, and keeping replaces the
	// credentials.
	c.keep(a, keptBasic("inner"), wrong, "/d/e/page")
	if k, _ := c.forPath(a, "/d/e/x"); k.field != `Basic realm="inner"` || k.credentials != wrong {
		t.Errorf("the closest is %+v", k)
	}
	c.keep(a, keptBasic("inner"), right, "/d/e/page")
	if cred, ok := c.forRealm(a, "inner", "basic"); !ok || cred != right {
		t.Errorf("forRealm = %v, %v", cred, ok)
	}
	for _, realm := range [][2]string{{"none", "basic"}, {"inner", "digest"}} {
		if _, ok := c.forRealm(a, realm[0], realm[1]); ok {
			t.Errorf("%s in %s, never answered", realm[0], realm[1])
		}
	}
	// Only the credentials turned down are forgotten, of their scheme.
	c.drop(a, "inner", "basic", wrong)
	c.drop(a, "nowhere", "basic", right)
	c.drop(a, "inner", "digest", right)
	if _, ok := c.forRealm(a, "inner", "basic"); !ok {
		t.Error("newer credentials were forgotten")
	}
	c.drop(a, "inner", "basic", right)
	if _, ok := c.forRealm(a, "inner", "basic"); ok {
		t.Error("credentials turned down are kept")
	}
}

func TestTheCacheCountsTheAnswersToAChallenge(t *testing.T) {
	at := origin{"https", "a.test", "443"}
	cred := credentials{"u", "p"}
	first := challenge{scheme: "digest", field: `Digest realm="r", nonce="1"`, realm: "r"}
	var c authCache
	c.keep(at, first, cred, "/d/a")
	// Each answer sent unasked counts on from the one a 401 was answered
	// with, from wherever in the realm it is sent.
	for want, path := range []string{"/d/b", "/d/c", "/d/e/f"} {
		if k, ok := c.forPath(at, path); !ok || k.count != want+2 || k.field != first.field {
			t.Errorf("forPath(%s) = %+v, %v", path, k, ok)
		}
	}
	// A challenge answered again begins it again, kept in place of the one
	// before, for each directory.
	again := challenge{scheme: "digest", field: `Digest realm="r", nonce="2"`, realm: "r"}
	c.keep(at, again, cred, "/e/a")
	if k, _ := c.forPath(at, "/d/x"); k.count != 2 || k.field != again.field {
		t.Errorf("after another answer %+v", k)
	}
	// A challenge that says the nonce is out of date takes its place, its
	// count begun again too; and a realm or scheme with nothing kept takes
	// nothing.
	if !c.renew(at, "r", "digest", `Digest realm="r", nonce="3", stale=true`) {
		t.Fatal("nothing kept to renew")
	}
	if k, _ := c.forPath(at, "/e/x"); k.count != 2 || k.field != `Digest realm="r", nonce="3", stale=true` {
		t.Errorf("after a nonce out of date %+v", k)
	}
	if c.renew(at, "r", "basic", "Basic") || c.renew(at, "other", "digest", "Digest") ||
		c.renew(origin{"https", "b.test", "443"}, "r", "digest", "Digest") {
		t.Error("renewed what is not kept")
	}
	// A realm of another scheme is another entry.
	c.keep(at, keptBasic("r"), cred, "/f/a")
	if len(c.entries) != 2 {
		t.Errorf("%d entries", len(c.entries))
	}
}

func TestTheCacheForgetsWhatChromiumForgets(t *testing.T) {
	at := origin{"https", "a.test", "443"}
	cred := credentials{"u", "p"}
	var c authCache
	for i := range maxAuthPaths + 1 {
		c.keep(at, keptBasic("r"), cred, "/"+strconv.Itoa(i)+"/page")
	}
	if paths := c.entries[0].paths; len(paths) != maxAuthPaths || paths[0] != "/10/" || paths[len(paths)-1] != "/1/" {
		t.Errorf("paths %v", paths)
	}
	// The least recently used realm goes: asking for one uses it, and so
	// does renewing one.
	c = authCache{}
	for i := range maxAuthEntries {
		c.keep(at, keptBasic(strconv.Itoa(i)), cred, "/"+strconv.Itoa(i)+"/page")
	}
	c.forRealm(at, "0", "basic")
	c.forPath(at, "/1/x")
	c.renew(at, "2", "basic", `Basic realm="2"`)
	c.keep(at, keptBasic("new"), cred, "/new/page")
	if len(c.entries) != maxAuthEntries {
		t.Fatalf("%d entries", len(c.entries))
	}
	for realm, kept := range map[string]bool{"0": true, "1": true, "2": true, "3": false, "new": true} {
		if _, ok := c.forRealm(at, realm, "basic"); ok != kept {
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
				c.keep(at, keptBasic(realm), credentials{"u", realm}, "/"+realm+"/page")
				c.forPath(at, "/"+realm+"/x")
				c.forRealm(at, realm, "basic")
				c.renew(at, realm, "basic", `Basic realm="`+realm+`"`)
				c.drop(at, realm, "basic", credentials{"u", "?"})
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
	onEveryPlatform(t, func(t *testing.T, p *profile.Profile) {
		for proto, want := range map[string][]chromeRequest{"h2": measured.H2[:2], "h1": measured.H1[:2]} {
			t.Run(proto, func(t *testing.T) {
				server := newRecorder(t, proto, answeringAsMeasured)
				client := newTestClient(t, WithProfileValue(p), server.dialing())
				res, err := client.Get(authURL("u:p", "auth-nav-typed/a?next=/auth/auth-nav-typed/b%3Fnext%3D/p/auth-nav-typed-end"))
				if err != nil || res.Status != http.StatusOK || strings.Contains(res.URL, "u:p") {
					t.Fatalf("Get: %v, %+v", err, res)
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
	})
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

func TestA401ChromeWouldAnswerInAnotherSchemeIsLeftAsItIs(t *testing.T) {
	for name, tc := range map[string]struct {
		challenges []string
		status     int
		header     Header
		profile    string
	}{
		"NTLM offered too":                  {[]string{`NTLM`, `Digest realm="r", nonce="n"`, `Basic realm="r"`}, http.StatusUnauthorized, nil, "chrome_155_macos"},
		"Negotiate offered too, on Windows": {[]string{`Negotiate`, `Basic realm="r"`}, http.StatusUnauthorized, nil, "chrome_155_windows"},
		"a scheme Chrome does not know":     {[]string{`Bearer realm="r"`}, http.StatusUnauthorized, nil, "chrome_155_macos"},
		"no challenge":                      {nil, http.StatusUnauthorized, nil, "chrome_155_macos"},
		"a challenge that is no 401":        {[]string{`Basic realm="r"`}, http.StatusForbidden, nil, "chrome_155_macos"},
		"an Authorization of the caller":    {[]string{`Basic realm="r"`}, http.StatusUnauthorized, NewHeader("Authorization", "Bearer mine"), "chrome_155_macos"},
	} {
		t.Run(name, func(t *testing.T) {
			server := newRecorder(t, "h2", func(w http.ResponseWriter, _ *http.Request) {
				for _, c := range tc.challenges {
					w.Header().Add("WWW-Authenticate", c)
				}
				w.WriteHeader(tc.status)
			})
			client := newTestClient(t, WithProfile(tc.profile), server.dialing())
			res, err := client.Do(&Request{URL: authURL("u:p", "x"), Header: tc.header})
			if err != nil || res.Status != tc.status {
				t.Fatalf("Do: %v, %+v", err, res)
			}
			// Sent once, and never with the URL's credentials.
			if got := authorizations(server.requests()); len(got) != 1 || strings.HasPrefix(got[0], "Basic") ||
				strings.HasPrefix(got[0], "Digest") {
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

func TestAnAnswerSentUnaskedForAnotherRealmIsNoReasonToForgetItsOwn(t *testing.T) {
	// /d/ and /e/ ask for the realm "one" but for /d/b and /e/a answered,
	// which ask for "two", which nothing answers.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		realm := "one"
		if r.URL.Path == "/d/b" || r.URL.Path == "/e/a" && r.Header.Get("Authorization") != "" {
			realm = "two"
		}
		if r.Header.Get("Authorization") != "Basic dTpw" || realm == "two" {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	for _, u := range []string{"https://u:p@www.example.com/d/a", "https://www.example.com/d/b", "https://www.example.com/d/c",
		"https://u:p@www.example.com/e/a", "https://www.example.com/e/b"} {
		if _, err := client.Get(u); err != nil {
			t.Fatalf("Get %s: %v", u, err)
		}
	}
	// What was kept for /d/ was sent unasked to /d/b, which asked for another
	// realm, and is still sent to /d/c; what /e/a answered with, from its URL,
	// was turned down for another realm, and nothing is kept for /e/.
	want := []string{"", "Basic dTpw", "Basic dTpw", "Basic dTpw", "", "Basic dTpw", ""}
	if got := authorizations(server.requests()); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Authorization sent %q,\nwant %q", got, want)
	}
}

func TestAChallengeKeptThatCannotBeReadIsSentNothingUnasked(t *testing.T) {
	// /d/a says the nonce of an answer is out of date with a challenge that
	// has no nonce, which is kept for the realm and cannot be answered.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/d/a" {
			return
		}
		challenge := `Digest realm="r", nonce="1", qop="auth"`
		if r.Header.Get("Authorization") != "" {
			challenge = `Digest realm="r", stale=true`
		}
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	for _, u := range []string{"https://u:p@www.example.com/d/a", "https://www.example.com/d/b"} {
		if _, err := client.Get(u); err != nil {
			t.Fatalf("Get %s: %v", u, err)
		}
	}
	got := authorizations(server.requests())
	if len(got) != 3 || !strings.HasPrefix(got[1], "Digest ") || got[0] != "" || got[2] != "" {
		t.Errorf("Authorization sent %q", got)
	}
}

func TestANonceOutOfDateIsAnsweredAgainOnlyWithWhatIsKept(t *testing.T) {
	client := newTestClient(t, WithProfile("chrome_155_macos"))
	u, _ := url.Parse("https://www.example.com/d/a")
	at := originOf(u)
	answered, _ := readChallenge(`Digest realm="r", nonce="1", qop="auth"`, false)
	stale := &fhttp.Response{StatusCode: http.StatusUnauthorized, Request: &fhttp.Request{Method: http.MethodGet, URL: u},
		Header: fhttp.Header{"Www-Authenticate": {`Digest realm="r", nonce="2", qop="auth", stale=true`}}}
	client.session.auth.draw = func() string { return "0123456789abcdef" }
	for _, kept := range []bool{false, true} {
		if kept {
			client.session.auth.keep(at, answered, credentials{"u", "p"}, "/d/a")
		}
		// The URL's credentials answered the hop: with nothing kept for the
		// realm, as Chromium has it, they do not answer it again.
		ch := &chain{client: client, credentials: url.UserPassword("u", "p"), embedded: true,
			sent: &sentAuth{challenge: answered, credentials: credentials{"u", "p"}, from: "url"}}
		value, again, err := ch.challenged(stale)
		if err != nil || again != kept || kept && !strings.Contains(value, `nonce="2"`) {
			t.Errorf("kept %v: %q, %v, %v", kept, value, again, err)
		}
	}
}

func TestEachHopIsAnsweredAsOftenAsChromeAnswersOne(t *testing.T) {
	// /a says 30 answers are out of date and takes the 31st, which is as
	// many as Chrome sends one hop, then redirects to /b, which takes its
	// first: the count begins again on each hop.
	var mu sync.Mutex
	answers := map[string]int{}
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="0", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		answers[r.URL.Path]++
		switch {
		case r.URL.Path == "/a" && answers["/a"] <= 30:
			w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="`+strconv.Itoa(answers["/a"])+`", qop="auth", stale=true`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/a":
			w.Header().Set("Location", "/x/b")
			w.WriteHeader(http.StatusFound)
		}
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	if res, err := client.Get("https://u:p@www.example.com/a"); err != nil || res.Status != http.StatusOK {
		t.Fatalf("Get: %v, %+v", err, res)
	}
	if got := len(server.requests()); got != 34 {
		t.Errorf("%d requests, want 34", got)
	}
}

func TestADigestAnswerIsLoggedWithoutItsCredentials(t *testing.T) {
	// The first nonce is out of date when answered, the second taken.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		switch said := r.Header.Get("Authorization"); {
		case said == "":
			w.Header().Set("WWW-Authenticate", `Digest realm="bench", nonce="1", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
		case strings.Contains(said, `nonce="1"`):
			w.Header().Set("WWW-Authenticate", `Digest realm="bench", nonce="2", qop="auth", stale=true`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithProfile("chrome_155_macos"), WithLogger(log), server.dialing())
	for _, u := range []string{"https://u:secret5@www.example.com/x/a", "https://www.example.com/x/b"} {
		if res, err := client.Get(u); err != nil || res.Status != http.StatusOK {
			t.Fatalf("Get %s: %v, %+v", u, err, res)
		}
	}
	// The first nonce out of date, both answered with the URL's credentials;
	// then the second sent unasked, its second answer.
	answered := book.with(t, "challenge answered")
	if len(answered) != 2 || answered[0].get("scheme") != "digest" || answered[1].get("credentials") != "url" {
		t.Errorf("answered %v", answered)
	}
	if refused := book.one(t, "answer refused"); refused.get("said") != "out of date" || refused.get("scheme") != "digest" ||
		refused.get("realm") != "bench" {
		t.Errorf("refused %v", refused)
	}
	if sent := book.one(t, "authorization sent"); sent.get("scheme") != "digest" || sent.get("nonce_count") != "2" {
		t.Errorf("sent %v", sent)
	}
	if text := book.text(); strings.Contains(text, "secret5") || strings.Contains(text, "response=") {
		t.Errorf("the credentials were logged: %s", text)
	}
}

func TestAnAnswerSentUnaskedIsWorkedOutForItsOwnRequest(t *testing.T) {
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	client.session.auth.draw = func() string { return "c" }
	if _, err := client.Get("https://u:p@www.example.com/d/a"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := client.Do(&Request{Method: http.MethodPost, URL: "https://www.example.com/d/b?x=1", Body: []byte("a")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	// Its method, its path and query, its count: the second answer.
	h := md5Hash
	response := hexDigest(h, hexDigest(h, "u:r:p")+":n:00000002:c:auth:"+hexDigest(h, "POST:/d/b?x=1"))
	got := authorizations(server.requests())
	if want := `Digest username="u", realm="r", nonce="n", uri="/d/b?x=1", response="` + response +
		`", qop=auth, nc=00000002, cnonce="c"`; len(got) != 3 || got[2] != want {
		t.Errorf("Authorization sent %q,\nwant the last %q", got, want)
	}
}

func TestAHopAnsweredAsOftenAsChromeAnswersOneFailsAndLeavesItsConnection(t *testing.T) {
	server := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forever" {
			w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n", qop="auth", stale=true`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "<p>401</p>")
		}
	})
	var dials atomic.Int32
	client := newTestClient(t, WithProfile("chrome_155_macos"),
		WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, server.addr)
		})))
	_, err := client.Get("https://u:p@www.example.com/forever")
	if err == nil || err.Error() != "tlsforge: GET https://www.example.com/forever asked for authentication again after 31 answers, "+
		"and Chrome answers it no more" {
		t.Fatalf("Get: %v", err)
	}
	if res, err := client.Get("https://www.example.com/after"); err != nil || res.Status != http.StatusOK {
		t.Fatalf("Get: %v, %+v", err, res)
	}
	// The last 401 was read to its end, so what came after went on its
	// connection.
	if got := len(server.requests()); got != 33 || dials.Load() != 1 {
		t.Errorf("%d requests over %d connections", got, dials.Load())
	}
}

func TestTheRealmsCredentialsAnswerTheNonceTheyMadeOutOfDate(t *testing.T) {
	// /k/a asks for the realm "s" and takes u:p. /d/a asks for "r", and for
	// "s" once it is answered; then says the answer of u:p of the nonce 1 is
	// out of date, and takes u:p with the nonce 2.
	answer := func(r *http.Request, realm, nonce, password string) string {
		d := digest{realm: realm, nonce: nonce, qop: true}
		return d.answer(credentials{"u", password}, realm, r.Method, r.URL.RequestURI(), 1, func() string { return "c" })
	}
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		said := r.Header.Get("Authorization")
		challenge := `Digest realm="s", nonce="1", qop="auth"`
		switch {
		case r.URL.Path == "/k/a" && said == answer(r, "s", "1", "p"), r.URL.Path == "/d/a" && said == answer(r, "s", "2", "p"):
			return
		case r.URL.Path == "/d/a" && said == "":
			challenge = `Digest realm="r", nonce="1", qop="auth"`
		case r.URL.Path == "/d/a" && said == answer(r, "s", "1", "p"):
			challenge = `Digest realm="s", nonce="2", qop="auth", stale=true`
		}
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	client.session.auth.draw = func() string { return "c" }
	if res, err := client.Get("https://u:p@www.example.com/k/a"); err != nil || res.Status != http.StatusOK {
		t.Fatalf("Get: %v, %+v", err, res)
	}
	// The URL's credentials answer "r", which is answered with "s": what is
	// kept for "s" answers, and answers the nonce it made out of date again,
	// and not the URL's.
	if res, err := client.Get("https://u:x@www.example.com/d/a"); err != nil || res.Status != http.StatusOK {
		t.Fatalf("Get: %v, %+v", err, res)
	}
	if got := len(server.requests()); got != 6 {
		t.Errorf("%d requests, want 6", got)
	}
}

func TestARedirectedHopIsSentUnaskedAnAnswerOfItsOwnMethod(t *testing.T) {
	for name, browser := range map[string]*BrowserContext{"without a context": nil, "a form": {Kind: KindForm,
		Initiator: "https://www.example.com/run/x"}} {
		t.Run(name, func(t *testing.T) {
			server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/r":
					w.Header().Set("Location", "/d/b")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case r.Header.Get("Authorization") == "":
					w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n", qop="auth"`)
					w.WriteHeader(http.StatusUnauthorized)
				}
			})
			client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
			client.session.auth.draw = func() string { return "c" }
			if _, err := client.Get("https://u:p@www.example.com/d/a"); err != nil {
				t.Fatalf("Get: %v", err)
			}
			req := &Request{Method: http.MethodPost, URL: "https://www.example.com/r", Body: []byte("a"), Browser: browser,
				Header: NewHeader("Content-Type", "application/x-www-form-urlencoded")}
			if _, err := client.Do(req); err != nil {
				t.Fatalf("Do: %v", err)
			}
			// The first hop of a POST is sent unasked an answer for it too.
			req.URL = "https://www.example.com/d/c"
			if _, err := client.Do(req); err != nil {
				t.Fatalf("Do: %v", err)
			}
			// A 307 keeps the POST, which the answer of the hop is worked out
			// for.
			got := authorizations(server.requests())
			h := md5Hash
			hop := hexDigest(h, hexDigest(h, "u:r:p")+":n:00000002:c:auth:"+hexDigest(h, "POST:/d/b"))
			first := hexDigest(h, hexDigest(h, "u:r:p")+":n:00000003:c:auth:"+hexDigest(h, "POST:/d/c"))
			if len(got) != 5 || !strings.Contains(got[3], `response="`+hop+`"`) || !strings.Contains(got[4], `response="`+first+`"`) {
				t.Errorf("Authorization sent %q, want the last two for POST", got)
			}
		})
	}
}

func TestEachDigestAnswerDrawsAClientNonceOfItsOwn(t *testing.T) {
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	client := newTestClient(t, WithProfile("chrome_155_macos"), server.dialing())
	for _, u := range []string{"https://u:p@www.example.com/d/a", "https://www.example.com/d/b"} {
		if _, err := client.Get(u); err != nil {
			t.Fatalf("Get %s: %v", u, err)
		}
	}
	var drawn []string
	for _, a := range authorizations(server.requests()) {
		if found := chromeCnonce.FindStringSubmatch(a); found != nil {
			drawn = append(drawn, found[1])
		}
	}
	if len(drawn) != 2 || drawn[0] == drawn[1] {
		t.Errorf("client nonces %q", drawn)
	}
}
