package tlsforge

import (
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", raw, err)
	}
	return u
}

// newTestJar wraps the jar a client gets by default: the transport's RFC 6265
// one, with the public suffix list.
func newTestJar() *keptJar {
	inner, err := newDefaultCookieJar()
	if err != nil {
		panic(err)
	}
	return newKeptJar(inner)
}

// held is the one cookie of a name the jar lists, failing the test when there
// is not exactly one.
func held(t *testing.T, cookies []Cookie, name string) Cookie {
	t.Helper()
	var found []Cookie
	for _, c := range cookies {
		if c.Name == name {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d cookies named %s in %+v, want one", len(found), name, cookies)
	}
	return found[0]
}

func TestTheJarKeepsWhatItDoesNotSay(t *testing.T) {
	jar := newTestJar()
	sub := mustURL(t, "https://sub.example.test/a/b/page")
	in := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	jar.SetCookies(sub, []*fhttp.Cookie{
		{Name: "host", Value: "1"},
		{Name: "domain", Value: "2", Domain: "example.test", Path: "/"},
		{Name: "dotted", Value: "3", Domain: ".Example.Test", Path: "/"},
		{Name: "aged", Value: "4", MaxAge: 60, Path: "/"},
		{Name: "dated", Value: "5", Expires: in, Path: "/"},
		{Name: "strict", Value: "6", SameSite: fhttp.SameSiteStrictMode, Path: "/"},
		{Name: "lax", Value: "7", SameSite: fhttp.SameSiteLaxMode, Path: "/"},
		{Name: "none", Value: "8", SameSite: fhttp.SameSiteNoneMode, Secure: true, Path: "/"},
		{Name: "relative", Value: "9", Path: "not-absolute"},
		nil,
	})
	all := jar.all()

	host := held(t, all, "host")
	if !host.HostOnly || host.Domain != "sub.example.test" || host.Path != "/a/b" || !host.Expires.IsZero() {
		t.Errorf("a cookie set without a Domain: %+v; want sub.example.test's alone, at /a/b, for the session", host)
	}
	for _, name := range []string{"domain", "dotted"} {
		if c := held(t, all, name); c.HostOnly || c.Domain != "example.test" {
			t.Errorf("%s: %+v; want example.test's, for its subdomains too", name, c)
		}
	}
	if aged := held(t, all, "aged"); aged.Expires.IsZero() || time.Until(aged.Expires) > time.Minute {
		t.Errorf("a Max-Age cookie: expires %v, want about a minute from now", aged.Expires)
	}
	if dated := held(t, all, "dated"); !dated.Expires.Equal(in) {
		t.Errorf("an Expires cookie: expires %v, want %v", dated.Expires, in)
	}
	for name, want := range map[string]string{"strict": "strict", "lax": "lax", "none": "none", "host": ""} {
		if got := held(t, all, name).SameSite; got != want {
			t.Errorf("%s: SameSite %q, want %q", name, got, want)
		}
	}
	if relative := held(t, all, "relative"); relative.Path != "/a/b" {
		t.Errorf("a relative Path: %q, want the default /a/b", relative.Path)
	}

	// What goes to a URL says the same of each cookie.
	for _, c := range jar.forURL(mustURL(t, "https://sub.example.test/a/b/x")) {
		if c.Name == "host" && !c.HostOnly {
			t.Errorf("forURL lost the scope: %+v", c)
		}
	}
	if got := jar.forURL(mustURL(t, "https://other.example.test/")); len(got) == 0 {
		t.Error("a domain's cookies did not go to another of its subdomains")
	} else {
		for _, c := range got {
			if c.Name == "host" {
				t.Errorf("a host's cookie went to another host: %+v", c)
			}
		}
	}
}

func TestTheJarForgetsWhatIsTakenAway(t *testing.T) {
	jar := newTestJar()
	u := mustURL(t, "https://example.test/")
	jar.SetCookies(u, []*fhttp.Cookie{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}, {Name: "c", Value: "3"}})
	jar.SetCookies(u, []*fhttp.Cookie{
		{Name: "a", MaxAge: -1},
		{Name: "b", Expires: time.Now().Add(-time.Hour)},
	})
	all := jar.all()
	if len(all) != 1 || all[0].Name != "c" {
		t.Errorf("after a Max-Age of -1 and an Expires in the past: %+v, want c alone", all)
	}

	// Taken away behind the wrapper's back, through the jar it wraps: the jar's
	// answer wins, and the wrapper forgets.
	jar.inner.SetCookies(u, []*fhttp.Cookie{{Name: "c", MaxAge: -1}})
	if all := jar.all(); len(all) != 0 {
		t.Errorf("a cookie the jar no longer holds was listed: %+v", all)
	}
	if len(jar.kept) != 0 {
		t.Errorf("the wrapper still remembers %v", jar.kept)
	}
}

func TestTheJarRefusesWhatItsJarRefuses(t *testing.T) {
	// A cookie the jar will not file is not remembered either.
	jar := newTestJar()
	jar.SetCookies(mustURL(t, "https://www.example.test/"), []*fhttp.Cookie{
		{Name: "elsewhere", Value: "1", Domain: "other.test"},
		{Name: "dot", Value: "1", Domain: "."},
		{Name: "dots", Value: "1", Domain: "..example.test"},
		{Name: "trailing", Value: "1", Domain: "example.test."},
		{Name: "suffix", Value: "1", Domain: "test"},
	})
	jar.SetCookies(mustURL(t, "https://127.0.0.1:8443/"), []*fhttp.Cookie{
		{Name: "address", Value: "1", Domain: "127.0.0.1"},
	})
	if all := jar.all(); len(all) != 0 || len(jar.kept) != 0 {
		t.Errorf("refused cookies were kept: %+v, %v", all, jar.kept)
	}
}

func TestAPublicSuffixHostKeepsItsOwnCookies(t *testing.T) {
	// A Domain that is a public suffix makes a cookie its host's when the host
	// is that suffix, and is refused from anywhere under it.
	key, hostOnly, filed := jarKeyOf(mustURL(t, "https://github.io/"), &fhttp.Cookie{Name: "a", Domain: "github.io"})
	if !filed || !hostOnly || key.domain != "github.io" {
		t.Errorf("from the suffix itself: %+v, host only %v, filed %v", key, hostOnly, filed)
	}
	if _, _, filed := jarKeyOf(mustURL(t, "https://someone.github.io/"), &fhttp.Cookie{Name: "a", Domain: "github.io"}); filed {
		t.Error("a cookie for a public suffix was filed from under it")
	}
}

func TestTheJarCutsALifetimeToChromes(t *testing.T) {
	jar := newTestJar()
	u := mustURL(t, "https://example.test/")
	jar.SetCookies(u, []*fhttp.Cookie{
		{Name: "centuries", Value: "1", MaxAge: 1 << 40},
		{Name: "far", Value: "2", Expires: time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Name: "near", Value: "3", Expires: time.Now().Add(24 * time.Hour)},
	})
	limit := time.Now().Add(maxCookieLifetime)
	for _, c := range jar.all() {
		if c.Expires.After(limit.Add(time.Second)) || c.Expires.Before(time.Now()) {
			t.Errorf("%s expires %v, want no later than 400 days from now", c.Name, c.Expires)
		}
		if c.Name == "near" && c.Expires.After(time.Now().Add(25*time.Hour)) {
			t.Errorf("a lifetime within the limit was changed: %v", c.Expires)
		}
	}
	original := &fhttp.Cookie{Name: "x", MaxAge: 1 << 40}
	if capLifetime(original, time.Now()); original.MaxAge != 1<<40 {
		t.Error("capLifetime changed the cookie it was given rather than a copy")
	}
}

func TestACookieTheWrapperNeverSawIsTakenAtTheJarsWord(t *testing.T) {
	// Set through the jar it wraps, as a jar shared with another client is:
	// a domain's, as every cookie used to be, and a session's when its expiry
	// is the jar's own word for never.
	jar := newTestJar()
	u := mustURL(t, "https://example.test/")
	jar.inner.SetCookies(u, []*fhttp.Cookie{
		{Name: "session", Value: "1"},
		{Name: "dated", Value: "2", Expires: time.Now().Add(time.Hour)},
	})
	got := jar.forURL(u)
	if s := held(t, got, "session"); s.HostOnly || !s.Expires.IsZero() {
		t.Errorf("an unseen session cookie: %+v", s)
	}
	if d := held(t, got, "dated"); d.Expires.IsZero() {
		t.Errorf("an unseen persistent cookie lost its expiry: %+v", d)
	}
	if all := jar.all(); len(all) != 0 {
		t.Errorf("all listed cookies set through another wrapper: %+v", all)
	}
}

func TestASessionComesBackWithEachCookiesScope(t *testing.T) {
	// The bug this keeps away: a host's cookie written down and read back went
	// to every subdomain, and a session cookie came back expiring in 9999.
	first := newTestClient(t)
	first.session.seed(mustURL(t, "https://example.test/"), []Cookie{
		{Name: "host", Value: "1"},
		{Name: "domain", Value: "2", Domain: "example.test"},
		{Name: "kept", Value: "3", Expires: time.Now().Add(time.Hour), SameSite: "lax"},
	})
	saved := first.AllCookies()

	second := newTestClient(t, WithCookies(saved))
	sub := mustURL(t, "https://sub.example.test/")
	second.session.seedWarm(sub)
	names := map[string]bool{}
	for _, c := range second.session.jar.Cookies(sub) {
		names[c.Name] = true
	}
	if names["host"] || names["kept"] || !names["domain"] {
		t.Errorf("a subdomain was sent %v; want the domain's cookie alone", names)
	}
	second.session.seedWarm(mustURL(t, "https://example.test/"))
	again := second.AllCookies()
	if host := held(t, again, "host"); !host.HostOnly || !host.Expires.IsZero() {
		t.Errorf("read back, the host's session cookie is %+v", host)
	}
	if kept := held(t, again, "kept"); kept.Expires.IsZero() || kept.SameSite != "lax" || !kept.HostOnly {
		t.Errorf("read back, the persistent cookie is %+v", kept)
	}
	if domain := held(t, again, "domain"); domain.HostOnly {
		t.Errorf("read back, the domain's cookie is %+v", domain)
	}
}

func TestAHostsCookieIsNotFiledUnderAnother(t *testing.T) {
	client := newTestClient(t)
	u := mustURL(t, "https://example.test/")
	client.session.seed(u, []Cookie{
		{Name: "theirs", Value: "1", Domain: "other.test", HostOnly: true},
		{Name: "address", Value: "2", Domain: "192.0.2.1"},
		{Name: "mine", Value: "3", Domain: ".Example.Test", HostOnly: true},
	})
	all := client.AllCookies()
	if len(all) != 1 || all[0].Name != "mine" || !all[0].HostOnly || all[0].Domain != "example.test" {
		t.Errorf("filed under example.test: %+v; want its own cookie alone", all)
	}

	// An address spelled as a Domain is that address's cookie alone.
	ip := mustURL(t, "https://192.0.2.1/")
	client.session.seed(ip, []Cookie{{Name: "address", Value: "2", Domain: "192.0.2.1"}})
	for _, c := range client.AllCookies() {
		if c.Name == "address" && (!c.HostOnly || c.Domain != "192.0.2.1") {
			t.Errorf("an address cookie: %+v", c)
		}
	}
}

func TestASeededCookieWithNoPathIsTheWholeSites(t *testing.T) {
	// As a browser export says it, a cookie with no path is the site's, not
	// the path's the request was made to, which RFC 6265 would give it.
	client := newTestClient(t)
	client.session.seed(mustURL(t, "https://example.test/dir/page"), []Cookie{{Name: "a", Value: "1"}})
	if sent, err := client.CookiesFor("https://example.test/other"); err != nil || len(sent) != 1 || sent[0].Path != "/" {
		t.Errorf("CookiesFor = %+v, %v", sent, err)
	}
}

func TestAClientWithoutAJarListsNothing(t *testing.T) {
	client := newTestClient(t, WithoutCookieJar())
	if all := client.AllCookies(); all != nil {
		t.Errorf("AllCookies = %+v", all)
	}
}

func TestAJarThatDoesNotSayWhereACookieIsFiledListsNone(t *testing.T) {
	// Keep the negative contract independent of any particular adapter: this
	// owned jar intentionally strips filing metadata but still selects cookies
	// by the underlying protocol rules.
	client := newTestClient(t, WithCookieJar(metadataFreeJar{inner: tls_client.NewCookieJar()}))
	u := mustURL(t, "https://example.test/")
	client.session.seed(u, []Cookie{{Name: "a", Value: "1"}})
	if all := client.AllCookies(); len(all) != 0 {
		t.Errorf("AllCookies = %+v", all)
	}
	if sent, err := client.CookiesFor(u.String()); err != nil || len(sent) != 1 {
		t.Errorf("CookiesFor = %+v, %v", sent, err)
	}
}

// metadataFreeJar withholds the fields a complete inventory needs. Returning
// fresh name/value cookies also ensures the fixture cannot mutate its backend.
type metadataFreeJar struct{ inner fhttp.CookieJar }

func (j metadataFreeJar) SetCookies(u *url.URL, cookies []*fhttp.Cookie) {
	j.inner.SetCookies(u, cookies)
}
func (j metadataFreeJar) Cookies(u *url.URL) []*fhttp.Cookie {
	var out []*fhttp.Cookie
	for _, cookie := range j.inner.Cookies(u) {
		out = append(out, &fhttp.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	return out
}
func TestRepairedTransportJarReportsFilingMetadata(t *testing.T) {
	client := newTestClient(t, WithCookieJar(tls_client.NewCookieJar()))
	client.session.seed(mustURL(t, "https://example.test/"), []Cookie{{Name: "root", Value: "1"}})
	client.session.seed(mustURL(t, "https://example.test/dir/"), []Cookie{{Name: "scoped", Value: "2", Path: "/dir"}})
	all := client.AllCookies()
	if len(all) != 2 {
		t.Fatalf("AllCookies=%+v", all)
	}
	for _, cookie := range all {
		if cookie.Domain != "example.test" || !cookie.HostOnly {
			t.Errorf("filing metadata=%+v", cookie)
		}
	}
	if got, err := client.CookiesFor("https://example.test/other"); err != nil || len(got) != 1 || got[0].Name != "root" {
		t.Fatalf("path selection=%+v,%v", got, err)
	}
	if got, err := client.CookiesFor("https://other.test/"); err != nil || len(got) != 0 {
		t.Fatalf("host selection=%+v,%v", got, err)
	}
}

func TestCanonicalHost(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"Example.TEST", "example.test", true},
		{"example.test:8443", "example.test", true},
		{"example.test.", "example.test", true},
		{"[::1]:8443", "::1", true},
		{"[::1]", "[::1]", true},
		{"::1", "::1", true},
		{"bücher.example", "xn--bcher-kva.example", true},
		{"[::1]:80:90", "", false},
	} {
		got, ok := canonicalHost(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("canonicalHost(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	if _, _, filed := jarKeyOf(&url.URL{Host: "[::1]:80:90"}, &fhttp.Cookie{Name: "a"}); filed {
		t.Error("a cookie from a host that will not parse was filed")
	}
}

func TestDefaultCookiePath(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "relative": "/", "/": "/", "/page": "/", "/a/b": "/a", "/a/b/": "/a/b",
	} {
		if got := defaultCookiePath(in); got != want {
			t.Errorf("defaultCookiePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlaceURL(t *testing.T) {
	if got := placeURL("example.test", "/a").String(); got != "https://example.test:443/a" {
		t.Errorf("placeURL = %s", got)
	}
	if got := placeURL("::1", "/").Host; got != "[::1]:443" {
		t.Errorf("an IPv6 domain: %s", got)
	}
	if got := placeURL("[::1]", "/").Host; got != "[::1]" {
		t.Errorf("a domain filed with its brackets: %s", got)
	}
}

func TestSameSiteNames(t *testing.T) {
	for _, tc := range []struct {
		mode fhttp.SameSite
		name string
	}{
		{fhttp.SameSiteStrictMode, "strict"},
		{fhttp.SameSiteLaxMode, "lax"},
		{fhttp.SameSiteNoneMode, "none"},
		{fhttp.SameSiteDefaultMode, ""},
		{0, ""},
	} {
		if got := sameSiteName(tc.mode); got != tc.name {
			t.Errorf("sameSiteName(%v) = %q, want %q", tc.mode, got, tc.name)
		}
	}
	for name, want := range map[string]fhttp.SameSite{
		"strict": fhttp.SameSiteStrictMode, "Lax": fhttp.SameSiteLaxMode, "NONE": fhttp.SameSiteNoneMode,
		"": 0, "unspecified": 0,
	} {
		if got := sameSiteMode(name); got != want {
			t.Errorf("sameSiteMode(%q) = %v, want %v", name, got, want)
		}
	}
	if strings.Contains(sameSiteName(fhttp.SameSiteDefaultMode), "default") {
		t.Error("the default mode has a name of its own")
	}
}

func TestAScriptsAnswerFromAnotherSiteSetsSameSiteNoneAlone(t *testing.T) {
	// As Chrome keeps them: a script's request to another site files a cookie
	// of SameSite=None alone; one to its page's site, a page's, and a request
	// without a browser context file any.
	for _, tc := range []struct {
		name string
		rule sendRule
		want []string
	}{
		{"a script to another site", sendRule{crossSite: true}, []string{"none"}},
		{"a script's unsafe request to another site", sendRule{crossSite: true, safe: false}, []string{"none"}},
		{"a navigation to another site", sendRule{crossSite: true, topLevel: true, safe: true}, []string{"lax", "none", "strict", "unnamed", "word"}},
		{"a form posted to another site", sendRule{crossSite: true, topLevel: true}, []string{"lax", "none", "strict", "unnamed", "word"}},
		{"a script to its page's site", sendRule{}, []string{"lax", "none", "strict", "unnamed", "word"}},
	} {
		jar := newTestJar()
		u := mustURL(t, "https://www.example.com/")
		jar.restrict(u, tc.rule)
		jar.SetCookies(u, []*fhttp.Cookie{
			{Name: "unnamed", Value: "1"},
			{Name: "none", Value: "1", SameSite: fhttp.SameSiteNoneMode, Secure: true},
			{Name: "lax", Value: "1", SameSite: fhttp.SameSiteLaxMode},
			{Name: "strict", Value: "1", SameSite: fhttp.SameSiteStrictMode},
			{Name: "word", Value: "1", SameSite: fhttp.SameSiteDefaultMode},
		})
		jar.release(u)
		var got []string
		for _, c := range jar.inner.Cookies(u) {
			got = append(got, c.Name)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: filed %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAServersCookieIsHeldToWhatChromeTakes(t *testing.T) {
	// What Chrome was measured to file of a server's Set-Cookie (the
	// set-cookie-prefixes, -insecure-*, -size scenarios), one cookie at a
	// time, beside a valid one that is filed whatever its neighbour is.
	big := func(n int) string { return strings.Repeat("x", n) }
	for _, tc := range []struct {
		from   string
		cookie fhttp.Cookie
		filed  bool
		path   string
	}{
		{"https://www.example.com/a", fhttp.Cookie{Name: "plain", Value: "1"}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Secure-ok", Value: "1", Secure: true}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Secure-bad", Value: "1"}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__secure-lower", Value: "1"}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Host-ok", Value: "1", Secure: true, Path: "/"}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__HOST-upper", Value: "1", Path: "/"}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Host-path", Value: "1", Secure: true, Path: "/p"}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Host-nopath", Value: "1", Secure: true}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Host-domain", Value: "1", Secure: true, Path: "/", Domain: "www.example.com"}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Http-x", Value: "1", Secure: true}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Http-y", Value: "1", Secure: true, HttpOnly: true}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Http-z", Value: "1", HttpOnly: true}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Host-Http-y", Value: "1", Secure: true, HttpOnly: true, Path: "/"}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "__Host-Http-z", Value: "1", Secure: true, Path: "/"}, false, ""},
		{"https://www.example.com/a", fhttp.Cookie{Name: "none-ok", Value: "1", Secure: true, SameSite: fhttp.SameSiteNoneMode}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "none-bad", Value: "1", SameSite: fhttp.SameSiteNoneMode}, false, ""},
		{"http://www.example.com/a", fhttp.Cookie{Name: "sec", Value: "1", Secure: true}, false, ""},
		{"http://www.example.com/a", fhttp.Cookie{Name: "__Secure-x", Value: "1", Secure: true}, false, ""},
		{"http://localhost/a", fhttp.Cookie{Name: "sec", Value: "1", Secure: true}, true, "/"},
		{"http://127.0.0.1/a", fhttp.Cookie{Name: "__Host-y", Value: "1", Secure: true, Path: "/"}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "n", Value: big(4095)}, true, "/"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "m", Value: big(4096)}, false, ""},
		{"https://www.example.com/a/b", fhttp.Cookie{Name: "long", Value: "1", Path: "/" + big(1100)}, true, "/a"},
		{"https://www.example.com/a", fhttp.Cookie{Name: "wide", Value: "1", Domain: big(1100) + ".example.com"}, true, "/"},
	} {
		jar := newTestJar()
		u := mustURL(t, tc.from)
		cookie := tc.cookie
		jar.SetCookies(u, []*fhttp.Cookie{&cookie, {Name: "neighbour", Value: "1"}})
		var filed, path string
		var neighbour bool
		for _, c := range jar.all() {
			switch c.Name {
			case cookie.Name:
				filed, path = c.Name, c.Path
			case "neighbour":
				neighbour = true
			}
		}
		if (filed != "") != tc.filed || filed != "" && path != tc.path || !neighbour {
			t.Errorf("%s from %s: filed %v at %q, its neighbour %v; want %v at %q", cookie.Name, tc.from, filed != "", path,
				neighbour, tc.filed, tc.path)
		}
	}
}

func TestACookieFromAnOriginThatIsNotSecureLeavesASecureOneAlone(t *testing.T) {
	// RFC 6265bis 5.7: one without Secure from plain http does not replace
	// or shadow a Secure cookie of its name whose domain matches its either
	// way and whose path its own is within; from https it does.
	secure := mustURL(t, "https://www.example.com/")
	plain := mustURL(t, "http://www.example.com/")
	held := func(jar *keptJar) []string {
		var out []string
		for _, c := range jar.all() {
			out = append(out, c.Name+"="+c.Value+" "+c.Domain+c.Path)
		}
		slices.Sort(out)
		return out
	}
	for _, tc := range []struct {
		name string
		from *url.URL
		set  fhttp.Cookie
		want []string
	}{
		{"the same, from http", plain, fhttp.Cookie{Name: "s", Value: "2", Path: "/"}, []string{"s=1 www.example.com/"}},
		{"under its path, from http", plain, fhttp.Cookie{Name: "s", Value: "2", Path: "/sub"}, []string{"s=1 www.example.com/"}},
		{"its domain's, from http", plain, fhttp.Cookie{Name: "s", Value: "2", Path: "/", Domain: "example.com"},
			[]string{"s=1 www.example.com/"}},
		{"another name, from http", plain, fhttp.Cookie{Name: "t", Value: "2", Path: "/"},
			[]string{"s=1 www.example.com/", "t=2 www.example.com/"}},
		{"the same, from https", secure, fhttp.Cookie{Name: "s", Value: "2", Path: "/"}, []string{"s=2 www.example.com/"}},
	} {
		jar := newTestJar()
		jar.SetCookies(secure, []*fhttp.Cookie{{Name: "s", Value: "1", Path: "/", Secure: true}})
		set := tc.set
		jar.SetCookies(tc.from, []*fhttp.Cookie{&set})
		if got := held(jar); !slices.Equal(got, tc.want) {
			t.Errorf("%s: holds %v, want %v", tc.name, got, tc.want)
		}
	}
	// What its path and domain are within, or under, decides.
	for _, tc := range []struct {
		name          string
		secure, plain fhttp.Cookie
		want          []string
		// from is where the Secure cookie is set, the https origin unless said.
		from string
	}{
		{"a wider path", fhttp.Cookie{Name: "s", Value: "1", Path: "/sub", Secure: true}, fhttp.Cookie{Name: "s", Value: "2", Path: "/"},
			[]string{"s=1 www.example.com/sub", "s=2 www.example.com/"}, ""},
		{"a path that only begins so", fhttp.Cookie{Name: "s", Value: "1", Path: "/sub", Secure: true},
			fhttp.Cookie{Name: "s", Value: "2", Path: "/subx"}, []string{"s=1 www.example.com/sub", "s=2 www.example.com/subx"}, ""},
		{"under a directory", fhttp.Cookie{Name: "s", Value: "1", Path: "/dir/", Secure: true},
			fhttp.Cookie{Name: "s", Value: "2", Path: "/dir/x"}, []string{"s=1 www.example.com/dir/"}, ""},
		{"under the domain's", fhttp.Cookie{Name: "s", Value: "1", Path: "/", Domain: "example.com", Secure: true},
			fhttp.Cookie{Name: "s", Value: "2", Path: "/"}, []string{"s=1 example.com/"}, ""},
		{"one without Secure", fhttp.Cookie{Name: "s", Value: "1", Path: "/"}, fhttp.Cookie{Name: "s", Value: "2", Path: "/"},
			[]string{"s=2 www.example.com/"}, ""},
		{"another host's", fhttp.Cookie{Name: "s", Value: "1", Path: "/", Secure: true}, fhttp.Cookie{Name: "s", Value: "2", Path: "/"},
			[]string{"s=1 api.example.com/", "s=2 www.example.com/"}, "https://api.example.com/"},
	} {
		jar := newTestJar()
		first, then := tc.secure, tc.plain
		from := secure
		if tc.from != "" {
			from = mustURL(t, tc.from)
		}
		jar.SetCookies(from, []*fhttp.Cookie{&first})
		jar.SetCookies(plain, []*fhttp.Cookie{&then})
		if got := held(jar); !slices.Equal(got, tc.want) {
			t.Errorf("%s: holds %v, want %v", tc.name, got, tc.want)
		}
	}
	// One the jar no longer holds shadows nothing, though the wrapper filed it.
	jar := newTestJar()
	jar.SetCookies(secure, []*fhttp.Cookie{{Name: "s", Value: "1", Path: "/", Secure: true}, {Name: "other", Value: "1", Path: "/"}})
	jar.inner.SetCookies(secure, []*fhttp.Cookie{{Name: "s", Value: "1", Path: "/", Secure: true, MaxAge: -1}})
	jar.SetCookies(plain, []*fhttp.Cookie{{Name: "s", Value: "2", Path: "/"}})
	if got := held(jar); !slices.Equal(got, []string{"other=1 www.example.com/", "s=2 www.example.com/"}) {
		t.Errorf("after the Secure one went: holds %v", got)
	}
	// One the jar refuses itself is no question of shadowing.
	jar = newTestJar()
	jar.SetCookies(plain, []*fhttp.Cookie{{Name: "s", Value: "2", Domain: "example.net"}})
	if got := held(jar); len(got) != 0 {
		t.Errorf("another site's: holds %v", got)
	}
}

func TestTheJarIsAskedAsHTTPSForTheMachineItself(t *testing.T) {
	for raw, want := range map[string]string{
		"http://localhost:8080/a?q": "https://localhost:8080/a?q",
		"http://127.0.0.1/":         "https://127.0.0.1/",
		"http://www.example.com/":   "http://www.example.com/",
		"https://localhost/":        "https://localhost/",
	} {
		if got := jarURL(mustURL(t, raw)).String(); got != want {
			t.Errorf("jarURL(%s) = %s, want %s", raw, got, want)
		}
	}
}
