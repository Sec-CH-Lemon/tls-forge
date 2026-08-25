package tlsforge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// cookieEcho reports what it was sent and sets one of its own.
func cookieEcho(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "given", Value: "by-the-server", Path: "/",
				Secure: true, HttpOnly: true})
		}
		names := make([]string, 0, 4)
		for _, c := range r.Cookies() {
			names = append(names, c.Name+"="+c.Value)
		}
		sort.Strings(names)
		_, _ = fmt.Fprint(w, strings.Join(names, " "))
	}))
	t.Cleanup(server.Close)
	return server
}

// mustHost is the hostname out of a URL, which is what a cookie's domain is.
func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing %s: %v", rawURL, err)
	}
	return u.Hostname()
}

func TestWithCookies(t *testing.T) {
	// A warmed session belongs to the client, which is the identity it was
	// warmed for, so it is there from the first request rather than added to
	// each one.
	server := cookieEcho(t)
	// The hostname alone: a cookie's domain never carries a port.
	host := mustHost(t, server.URL)

	client, err := New(WithInsecureSkipVerify(), WithCookies([]Cookie{
		// One that names its host, and one that does not: a cookie given as a
		// bare name and value has none until a request supplies one.
		{Name: "warm", Value: "1", Domain: host, Path: "/", Secure: true, HTTPOnly: true},
		{Name: "homeless", Value: "2"},
		{Name: "elsewhere", Value: "3", Domain: "example.com"},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	for _, path := range []string{"/first", "/second"} {
		res, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got := string(res.Body); got != "homeless=2 warm=1" {
			t.Errorf("%s was sent %q", path, got)
		}
	}
}

func TestWarmedCookieDoesNotOverwriteAServerRefresh(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			t.Errorf("request has no session cookie: %v", err)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "session", Value: "refreshed", Path: "/", Secure: true,
		})
		_, _ = fmt.Fprint(w, cookie.Value)
	}))
	t.Cleanup(server.Close)

	client, err := New(WithInsecureSkipVerify(), WithCookies([]Cookie{{
		Name: "session", Value: "warmed", Domain: mustHost(t, server.URL),
		Path: "/", Secure: true,
	}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	for request, want := range []string{"warmed", "refreshed"} {
		res, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("request %d: %v", request+1, err)
		}
		if got := res.Text(); got != want {
			t.Errorf("request %d sent %q, want %q", request+1, got, want)
		}
	}
}

func TestCookiesForReadsTheJarBack(t *testing.T) {
	// How a session warmed by a run is written down.
	server := cookieEcho(t)
	client, err := New(WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Get(server.URL + "/set"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	held, err := client.CookiesFor(server.URL + "/")
	if err != nil {
		t.Fatalf("CookiesFor: %v", err)
	}
	if len(held) != 1 || held[0].Name != "given" || held[0].Value != "by-the-server" {
		t.Fatalf("held %+v", held)
	}
	// The flags are part of what the server set, and a session is not portable
	// without them.
	if !held[0].Secure || !held[0].HTTPOnly {
		t.Errorf("the flags were lost: %+v", held[0])
	}
	if held[0].Domain == "" {
		t.Errorf("the host was lost: %+v", held[0])
	}
}

func TestCookiesForRejectsAURLItCannotRead(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CookiesFor("://not a url"); err == nil {
		t.Error("no error")
	}
}

func TestSeededCookiesCarryTheirExpiry(t *testing.T) {
	server := cookieEcho(t)
	// The hostname alone: a cookie's domain never carries a port.
	host := mustHost(t, server.URL)
	client, err := New(WithInsecureSkipVerify(), WithCookies([]Cookie{
		{Name: "keeps", Value: "1", Domain: host, Path: "/",
			Expires: time.Now().Add(24 * time.Hour)},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	res, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(string(res.Body), "keeps=1") {
		t.Errorf("sent %q", res.Body)
	}
}

func TestWithoutCookieJar(t *testing.T) {
	// A proxy forwards whatever Cookie header its caller sent, and a jar
	// underneath would add a second one from its own store, leaving the
	// caller's session and the proxy's quietly diverging.
	server := cookieEcho(t)
	client, err := New(WithInsecureSkipVerify(), WithoutCookieJar())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The server sets two cookies here.
	res, err := client.Get(server.URL + "/set")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Cookies) != 0 {
		t.Errorf("a jarless client reported cookies: %v", res.Cookies)
	}

	// And nothing was kept, so the next request carries none of its own.
	res, err = client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := string(res.Body); got != "" {
		t.Errorf("the second request carried %q", got)
	}

	// There is nothing to read back either, rather than a panic on a nil jar.
	held, err := client.CookiesFor(server.URL + "/")
	if err != nil || len(held) != 0 {
		t.Errorf("CookiesFor = %v, %v", held, err)
	}
	held, err = client.Cookies(server.URL + "/")
	if err != nil || len(held) != 0 {
		t.Errorf("Cookies = %v, %v", held, err)
	}
}

func TestDefaultJarEnforcesCookieScope(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	source, _ := url.Parse("https://a.co.uk/private/start")
	client.jar.SetCookies(source, []*fhttp.Cookie{
		{Name: "auth", Value: "secret", Domain: "a.co.uk", Path: "/private", Secure: true},
		{Name: "expired", Value: "old", Domain: "a.co.uk", Path: "/", Expires: time.Now().Add(-time.Hour)},
	})

	for _, rawURL := range []string{
		"http://a.co.uk/private/start",  // Secure cookies never travel over HTTP.
		"https://a.co.uk/public",        // Path is part of a cookie's scope.
		"https://b.co.uk/private/start", // Public suffixes do not join unrelated sites.
	} {
		target, _ := url.Parse(rawURL)
		if got := client.jar.Cookies(target); len(got) != 0 {
			t.Errorf("%s received %+v", rawURL, got)
		}
	}

	target, _ := url.Parse("https://a.co.uk/private/page")
	got := client.jar.Cookies(target)
	if len(got) != 1 || got[0].Name != "auth" {
		t.Fatalf("same-site cookie = %+v", got)
	}
}

func TestResponseCookiesBelongToTheFinalRedirectURL(t *testing.T) {
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "final", Value: "1", Path: "/", Secure: true})
	}))
	t.Cleanup(destination.Close)
	finalURL := strings.Replace(destination.URL, "127.0.0.1", "localhost", 1)

	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, finalURL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	client, err := New(WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()
	res, err := client.Get(redirect.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Cookies) != 1 || res.Cookies[0] != "final=1" {
		t.Fatalf("response cookies = %v", res.Cookies)
	}
}

func TestWithoutCookieJarIgnoresCookiesItIsHanded(t *testing.T) {
	// Asking for no jar and then handing it cookies is a contradiction; the
	// jarless half wins, because that is the one that was asked for explicitly
	// and the one a proxy depends on.
	server := cookieEcho(t)
	client, err := New(WithInsecureSkipVerify(), WithoutCookieJar(),
		WithCookies([]Cookie{{Name: "warm", Value: "1", Domain: mustHost(t, server.URL)}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	res, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := string(res.Body); got != "" {
		t.Errorf("a jarless client sent %q", got)
	}
}
