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
