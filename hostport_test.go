package tlsforge

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
)

// toHosts answers /to/... with a redirect to the rest of the path made a URL
// again, http:// or https:// as it begins, /rel/... with one to the rest of
// the path on its own host, and anything else with a page.
func toHosts(w http.ResponseWriter, r *http.Request) {
	if rest, ok := strings.CutPrefix(r.URL.Path, "/rel"); ok {
		w.Header().Set("Location", rest)
		w.WriteHeader(http.StatusFound)
		return
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/to/"); ok {
		scheme, target, _ := strings.Cut(rest, "/")
		w.Header().Set("Location", scheme+"://"+target)
		w.WriteHeader(http.StatusFound)
		return
	}
	_, _ = w.Write([]byte("page"))
}

func TestPlainAndSecureRequestsToOneHostOnOneClient(t *testing.T) {
	// tls-client took a plain-http URL with no port for one on 443, and sent
	// it on the transport the host's HTTPS had, or the other way about.
	for _, proto := range []string{"h2", "h1"} {
		for _, tc := range []struct {
			name string
			urls []string
			// want is each request the server was sent, as the recorder
			// keeps it, and shown the URL of the last answer.
			want  []string
			shown string
		}{
			{"https, then http", []string{"https://www.example.com/a", "http://www.example.com/b"},
				[]string{"https://www.example.com/a", "http://www.example.com/b"}, "http://www.example.com/b"},
			{"http, then https", []string{"http://www.example.com/a", "https://www.example.com/b"},
				[]string{"http://www.example.com/a", "https://www.example.com/b"}, "https://www.example.com/b"},
			{"http redirected to https", []string{"http://www.example.com/to/https/www.example.com/landed"},
				[]string{"http://www.example.com/to/https/www.example.com/landed", "https://www.example.com/landed"},
				"https://www.example.com/landed"},
			{"https redirected to http", []string{"https://www.example.com/a",
				"https://www.example.com/to/http/www.example.com/landed"},
				[]string{"https://www.example.com/a", "https://www.example.com/to/http/www.example.com/landed",
					"http://www.example.com/landed"}, "http://www.example.com/landed"},
			{"http redirected on its own host", []string{"http://www.example.com/to/http/www.example.com/next"},
				[]string{"http://www.example.com/to/http/www.example.com/next", "http://www.example.com/next"},
				"http://www.example.com/next"},
		} {
			t.Run(proto+"/"+tc.name, func(t *testing.T) {
				secure := newRecorder(t, proto, toHosts)
				plain := newRecorder(t, "http", toHosts)
				client := newTestClient(t, secure.dialingWith(plain))
				var res *Response
				for _, u := range tc.urls {
					var err error
					if res, err = client.Get(u); err != nil {
						t.Fatalf("Get %s: %v", u, err)
					}
				}
				if res.URL != tc.shown {
					t.Errorf("the answer is shown as of %s, want %s", res.URL, tc.shown)
				}
				got := secure.requests()
				if len(got) != len(tc.want) {
					t.Fatalf("%d requests were sent, want %d", len(got), len(tc.want))
				}
				for i, req := range got {
					host := req.headers[0]
					if req.url != tc.want[i] || !strings.EqualFold(host[0], "host") && host[0] != ":method" {
						t.Errorf("request %d: %s %v, want %s", i+1, req.url, host, tc.want[i])
					}
					if strings.HasPrefix(req.url, "https:") && proto == "h2" && req.priority == nil {
						t.Errorf("request %d went out over HTTP/1.1, not HTTP/2", i+1)
					}
					if strings.HasPrefix(req.url, "http:") && host[1] != "www.example.com" {
						t.Errorf("request %d said Host: %s", i+1, host[1])
					}
				}
			})
		}
	}
}

func TestARedirectToAnotherAuthorityWithoutASchemeNamesItsOwnHost(t *testing.T) {
	// //host:port after a plain URL that names no port is that host and port:
	// the Host the hop before was sent with does not go on with it.
	plain := newRecorder(t, "http", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/away" {
			w.Header().Set("Location", "//www.example.net:8080/x")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("page"))
	})
	client := newTestClient(t, WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, plain.addr)
	})))
	res, err := client.Get("http://www.example.com/away")
	if err != nil || res.URL != "http://www.example.net:8080/x" {
		t.Fatalf("Get: %v, %v", res, err)
	}
	if got := plain.requests(); len(got) != 2 || got[1].headers[0][1] != "www.example.net:8080" {
		t.Errorf("sent %+v", got)
	}
}

func TestAPlainRequestThatNamesPort80IsSentAsOneThatNamesNone(t *testing.T) {
	// Chrome leaves out the port a scheme means: the request goes out, and
	// is shown, as if the URL had named none.
	secure := newRecorder(t, "h2", toHosts)
	plain := newRecorder(t, "http", toHosts)
	client := newTestClient(t, secure.dialingWith(plain))
	res, err := client.Get("http://www.example.com:80/a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if res.URL != "http://www.example.com/a" {
		t.Errorf("shown as %s", res.URL)
	}
	if got := secure.requests(); len(got) != 1 || got[0].headers[0][1] != "www.example.com" {
		t.Errorf("sent %+v", got)
	}
}

func TestARedirectIsToldOfAndLoggedAsAsked(t *testing.T) {
	secure := newRecorder(t, "h2", toHosts)
	plain := newRecorder(t, "http", toHosts)
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, secure.dialingWith(plain), WithLogger(log))
	var told []string
	trace := &Trace{Redirect: func(_ int, location string) { told = append(told, location) }}
	// The second hop is relative to the first, which the transport was told
	// the port of.
	res, err := client.Do(&Request{URL: "http://www.example.com/to/http/www.example.com/rel/end", Trace: trace})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	want := []string{"http://www.example.com/rel/end", "http://www.example.com/end"}
	if strings.Join(told, " ") != strings.Join(want, " ") || res.URL != want[1] {
		t.Errorf("told of %v, answered as of %s; want %v", told, res.URL, want)
	}
	for i, hop := range book.with(t, "redirect") {
		if hop.get("location") != want[i] {
			t.Errorf("hop %d logged as %s", i+1, hop.get("location"))
		}
	}
}

func TestATransportFailureQuotesThePlainURLAsAsked(t *testing.T) {
	refusing := WithTransportOption(tls_client.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("refused here")
	}))
	client := newTestClient(t, refusing)
	_, err := client.Get("http://www.example.com/x?y")
	if err == nil || !strings.Contains(err.Error(), `"http://www.example.com/x?y"`) || strings.Contains(err.Error(), ":80") {
		t.Errorf("error = %v", err)
	}
	_, err = client.Do(&Request{URL: "http://localhost/cors/x", Header: NewHeader("X-Foo", "1"),
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}})
	if err == nil || !strings.Contains(err.Error(), `"http://localhost/cors/x"`) || strings.Contains(err.Error(), ":80") {
		t.Errorf("the preflight's error = %v", err)
	}
}

func TestAPreflightToPlainHTTPAfterHTTPS(t *testing.T) {
	secure := newRecorder(t, "h2", answeringAsMeasured)
	plain := newRecorder(t, "http", answeringAsMeasured)
	client := newTestClient(t, WithProfile("chrome_155_macos"), secure.dialingWith(plain))
	// fetch() goes out on a client of its own: its HTTPS first, on HTTP/2.
	fetch := &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}
	if _, err := client.Do(&Request{URL: "https://localhost/cors/x", Browser: fetch}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, err := client.Do(&Request{URL: "http://localhost/cors/x", Header: NewHeader("X-Foo", "1"), Browser: fetch})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := secure.requests()
	if len(got) != 3 || got[1].method != "OPTIONS" || got[1].url != "http://localhost/cors/x" ||
		got[2].method != "GET" || got[1].headers[0][1] != "localhost" {
		t.Errorf("sent %+v", got)
	}
}

func TestWithPort(t *testing.T) {
	for _, tc := range []struct {
		url, host, urlHost string
	}{
		{"http://www.example.com/a", "www.example.com", "www.example.com:80"},
		{"http://[::1]/a", "[::1]", "[::1]:80"},
		{"http://www.example.com:8080/a", "www.example.com:8080", "www.example.com:8080"},
		{"http://www.example.com:80/a", "www.example.com:80", "www.example.com:80"},
		{"https://www.example.com/a", "www.example.com", "www.example.com"},
	} {
		req, err := fhttp.NewRequest("GET", tc.url, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		withPort(req)
		if req.Host != tc.host || req.URL.Host != tc.urlHost {
			t.Errorf("%s: Host %s, URL host %s", tc.url, req.Host, req.URL.Host)
		}
		if shown := shownURL(req).String(); shown != tc.url {
			t.Errorf("%s: shown as %s", tc.url, shown)
		}
	}
	// A hop of the transport's, with no Host of its own, is shown as it is.
	for _, raw := range []string{"http://www.example.com:80/a", "http://:80/a"} {
		req, _ := fhttp.NewRequest("GET", raw, nil)
		req.Host = ""
		if shownURL(req) != req.URL {
			t.Errorf("%s with no Host is shown anew", raw)
		}
	}
	for _, tc := range []struct{ host, url string }{
		{"other.example", "http://www.example.com:80/a"},
		{"www.example.com", "https://www.example.com:80/a"},
		{"www.example.com", "http://www.example.com:8080/a"},
	} {
		req, _ := fhttp.NewRequest("GET", tc.url, nil)
		req.Host = tc.host
		if shownURL(req) != req.URL {
			t.Errorf("%s with Host %s is shown anew", tc.url, tc.host)
		}
	}
}

func TestWithoutDefaultPort(t *testing.T) {
	for raw, want := range map[string]string{
		"http://x:80/p":       "http://x/p",
		"http://x:80":         "http://x",
		"http://x:80?q":       "http://x?q",
		"http://x:80#f":       "http://x#f",
		"http://u:***@x:80/p": "http://u:***@x/p",
		"http://[::1]:80/":    "http://[::1]/",
		"http://x:8080/":      "http://x:8080/",
		"http://x:180/":       "http://x:180/",
		"http://x/p:80":       "http://x/p:80",
		"http://x/?a=b:80":    "http://x/?a=b:80",
		"https://x:80/":       "https://x:80/",
		"http://u:80@x/":      "http://u:80@x/",
		"http://u:80@x:80/":   "http://u:80@x/",
		"http://[::80]/":      "http://[::80]/",
		"":                    "",
		"no URL":              "no URL",
	} {
		if got := withoutDefaultPort(raw); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}
