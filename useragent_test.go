package tlsforge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v6/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v6/echo"
	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
)

// userAgentsSent is every user-agent field the echo server saw from a client,
// over HTTP/1.1 and over HTTP/2.
func userAgentsSent(t *testing.T, opts ...Option) (http1, http2 []string) {
	t.Helper()
	server, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	defer func() { _ = server.Close() }()
	client, err := New(append(opts, WithInsecureSkipVerify())...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	for _, base := range []string{server.CaptureURL(), server.URL()} {
		res, err := client.Do(&Request{Context: context.Background(), URL: base + "/api/all"})
		if err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		var measured capture.Capture
		if err := json.Unmarshal(res.Body, &measured); err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		if measured.HTTP1 != nil {
			for _, field := range measured.HTTP1.Headers {
				if strings.EqualFold(field.Name, "user-agent") {
					http1 = append(http1, field.Value)
				}
			}
		}
		if measured.HTTP2 != nil {
			for _, field := range measured.HTTP2.Headers {
				if field.Name == "user-agent" {
					http2 = append(http2, field.Value)
				}
			}
		}
	}
	return http1, http2
}

// withoutUserAgent is a profile that names no user agent, with its HTTP/1.1
// layout or without one.
func withoutUserAgent(t *testing.T, layout bool) *profile.Profile {
	t.Helper()
	p, err := profile.Get("chrome")
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	p.Name, p.UserAgent = "no_user_agent", ""
	var kept []profile.Field
	for _, field := range p.Headers {
		if field.Name != "user-agent" {
			kept = append(kept, field)
		}
	}
	p.Headers = kept
	if !layout {
		p.HTTP1 = nil
	}
	return p
}

func TestARequestNeverNamesTheTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		// A handshake from the catalogue, and no headers at all.
		{"a catalogue profile", []Option{WithProfile("firefox_148")}},
		{"a profile with no user agent", []Option{WithProfileValue(withoutUserAgent(t, false))}},
		{"one with an HTTP/1.1 layout", []Option{WithProfileValue(withoutUserAgent(t, true))}},
	} {
		http1, http2 := userAgentsSent(t, tc.opts...)
		if len(http1) != 0 || len(http2) != 0 {
			t.Errorf("%s: sent user-agent %q over HTTP/1.1 and %q over HTTP/2", tc.name, http1, http2)
		}
	}
}

func TestARequestSendsTheUserAgentItIsGiven(t *testing.T) {
	const given = "Mozilla/5.0 (given)"
	for _, tc := range []struct {
		name string
		opts []Option
		want string
	}{
		{"the profile's", nil, ""},
		{"the caller's, over a catalogue profile", []Option{WithProfile("firefox_148"),
			WithHeaders(NewHeader("User-Agent", given))}, given},
		{"the caller's, over one with a layout", []Option{WithProfileValue(withoutUserAgent(t, true)),
			WithHeaders(NewHeader("user-agent", given))}, given},
	} {
		want := tc.want
		if want == "" {
			p, err := profile.Get(DefaultProfile)
			if err != nil {
				t.Fatalf("profile.Get: %v", err)
			}
			want = p.UserAgent
		}
		http1, http2 := userAgentsSent(t, tc.opts...)
		if len(http1) != 1 || http1[0] != want || len(http2) != 1 || http2[0] != want {
			t.Errorf("%s: sent %q over HTTP/1.1 and %q over HTTP/2, want %q", tc.name, http1, http2, want)
		}
	}
}

func TestARedirectNeverNamesTheTransport(t *testing.T) {
	// The hop fhttp makes on its own, from the request it copies, over both
	// protocols and from both kinds of profile.
	for _, h2 := range []bool{false, true} {
		for _, p := range []*profile.Profile{withoutUserAgent(t, false), withoutUserAgent(t, true)} {
			var mu sync.Mutex
			var seen []string
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/from" {
					http.Redirect(w, r, "/to", http.StatusFound)
					return
				}
				mu.Lock()
				seen = append(seen, r.Header.Values("User-Agent")...)
				mu.Unlock()
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			client, err := New(WithProfileValue(p), WithInsecureSkipVerify())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			res, err := client.Do(&Request{URL: server.URL + "/from"})
			_ = client.Close()
			server.Close()
			if err != nil || res.Status != http.StatusOK {
				t.Fatalf("h2 %v, layout %v: %v", h2, p.HTTP1 != nil, err)
			}
			if len(seen) != 0 {
				t.Errorf("h2 %v, layout %v: the redirected request said %q", h2, p.HTTP1 != nil, seen)
			}
		}
	}
}
