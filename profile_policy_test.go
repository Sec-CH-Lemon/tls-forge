package tlsforge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	fhttp "github.com/igor-lemon/fhttp"
	tc "github.com/igor-lemon/tls-client"
)

// Each scenario changes a real JSON file, then loads it through the public
// profile parser. No transport/test-only setter substitutes for that path.
func policyFile(t *testing.T, values map[string]any) *profile.Profile {
	t.Helper()
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "neutral_profile"
	p.UserAgent = "Metadata without a browser family"
	for k, v := range values {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		p.Behavior[k] = b
	}
	b, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "browser.json")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err = profile.Load(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProfileJSONChangesActualHeadersAndPriority(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			s := newRecorder(t, proto, nil)
			p := policyFile(t, map[string]any{"headers.navigation_order": []string{"accept", "user-agent", "@hints", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie", "priority"}, "headers.priority_fetch": "u=6", "headers.script_priority_weight": 41, "headers.script_priority_exclusive": false, "headers.renderer_order": "sorted", "headers.h1_generated_priority": true})
			c := newTestClient(t, WithProfileValue(p), s.dialing())
			for _, req := range []*Request{{URL: "https://example.com/nav", Browser: &BrowserContext{Kind: KindNavigation}}, {URL: "https://example.com/fetch", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/nav"}, Header: NewHeader("X-Z", "z", "X-A", "a")}} {
				if _, err := c.Do(req); err != nil {
					t.Fatal(err)
				}
			}
			got := s.requests()
			if len(got) != 2 {
				t.Fatalf("%d requests", len(got))
			}
			names := []string{}
			for _, h := range got[0].headers {
				names = append(names, strings.ToLower(h[0]))
			}
			if slices.Index(names, "accept") >= slices.Index(names, "user-agent") {
				t.Fatalf("file order ignored: %v", names)
			}
			if v, ok := got[1].header("priority"); !ok || v != "u=6" {
				t.Fatalf("priority header %q,%v", v, ok)
			}
			names = nil
			for _, h := range got[1].headers {
				names = append(names, strings.ToLower(h[0]))
			}
			if slices.Index(names, "x-a") >= slices.Index(names, "x-z") {
				t.Fatal("renderer primitive ignored")
			}
			if proto == "h2" && (got[1].priority == nil || got[1].priority[0] != 0 || got[1].priority[2] != 41) {
				t.Fatalf("frame priority %v", got[1].priority)
			}
		})
	}
}

func TestProfileJSONChangesActualH2FrameCuts(t *testing.T) {
	server, err := harness.StartHPACKServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	port := server.PortFor(harness.H2Settings{Frame: 16384})
	p := policyFile(t, map[string]any{"h2.header_frame_payload": 1024, "h2.data_frame_payload": 257})
	c := newTestClient(t, WithProfileValue(p), WithTimeout(5*time.Second), WithTransportOption(tc.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, at, _ := net.SplitHostPort(addr)
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", at))
	})))
	body := strings.Repeat("b", 1000)
	if _, err = c.Do(&Request{URL: fmt.Sprintf("https://example.com:%d/policy", port), Method: "POST", Header: NewHeader("X-Long", strings.Repeat("a", 4000)), Body: []byte(body)}); err != nil {
		t.Fatal(err)
	}
	es, err := server.Requests()
	if err != nil || len(es) != 1 {
		t.Fatalf("requests %d: %v", len(es), err)
	}
	e := es[0]
	if len(e.Frames) < 2 || e.Frames[0] != 1024 {
		t.Fatalf("header cuts %v", e.Frames)
	}
	if !slices.Equal(e.Data, []int{257, 257, 257, 229}) || e.Body != body {
		t.Fatalf("data cuts %v body %d", e.Data, len(e.Body))
	}
}

func TestProfileJSONChangesH1LimitAndRedirectBoundary(t *testing.T) {
	for _, limit := range []int{1024, 4096} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			s := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Large", strings.Repeat("x", 2048))
				io.WriteString(w, "ok")
			})
			c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h1.response_header_bytes": limit})), s.dialing())
			_, err := c.Get("https://example.com/")
			if (err != nil) != (limit == 1024) {
				t.Fatalf("limit%d: %v", limit, err)
			}
		})
	}
	for _, kind := range []RequestKind{KindNavigation, KindFetch} {
		t.Run(string(kind), func(t *testing.T) {
			s := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Location", "/again"); w.WriteHeader(302) })
			c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"http.redirects_navigation": 2, "http.redirects_fetch": 1})), s.dialing())
			_, err := c.Do(&Request{URL: "https://example.com/start", Browser: &BrowserContext{Kind: kind, Initiator: "https://example.com/page"}})
			want := map[RequestKind]int{KindNavigation: 3, KindFetch: 2}[kind]
			if err == nil || len(s.requests()) != want {
				t.Fatalf("requests%d error%v", len(s.requests()), err)
			}
		})
	}
}

func TestProfileJSONChangesCookieAndCacheLimits(t *testing.T) {
	var count atomic.Int32
	s := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Add("Set-Cookie", "name=123456; Secure; Path=/")
		w.Header().Add("Set-Cookie", "a=1; Secure; Path=/; Max-Age=1000")
		io.WriteString(w, "12345")
	})
	p := policyFile(t, map[string]any{"cookie.max_pair_bytes": 8, "cookie.max_age_seconds": 10, "cache.entry_bytes": 4, "cache.total_bytes": 8, "cache.entries": 2})
	c := newTestClient(t, WithProfileValue(p), s.dialing())
	for range 2 {
		if _, err := c.Do(&Request{URL: "https://example.com/", Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
			t.Fatal(err)
		}
	}
	if count.Load() != 2 {
		t.Fatal("over-size response was cached")
	}
	cookies, err := c.CookiesFor("https://example.com/")
	if err != nil || len(cookies) != 1 || cookies[0].Name != "a" || cookies[0].Expires.After(time.Now().Add(11*time.Second)) {
		t.Fatalf("cookies %+v %v", cookies, err)
	}
}

func TestProfileJSONControlsTLSRetryWithoutRequestReplay(t *testing.T) {
	for _, retries := range []int{0, 2} {
		t.Run(fmt.Sprint(retries), func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); b, _ := io.ReadAll(r.Body); w.Write(b) }))
			ln := &badFirstTLS{Listener: srv.Listener, bad: 2, alerts: make(chan []byte, 8)}
			srv.Listener = ln
			srv.StartTLS()
			defer srv.Close()
			p := policyFile(t, map[string]any{"tls.handshake_retries": retries})
			c := newTestClient(t, WithProfileValue(p), WithTimeout(3*time.Second), WithTransportOption(tc.WithForceHttp1()))
			res, err := c.Do(&Request{URL: srv.URL, Method: "POST", Body: []byte("one effect")})
			if retries == 0 {
				if err == nil || requests.Load() != 0 || ln.accepts.Load() != 1 {
					t.Fatalf("error%v requests%d attempts%d", err, requests.Load(), ln.accepts.Load())
				}
			} else if err != nil || string(res.Body) != "one effect" || requests.Load() != 1 || ln.accepts.Load() != 3 {
				t.Fatalf("error%v response%v requests%d attempts%d", err, res, requests.Load(), ln.accepts.Load())
			}
		})
	}
}

func TestProfileJSONControlsActualQUICConnectionIDs(t *testing.T) {
	var once sync.Once
	ids := make(chan [2]int, 1)
	url, tcp, conns := h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { io.WriteString(w, "h3") }), func(b []byte, _ net.Addr) {
		if len(b) > 7 && b[0]&0xf0 == 0xc0 {
			n := int(b[5])
			if len(b) > 6+n {
				once.Do(func() { ids <- [2]int{n, int(b[6+n])} })
			}
		}
	})
	p := policyFile(t, map[string]any{"quic.initial_dcid_bytes": 12, "quic.source_cid_bytes": 4})
	c := newTestClient(t, WithProfileValue(p), WithTimeout(5*time.Second), WithTransportOption(tc.WithProtocolRacing()))
	res, err := c.Get(url)
	if err != nil || string(res.Body) != "h3" {
		t.Fatalf("%v %v", res, err)
	}
	select {
	case got := <-ids:
		if got != [2]int{12, 4} {
			t.Fatalf("wire CIDs %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no original Initial")
	}
	if tcp.Load() != 0 || conns.Load() != 1 {
		t.Fatalf("TCP %d QUIC %d", tcp.Load(), conns.Load())
	}
}

func TestProfileJSONControlsDigestNonceAndAlgorithms(t *testing.T) {
	s := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Add("WWW-Authenticate", `Digest realm="owned", nonce="one", algorithm=SHA-256, qop="auth"`)
			w.Header().Add("WWW-Authenticate", `Digest realm="owned", nonce="one", algorithm=MD5, qop="auth"`)
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, r.Header.Get("Authorization"))
	})
	p := policyFile(t, map[string]any{"http.digest_algorithms": []string{"SHA-256"}, "http.digest_cnonce_bytes": 16, "http.negotiate_auth": true})
	c := newTestClient(t, WithProfileValue(p), s.dialing())
	res, err := c.Get("https://owned:password@example.com/")
	if err != nil {
		t.Fatal(err)
	}
	value := string(res.Body)
	match := regexp.MustCompile(`cnonce="([0-9a-f]+)"`).FindStringSubmatch(value)
	if len(s.requests()) != 2 || !strings.Contains(value, "algorithm=SHA-256") || len(match) != 2 || len(match[1]) != 32 {
		t.Fatalf("Digest policy not on wire: %q", value)
	}
	if _, ok := c.challengeOf("Negotiate"); !ok {
		t.Fatal("explicit Negotiate disabled by neutral profile name")
	}
	p = policyFile(t, map[string]any{"http.negotiate_auth": false})
	p.Name = "chrome_155_windows"
	c2 := newTestClient(t, WithProfileValue(p), s.dialing())
	if _, ok := c2.challengeOf("Negotiate"); ok {
		t.Fatal("profile name enabled Negotiate")
	}
}

func TestProfileJSONControlsRawCookieAnchorAndNavigationMarker(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			s := newRecorder(t, proto, nil)
			p := policyFile(t, map[string]any{"headers.cookie_after": "accept", "headers.navigation_fetch_user": "?0"})
			c := newTestClient(t, WithProfileValue(p), s.dialing())
			if _, err := c.Do(&Request{URL: "https://example.com/raw", Cookies: []Cookie{{Name: "a", Value: "1"}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Do(&Request{URL: "https://example.com/nav", Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
				t.Fatal(err)
			}
			got := s.requests()
			var names []string
			for _, h := range got[0].headers {
				names = append(names, strings.ToLower(h[0]))
			}
			at := slices.Index(names, "accept")
			if at < 0 || at+1 >= len(names) || names[at+1] != "cookie" {
				t.Fatalf("cookie slot ignored: %v", names)
			}
			if v, ok := got[1].header("sec-fetch-user"); !ok || v != "?0" {
				t.Fatalf("navigation marker %q %v", v, ok)
			}
		})
	}
}
