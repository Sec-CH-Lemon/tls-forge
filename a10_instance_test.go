package tlsforge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls/http3"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The target observes state, connections and request count independently of
// client traces. A cold browser gets the configured input, never another
// browser's received cookies, hints, validators or cached body.
func TestA10EachDoIsAFreshBrowser(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, kind := range []string{"typed", "fetch", "fresh"} {
			t.Run(fmt.Sprintf("h2=%v/%s", h2, kind), func(t *testing.T) {
				var mu sync.Mutex
				var asked []string
				site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					asked = append(asked, r.RemoteAddr)
					for _, field := range []string{"Cookie", "If-None-Match", "If-Modified-Since", "Sec-Ch-Ua-Arch"} {
						if value := r.Header.Get(field); value != "" {
							t.Errorf("new instance inherited %s=%q", field, value)
						}
					}
					w.Header().Set("Cache-Control", "max-age=600")
					w.Header().Set("ETag", `"v1"`)
					w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
					w.Header().Set("Set-Cookie", "received=secret; Path=/; Secure; SameSite=None")
					w.Header().Set("Accept-CH", "Sec-CH-UA-Arch")
					_, _ = fmt.Fprintf(w, "body-%d", len(asked))
				}))
				site.EnableHTTP2 = h2
				site.StartTLS()
				t.Cleanup(site.Close)
				c, err := New(WithInsecureSkipVerify())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				for i := 1; i <= 2; i++ {
					current := c
					if kind == "fresh" && i == 2 {
						current, err = c.Fresh()
						if err != nil {
							t.Fatal(err)
						}
						defer current.Close()
					}
					req := &Request{URL: site.URL + "/page"}
					if kind != "typed" {
						req.Browser = &BrowserContext{Kind: KindFetch, Initiator: site.URL + "/start"}
					}
					res, e := current.Do(req)
					if e != nil {
						t.Fatal(e)
					}
					if string(res.Body) != fmt.Sprintf("body-%d", i) {
						t.Errorf("call%d body=%q", i, res.Body)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if len(asked) != 2 {
					t.Errorf("origin requests=%d,want2", len(asked))
				} else if asked[0] == asked[1] {
					t.Errorf("two browser instances reused connection %s", asked[0])
				}
				t.Logf("origin peers=%v", asked)
			})
		}
	}
}

func TestA10ParallelDoDoesNotCollapseBrowserInstances(t *testing.T) {
	var mu sync.Mutex
	peers := map[string]bool{}
	count := 0
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		n := count
		peers[r.RemoteAddr] = true
		mu.Unlock()
		time.Sleep(40 * time.Millisecond)
		w.Header().Set("Cache-Control", "max-age=600")
		_, _ = fmt.Fprintf(w, "body-%d", n)
	}))
	site.EnableHTTP2 = true
	site.StartTLS()
	t.Cleanup(site.Close)
	c, err := New(WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, e := c.Do(&Request{URL: site.URL, Browser: &BrowserContext{Kind: KindFetch, Initiator: site.URL + "/page"}, Context: ctx})
			if e != nil || res == nil || !strings.HasPrefix(string(res.Body), "body-") {
				t.Errorf("Do=%v,%v", res, e)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if count != 4 || len(peers) != 4 {
		t.Errorf("requests=%d connections=%d,want4/4", count, len(peers))
	}
}

func TestA10RedirectsShareOnlyTheirOwnBrowser(t *testing.T) {
	var mu sync.Mutex
	var peers []string
	var initialCookies []string
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		peers = append(peers, r.RemoteAddr)
		if r.URL.Path == "/start" {
			initialCookies = append(initialCookies, r.Header.Get("Cookie"))
			w.Header().Set("Set-Cookie", "chain=secret; Path=/; Secure")
			w.Header().Set("Location", "/end")
			w.WriteHeader(302)
			return
		}
		if r.Header.Get("Cookie") != "chain=secret" {
			t.Error("redirect lost its browser cookie", r.Header)
		}
		fmt.Fprint(w, "landed")
	}))
	defer site.Close()
	c, err := New(WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 2 {
		res, e := c.Get(site.URL + "/start")
		if e != nil || res.Status != 200 || string(res.Body) != "landed" {
			t.Fatalf("%v %v", res, e)
		}
		cookies := res.AllCookies()
		if len(cookies) != 1 || cookies[0].Name != "chain" {
			t.Fatal(cookies)
		}
		cookies[0].Value = "mutated"
		if res.AllCookies()[0].Value != "secret" {
			t.Fatal("mutable snapshot")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(peers) != 4 || peers[0] != peers[1] || peers[2] != peers[3] || peers[0] == peers[2] {
		t.Fatal("redirect ownership", peers)
	}
	for _, cookie := range initialCookies {
		if cookie != "" {
			t.Fatal("next browser inherited cookie", cookie)
		}
	}
	if len(c.AllCookies()) != 0 {
		t.Fatal("factory received cookies")
	}
}

func TestA10H3RequestsOwnConnectionsAndState(t *testing.T) {
	var mu sync.Mutex
	var peers []string
	udp, tcp := udpAndTCP(t)
	defer tcp.Close()
	defer udp.Close()
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := seed.TLS.Certificates[0]
	seed.Close()
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.ProtoMajor != 3 {
			t.Error(r.Proto)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("If-None-Match") != "" {
			t.Error("inherited state", r.Header)
		}
		peers = append(peers, r.RemoteAddr)
		w.Header().Set("Set-Cookie", "received=secret; Path=/; Secure; SameSite=None")
		w.Header().Set("Cache-Control", "max-age=600")
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprintf(w, "body-%d", len(peers))
	})}
	go func() { _ = server.Serve(udp) }()
	defer server.Close()
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"h3.h3.test": service(1, "h3.h3.test", alpnParam("h3"))}, 0, 0)
	url := "https://h3.h3.test:" + port
	c, err := New(WithInsecureSkipVerify(), WithDNSServer(dns.addr), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 1; i <= 2; i++ {
		r, e := c.Do(&Request{URL: url + "/page", Browser: &BrowserContext{Kind: KindFetch, Initiator: url + "/start"}})
		if e != nil || r.Status != 200 || string(r.Body) != fmt.Sprintf("body-%d", i) {
			t.Fatalf("%v %v", r, e)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(peers) != 2 || peers[0] == peers[1] {
		t.Fatal(peers)
	}
}

func TestA10OpaqueSharedInputsAreRejectedBeforeConstruction(t *testing.T) {
	count := 0
	option := WithTransportOption(tc.WithTransportWrapper(func(tr fhttp.RoundTripper) fhttp.RoundTripper { count++; return tr }))

	if c, err := New(option); err == nil {
		c.Close()
		t.Fatal("accepted opaque option")
	}
	if count != 0 {
		t.Fatal("transport was constructed")
	}
}

func TestA10FailureSnapshotIsPrivateAndPreservesCause(t *testing.T) {
	cause := context.Canceled
	e := &RequestError{cause: cause, cookies: []Cookie{{Name: "received", Value: "secret"}}}
	if e.Error() != cause.Error() || !errors.Is(e, cause) {
		t.Fatal("lost cause", e)
	}
	cookies := e.AllCookies()
	cookies[0].Value = "changed"
	if e.AllCookies()[0].Value != "secret" {
		t.Fatal("snapshot is mutable")
	}
}

func TestA10ConstructionAndCloseRacesSendNothing(t *testing.T) {
	original := newInnerClient
	t.Cleanup(func() { newInnerClient = original })
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.prototype.timeout = 0
	if _, err = c.Get("https://never.test"); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatal(err)
	}
	c.prototype.timeout = Timeout
	closed := false
	newInnerClient = func(logger tc.Logger, opts ...tc.HttpClientOption) (tc.HttpClient, error) {
		if !closed {
			closed = true
			c.Close()
		}
		return original(logger, opts...)
	}
	if _, err = c.Get("https://never.test"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatal(err)
	}
}

func TestA10OpaqueJarCannotCrossBrowserOwnership(t *testing.T) {
	jar, err := newDefaultCookieJar()
	if err != nil {
		t.Fatal(err)
	}
	if c, e := New(WithCookieJar(jar)); e == nil {
		c.Close()
		t.Fatal("accepted shared jar")
	}
	c := newTestClient(t, WithCookieJar(jar))
	if _, e := c.Fresh(); e == nil {
		t.Fatal("cloned opaque jar")
	}
	c.profile.EngineMajor = new(int)
	if _, e := c.Get("https://never.test"); e == nil {
		t.Fatal("invalidated profile executed")
	}
}

func TestA10AuthenticationStaysInsideItsRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Header.Get("Authorization") != "Basic dTpw" {
			w.Header().Set("WWW-Authenticate", `Basic realm="owned"`)
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, "authenticated")
	}))
	defer site.Close()
	c, err := New(WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	credentialsURL := strings.Replace(site.URL, "https://", "https://u:p@", 1)
	first, err := c.Get(credentialsURL)
	if err != nil || first.Status != 200 {
		t.Fatalf("challenge restart %v %v", first, err)
	}
	second, err := c.Get(site.URL)
	if err != nil || second.Status != 401 {
		t.Fatalf("next browser inherited auth %v %v", second, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ",") != ",Basic dTpw," {
		t.Fatal(seen)
	}
}

func TestA10RequestInstancesNeverResumeEachOthersTLS(t *testing.T) {
	var mu sync.Mutex
	var resumed []bool
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		resumed = append(resumed, r.TLS.DidResume)
		mu.Unlock()
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "page")
	}))
	defer site.Close()
	for _, scope := range []string{"client", "request"} {
		p := shippedProfile(t, "chrome_150_PSK").Clone()
		p.Behavior["http.instance_scope"] = json.RawMessage(`"` + scope + `"`)
		c, err := New(WithProfileValue(p), WithInsecureSkipVerify())
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, e := c.Get(site.URL); e != nil {
				t.Fatal(e)
			}
		}
		c.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(resumed, []bool{false, true, false, false}) {
		t.Fatal("positive resumption control / isolated browsers", resumed)
	}
}
