package tlsforge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChromeH1ResponseHeadBoundaryAndRecovery(t *testing.T) {
	for _, n := range []int{262143, 262144, 262145, 270000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/after" {
					io.WriteString(w, "ok")
					return
				}
				c, b, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				prefix := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Limit: "
				io.WriteString(b, prefix+strings.Repeat("a", n-len(prefix)-4)+"\r\n\r\nok")
				b.Flush()
			})
			c := contextClient(t, s)
			_, err := c.Get("https://example.com/test")
			if (err != nil) != (n > 262144) {
				t.Fatalf("head %d: %v", n, err)
			}
			r, err := c.Get("https://example.com/after")
			if err != nil || string(r.Body) != "ok" {
				t.Fatalf("recovery: %v %v", r, err)
			}
		})
	}
}

func TestChromeHuffmanHeaderBudgetPreservesH2Connection(t *testing.T) {
	s := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			w.Header().Set("X-Limit", strings.Repeat("a", 270000))
		}
		io.WriteString(w, "ok")
	})
	c := contextClient(t, s)
	if _, err := c.Get("https://example.com/seed"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("https://example.com/large"); err == nil {
		t.Fatal("over-budget header accepted")
	}
	r, err := c.Get("https://example.com/after")
	if err != nil || string(r.Body) != "ok" {
		t.Fatalf("recovery: %v %v", r, err)
	}
	got := s.requests()
	if len(got) != 3 || got[0].conn != got[2].conn {
		t.Fatal("header rejection lost the shared H2 connection")
	}
}

func TestChromeH1QueuesAndCancelsBeforeOriginContact(t *testing.T) {
	var count atomic.Int32
	six := make(chan struct{})
	release := make(chan struct{})
	s := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			if count.Add(1) == 6 {
				close(six)
			}
			<-release
		}
		io.WriteString(w, "ok")
	})
	c := contextClient(t, s)
	done := make(chan error, 6)
	for range 6 {
		go func() { _, err := c.Get("https://example.com/hold"); done <- err }()
	}
	select {
	case <-six:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("six concurrent requests did not arrive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	_, err := c.Do(&Request{URL: "https://example.com/hold", Context: ctx})
	cancel()
	close(release)
	for range 6 {
		if e := <-done; e != nil {
			t.Error(e)
		}
	}
	if err == nil || count.Load() != 6 {
		t.Fatalf("canceled queued request reached origin: count=%d err=%v", count.Load(), err)
	}
	if _, err := c.Get("https://example.com/after"); err != nil {
		t.Fatal(err)
	}
}

func TestChromeCookieBytesAndReplacementReachBothProtocols(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/set":
					for _, cookie := range []string{"bad name=value; Secure; Path=/", "lab=a b; Secure; Path=/", "slash=a\\b; Secure; Path=/", "=owned; Secure; Path=/", "café=café; Secure; Path=/"} {
						w.Header().Add("Set-Cookie", cookie)
					}
				case "/change":
					w.Header().Add("Set-Cookie", "lab=changed; Secure; Path=/")
				case "/same":
					w.Header().Add("Set-Cookie", "bad name=value; Secure; Path=/; Max-Age=30")
				}
				io.WriteString(w, "ok")
			})
			c := contextClient(t, s)
			for _, path := range []string{"/set", "/probe", "/same", "/probe", "/change", "/probe"} {
				if _, err := c.Get("https://example.com" + path); err != nil {
					t.Fatal(err)
				}
			}
			got := s.requests()
			want := "bad name=value; lab=a b; slash=a\\b; owned; café=café"
			cookie := func(q *keptRequest) string {
				var parts []string
				for _, h := range q.headers {
					if strings.EqualFold(h[0], "cookie") {
						parts = append(parts, h[1])
					}
				}
				return strings.Join(parts, "; ")
			}
			for _, i := range []int{1, 3} {
				if v := cookie(got[i]); v != want {
					t.Fatalf("%s cookie bytes %q,want %q", proto, v, want)
				}
			}
			want = "bad name=value; slash=a\\b; owned; café=café; lab=changed"
			if v := cookie(got[5]); v != want {
				t.Fatalf("replacement cookie %q,want %q", v, want)
			}
		})
	}
}

func TestBrowserExposesOriginalChunkedDeclarations(t *testing.T) {
	s := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
		c, b, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		io.WriteString(b, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Edge\r\n\r\n2\r\nok\r\n0\r\nX-Edge: final\r\n\r\n")
		b.Flush()
	})
	c := contextClient(t, s)
	r, err := c.Do(&Request{URL: "https://example.com/test", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "ok" || strings.Join(r.Header["transfer-encoding"], ",") != "chunked" || strings.Join(r.Header["trailer"], ",") != "X-Edge" || len(r.Header["x-edge"]) != 0 {
		t.Fatalf("browser framing metadata: %#v", r)
	}
	r, err = c.Get("https://example.com/test")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Header["transfer-encoding"])+len(r.Header["trailer"]) != 0 {
		t.Fatal("low-level dechunked contract changed")
	}
}

func TestChromeMissingNumericH1StatusUsesBrowserFallback(t *testing.T) {
	s := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
		c, b, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		io.WriteString(b, "HTTP/1.1 nope Invalid\r\nContent-Length: 0\r\n\r\n")
		b.Flush()
	})
	c := contextClient(t, s)
	r, err := c.Get("https://example.com/test")
	if err != nil || r.Status != 200 || len(r.Body) != 0 {
		t.Fatalf("Chrome fallback: %v %v", r, err)
	}
}

func TestCriticalCHNavigationRestartsOnMissingGrantedHint(t *testing.T) {
	s := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
		w.Header()["accept-ch"] = []string{"sec-ch-ua-arch"}
		w.Header()["critical-ch"] = []string{"sec-ch-ua-arch"}
		io.WriteString(w, "ok")
	})
	c := contextClient(t, s)
	_, err := c.Do(&Request{URL: "https://ctx-010-critical-navigation-h1.netfp.test:19100/test", Browser: &BrowserContext{Kind: KindNavigation}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.requests(); len(got) != 2 {
		t.Fatalf("got %d requests,profile hints=%v,stored=%v", len(got), c.profile.ClientHints, c.session.hints.asked)
	}
}

func TestNarrowPreflightGrantReplacesPreviousPermissions(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			var options atomic.Int32
			s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				if r.Method == "OPTIONS" {
					options.Add(1)
					w.Header().Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
					w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
					w.Header().Set("Access-Control-Max-Age", "60")
					w.WriteHeader(204)
					return
				}
				io.WriteString(w, "ok")
			})
			c := contextClient(t, s)
			for _, method := range []string{"PUT", "PUT", "DELETE", "PUT"} {
				_, err := c.Do(&Request{URL: "https://other.example/test", Method: method, Header: NewHeader("X-Lab", "one"), Body: []byte("owned"), Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed", Credentials: "include"}})
				if err != nil {
					t.Fatal(err)
				}
			}
			if options.Load() != 3 {
				t.Fatalf("preflights=%d,want 3", options.Load())
			}
		})
	}
}

func TestBrowserCacheRevalidatesHEADAndRetainsGETBody(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "max-age=0")
				w.Header().Set("ETag", `"v1"`)
				if r.Header.Get("If-None-Match") == `"v1"` {
					w.Header().Set("X-Version", "updated")
					w.WriteHeader(304)
					return
				}
				io.WriteString(w, "owned")
			})
			c := contextClient(t, s)
			for _, method := range []string{"GET", "HEAD", "GET"} {
				r, err := c.Do(&Request{URL: "https://example.com/test", Method: method, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}})
				if err != nil {
					t.Fatal(err)
				}
				want := "owned"
				if method == "HEAD" {
					want = ""
				}
				if r.Status != 200 || string(r.Body) != want {
					t.Fatalf("%s cache response: %v", method, r)
				}
			}
			got := s.requests()
			if len(got) != 3 {
				t.Fatalf("requests=%d", len(got))
			}
			for _, i := range []int{1, 2} {
				found := false
				for _, h := range got[i].headers {
					found = found || strings.EqualFold(h[0], "if-none-match") && h[1] == `"v1"`
				}
				if !found {
					t.Fatalf("missing conditional %s", got[i].method)
				}
			}
		})
	}
}

func TestBrowserCacheKeepsExplicitlyFreshRedirects(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		for _, status := range []int{301, 302, 307, 308} {
			t.Run(fmt.Sprintf("%s-%d", proto, status), func(t *testing.T) {
				s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "max-age=60")
					if r.URL.Path == "/start" {
						w.Header().Set("Location", "/final")
						w.WriteHeader(status)
						io.WriteString(w, "hop")
						return
					}
					io.WriteString(w, "owned")
				})
				c := contextClient(t, s)
				for range 2 {
					r, err := c.Do(&Request{URL: "https://example.com/start", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}})
					if err != nil || string(r.Body) != "owned" {
						t.Fatalf("redirect: %v %v", r, err)
					}
				}
				if got := s.requests(); len(got) != 2 {
					t.Fatalf("fresh redirect repeated origin traffic: %d", len(got))
				}
			})
		}
	}
}

// A redirect is kept complete without its body, which Chrome never reads:
// one whose body has not come when the client goes on from it, over HTTP/2
// where its stream is reset then, and one larger than HTTP/1.1's drain, are
// kept as one whose body came at once.
func TestBrowserCacheKeepsARedirectWithoutItsBody(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		for _, status := range []int{301, 302, 307, 308} {
			for _, body := range []string{"held", "large"} {
				t.Run(fmt.Sprintf("%s-%d-%s", proto, status, body), func(t *testing.T) {
					release := make(chan struct{})
					s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Cache-Control", "max-age=60")
						if r.URL.Path != "/start" {
							io.WriteString(w, "owned")
							return
						}
						w.Header().Set("Location", "/final")
						if body == "large" {
							w.WriteHeader(status)
							io.WriteString(w, strings.Repeat("x", 16385))
							return
						}
						w.Header().Set("Content-Length", "3")
						w.WriteHeader(status)
						w.(http.Flusher).Flush()
						<-release
						io.WriteString(w, "hop")
					})
					t.Cleanup(func() { close(release) })
					c := contextClient(t, s)
					for i := range 2 {
						r, err := c.Do(&Request{URL: "https://example.com/start", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}})
						if err != nil || string(r.Body) != "owned" {
							t.Fatalf("round %d: %v %v", i+1, r, err)
						}
					}
					if got := s.requests(); len(got) != 2 {
						t.Fatalf("the origin was asked %d times", len(got))
					}
				})
			}
		}
	}
}

func TestBrowserCacheCoalescesIdenticalBufferedRequests(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			var count atomic.Int32
			s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.Header().Set("Cache-Control", "max-age=60")
				time.Sleep(50 * time.Millisecond)
				io.WriteString(w, "owned")
			})
			c := contextClient(t, s)
			done := make(chan error, 12)
			for range 12 {
				go func() {
					r, err := c.Do(&Request{URL: "https://example.com/test", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}})
					if err == nil && string(r.Body) != "owned" {
						err = fmt.Errorf("body %q", r.Body)
					}
					done <- err
				}()
			}
			for range 12 {
				if err := <-done; err != nil {
					t.Error(err)
				}
			}
			if n := count.Load(); n != 1 {
				t.Fatalf("identical network requests=%d,want 1", n)
			}
		})
	}
}

func TestBrowserRangeNetworkFieldsAndCompleteCacheHit(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "max-age=60")
				w.Header().Set("ETag", `"v1"`)
				io.WriteString(w, "0123456789abcdefghij")
			})
			c := contextClient(t, s)
			fetch := func(path string, h Header) *Response {
				t.Helper()
				r, err := c.Do(&Request{URL: "https://example.com/" + path, Header: h, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}})
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			fetch("complete", nil)
			r := fetch("complete", NewHeader("range", "bytes=0-4"))
			if r.Status != 206 || string(r.Body) != "01234" || strings.Join(r.Header["content-range"], "") != "bytes 0-4/20" || len(s.requests()) != 1 {
				t.Fatalf("cached range: %v requests=%d", r, len(s.requests()))
			}
			fetch("network", NewHeader("range", "bytes=0-4"))
			fetch("conditional", NewHeader("range", "bytes=0-4", "if-range", `"v1"`))
			got := s.requests()
			get := func(q *keptRequest, name string) (int, string) {
				for i, h := range q.headers {
					if strings.EqualFold(h[0], name) {
						return i, h[1]
					}
				}
				return -1, ""
			}
			ri, _ := get(got[1], "range")
			li, _ := get(got[1], "accept-language")
			_, encoding := get(got[1], "accept-encoding")
			if ri <= li || encoding != "identity" {
				t.Fatalf("network Range slot/encoding: %v", got[1].headers)
			}
			if proto == "h1" && got[1].headers[ri][0] != "Range" {
				t.Fatalf("network Range spelling: %v", got[1].headers)
			}
			ci, cc := get(got[2], "cache-control")
			ri, _ = get(got[2], "range")
			_, encoding = get(got[2], "accept-encoding")
			if ci < 0 || ci >= ri || cc != "max-age=0" || encoding != "identity" {
				t.Fatalf("If-Range fields: %v", got[2].headers)
			}
		})
	}
}

func TestBrowserPartialCacheValidatesBeforeJoining(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		for _, mode := range []string{"same", "changed", "wrong-range", "wrong-tag", "truncated", "weak"} {
			t.Run(proto+"-"+mode, func(t *testing.T) {
				var count atomic.Int32
				s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
					count.Add(1)
					w.Header().Set("Cache-Control", "max-age=60")
					w.Header().Set("ETag", `"v1"`)
					if r.Header.Get("If-None-Match") == `"v1"` {
						w.WriteHeader(304)
						return
					}
					if r.Header.Get("Range") == "bytes=0-4" {
						if mode == "weak" {
							w.Header().Set("ETag", `W/"v1"`)
						}
						w.Header().Set("Content-Range", "bytes 0-4/20")
						w.WriteHeader(206)
						io.WriteString(w, "01234")
						return
					}
					if r.Header.Get("Range") == "bytes=5-19" {
						if r.Header.Get("If-Range") != `"v1"` {
							t.Error("missing strong If-Range")
						}
						if mode == "changed" {
							w.Header().Set("ETag", `"v2"`)
							io.WriteString(w, "new entity")
							return
						}
						w.Header().Set("Content-Range", "bytes 5-19/20")
						if mode == "wrong-range" {
							w.Header().Set("Content-Range", "bytes 4-18/20")
						}
						if mode == "wrong-tag" {
							w.Header().Set("ETag", `"v2"`)
						}
						w.WriteHeader(206)
						body := "56789abcdefghij"
						if mode == "truncated" {
							body = "56789"
						}
						io.WriteString(w, body)
						return
					}
					io.WriteString(w, "0123456789abcdefghij")
				})
				c := contextClient(t, s)
				fetch := func(h Header) (*Response, error) {
					return c.Do(&Request{URL: "https://example.com/test", Header: h, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}})
				}
				if r, err := fetch(NewHeader("range", "bytes=0-4")); err != nil || string(r.Body) != "01234" {
					t.Fatalf("initial prefix: %v %v", r, err)
				}
				r, err := fetch(nil)
				if mode == "truncated" {
					if err == nil {
						t.Fatal("truncated prefix completion accepted")
					}
				} else {
					want := "0123456789abcdefghij"
					if mode == "changed" {
						want = "new entity"
					}
					if err != nil || r.Status != 200 || string(r.Body) != want {
						t.Fatalf("full entity: %v %v", r, err)
					}
				}
				wantCount := int32(3)
				if mode == "weak" {
					wantCount = 2
				}
				if mode == "wrong-range" || mode == "wrong-tag" {
					wantCount = 4
				}
				if count.Load() != wantCount {
					t.Fatalf("network count=%d,want %d", count.Load(), wantCount)
				}
				if _, err := fetch(nil); err != nil {
					t.Fatal(err)
				}
				if mode != "truncated" && count.Load() != wantCount {
					t.Fatal("complete entity not cached")
				}
			})
		}
	}
}
