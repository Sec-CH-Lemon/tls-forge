package tlsforge

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestA10JSONCacheChoicesReachProduction(t *testing.T) {
	cases := []struct {
		name, key string
		value     any
		control   string
		implicit  bool
		requests  int
	}{
		{"invalid-ignore", "cache.invalid_freshness_policy", "ignore", "max-age=bogus", false, 1},
		{"invalid-stale", "cache.invalid_freshness_policy", "stale", "max-age=bogus", false, 2},
		{"quoted-reject", "cache.freshness_quoted_values", false, `max-age="600"`, false, 2},
		{"quoted-accept", "cache.freshness_quoted_values", true, `max-age="600"`, false, 1},
		{"delta-low", "cache.delta_seconds_limit", 100, "max-age=600", false, 2},
		{"delta-high", "cache.delta_seconds_limit", 1000, "max-age=600", false, 1},
		{"typed-network", "http.cache_scope", "explicit-context", "max-age=600", true, 2},
		{"typed-cache", "http.cache_scope", "browser-context", "max-age=600", true, 1},
	}
	for _, protocol := range []string{"h1", "h2"} {
		for _, tt := range cases {
			t.Run(protocol+"/"+tt.name, func(t *testing.T) {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					now := time.Now().UTC()
					w.Header().Set("Date", now.Format(http.TimeFormat))
					w.Header().Set("Age", "120")
					w.Header().Set("Cache-Control", tt.control)
					expiry := now.Add(-600 * time.Second)
					if tt.key == "cache.invalid_freshness_policy" {
						expiry = now.Add(600 * time.Second)
					}
					w.Header().Set("Expires", expiry.Format(http.TimeFormat))
					fmt.Fprint(w, "page")
				})
				p := policyFile(t, map[string]any{tt.key: tt.value})
				c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), s.dialing())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				req := &Request{URL: "https://www.example.com/cache"}
				if !tt.implicit {
					req.Browser = &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/start"}
				}
				for range 2 {
					r, e := c.Do(req)
					if e != nil || r.Status != 200 || string(r.Body) != "page" {
						t.Fatalf("%v %v", r, e)
					}
				}
				if got := len(s.requests()); got != tt.requests {
					t.Fatal(got, tt.requests)
				}
			})
		}
	}
}

func TestA10JSONSelectsOnlyTheNamedValidator(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "max-age=0")
				w.Header().Set("ETag", `"v1"`)
				w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
				if r.Header.Get("If-None-Match") != "" {
					t.Error("unselected validator on wire")
				}
				if r.Header.Get("If-Modified-Since") != "" {
					w.WriteHeader(304)
					return
				}
				fmt.Fprint(w, "page")
			})
			p := policyFile(t, map[string]any{"http.cache_validators": []string{"if-modified-since"}})
			c := newTestClient(t, WithProfileValue(p), s.dialing())
			for range 2 {
				r, e := c.Do(&Request{URL: "https://www.example.com/cache", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/start"}})
				if e != nil || r.Status != 200 || string(r.Body) != "page" {
					t.Fatalf("%v %v", r, e)
				}
			}
			got := s.requests()
			if len(got) != 2 || !strings.Contains(strings.ToLower(strings.Join(regular(got[1]), ",")), "if-modified-since") {
				t.Fatal("missing selected validator")
			}
		})
	}
}

func TestA10JSONOrdersGeneratedRangeOnTheWire(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, before := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/before=%v", protocol, before), func(t *testing.T) {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "max-age=600")
					w.Header().Set("ETag", `"v1"`)
					if r.Header.Get("If-None-Match") != "" {
						w.WriteHeader(304)
						return
					}
					body, content := "abcd", "bytes 0-3/8"
					if r.Header.Get("If-Range") != "" {
						body, content = "efgh", "bytes 4-7/8"
					}
					w.Header().Set("Content-Range", content)
					w.WriteHeader(206)
					fmt.Fprint(w, body)
				})
				values := map[string]any{}
				if before {
					values["cache.generated_header_order"] = []string{"range", "if-range", "if-none-match", "if-modified-since", "priority"}
				}
				c := newTestClient(t, WithProfileValue(policyFile(t, values)), s.dialing())
				browser := &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/start"}
				if r, e := c.Do(&Request{URL: "https://www.example.com/cache", Browser: browser, Header: NewHeader("Range", "bytes=0-3")}); e != nil || r.Status != 206 || string(r.Body) != "abcd" {
					t.Fatalf("%v %v", r, e)
				}
				if r, e := c.Do(&Request{URL: "https://www.example.com/cache", Browser: browser}); e != nil || r.Status != 200 || string(r.Body) != "abcdefgh" {
					t.Fatalf("%v %v", r, e)
				}
				got := s.requests()
				if len(got) != 3 {
					t.Fatal("prefix validation/completion missing", len(got))
				}
				rangeAt, tagAt := -1, -1
				for i, name := range regular(got[1]) {
					switch strings.ToLower(name) {
					case "range":
						rangeAt = i
					case "if-none-match":
						tagAt = i
					}
				}
				if rangeAt < 0 || tagAt < 0 || (rangeAt < tagAt) != before {
					t.Fatal("JSON relative order lost", regular(got[1]))
				}
			})
		}
	}
}
