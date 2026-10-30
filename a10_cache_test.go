package tlsforge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	tc "github.com/igor-lemon/tls-client"
)

type a10CacheCase struct {
	ID                  string   `json:"id"`
	Control             []string `json:"cache_control"`
	Expires, Validators string
	Changed             bool
	Requests            int `json:"origin_requests"`
	API                 []struct {
		Status int
		Body   string
	} `json:"api"`
}

func TestA10CacheProductionMatrix(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome156-cache-a10.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Cases []a10CacheCase }
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			var mu sync.Mutex
			counts := map[string]int{}
			answer := func(header fhttp.Header, path string, request fhttp.Header) (int, string) {
				mu.Lock()
				defer mu.Unlock()
				counts[path]++
				n := counts[path]
				for _, s := range fixture.Cases {
					if path != "/case/"+s.ID {
						continue
					}
					now := time.Now().UTC()
					expiry := now.Add(-600 * time.Second)
					if s.Expires == "future" {
						expiry = now.Add(600 * time.Second)
					}
					for _, v := range s.Control {
						header.Add("Cache-Control", v)
					}
					header.Set("Date", now.Format(http.TimeFormat))
					header.Set("Age", "120")
					header.Set("Expires", expiry.Format(http.TimeFormat))
					if s.Validators == "both" || s.Validators == "etag" {
						header.Set("ETag", `"v1"`)
					}
					if s.Validators == "both" || s.Validators == "modified" {
						header.Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
					}
					if n > 1 && s.Validators != "" {
						if (s.Validators == "both" || s.Validators == "etag") && request.Get("If-None-Match") != `"v1"` {
							t.Error("missing ETag validator", s.ID, request)
						}
						if (s.Validators == "both" || s.Validators == "modified") && request.Get("If-Modified-Since") != "Wed, 21 Oct 2026 07:28:00 GMT" {
							t.Error("missing date validator", s.ID, request)
						}
						if !s.Changed {
							return 304, ""
						}
					}
					return 200, fmt.Sprintf("body-%s-%d", s.ID, n)
				}
				t.Error("unknown stimulus", path)
				return 404, ""
			}
			var origin string
			opts := []Option{WithInsecureSkipVerify()}
			if protocol == "h3" {
				u, tcpRequests, _ := h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
					if r.ProtoMajor != 3 {
						t.Error(r.Proto)
					}
					status, body := answer(w.Header(), r.URL.Path, r.Header)
					w.WriteHeader(status)
					fmt.Fprint(w, body)
				}))
				origin = u
				opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
				defer func() {
					if tcpRequests.Load() != 0 {
						t.Error("H3 fell back to TCP")
					}
				}()
			} else {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					status, body := answer(fhttp.Header(w.Header()), r.URL.Path, fhttp.Header(r.Header))
					w.WriteHeader(status)
					fmt.Fprint(w, body)
				})
				origin = "https://www.example.com"
				opts = append(opts, s.dialing())
			}
			p := policyFile(t, map[string]any{"http.instance_scope": "client"})
			c, err := New(append(opts, WithProfileValue(p))...)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for _, s := range fixture.Cases {
				for i, want := range s.API {
					r, e := c.Do(&Request{URL: origin + "/case/" + s.ID, Browser: &BrowserContext{Kind: KindFetch, Initiator: origin + "/start"}})
					if e != nil {
						t.Fatal(s.ID, i, e)
					}
					if r.Status != want.Status || string(r.Body) != want.Body {
						t.Errorf("%s/%d: %d %q, want %d %q", s.ID, i, r.Status, r.Body, want.Status, want.Body)
					}
				}
				mu.Lock()
				n := counts["/case/"+s.ID]
				mu.Unlock()
				if n != s.Requests {
					t.Errorf("%s origin count %d want %d", s.ID, n, s.Requests)
				}
			}
		})
	}
}

func TestA10JSONControlsFreshnessAndValidatorWireOrder(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, strategy := range []string{"first", "stale"} {
			t.Run(protocol+"/"+strategy, func(t *testing.T) {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "max-age=600,max-age=600")
					w.Header().Set("ETag", `"v1"`)
					w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
					if r.Header.Get("If-Modified-Since") != "" {
						w.WriteHeader(304)
						return
					}
					fmt.Fprint(w, "page")
				})
				p := policyFile(t, map[string]any{"http.instance_scope": "client", "cache.duplicate_freshness_policy": strategy})
				// Swap actual JSON slots. This must change the network order while profile
				// name and User-Agent remain irrelevant to the selected strategy.
				order := p.Behavior.Strings("headers.script_trailing")
				for i, name := range order {
					switch name {
					case "if-none-match":
						order[i] = "if-modified-since"
					case "if-modified-since":
						order[i] = "if-none-match"
					}
				}
				p = policyFile(t, map[string]any{"http.instance_scope": "client", "cache.duplicate_freshness_policy": strategy, "headers.script_trailing": order})
				c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), s.dialing())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				for range 2 {
					r, e := c.Do(&Request{URL: "https://www.example.com/cache", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/start"}})
					if e != nil || r.Status != 200 || string(r.Body) != "page" {
						t.Fatalf("%v %v", r, e)
					}
				}
				got := s.requests()
				want := 1
				if strategy == "stale" {
					want = 2
				}
				if len(got) != want {
					t.Fatalf("origin requests=%d want%d", len(got), want)
				}
				if want == 2 {
					names := regular(got[1])
					a, b := -1, -1
					for i, name := range names {
						switch strings.ToLower(name) {
						case "if-none-match":
							a = i
						case "if-modified-since":
							b = i
						}
					}
					if a < 0 || b < 0 || b >= a {
						t.Fatal("JSON validator order lost", names)
					}
				}
			})
		}
	}
}
