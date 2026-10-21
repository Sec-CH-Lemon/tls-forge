package tlsforge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestRequestedHintSubsetsReachTheWireInChromeOrder(t *testing.T) {
	data, err := os.ReadFile("testdata/chrome155-requested-hint-order.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			ID    string   `json:"id"`
			Grant []string `json:"grant"`
			Order []string `json:"order"`
		}
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, tc := range f.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			proto := "h2"
			if strings.HasSuffix(tc.ID, "-h1") {
				proto = "h1"
			}
			server := newRecorder(t, proto, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/seed" {
					w.Header().Set("Accept-CH", strings.Join(tc.Grant, ", "))
				}
				fmt.Fprint(w, "ok")
			}))
			c := contextClient(t, server)
			if _, err := c.Do(&Request{URL: "https://example.com/seed", Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Do(&Request{URL: "https://example.com/probe", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/seed"}}); err != nil {
				t.Fatal(err)
			}
			requests := server.requests()
			if len(requests) != 2 {
				t.Fatalf("%d requests", len(requests))
			}
			var order []string
			for _, f := range requests[1].headers {
				if strings.HasPrefix(strings.ToLower(f[0]), "sec-ch-") {
					order = append(order, strings.ToLower(f[0]))
				}
			}
			if !slices.Equal(order, tc.Order) {
				t.Fatalf("wire order %v;Chrome %v", order, tc.Order)
			}
		})
	}
}

func TestPartitionedCookiesStayWithTheirTopLevelSite(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			s := newRecorder(t, proto, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				if value := r.URL.Query().Get("set"); value != "" {
					w.Header().Add("Set-Cookie", "chip="+value+"; Secure; SameSite=None; Partitioned; Path=/")
				}
				fmt.Fprint(w, r.Header.Get("Cookie"))
			}))
			c := contextClient(t, s)
			for _, tc := range []struct{ site, path, want string }{{"a.test", "/?set=A", ""}, {"b.test", "/read", ""}, {"b.test", "/?set=B", ""}, {"a.test", "/read", "chip=A"}, {"b.test", "/read", "chip=B"}} {
				r, err := c.Do(&Request{URL: "https://third.example" + tc.path, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://" + tc.site + "/page", Credentials: "include"}})
				if err != nil {
					t.Fatal(err)
				}
				if string(r.Body) != tc.want {
					t.Fatalf("%s%s:cookie %q,want %q", tc.site, tc.path, r.Body, tc.want)
				}
			}
		})
	}
}

func TestBrowserCacheUsesFreshResponsesAndConditionalRevalidation(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			var mu sync.Mutex
			counts := map[string]int{}
			s := newRecorder(t, proto, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "OPTIONS" {
					w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.Header().Set("Access-Control-Allow-Headers", "x-flavor")
					w.Header().Set("Access-Control-Allow-Methods", "GET")
					w.Header().Set("Access-Control-Max-Age", "600")
					w.WriteHeader(204)
					return
				}
				mu.Lock()
				counts[r.URL.Path]++
				mu.Unlock()
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				switch r.URL.Path {
				case "/fresh":
					w.Header().Set("Cache-Control", "max-age=60")
				case "/etag":
					w.Header().Set("Cache-Control", "max-age=0")
					w.Header().Set("ETag", `"v1"`)
					if r.Header.Get("If-None-Match") == `"v1"` {
						w.WriteHeader(304)
						return
					}
				case "/no-store":
					w.Header().Set("Cache-Control", "no-store,max-age=60")
				case "/vary":
					w.Header().Set("Cache-Control", "max-age=60")
					w.Header().Set("Vary", "X-Flavor")
				}
				fmt.Fprint(w, "page"+r.Header.Get("X-Flavor"))
			}))
			c := contextClient(t, s)
			for _, tc := range []struct{ path, site, flavor string }{{"/fresh", "a.test", ""}, {"/fresh", "a.test", ""}, {"/fresh", "b.test", ""}, {"/fresh", "a.test", ""}, {"/etag", "a.test", ""}, {"/etag", "a.test", ""}, {"/no-store", "a.test", ""}, {"/no-store", "a.test", ""}, {"/vary", "a.test", "A"}, {"/vary", "a.test", "B"}, {"/vary", "a.test", "A"}} {
				r, err := c.Do(&Request{URL: "https://third.example" + tc.path, Header: NewHeader("X-Flavor", tc.flavor), Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://" + tc.site + "/page", Credentials: "include"}})
				if err != nil {
					t.Fatal(err)
				}
				if r.Status != 200 || string(r.Body) != "page"+tc.flavor {
					t.Fatalf("%s:status%d body%q", tc.path, r.Status, r.Body)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			for path, want := range map[string]int{"/fresh": 2, "/etag": 2, "/no-store": 2, "/vary": 3} {
				if counts[path] != want {
					t.Errorf("%s:%d wire requests,want%d", path, counts[path], want)
				}
			}
			found := false
			for _, r := range s.requests() {
				for _, h := range r.headers {
					if strings.EqualFold(h[0], "if-none-match") && h[1] == `"v1"` {
						found = true
					}
				}
			}
			if !found {
				t.Error("no validator on actual wire")
			}
		})
	}
}

func TestGzipTrailerToleranceDoesNotAcceptTruncatedDeflate(t *testing.T) {
	payload := bytes.Repeat([]byte("browser body\n"), 3072)
	valid := gzipped(t, payload)
	crc := bytes.Clone(valid)
	crc[len(crc)-8] ^= 1
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			s := startCoded(t, proto.h2, map[string]coded{"/crc": {encoding: []string{"gzip"}, body: crc}, "/trailer": {encoding: []string{"gzip"}, body: valid[:len(valid)-6]}, "/payload": {encoding: []string{"gzip"}, body: valid[:len(valid)/2]}})
			c := newTestClient(t)
			for _, path := range []string{"/crc", "/trailer"} {
				r, err := c.Get(s.url + path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(r.Body, payload) {
					t.Fatalf("%s:changed body", path)
				}
			}
			if _, err := c.Get(s.url + "/payload"); err == nil {
				t.Error("truncated DEFLATE accepted")
			}
			if _, err := c.Get(s.url + "/crc"); err != nil {
				t.Fatalf("following request:%v", err)
			}
		})
	}
}

func TestBrowserResponseKeepsEncodedRepresentationHeaders(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			compressed := gzipped(t, page)
			s := startCoded(t, proto.h2, map[string]coded{"/body": {encoding: []string{"gzip"}, body: compressed}})
			c := newTestClient(t)
			r, err := c.Do(&Request{URL: s.url + "/body", Browser: &BrowserContext{Kind: KindFetch, Initiator: s.url + "/page"}})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(r.Body, page) || r.Encoding != "gzip" {
				t.Fatal("body was not decoded once")
			}
			if r.Header["content-encoding"][0] != "gzip" || r.Header["content-length"][0] != fmt.Sprint(len(compressed)) {
				t.Fatalf("received representation metadata:%v", r.Header)
			}
		})
	}
}

func TestFetchAndXHRFollowTwentyRedirects(t *testing.T) {
	for _, kind := range []RequestKind{KindFetch, KindXHR} {
		for _, n := range []int{19, 20, 21} {
			t.Run(fmt.Sprintf("%s/%d", kind, n), func(t *testing.T) {
				server, count := chainServer(t)
				client := newTestClient(t)
				res, err := client.Do(&Request{URL: fmt.Sprintf("%s/chain/%d", server.URL, n), Browser: &BrowserContext{Kind: kind, Initiator: server.URL + "/page"}})
				if n <= 20 {
					if err != nil || string(res.Body) != "landed" {
						t.Fatalf("response=%v,error=%v", res, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "the 21st redirect was not followed") {
					t.Fatalf("error=%v", err)
				}
				requests, ends := count()
				wantEnds := int32(0)
				if n <= 20 {
					wantEnds = 1
				}
				if requests != int32(min(n+1, 21)) || ends != wantEnds {
					t.Fatalf("requests=%d,ends=%d", requests, ends)
				}
			})
		}
	}
}

func TestScriptFieldsOwnOneWireSlot(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, nil)
			client := contextClient(t, server)
			_, err := client.Do(&Request{URL: "https://example.com/test", Header: NewHeader("Accept-Language", "en", "Priority", "u=4"), Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/page"}})
			if err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]string{"accept-language": "en", "priority": "u=4"} {
				values := []string{}
				for _, f := range server.requests()[0].headers {
					if strings.EqualFold(f[0], name) {
						values = append(values, f[1])
					}
				}
				// Chrome strips request Priority on H1;the field owns one slot on H2.
				if proto == "h1" && name == "priority" {
					if len(values) != 0 {
						t.Fatal(values)
					}
					continue
				}
				if !slices.Equal(values, []string{want}) {
					t.Fatalf("%s: %v", name, values)
				}
			}
		})
	}
}
