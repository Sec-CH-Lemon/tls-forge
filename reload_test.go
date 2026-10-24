package tlsforge

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// A page reloaded as Ctrl+R reloads it, held to Chrome's:
// testdata/chrome155-reload.json, Chrome 155 driven over its DevTools port,
// each page refused (403) the first time it was asked for, then reloaded:
// typed, reached by a person's click or by its page's script, a form's POST
// clicked or submitted by its page's script.

type reloadFixture struct {
	Scenarios map[string]reloadScenario `json:"scenarios"`
}

type reloadScenario struct {
	H2 []reloadRequest `json:"h2"`
	H1 []reloadRequest `json:"h1"`
}

// reloadRequest is a request Chrome sent: where, on which of the run's
// connections, its fields, its body and the status it was answered with.
type reloadRequest struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Conn    int         `json:"conn"`
	Headers [][2]string `json:"headers"`
	Body    string      `json:"body"`
	Status  int         `json:"status"`
}

// reloadKinds say how each scenario reached the page it reloads: typed (no
// kind), or from the page its first request opened, by a link or a form, a
// person's click or the page's script; redirected or not.
var reloadKinds = map[string]struct {
	kind    RequestKind
	clicked bool
}{
	"typed": {}, "typed-empty": {}, "typed-twice": {},
	"link": {KindNavigation, true}, "form": {KindForm, true},
	"script-nav": {KindNavigation, false}, "script-form": {KindForm, false},
	"redirected-typed": {}, "redirected-link": {KindNavigation, true},
	"redirected-form307": {KindForm, true}, "redirected-form302": {KindForm, true},
}

// reloadNotSent are the scenarios tls-forge does not send as Chrome did.
var reloadNotSent = map[string]string{
	"typed-hard": "a reload that bypasses the cache (Ctrl+Shift+R: Pragma and Cache-Control no-cache) is not modelled",
}

func readReloadFixture(t *testing.T) reloadFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/chrome155-reload.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var fixture reloadFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return fixture
}

// refusingAsTheOrderServer answers as the bench's order server did: the
// first n (1) requests for /deny/NAME are refused (403), with cookie setting
// dn and dl to the request's number, asking for the client hints ch, with no
// body with empty; /r redirects to to by status (302); every other request
// is a page.
func refusingAsTheOrderServer() http.HandlerFunc {
	var mu sync.Mutex
	asked := map[string]int{}
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := "<!doctype html><title>page</title>"
		if r.URL.Path == "/r" {
			status, err := strconv.Atoi(r.URL.Query().Get("status"))
			if err != nil {
				status = http.StatusFound
			}
			w.Header().Set("Location", r.URL.Query().Get("to"))
			w.WriteHeader(status)
			return
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/deny/"); ok {
			q := r.URL.Query()
			mu.Lock()
			asked[name]++
			k := asked[name]
			mu.Unlock()
			n, err := strconv.Atoi(q.Get("n"))
			if err != nil {
				n = 1
			}
			if k <= n {
				if q.Has("cookie") {
					w.Header().Add("Set-Cookie", "dn="+strconv.Itoa(k)+"; Path=/; SameSite=None; Secure")
					w.Header().Add("Set-Cookie", "dl="+strconv.Itoa(k)+"; Path=/")
				}
				if ch := q.Get("ch"); ch != "" {
					w.Header().Set("Accept-CH", ch)
				}
				w.WriteHeader(http.StatusForbidden)
				if q.Has("empty") {
					return
				}
			}
		}
		_, _ = io.WriteString(w, page)
	}
}

// ordinals are a run's connections numbered by first use, as the fixture
// numbers Chrome's.
func ordinals(conns []int64) []int {
	seen := map[int64]int{}
	out := make([]int, len(conns))
	for i, c := range conns {
		if _, ok := seen[c]; !ok {
			seen[c] = len(seen) + 1
		}
		out[i] = seen[c]
	}
	return out
}

func TestAPageIsReloadedAsChromeReloadedIt(t *testing.T) {
	fixture := readReloadFixture(t)
	for name, scenario := range fixture.Scenarios {
		for _, proto := range []string{"h2", "h1"} {
			t.Run(name+"/"+proto, func(t *testing.T) {
				if why, ok := reloadNotSent[name]; ok {
					t.Skip(why)
				}
				how, ok := reloadKinds[name]
				if !ok {
					t.Fatalf("%s: no way to reach its page is said", name)
				}
				chrome := map[string][]reloadRequest{"h2": scenario.H2, "h1": scenario.H1}[proto]
				server := newRecorder(t, proto, refusingAsTheOrderServer())
				client := contextClient(t, server)
				// The page a context's request is sent from, typed.
				first := 0
				if how.kind != "" {
					if _, err := client.Do(&Request{URL: placed.Replace("{A}" + chrome[0].URL)}); err != nil {
						t.Fatalf("the page: %v", err)
					}
					first = 1
				}
				req := Request{Method: chrome[first].Method, URL: placed.Replace("{A}" + chrome[first].URL)}
				if how.kind != "" {
					req.Browser = &BrowserContext{Kind: how.kind, Initiator: placed.Replace("{A}" + chrome[0].URL),
						Clicked: how.clicked}
				}
				if req.Method == http.MethodPost {
					req.Body = []byte(chrome[first].Body)
				}
				refused := slices.IndexFunc(chrome, func(r reloadRequest) bool { return r.Status == http.StatusForbidden })
				for range len(chrome) - refused {
					res, err := client.Do(&req)
					if err != nil {
						t.Fatalf("%s %s: %v", req.Method, req.URL, err)
					}
					req = req.Reloaded(res)
				}
				sent := server.requests()
				if len(sent) != len(chrome) {
					t.Fatalf("sent %d requests, Chrome %d", len(sent), len(chrome))
				}
				var conns []int64
				var chromes []int64
				for i, k := range sent {
					want := chrome[i]
					conns, chromes = append(conns, k.conn), append(chromes, int64(want.Conn))
					if path := strings.TrimPrefix(unplaced.Replace(k.url), "{A}"); k.method != want.Method || path != want.URL {
						t.Errorf("request %d: %s %s, Chrome %s %s", i, k.method, path, want.Method, want.URL)
					}
					if k.body != want.Body {
						t.Errorf("request %d: body %q, Chrome's %q", i, k.body, want.Body)
					}
					var got [][2]string
					for _, h := range k.headers {
						if !strings.HasPrefix(h[0], ":") {
							got = append(got, [2]string{h[0], unplaced.Replace(h[1])})
						}
					}
					same := len(got) == len(want.Headers)
					for j := 0; same && j < len(got); j++ {
						same = got[j][0] == want.Headers[j][0] &&
							(got[j][1] == want.Headers[j][1] || strings.EqualFold(got[j][0], "host"))
					}
					if !same {
						t.Errorf("request %d: fields\n%v\nChrome's\n%v", i, got, want.Headers)
					}
				}
				if got, want := ordinals(conns), ordinals(chromes); !equalInts(got, want) {
					t.Errorf("connections %v, Chrome's %v", got, want)
				}
			})
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEveryReloadScenarioMeasuredIsReplayedOrSaysWhyNot(t *testing.T) {
	fixture := readReloadFixture(t)
	for name := range fixture.Scenarios {
		_, how := reloadKinds[name]
		_, not := reloadNotSent[name]
		if how == not {
			t.Errorf("%s: replayed %v, said not to be %v", name, how, not)
		}
	}
	for name := range reloadKinds {
		if _, ok := fixture.Scenarios[name]; !ok {
			t.Errorf("%s: replayed, and not in the fixture", name)
		}
	}
	for name := range reloadNotSent {
		if _, ok := fixture.Scenarios[name]; !ok {
			t.Errorf("%s: said not to be replayed, and not in the fixture", name)
		}
	}
}

func TestReloadedIsTheRequestThatReloadsThePage(t *testing.T) {
	page := "https://www.example.com/page"
	form := &BrowserContext{Kind: KindForm, Initiator: page, Clicked: true}
	link := &BrowserContext{Kind: KindNavigation, Initiator: page}
	script := &BrowserContext{Kind: KindFetch, Initiator: page}
	xhr := &BrowserContext{Kind: KindXHR, Initiator: page}
	encoded := NewHeader("Content-Type", "multipart/form-data; boundary=x")
	for _, tc := range []struct {
		name string
		req  Request
		res  *Response
		want Request
	}{
		{"fetch() is sent again as it is", Request{Method: "POST", URL: "u", Body: []byte("x"), Browser: script},
			&Response{URL: "v", Method: "GET"}, Request{Method: "POST", URL: "u", Body: []byte("x"), Browser: script}},
		{"an XHR is sent again as it is", Request{URL: "u", Browser: xhr}, &Response{URL: "v", Method: "GET"},
			Request{URL: "u", Browser: xhr}},
		{"no answer reloads its own URL", Request{URL: "u"}, nil, Request{URL: "u", Reload: true}},
		{"a typed navigation reloads where it ended", Request{URL: "u"}, &Response{URL: "v", Method: "GET"},
			Request{URL: "v", Reload: true}},
		{"a method in another case is the same", Request{Method: "get", URL: "u"}, &Response{URL: "v", Method: "GET"},
			Request{Method: "get", URL: "v", Reload: true}},
		{"a navigation from a page keeps it", Request{URL: "u", Browser: link}, &Response{URL: "v", Method: "GET"},
			Request{URL: "v", Browser: link, Reload: true}},
		{"a form posted to the end is posted again",
			Request{Method: "POST", URL: "u", Header: encoded, Body: []byte("a=b"), Browser: form},
			&Response{URL: "v", Method: "POST"},
			Request{Method: "POST", URL: "v", Header: encoded, Body: []byte("a=b"), Browser: form, Reload: true}},
		{"a form a redirect made a GET is reloaded as the navigation it ended as",
			Request{Method: "POST", URL: "u", Header: encoded, Body: []byte("a=b"), Browser: form},
			&Response{URL: "v", Method: "GET"},
			Request{Method: "GET", URL: "v", Browser: &BrowserContext{Kind: KindNavigation, Initiator: page, Clicked: true},
				Reload: true}},
		{"an answer that says no method keeps the request's",
			Request{Method: "POST", URL: "u", Body: []byte("a=b"), Browser: form}, &Response{URL: "v"},
			Request{Method: "POST", URL: "v", Body: []byte("a=b"), Browser: form, Reload: true}},
		{"a request given other fields keeps them",
			Request{Method: "POST", URL: "u", Header: NewHeader("X-Foo", "1", "content-type", "text/plain"),
				Body: []byte("x")},
			&Response{URL: "v", Method: "GET"}, Request{Method: "GET", URL: "v", Header: NewHeader("X-Foo", "1"), Reload: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kept := tc.req.Browser
			var before BrowserContext
			if kept != nil {
				before = *kept
			}
			got := tc.req.Reloaded(tc.res)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%+v\nwant %+v", got, tc.want)
			}
			if kept != nil && *kept != before {
				t.Errorf("the request's browser context became %+v", *kept)
			}
		})
	}
}

func TestAReloadIsRefusedWhereChromeReloadsNoPage(t *testing.T) {
	page := "https://www.example.com/page"
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	stripped, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	stripped = stripped.Clone()
	stripped.Behavior = stripped.RuntimeBehavior().Clone()
	for _, k := range []string{"headers.reload_cache_control", "headers.form_reload_order"} {
		delete(stripped.Behavior, k)
	}
	silent := newTestClient(t, WithProfileValue(stripped), server.dialing())
	catalogue := newTestClient(t, WithProfile("firefox_148"), server.dialing())
	for _, tc := range []struct {
		name   string
		client *Client
		req    Request
		says   string
	}{
		{"fetch()", client, Request{URL: page, Browser: &BrowserContext{Kind: KindFetch, Initiator: page}},
			"fetch() opens no page to reload: Ctrl+R reloads the page that sent it"},
		{"an XHR", client, Request{URL: page, Browser: &BrowserContext{Kind: KindXHR, Initiator: page}},
			"an XHR opens no page to reload"},
		{"a browser's own request", client,
			Request{URL: page, Browser: &BrowserContext{Kind: KindNavigation, Initiator: page, Sent: true}},
			"a request a browser sent is reloaded by the browser"},
		{"a profile that says nothing of it", silent, Request{URL: page},
			"the profile says nothing of how Chrome reloads a page (headers.reload_cache_control)"},
		{"a profile that sends a request as it is given", catalogue, Request{URL: page},
			`profile "firefox_148" sends a request without a browser context as it is given, which opens no page to reload`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Reload = true
			if err := tc.client.Validate(&tc.req); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("Validate: %v, want %q", err, tc.says)
			}
			if _, err := tc.client.Do(&tc.req); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("Do: %v, want %q", err, tc.says)
			}
		})
	}
	if n := len(server.requests()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}

func TestAResponseSaysTheMethodItAnswers(t *testing.T) {
	server := newRecorder(t, "h2", refusingAsTheOrderServer())
	client := contextClient(t, server)
	form := &BrowserContext{Kind: KindForm, Initiator: "https://www.example.com/page"}
	for _, tc := range []struct {
		method, url, want string
	}{
		{"", "https://www.example.com/p", "GET"},
		{"POST", "https://www.example.com/r?status=302&to=/p", "GET"},
		{"POST", "https://www.example.com/r?status=303&to=/p", "GET"},
		{"POST", "https://www.example.com/r?status=307&to=/p", "POST"},
		{"POST", "https://www.example.com/r?status=308&to=/p", "POST"},
		{"POST", "https://www.example.com/p", "POST"},
	} {
		req := &Request{Method: tc.method, URL: tc.url}
		if tc.method == "POST" {
			req.Body, req.Browser = []byte("a=b"), form
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.url, err)
		}
		if res.Method != tc.want {
			t.Errorf("%s %s: answers %q, want %q", tc.method, tc.url, res.Method, tc.want)
		}
	}
}

func TestAReloadedPageKeepsTheFieldsItWasGiven(t *testing.T) {
	// A navigation typed into the address bar goes with what it is given
	// where Chrome driven over DevTools writes it, reloaded too: after
	// User-Agent, after the reload's Cache-Control (as Chrome's hard reload
	// of one given fields was measured, testdata/chrome155-given.json).
	for _, proto := range []string{"h2", "h1"} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, refusingAsTheOrderServer())
			client := contextClient(t, server)
			req := Request{URL: "https://www.example.com/deny/given", Header: NewHeader("X-Foo", "1")}
			res, err := client.Do(&req)
			if err != nil || res.Status != http.StatusForbidden {
				t.Fatalf("%v %v", res, err)
			}
			again := req.Reloaded(res)
			if _, err := client.Do(&again); err != nil {
				t.Fatal(err)
			}
			sent := server.requests()
			var names []string
			for _, h := range sent[len(sent)-1].headers {
				if lower := strings.ToLower(h[0]); !strings.HasPrefix(lower, ":") && lower != "host" && lower != "connection" {
					names = append(names, lower)
				}
			}
			ua := slices.Index(names, "user-agent")
			if len(names) == 0 || names[0] != "cache-control" || ua < 0 || ua+1 >= len(names) || names[ua+1] != "x-foo" {
				t.Errorf("the reload's fields: %v", names)
			}
		})
	}
}
