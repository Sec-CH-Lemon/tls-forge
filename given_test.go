package tlsforge

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
)

// The fields a request without a browser context is given, held to Chrome's:
// testdata/chrome155-given.json, Chrome 155 driven over its DevTools port as
// Playwright drives it, given the extra headers of each scenario, and its own
// reloads and revalidations.

type givenFixture struct {
	Scenarios map[string]givenScenario `json:"scenarios"`
}

type givenScenario struct {
	Steps []givenStep    `json:"steps"`
	H2    []givenRequest `json:"h2"`
	H1    []givenRequest `json:"h1"`
}

// givenStep is what the scenario did: give the page's requests headers, go
// to a URL, or reload the page.
type givenStep struct {
	Headers  [][2]string `json:"headers"`
	Navigate string      `json:"navigate"`
	Reload   *bool       `json:"reload"`
}

type givenRequest struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers [][2]string `json:"headers"`
}

// givenApart are the scenarios tls-forge sends otherwise than Chrome over
// DevTools did, by design: the fields of slots go in the slot Chrome writes
// each in when it is its own, where DevTools wrote the ones it was given
// after User-Agent, and those of values say what the request was given, where
// Chrome wrote its own. Each of the others is sent as Chrome sent it.
var givenApart = map[string]struct{ slots, values []string }{
	"network":              {slots: []string{"authorization", "cache-control", "pragma"}},
	"own":                  {slots: []string{"accept-language"}, values: []string{"accept"}},
	"computed":             {slots: []string{"accept-encoding", "priority", "sec-fetch-site"}, values: []string{"sec-fetch-site"}},
	"cookie":               {slots: []string{"cookie"}, values: []string{"cookie"}},
	"cond":                 {slots: []string{"if-none-match", "if-modified-since"}},
	"reload-given":         {slots: []string{"authorization"}},
	"revalidate-given":     {slots: []string{"cookie"}},
	"redirect-given":       {slots: []string{"accept-language", "authorization", "cookie"}},
	"redirect-cross-given": {slots: []string{"accept-language", "authorization", "cookie"}, values: []string{"authorization"}},
	"critical-given":       {slots: []string{"accept-language", "authorization", "cookie"}},
	"hints-given":          {slots: []string{"accept-language", "authorization", "cookie"}},
	"redirect-hints-given": {slots: []string{"accept-language", "authorization", "cookie"}},
	"jar-redirect":         {slots: []string{"cookie"}, values: []string{"cookie"}},
}

// givenNotSent are the scenarios no request without a context can be.
var givenNotSent = map[string]string{
	"form-given": "a form's POST goes in a browser context, which a form gives no fields of its own",
}

// organic are the fields Chrome gives a navigation itself, reloaded or
// revalidated, which the replay gives the request where Chrome's had them.
var organic = []string{"pragma", "cache-control", "if-none-match", "if-modified-since"}

// answeringAsTheOrderServer answers as the bench's order server did.
func answeringAsTheOrderServer(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/set":
		w.Header().Add("Set-Cookie", q.Get("c")+"; Path=/; SameSite=None; Secure")
	case r.URL.Path == "/r":
		http.Redirect(w, r, q.Get("to"), http.StatusFound)
		return
	case r.URL.Path == "/ch":
		w.Header().Set("Accept-CH", q.Get("accept"))
		if c := q.Get("critical"); c != "" {
			w.Header().Set("Critical-CH", c)
		}
	case strings.HasPrefix(r.URL.Path, "/cache/"):
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><title>page</title>"))
}

// placed is a URL of the fixture as the replay asks for it, and back.
var placed = strings.NewReplacer("{AA}", "https://api.example.com", "{A}", "https://www.example.com")
var unplaced = strings.NewReplacer("https://api.example.com", "{AA}", "https://www.example.com", "{A}",
	"api.example.com", "a.localhost", "www.example.com", "localhost")

func TestARequestWithoutAContextGivesItsFieldsAsChromeOverDevToolsDid(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome155-given.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var fixture givenFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for name, scenario := range fixture.Scenarios {
		for _, proto := range []string{"h2", "h1"} {
			t.Run(name+"/"+proto, func(t *testing.T) {
				if why, ok := givenNotSent[name]; ok {
					t.Skip(why)
				}
				chrome := map[string][]givenRequest{"h2": scenario.H2, "h1": scenario.H1}[proto]
				server := newRecorder(t, proto, answeringAsTheOrderServer)
				client := contextClient(t, server)
				var given Header
				last := ""
				for _, step := range scenario.Steps {
					switch {
					case step.Headers != nil:
						given = nil
						for _, f := range step.Headers {
							given = append(given, Header{{Name: f[0], Value: f[1]}}...)
						}
						continue
					case step.Navigate != "":
						last = placed.Replace(step.Navigate)
					case step.Reload == nil:
						continue
					}
					// The reload or revalidation Chrome made of it, which the
					// request is given; a reload that does not bypass the
					// cache is a reload (Request.Reload), whose Cache-Control
					// is its own.
					header := given.Clone()
					reload := step.Reload != nil && !*step.Reload
					if at := len(server.requests()); at < len(chrome) {
						for _, f := range chrome[at].Headers {
							if slices.Contains(organic, strings.ToLower(f[0])) &&
								!(reload && strings.EqualFold(f[0], "cache-control")) {
								header = append(header, Header{{Name: f[0], Value: f[1]}}...)
							}
						}
					}
					if _, err := client.Do(&Request{URL: last, Header: header, Reload: reload}); err != nil {
						t.Fatalf("%s: %v", last, err)
					}
				}
				sent := server.requests()
				if len(sent) != len(chrome) {
					t.Fatalf("sent %d requests, Chrome %d", len(sent), len(chrome))
				}
				apart := givenApart[name]
				for i, k := range sent {
					want := chrome[i]
					if path := strings.TrimPrefix(unplaced.Replace(k.url), "{A}"); k.method != want.Method ||
						strings.TrimPrefix(path, "{AA}") != want.URL {
						t.Errorf("request %d: %s %s, Chrome %s %s", i, k.method, k.url, want.Method, want.URL)
					}
					var got, wanted [][2]string
					for _, h := range k.headers {
						if !strings.HasPrefix(h[0], ":") && !slices.Contains(apart.slots, strings.ToLower(h[0])) {
							got = append(got, [2]string{h[0], unplaced.Replace(h[1])})
						}
					}
					for _, h := range want.Headers {
						if !slices.Contains(apart.slots, strings.ToLower(h[0])) {
							wanted = append(wanted, h)
						}
					}
					if len(got) != len(wanted) {
						t.Errorf("request %d: fields\n%v\nChrome's\n%v", i, got, wanted)
						continue
					}
					for j := range got {
						name := strings.ToLower(got[j][0])
						if got[j][0] != wanted[j][0] ||
							got[j][1] != wanted[j][1] && !slices.Contains(apart.values, name) && name != "host" {
							t.Errorf("request %d: fields\n%v\nChrome's\n%v", i, got, wanted)
							break
						}
					}
				}
			})
		}
	}
}
