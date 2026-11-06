package tlsforge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
)

// cacheRulesFixture is what of each fetch() of a page reached Chrome's
// network: testdata/chrome156-cache-rules.json.
type cacheRulesFixture struct {
	Browser   string `json:"browser"`
	Scenarios map[string]struct {
		Steps []struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Network []string          `json:"network"`
		} `json:"steps"`
	} `json:"scenarios"`
}

// cacheRulesKeys are the keys of what the cache keeps and for how long.
var cacheRulesKeys = []string{"cache.store_any_status", "cache.validated_statuses", "cache.response_pragma_no_cache",
	"cache.request_no_cache", "cache.heuristic_percent", "cache.heuristic_statuses",
	"cache.heuristic_with_must_revalidate", "cache.implicit_fresh_statuses"}

// answerAsTheCacheBench answers /s/STATUS as the bench Chrome was measured
// against did, as its query says, and anything else with no-store.
func answerAsTheCacheBench(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !strings.HasPrefix(r.URL.Path, "/s/") {
		w.Header().Set("Cache-Control", "no-store")
		return
	}
	status, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/s/"))
	now := time.Now().UTC()
	w.Header().Set("Date", now.Format(http.TimeFormat))
	if v := q.Get("cc"); v != "" {
		w.Header().Set("Cache-Control", v)
	}
	if q.Get("pragma") != "" {
		w.Header().Set("Pragma", "no-cache")
	}
	if q.Get("lm") != "" {
		w.Header().Set("Last-Modified", now.Add(-10*24*time.Hour).Format(http.TimeFormat))
	}
	if q.Get("etag") != "" {
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
	}
	if to := q.Get("to"); to != "" {
		w.Header().Set("Location", to)
	}
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, "body")
}

// cacheRulesSent sends every step of every scenario of the fixture through
// one client of p as a page's fetch(), over protocol, and gives what of each
// reached the server as the fixture says it, by scenario.
func cacheRulesSent(t *testing.T, protocol string, fixture cacheRulesFixture, values map[string]any) map[string][][]string {
	t.Helper()
	var mu sync.Mutex
	var reached []string
	s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; strings.HasPrefix(p, "/s/") || strings.HasPrefix(p, "/t/") {
			seen := []string{p}
			for _, name := range []string{"If-None-Match", "If-Modified-Since"} {
				if r.Header.Get(name) != "" {
					seen = append(seen, strings.ToLower(name))
				}
			}
			mu.Lock()
			reached = append(reached, strings.Join(seen, " "))
			mu.Unlock()
		}
		answerAsTheCacheBench(w, r)
	})
	c, err := New(WithProfileValue(policyFile(t, values)), WithInsecureSkipVerify(), s.dialing())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	const origin = "https://www.example.com"
	out := map[string][][]string{}
	names := make([]string, 0, len(fixture.Scenarios))
	for name := range fixture.Scenarios {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, step := range fixture.Scenarios[name].Steps {
			separator := "?"
			if strings.Contains(step.URL, "?") {
				separator = "&"
			}
			var pairs []string
			for k, v := range step.Headers {
				pairs = append(pairs, k, v)
			}
			header := NewHeader(pairs...)
			mu.Lock()
			reached = nil
			mu.Unlock()
			if _, err := c.Do(&Request{URL: origin + step.URL + separator + "sc=" + name, Header: header,
				Browser: &BrowserContext{Kind: KindFetch, Initiator: origin + "/"}}); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			mu.Lock()
			out[name] = append(out[name], append([]string{}, reached...))
			mu.Unlock()
		}
	}
	return out
}

// Each fetch() of a page reaches the network, or is answered by the cache,
// as Chrome 156's did: a response of any status kept with freshness of its
// own, a 300, 301, 308 or 410 fresh for ever, a 200 or 203 fresh for a tenth
// of the time since its Last-Modified but with must-revalidate, a response's
// Pragma: no-cache its no-cache, a kept 200 alone asked again conditionally,
// a request's no-cache past the cache with no condition and its answer kept.
// Over HTTP/2 and HTTP/1.1. Without the profile's keys, the cache keeps as it
// did, and is not Chrome's.
func TestTheCacheKeepsWhatChromesKeepsForAsLong(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome156-cache-rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cacheRulesFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Scenarios) != 23 {
		t.Fatalf("%d scenarios", len(fixture.Scenarios))
	}
	for _, protocol := range []string{"h2", "h1"} {
		t.Run(protocol, func(t *testing.T) {
			got := cacheRulesSent(t, protocol, fixture, nil)
			without := map[string]any{}
			for _, k := range cacheRulesKeys {
				without[k] = nil
			}
			before := cacheRulesSent(t, protocol, fixture, without)
			differ := 0
			for name, s := range fixture.Scenarios {
				for i, step := range s.Steps {
					want := strings.Join(step.Network, "; ")
					if sent := strings.Join(got[name][i], "; "); sent != want {
						t.Errorf("%s, step %d: reached %q, Chrome's %q (%s)", name, i, sent, want, fixture.Browser)
					}
					if strings.Join(before[name][i], "; ") != want {
						differ++
					}
				}
			}
			if differ == 0 {
				t.Error("without the profile's keys the cache kept as Chrome's")
			}
			// A request's no-cache validated, where the profile says so.
			validated := cacheRulesSent(t, protocol, fixture, map[string]any{"cache.request_no_cache": "validate"})
			for _, name := range []string{"req-no-cache", "req-pragma"} {
				if got := strings.Join(validated[name][1], "; "); got != "/s/200 if-none-match" {
					t.Errorf("%s validated: reached %q", name, got)
				}
			}
		})
	}
}

// chromeCachePolicy is a cache of chrome_156_macos's policy, its cache keys
// Chrome's, over changes ("" leaves a key out).
func chromeCachePolicy(t *testing.T, changes map[string]string) *responseCache {
	t.Helper()
	p := shippedProfile(t, "chrome_156_macos").RuntimeBehavior().Clone()
	for k, v := range map[string]string{"cache.store_any_status": "true", "cache.validated_statuses": "[200]",
		"cache.response_pragma_no_cache": "true", "cache.request_no_cache": `"bypass"`, "cache.heuristic_percent": "10",
		"cache.heuristic_statuses": "[200, 203, 206]", "cache.heuristic_with_must_revalidate": "false",
		"cache.implicit_fresh_statuses": "[300, 301, 308, 410]"} {
		p[k] = json.RawMessage(v)
	}
	for k, v := range changes {
		if v == "" {
			delete(p, k)
		} else {
			p[k] = json.RawMessage(v)
		}
	}
	return &responseCache{behavior: p}
}

// A response's freshness is Chromium's: its max-age, else its Expires, else
// a tenth of the time from its Last-Modified to its Date for a 200, 203 or 206
// that does not say must-revalidate, else for ever for a 300, 301, 308 or
// 410, else none; Pragma: no-cache has it validated.
func TestAResponsesFreshnessIsChromiums(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	date := now.Format(http.TimeFormat)
	ago := func(d time.Duration) string { return now.Add(-d).Format(http.TimeFormat) }
	day := 24 * time.Hour
	for _, tc := range []struct {
		name     string
		changes  map[string]string
		status   int
		header   []string
		fresh    time.Duration
		validate bool
		store    bool
	}{
		{"a heuristic", nil, 200, []string{"Date", date, "Last-Modified", ago(10 * day)}, day, false, true},
		{"a heuristic of a 203", nil, 203, []string{"Date", date, "Last-Modified", ago(10 * day)}, day, false, true},
		{"a heuristic of a quarter", map[string]string{"cache.heuristic_percent": "25"}, 200,
			[]string{"Date", date, "Last-Modified", ago(10 * day)}, 60 * time.Hour, false, true},
		{"a heuristic from when it came", nil, 200, []string{"Last-Modified", ago(10 * day)}, day, false, true},
		{"no heuristic of a 404", nil, 404, []string{"Date", date, "Last-Modified", ago(10 * day)}, 0, false, true},
		{"no heuristic of a must-revalidate", nil, 200,
			[]string{"Date", date, "Last-Modified", ago(10 * day), "Cache-Control", "must-revalidate"}, 0, false, true},
		{"a heuristic of a must-revalidate where the profile says", map[string]string{"cache.heuristic_with_must_revalidate": "true"},
			200, []string{"Date", date, "Last-Modified", ago(10 * day), "Cache-Control", "must-revalidate"}, day, false, true},
		{"no heuristic of a Last-Modified to come", nil, 200, []string{"Date", date, "Last-Modified", ago(-day)}, 0, false, true},
		{"no heuristic where the profile gives none", map[string]string{"cache.heuristic_percent": "",
			"cache.heuristic_statuses": "", "cache.heuristic_with_must_revalidate": ""}, 200,
			[]string{"Date", date, "Last-Modified", ago(10 * day)}, 0, false, true},
		{"Expires before the heuristic", nil, 200,
			[]string{"Date", date, "Last-Modified", ago(10 * day), "Expires", ago(-time.Hour)}, time.Hour, false, true},
		{"a 410 for ever", nil, 410, nil, forever, false, true},
		{"a 300 for ever", nil, 300, nil, forever, false, true},
		{"a 410 of max-age=0", nil, 410, []string{"Cache-Control", "max-age=0"}, 0, false, true},
		{"a 302 not", nil, 302, nil, 0, false, false},
		{"no 410 for ever where the profile says none", map[string]string{"cache.implicit_fresh_statuses": ""}, 410, nil, 0, false, false},
		{"Pragma: no-cache", nil, 200, []string{"Cache-Control", "max-age=60", "Pragma", "no-cache"}, time.Minute, true, true},
		{"Pragma: no-cache where the profile reads it not", map[string]string{"cache.response_pragma_no_cache": ""}, 200,
			[]string{"Cache-Control", "max-age=60", "Pragma", "no-cache"}, time.Minute, false, true},
	} {
		c := chromeCachePolicy(t, tc.changes)
		h := fhttp.Header{}
		for i := 0; i < len(tc.header); i += 2 {
			h.Add(tc.header[i], tc.header[i+1])
		}
		fresh, _, validate, store := c.policy(h, tc.status, now)
		if fresh != tc.fresh || validate != tc.validate || store != tc.store {
			t.Errorf("%s: fresh %v, validate %v, store %v; want %v, %v, %v", tc.name, fresh, validate, store,
				tc.fresh, tc.validate, tc.store)
		}
	}
}

// Pragma names no-cache as a token of any of its fields, in any case; the
// statuses a cache keeps and asks again conditionally are the profile's.
func TestTheCachesStatusesAndPragmaAreTheProfiles(t *testing.T) {
	for _, tc := range []struct {
		values []string
		want   bool
	}{
		{[]string{"no-cache"}, true}, {[]string{"No-Cache"}, true}, {[]string{"x, no-cache"}, true},
		{[]string{"x", " no-cache "}, true}, {[]string{"no-cache=1"}, false}, {[]string{"x"}, false}, {nil, false},
	} {
		if got := pragmaNoCache(fhttp.Header{"Pragma": tc.values}); got != tc.want {
			t.Errorf("Pragma %q: %v", tc.values, got)
		}
	}
	chrome, before := chromeCachePolicy(t, nil), chromeCachePolicy(t, map[string]string{"cache.store_any_status": "",
		"cache.validated_statuses": ""})
	for status, want := range map[int][2]bool{199: {false, false}, 200: {true, true}, 203: {true, false},
		302: {true, true}, 304: {false, false}, 404: {true, false}, 410: {true, false}, 500: {true, false}} {
		if got := chrome.storesStatus(status); got != want[0] {
			t.Errorf("Chrome's keeps a %d: %v", status, got)
		}
		if got := before.storesStatus(status); got != want[1] {
			t.Errorf("the cache before keeps a %d: %v", status, got)
		}
	}
	if !chrome.validates(200) || chrome.validates(203) || !before.validates(203) {
		t.Error("a kept response asked again conditionally of the wrong statuses")
	}
}
