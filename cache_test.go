package tlsforge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/utls/behavior"
)

// cacheOrigin answers the cache's requests one after another as its answers
// say, keeping each request it was asked.
type cacheOrigin struct {
	mu      sync.Mutex
	answers []func(*fhttp.Request) (*fhttp.Response, error)
	asked   []*fhttp.Request
}

func (o *cacheOrigin) RoundTrip(req *fhttp.Request) (*fhttp.Response, error) {
	o.mu.Lock()
	o.asked = append(o.asked, req)
	answer := o.answers[len(o.asked)-1]
	o.mu.Unlock()
	return answer(req)
}

func (o *cacheOrigin) times() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.asked)
}

func cacheAnswer(status int, body string, header ...string) func(*fhttp.Request) (*fhttp.Response, error) {
	return func(req *fhttp.Request) (*fhttp.Response, error) {
		h := fhttp.Header{}
		for i := 0; i+1 < len(header); i += 2 {
			h.Add(header[i], header[i+1])
		}
		return &fhttp.Response{StatusCode: status, Status: http.StatusText(status), Header: h,
			Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	}
}

func cacheFailure(err error) func(*fhttp.Request) (*fhttp.Response, error) {
	return func(*fhttp.Request) (*fhttp.Response, error) { return nil, err }
}

// cacheOf is a cache with the policy of chrome_155_macos, the changes laid over it.
func cacheOf(t *testing.T, change map[string]string) *responseCache {
	t.Helper()
	pol := shippedProfile(t, "chrome_155_macos").RuntimeBehavior().Clone()
	for k, v := range change {
		pol[k] = json.RawMessage(v)
	}
	return &responseCache{behavior: pol, entries: map[string][]*cachedResponse{}}
}

// cacheFetch is the cache's answer to a page's GET (or method) of raw, read whole.
func cacheFetch(t *testing.T, c *responseCache, origin *cacheOrigin, method, raw string, header ...string) (*fhttp.Response, string, error) {
	t.Helper()
	req, err := fhttp.NewRequest(method, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	res, err := c.roundTrip(&chain{browser: &browserRequest{}}, req, origin)
	if err != nil {
		return nil, "", err
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, string(body), err
}

func TestACacheEntryIsFreshUntilItsExpiresWithoutADate(t *testing.T) {
	c := cacheOf(t, nil)
	in := time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
	for _, date := range []string{"", "not a date"} {
		origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
			cacheAnswer(200, "page", "Expires", in, "Date", date)}}
		url := "https://www.example.com/expires?date=" + date
		for range 2 {
			if _, body, err := cacheFetch(t, c, origin, "GET", url); err != nil || body != "page" {
				t.Fatalf("%q: %q, %v", date, body, err)
			}
		}
		if origin.times() != 1 {
			t.Errorf("Date %q: the origin was asked %d times", date, origin.times())
		}
	}
}

func TestACacheEntryWithoutAnETagIsRevalidatedByItsDate(t *testing.T) {
	c := cacheOf(t, nil)
	modified := "Wed, 21 Oct 2026 07:28:00 GMT"
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		cacheAnswer(200, "page", "Cache-Control", "max-age=0", "Last-Modified", modified),
		cacheAnswer(304, "", "Cache-Control", "no-store"),
		cacheAnswer(304, ""),
	}}
	url := "https://www.example.com/dated"
	for i := range 3 {
		res, body, err := cacheFetch(t, c, origin, "GET", url)
		if err != nil || body != "page" || res.StatusCode != 200 {
			t.Fatalf("request %d: %v %q %v", i, res, body, err)
		}
	}
	for i, req := range origin.asked[1:] {
		if got := req.Header.Get("If-Modified-Since"); got != modified {
			t.Errorf("revalidation %d asked If-Modified-Since %q", i, got)
		}
	}
	// The 304 that said no-store replaced nothing: the entry is the first one's.
	if entries := c.entries[c.key(&chain{browser: &browserRequest{}}, origin.asked[0])]; len(entries) != 1 ||
		cacheValue(entries[0].header, "Cache-Control") != "max-age=0" {
		t.Errorf("entries %+v", entries)
	}
}

func TestAnUnsafeRequestForgetsTheEntryOfItsURL(t *testing.T) {
	c := cacheOf(t, nil)
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		cacheAnswer(200, "page", "Cache-Control", "max-age=600"),
		cacheAnswer(200, "posted"),
		cacheAnswer(200, "again", "Cache-Control", "max-age=600"),
	}}
	url := "https://www.example.com/form"
	cacheFetch(t, c, origin, "GET", url)
	if _, body, _ := cacheFetch(t, c, origin, "POST", url); body != "posted" {
		t.Fatalf("POST %q", body)
	}
	if _, body, _ := cacheFetch(t, c, origin, "GET", url); body != "again" || origin.times() != 3 {
		t.Errorf("GET after a POST: %q, origin asked %d times", body, origin.times())
	}
	if c.bytes != len("again") {
		t.Errorf("cache holds %d bytes", c.bytes)
	}
}

func TestWhatACacheDoesNotStore(t *testing.T) {
	c := cacheOf(t, map[string]string{"cache.entry_bytes": "8", "cache.total_bytes": "16", "cache.entries": "1"})
	u := "https://www.example.com/"
	res := func(header ...string) *fhttp.Response {
		h := fhttp.Header{}
		for i := 0; i+1 < len(header); i += 2 {
			h.Add(header[i], header[i+1])
		}
		return &fhttp.Response{StatusCode: 200, Header: h}
	}
	c.store(u+"big", nil, res("Cache-Control", "max-age=60"), []byte("more than eight"))
	c.store(u+"star", nil, res("Cache-Control", "max-age=60", "Vary", "Accept, *"), []byte("x"))
	c.store(u+"nothing", nil, res(), []byte("x"))
	if len(c.entries) != 0 || c.bytes != 0 {
		t.Fatalf("stored %v (%d bytes)", c.entries, c.bytes)
	}
	// One entry at most: the one used longest ago goes.
	c.store(u+"a", nil, res("Cache-Control", "max-age=60"), []byte("a"))
	c.store(u+"b", nil, res("Cache-Control", "max-age=60"), []byte("bb"))
	if _, ok := c.entries[u+"a"]; ok || len(c.entries[u+"b"]) != 1 || c.bytes != 2 {
		t.Errorf("after two: %v (%d bytes)", c.entries, c.bytes)
	}
	// A cache with no policy of its own reads the legacy data.
	if !equalPolicies((&responseCache{}).runtimeBehavior(), legacyPolicy()) {
		t.Error("a cache without a policy reads another")
	}
}

func equalPolicies(a, b behavior.Policy) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

func TestARequestWaitingForTheSameRequestEndsWithItsContext(t *testing.T) {
	c := cacheOf(t, nil)
	held := make(chan struct{})
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		func(req *fhttp.Request) (*fhttp.Response, error) {
			res, _ := cacheAnswer(200, "page", "Cache-Control", "max-age=60")(req)
			res.Body = io.NopCloser(io.MultiReader(heldReader{held}, strings.NewReader("page")))
			return res, nil
		},
	}}
	url := "https://www.example.com/held"
	first, err := fhttp.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.roundTrip(&chain{browser: &browserRequest{}}, first, origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	second, _ := fhttp.NewRequestWithContext(ctx, "GET", url, nil)
	if _, err := c.roundTrip(&chain{browser: &browserRequest{}}, second, origin); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the waiter: %v", err)
	}
	close(held)
	if body, err := io.ReadAll(res.Body); err != nil || string(body) != "page" {
		t.Errorf("first: %q %v", body, err)
	}
	_ = res.Body.Close()
	if origin.times() != 1 {
		t.Errorf("origin asked %d times", origin.times())
	}
}

// heldReader gives nothing until held is closed.
type heldReader struct{ held chan struct{} }

func (r heldReader) Read([]byte) (int, error) {
	<-r.held
	return 0, io.EOF
}

func TestACacheBusyWithAsManyRequestsAsItKeepsEntriesGoesToTheOrigin(t *testing.T) {
	c := cacheOf(t, map[string]string{"cache.entries": "1"})
	held := make(chan struct{})
	defer close(held)
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		func(req *fhttp.Request) (*fhttp.Response, error) {
			res, _ := cacheAnswer(200, "", "Cache-Control", "max-age=60")(req)
			res.Body = io.NopCloser(heldReader{held})
			return res, nil
		},
		cacheAnswer(200, "other", "Cache-Control", "max-age=60"),
	}}
	first, _ := fhttp.NewRequest("GET", "https://www.example.com/a", nil)
	if _, err := c.roundTrip(&chain{browser: &browserRequest{}}, first, origin); err != nil {
		t.Fatal(err)
	}
	// Another URL while the first is pending: no place to wait in, so the
	// network path, and nothing it answers waits for it.
	if _, body, err := cacheFetch(t, c, origin, "GET", "https://www.example.com/b"); err != nil || body != "other" {
		t.Errorf("second: %q %v", body, err)
	}
	if len(c.inflight) != 1 {
		t.Errorf("inflight %v", c.inflight)
	}
}

func TestAPartialEntryAnswersNoRangeAndNoHEAD(t *testing.T) {
	c := cacheOf(t, nil)
	key := c.key(&chain{browser: &browserRequest{}}, mustRequest(t, "https://www.example.com/partial"))
	c.entries[key] = []*cachedResponse{{status: 206, partialTotal: 10, body: []byte("01234"),
		header: fhttp.Header{"Etag": {`"v1"`}}, fresh: time.Hour, stored: time.Now()}}
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		cacheAnswer(206, "56789", "Content-Range", "bytes 5-9/10"),
		cacheAnswer(200, ""),
	}}
	if res, _, err := cacheFetch(t, c, origin, "GET", "https://www.example.com/partial", "Range", "bytes=5-"); err != nil || res.StatusCode != 206 {
		t.Fatalf("a range: %v %v", res, err)
	}
	if res, _, err := cacheFetch(t, c, origin, "HEAD", "https://www.example.com/partial"); err != nil || res.StatusCode != 200 {
		t.Fatalf("HEAD: %v %v", res, err)
	}
	for i, req := range origin.asked {
		if req.Header.Get("If-None-Match") != "" || req.Header.Get("If-Range") != "" {
			t.Errorf("request %d was made conditional on the prefix: %v", i, req.Header)
		}
	}
}

func mustRequest(t *testing.T, raw string) *fhttp.Request {
	t.Helper()
	req, err := fhttp.NewRequest("GET", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestAContentRangeIsReadExactlyOrNotAtAll(t *testing.T) {
	for value, want := range map[string][4]int{
		"bytes 0-4/10":  {0, 4, 10, 1},
		"bytes 9-9/10":  {9, 9, 10, 1},
		"0-4/10":        {},
		"bytes 0-4":     {},
		"bytes 04/10":   {},
		"bytes a-4/10":  {},
		"bytes 0-b/10":  {},
		"bytes 0-4/c":   {},
		"bytes 5-4/10":  {},
		"bytes 0-10/10": {},
	} {
		first, last, total, ok := contentRange(fhttp.Header{"Content-Range": {value}})
		got := [4]int{first, last, total, 0}
		if ok {
			got[3] = 1
		}
		if got != want {
			t.Errorf("%q: %v, want %v", value, got, want)
		}
	}
}

func TestARangeOfACompleteEntryIsAnsweredOnlyWhenItIsOne(t *testing.T) {
	whole := &cachedResponse{status: 200, body: []byte("0123456789"), header: fhttp.Header{}}
	for value, want := range map[string]string{
		"bytes=2-4":     "234",
		"bytes=-3":      "789",
		"bytes=-30":     "0123456789",
		"bytes=7-":      "789",
		"bytes=7-100":   "789",
		"bytes=-0":      "",
		"bytes=-x":      "",
		"bytes=10-":     "",
		"bytes=x-":      "",
		"bytes=5-4":     "",
		"bytes=5-x":     "",
		"bytes=5":       "",
		"bytes=1-2,4-5": "",
		"items=1-2":     "",
	} {
		req := mustRequest(t, "https://www.example.com/")
		req.Header.Set("Range", value)
		res := whole.rangeResponse(req)
		if want == "" {
			if res != nil {
				t.Errorf("%q answered %s", value, res.Header.Get("Content-Range"))
			}
			continue
		}
		if res == nil {
			t.Errorf("%q not answered", value)
			continue
		}
		body, _ := io.ReadAll(res.Body)
		if string(body) != want || res.StatusCode != 206 {
			t.Errorf("%q: %d %q, want %q", value, res.StatusCode, body, want)
		}
	}
	// Nothing but a complete, unencoded 200 with a body answers a range.
	req := mustRequest(t, "https://www.example.com/")
	req.Header.Set("Range", "bytes=0-1")
	for _, e := range []*cachedResponse{
		{status: 301, body: []byte("01"), header: fhttp.Header{}},
		{status: 200, partialTotal: 4, body: []byte("01"), header: fhttp.Header{}},
		{status: 200, body: []byte("01"), header: fhttp.Header{"Content-Encoding": {"gzip"}}},
		{status: 200, header: fhttp.Header{}},
	} {
		if e.rangeResponse(req) != nil {
			t.Errorf("answered from %+v", e)
		}
	}
}

func TestAPrefixWhoseOriginFailsIsNotCompleted(t *testing.T) {
	broke := errors.New("connection reset")
	prefix := func(c *responseCache, key string) *cachedResponse {
		e := &cachedResponse{status: 206, partialTotal: 10, body: []byte("01234"), header: fhttp.Header{"Etag": {`"v1"`}}}
		c.entries[key] = []*cachedResponse{e}
		c.bytes = len(e.body)
		return e
	}
	tail := func(req *fhttp.Request) (*fhttp.Response, error) {
		res, _ := cacheAnswer(206, "", "Content-Range", "bytes 5-9/10", "Etag", `"v1"`)(req)
		res.Body = io.NopCloser(&failsAfter{bytes.NewReader([]byte("56")), broke})
		return res, nil
	}
	for name, answers := range map[string][]func(*fhttp.Request) (*fhttp.Response, error){
		"validation":     {cacheFailure(broke)},
		"tail":           {cacheAnswer(304, ""), cacheFailure(broke)},
		"tail's body":    {cacheAnswer(304, ""), tail},
		"the page again": {cacheAnswer(304, "", "Etag", `"v2"`), cacheFailure(broke)},
	} {
		t.Run(name, func(t *testing.T) {
			c := cacheOf(t, nil)
			req := mustRequest(t, "https://www.example.com/prefix")
			key := c.key(&chain{browser: &browserRequest{}}, req)
			e := prefix(c, key)
			_, err := c.completePrefix(key, req, e, &cacheOrigin{answers: answers})
			if !errors.Is(err, broke) {
				t.Errorf("%v, want %v", err, broke)
			}
			if name != "validation" && name != "tail" && len(c.entries[key]) != 0 {
				t.Errorf("the prefix stayed: %v", c.entries[key])
			}
		})
	}
}
