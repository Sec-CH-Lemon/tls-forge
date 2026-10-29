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
	"sync/atomic"
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
	// Establish a strict LRU order even when the host clock gives both
	// stores the same timestamp. Map iteration cannot break a time tie.
	c.entries[u+"a"][0].used = c.entries[u+"a"][0].used.Add(-time.Minute)
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

// detachable is a transport's body that says whether it was made its
// request's no more.
type detachable struct {
	io.Reader
	detached atomic.Bool
}

func (b *detachable) Detach()    { b.detached.Store(true) }
func (*detachable) Close() error { return nil }

func TestARedirectLeftUnreadIsKeptWithoutItsBody(t *testing.T) {
	c := cacheOf(t, nil)
	body := &detachable{Reader: strings.NewReader("hop")}
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		func(req *fhttp.Request) (*fhttp.Response, error) {
			res, _ := cacheAnswer(302, "", "Cache-Control", "max-age=60", "Location", "/final")(req)
			res.Body = body
			return res, nil
		},
	}}
	req := mustRequest(t, "https://www.example.com/start")
	res, err := c.roundTrip(&chain{browser: &browserRequest{}}, req, origin)
	if err != nil {
		t.Fatal(err)
	}
	leftUnread(res)
	// The transport's body is back, and what is read of it after is no
	// entry's: the redirect is kept without it, and nothing waits for it.
	if res.Body != io.ReadCloser(body) {
		t.Fatalf("the body is %T", res.Body)
	}
	_, _ = io.ReadAll(res.Body)
	key := c.key(&chain{browser: &browserRequest{}}, req)
	if e := c.entries[key]; len(e) != 1 || e[0].status != 302 || len(e[0].body) != 0 || c.bytes != 0 || len(c.inflight) != 0 {
		t.Fatalf("entries %+v, %d bytes, %d waited for", e, c.bytes, len(c.inflight))
	}
	// Asked again, it is the cache's answer: the origin is not asked.
	if res, got, err := cacheFetch(t, c, origin, "GET", req.URL.String()); err != nil || res.StatusCode != 302 || got != "" ||
		res.Header.Get("Location") != "/final" || origin.times() != 1 {
		t.Errorf("again: %v %q %v, the origin asked %d times", res, got, err, origin.times())
	}
}

func TestAnAnswerLeftUnreadThatIsNoRedirectIsKeptOnlyWithItsBody(t *testing.T) {
	c := cacheOf(t, nil)
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		cacheAnswer(200, "page", "Cache-Control", "max-age=60"),
		cacheAnswer(302, "hop", "Location", "/final"),
	}}
	req := mustRequest(t, "https://www.example.com/page")
	res, err := c.roundTrip(&chain{browser: &browserRequest{}}, req, origin)
	if err != nil {
		t.Fatal(err)
	}
	leftUnread(res)
	key := c.key(&chain{browser: &browserRequest{}}, req)
	if _, ok := res.Body.(*cacheBody); !ok || len(c.entries[key]) != 0 || len(c.inflight) != 1 {
		t.Fatalf("a page left unread: %T, entries %v, %d waited for", res.Body, c.entries[key], len(c.inflight))
	}
	if body, _ := io.ReadAll(res.Body); string(body) != "page" || len(c.entries[key]) != 1 || len(c.inflight) != 0 {
		t.Fatalf("read whole: %q, entries %v, %d waited for", body, c.entries[key], len(c.inflight))
	}
	// A redirect the cache would not keep is the transport's as it was.
	other := mustRequest(t, "https://www.example.com/other")
	res, err = c.roundTrip(&chain{browser: &browserRequest{}}, other, origin)
	if err != nil {
		t.Fatal(err)
	}
	leftUnread(res)
	if body, _ := io.ReadAll(res.Body); string(body) != "hop" || len(c.entries[c.key(&chain{browser: &browserRequest{}}, other)]) != 0 {
		t.Errorf("a redirect not kept: %q, entries %v", body, c.entries)
	}
}

func TestABodyCutShortIsNotKept(t *testing.T) {
	c := cacheOf(t, nil)
	broke := errors.New("connection reset")
	origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
		func(req *fhttp.Request) (*fhttp.Response, error) {
			res, _ := cacheAnswer(200, "", "Cache-Control", "max-age=60")(req)
			res.Body = io.NopCloser(&failsAfter{bytes.NewReader([]byte("pa")), broke})
			return res, nil
		},
	}}
	url := "https://www.example.com/cut"
	if _, body, err := cacheFetch(t, c, origin, "GET", url); !errors.Is(err, broke) || body != "pa" {
		t.Fatalf("%q %v", body, err)
	}
	if e := c.entries[c.key(&chain{browser: &browserRequest{}}, mustRequest(t, url))]; len(e) != 0 || len(c.inflight) != 0 {
		t.Errorf("kept %+v, %d waited for", e, len(c.inflight))
	}
}

func TestABodyIsKeptUpToTheLimitOfAnEntry(t *testing.T) {
	c := cacheOf(t, map[string]string{"cache.entry_bytes": "4"})
	for body, kept := range map[string]bool{"abcd": true, "abcde": false} {
		origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
			cacheAnswer(200, body, "Cache-Control", "max-age=60")}}
		url := "https://www.example.com/" + body
		if _, got, err := cacheFetch(t, c, origin, "GET", url); err != nil || got != body {
			t.Fatalf("%q: %q %v", body, got, err)
		}
		if _, ok := c.entries[c.key(&chain{browser: &browserRequest{}}, mustRequest(t, url))]; ok != kept {
			t.Errorf("%q kept: %v", body, ok)
		}
	}
}

func TestARedirectLetGoOfIsDrainedAsTheTransportsOwn(t *testing.T) {
	client := newTestClient(t, WithProfile("chrome_155_macos"))
	for _, major := range []int{1, 2} {
		c := cacheOf(t, nil)
		body := &detachable{Reader: strings.NewReader("hop")}
		origin := &cacheOrigin{answers: []func(*fhttp.Request) (*fhttp.Response, error){
			func(req *fhttp.Request) (*fhttp.Response, error) {
				res, _ := cacheAnswer(307, "", "Cache-Control", "max-age=60", "Location", "/final")(req)
				res.Body, res.ProtoMajor = body, major
				return res, nil
			},
		}}
		res, err := c.roundTrip(&chain{browser: &browserRequest{}}, mustRequest(t, "https://www.example.com/start"), origin)
		if err != nil {
			t.Fatal(err)
		}
		client.leave("dropped", res, -1)
		// Made its request's no more, as the drain makes a body of the
		// transport's, so that the request's end does not cut it.
		if !body.detached.Load() || res.Body != fhttp.NoBody {
			t.Errorf("HTTP/%d: detached %v, the body left %T", major, body.detached.Load(), res.Body)
		}
	}
}
