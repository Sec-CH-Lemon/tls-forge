package tlsforge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
)

// A browser-context request uses a private, partitioned response cache.
// Low-level requests retain their explicit always-network contract. Only
// complete GET representations with explicit freshness or a validator are
// stored. A strong-validator prefix is retained separately and must be
// validated/completed before answering a full GET. Truncated bodies and Vary:*
// never become cache entries.
type responseCache struct {
	behavior behavior.Policy
	mu       sync.Mutex
	entries  map[string][]*cachedResponse
	bytes    int
	inflight map[string]chan struct{}
}

type cachedResponse struct {
	header       fhttp.Header
	body         []byte
	vary         []string
	values       []string
	stored, used time.Time
	age, fresh   time.Duration
	validate     bool
	proto        string
	major, minor int
	status       int
	statusText   string
	partialTotal int // A validated prefix, never a complete representation.
}

var (
	cacheEntryBytes = legacyPolicy().Int("cache.entry_bytes")
	cacheTotalBytes = legacyPolicy().Int("cache.total_bytes")
	cacheMaxEntries = legacyPolicy().Int("cache.entries")
)

func cacheValue(h fhttp.Header, name string) string {
	return strings.Join(fieldValues(h, strings.ToLower(name)), ", ")
}

func cacheDirectives(h fhttp.Header) map[string]string {
	out := map[string]string{}
	for _, field := range fieldValues(h, "cache-control") {
		for _, part := range strings.Split(field, ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
			out[strings.ToLower(name)] = strings.Trim(value, "\" ")
		}
	}
	return out
}

func cacheSeconds(value string) time.Duration {
	n, err := strconv.ParseUint(value, 10, 63)
	if err != nil || n > uint64((1<<63-1)/int64(time.Second)) {
		return 0
	}
	return time.Duration(n) * time.Second
}

func cachePolicy(h fhttp.Header, now time.Time) (fresh, age time.Duration, validate, store bool) {
	d := cacheDirectives(h)
	if _, forbidden := d["no-store"]; forbidden {
		return
	}
	_, validate = d["no-cache"]
	date, dateErr := http.ParseTime(cacheValue(h, "Date"))
	if value, present := d["max-age"]; present {
		fresh = cacheSeconds(value)
		store = true
	} else if expires, err := http.ParseTime(cacheValue(h, "Expires")); err == nil {
		if dateErr != nil {
			date = now
		}
		fresh, store = max(0, expires.Sub(date)), true
	}
	age = cacheSeconds(cacheValue(h, "Age"))
	if dateErr == nil {
		age = max(age, now.Sub(date))
	}
	store = store || cacheValue(h, "ETag") != "" || cacheValue(h, "Last-Modified") != ""
	return
}

func (c *responseCache) key(ch *chain, req *fhttp.Request) string {
	return topSite(ch.browser, req.URL) + "\n" + req.URL.String()
}

func varyValue(h fhttp.Header, name string) string { return strings.Join(fieldValues(h, name), "\x00") }

func (c *responseCache) find(key string, header fhttp.Header) *cachedResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries[key] {
		match := true
		for i, name := range e.vary {
			match = match && e.values[i] == varyValue(header, name)
		}
		if match {
			e.used = time.Now()
			return e
		}
	}
	return nil
}

func (e *cachedResponse) response(req *fhttp.Request) *fhttp.Response {
	h := e.header.Clone()
	// A cache hit does not replay the original response's cookie mutation.
	h.Del("Set-Cookie")
	body := e.body
	if req.Method == "HEAD" {
		body = nil
	}
	return &fhttp.Response{StatusCode: e.status, Status: e.statusText, Header: h,
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(e.body)),
		Request: req, Proto: e.proto, ProtoMajor: e.major, ProtoMinor: e.minor}
}

func (c *responseCache) roundTrip(ch *chain, req *fhttp.Request, next fhttp.RoundTripper) (*fhttp.Response, error) {
	if c == nil || !ch.browser.explicit() {
		return next.RoundTrip(req)
	}
	key := c.key(ch, req)
	d := cacheDirectives(req.Header)
	_, noStore := d["no-store"]
	eligible := (req.Method == "GET" || req.Method == "HEAD") && !noStore && cacheValue(req.Header, "If-Range") == "" &&
		cacheValue(req.Header, "If-None-Match") == "" && cacheValue(req.Header, "If-Modified-Since") == ""
	release := func() {}
	if eligible && req.Method == "GET" {
		// Include the exact request fields and browser credentials scope. Only
		// identical buffered requests may share the pending cache representation.
		headers, _ := json.Marshal(req.Header)
		pendingKey := fmt.Sprintf("%s\n%s\n%x", key, ch.browser.credentials, sha256.Sum256(headers))
		var err error
		release, err = c.enter(req.Context(), pendingKey)
		if err != nil {
			return nil, err
		}
	}
	defer func() { release() }()
	var entry *cachedResponse
	conditional := false
	if eligible {
		entry = c.find(key, req.Header)
		if entry != nil {
			_, forced := d["no-cache"]
			forced = forced || d["max-age"] == "0" || strings.EqualFold(cacheValue(req.Header, "Pragma"), "no-cache")
			if entry.partialTotal != 0 {
				if req.Method == "GET" && cacheValue(req.Header, "Range") == "" {
					return c.completePrefix(key, req, entry, next)
				}
				entry = nil
			} else if !forced && !entry.validate && entry.age+time.Since(entry.stored) < entry.fresh {
				if cacheValue(req.Header, "Range") == "" {
					return entry.response(req), nil
				}
				if ranged := entry.rangeResponse(req); ranged != nil {
					return ranged, nil
				}
			}
		}
		if entry != nil && cacheValue(req.Header, "Range") == "" {
			if etag := cacheValue(entry.header, "ETag"); etag != "" {
				req = conditionalRequest(req, "If-None-Match", etag)
				conditional = true
			} else if modified := cacheValue(entry.header, "Last-Modified"); modified != "" {
				req = conditionalRequest(req, "If-Modified-Since", modified)
				conditional = true
			}
		}
	}
	res, err := next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if conditional && res.StatusCode == 304 {
		_ = res.Body.Close()
		merged := entry.response(req)
		for name, values := range res.Header {
			if !strings.EqualFold(name, "content-length") && !strings.EqualFold(name, "content-range") {
				merged.Header[name] = slices.Clone(values)
			}
		}
		c.store(key, req.Header, merged, entry.body)
		return merged, nil
	}
	if req.Method != "GET" && req.Method != "HEAD" && req.Method != "OPTIONS" && res.StatusCode < 400 {
		c.mu.Lock()
		for _, e := range c.entries[key] {
			c.bytes -= len(e.body)
		}
		delete(c.entries, key)
		c.mu.Unlock()
	}
	cacheStatus := res.StatusCode == 200 || res.StatusCode == 206 || res.StatusCode == 301 || res.StatusCode == 302 || res.StatusCode == 307 || res.StatusCode == 308
	if eligible && req.Method == "GET" && cacheStatus {
		_, _, _, store := cachePolicy(res.Header, time.Now())
		if store {
			done := release
			release = func() {}
			res.Body = &cacheBody{limit: c.runtimeBehavior().Int("cache.entry_bytes"), ReadCloser: res.Body, commit: func(body []byte) { c.store(key, req.Header, res, body) }, done: done}
		}
	}
	return res, nil
}

// enter bounds pending cache work as well as waiting on the caller's deadline.
// An uncacheable response releases its waiters at headers; complete cacheable
// bodies release them after commit (or any error/close), never after a timeout
// independent of the caller. Saturation falls back to the ordinary network path.
func (c *responseCache) enter(ctx context.Context, key string) (func(), error) {
	for {
		c.mu.Lock()
		if wait := c.inflight[key]; wait != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
			}
			continue
		}
		if len(c.inflight) >= c.runtimeBehavior().Int("cache.entries") {
			c.mu.Unlock()
			return func() {}, nil
		}
		if c.inflight == nil {
			c.inflight = make(map[string]chan struct{})
		}
		wait := make(chan struct{})
		c.inflight[key] = wait
		c.mu.Unlock()
		var once sync.Once
		return func() { once.Do(func() { c.mu.Lock(); delete(c.inflight, key); close(wait); c.mu.Unlock() }) }, nil
	}
}

func conditionalRequest(req *fhttp.Request, name, value string) *fhttp.Request {
	copy := *req
	copy.Header = req.Header.Clone()
	decorate := func(h fhttp.Header) fhttp.Header {
		h = h.Clone()
		h.Set(name, value)
		order := slices.DeleteFunc(slices.Clone(h[fhttp.HeaderOrderKey]), func(old string) bool {
			return strings.EqualFold(old, name)
		})
		at := len(order)
		if i := slices.Index(order, "priority"); i >= 0 {
			at = i
		}
		h[fhttp.HeaderOrderKey] = slices.Insert(order, at, strings.ToLower(name))
		return h
	}
	copy.Header = decorate(copy.Header)
	copy.HeaderFor = func(protocol string, h fhttp.Header) fhttp.Header {
		if req.HeaderFor != nil {
			if written := req.HeaderFor(protocol, h); written != nil {
				h = written
			}
		}
		return decorate(h)
	}
	return &copy
}

func (c *responseCache) store(key string, request fhttp.Header, res *fhttp.Response, body []byte) {
	if len(body) > c.runtimeBehavior().Int("cache.entry_bytes") {
		return
	}
	now := time.Now()
	fresh, age, validate, allowed := cachePolicy(res.Header, now)
	if !allowed {
		return
	}
	e := &cachedResponse{header: res.Header.Clone(), body: bytes.Clone(body), stored: now, used: now,
		fresh: fresh, age: age, validate: validate, proto: res.Proto, major: res.ProtoMajor, minor: res.ProtoMinor,
		status: res.StatusCode, statusText: res.Status}
	if res.StatusCode == 206 {
		first, last, total, ok := contentRange(res.Header)
		if !ok || first != 0 || last+1 != len(body) || total > c.runtimeBehavior().Int("cache.entry_bytes") || last+1 >= total ||
			strongETag(res.Header) == "" || cacheValue(res.Header, "Content-Encoding") != "" {
			return
		}
		e.partialTotal = total
	}
	for _, field := range fieldValues(res.Header, "vary") {
		for _, name := range strings.Split(field, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "*" {
				return
			}
			if name != "" && !slices.Contains(e.vary, name) {
				e.vary = append(e.vary, name)
				e.values = append(e.values, varyValue(request, name))
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Chromium retains one current representation per cache key. A Vary
	// mismatch replaces it;returning to an older variant contacts the origin.
	for _, old := range c.entries[key] {
		c.bytes -= len(old.body)
	}
	c.entries[key] = []*cachedResponse{e}
	c.bytes += len(body)
	for {
		count := 0
		var oldest *cachedResponse
		var oldestKey string
		for key, values := range c.entries {
			count += len(values)
			for _, old := range values {
				if oldest == nil || old.used.Before(oldest.used) {
					oldest, oldestKey = old, key
				}
			}
		}
		if c.bytes <= c.runtimeBehavior().Int("cache.total_bytes") && count <= c.runtimeBehavior().Int("cache.entries") {
			break
		}
		c.entries[oldestKey] = slices.DeleteFunc(c.entries[oldestKey], func(v *cachedResponse) bool { return v == oldest })
		if len(c.entries[oldestKey]) == 0 {
			delete(c.entries, oldestKey)
		}
		c.bytes -= len(oldest.body)
	}
}

type cacheBody struct {
	limit int
	io.ReadCloser
	data   []byte
	large  bool
	commit func([]byte)
	done   func()
}

func (r *cacheBody) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if !r.large {
		if len(r.data)+n > r.maxBytes() {
			r.large, r.data = true, nil
		} else {
			r.data = append(r.data, p[:n]...)
		}
	}
	if err == io.EOF && !r.large && r.commit != nil {
		r.commit(r.data)
		r.commit = nil
	}
	if err != nil && r.done != nil {
		r.done()
	}
	return n, err
}

func (r *cacheBody) Close() error {
	err := r.ReadCloser.Close()
	if r.done != nil {
		r.done()
	}
	return err
}

func (c *responseCache) runtimeBehavior() behavior.Policy {
	if c.behavior != nil {
		return c.behavior
	}
	return legacyPolicy()
}
func (r *cacheBody) maxBytes() int {
	if r.limit > 0 {
		return r.limit
	}
	return legacyPolicy().Int("cache.entry_bytes")
}
