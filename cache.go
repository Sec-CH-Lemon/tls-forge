package tlsforge

import (
	"bytes"
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
// complete GET 200 representations with explicit freshness or a validator
// are stored; incomplete bodies and Vary:* never become cache entries.
type responseCache struct {
	mu      sync.Mutex
	entries map[string][]*cachedResponse
	bytes   int
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
}

const (
	cacheEntryBytes = 8 << 20
	cacheTotalBytes = 64 << 20
	cacheMaxEntries = 256
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
	return &fhttp.Response{StatusCode: 200, Status: "200 OK", Header: h,
		Body: io.NopCloser(bytes.NewReader(e.body)), ContentLength: int64(len(e.body)),
		Request: req, Proto: e.proto, ProtoMajor: e.major, ProtoMinor: e.minor}
}

func (c *responseCache) roundTrip(ch *chain, req *fhttp.Request, next fhttp.RoundTripper) (*fhttp.Response, error) {
	if c == nil || ch.browser == nil {
		return next.RoundTrip(req)
	}
	key := c.key(ch, req)
	d := cacheDirectives(req.Header)
	_, noStore := d["no-store"]
	eligible := req.Method == "GET" && !noStore && cacheValue(req.Header, "Range") == "" &&
		cacheValue(req.Header, "If-None-Match") == "" && cacheValue(req.Header, "If-Modified-Since") == ""
	var entry *cachedResponse
	conditional := false
	if eligible {
		entry = c.find(key, req.Header)
		if entry != nil {
			_, forced := d["no-cache"]
			forced = forced || d["max-age"] == "0" || strings.EqualFold(cacheValue(req.Header, "Pragma"), "no-cache")
			if !forced && !entry.validate && entry.age+time.Since(entry.stored) < entry.fresh {
				return entry.response(req), nil
			}
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
	if eligible && res.StatusCode == 200 {
		_, _, _, store := cachePolicy(res.Header, time.Now())
		if store {
			res.Body = &cacheBody{ReadCloser: res.Body, commit: func(body []byte) { c.store(key, req.Header, res, body) }}
		}
	}
	return res, nil
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
	if len(body) > cacheEntryBytes {
		return
	}
	now := time.Now()
	fresh, age, validate, allowed := cachePolicy(res.Header, now)
	if !allowed {
		return
	}
	e := &cachedResponse{header: res.Header.Clone(), body: bytes.Clone(body), stored: now, used: now,
		fresh: fresh, age: age, validate: validate, proto: res.Proto, major: res.ProtoMajor, minor: res.ProtoMinor}
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
	variants := c.entries[key][:0]
	for _, old := range c.entries[key] {
		if slices.Equal(old.vary, e.vary) && slices.Equal(old.values, e.values) {
			c.bytes -= len(old.body)
		} else {
			variants = append(variants, old)
		}
	}
	c.entries[key] = append(variants, e)
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
		if c.bytes <= cacheTotalBytes && count <= cacheMaxEntries {
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
	io.ReadCloser
	data   []byte
	large  bool
	commit func([]byte)
}

func (r *cacheBody) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if !r.large {
		if len(r.data)+n > cacheEntryBytes {
			r.large, r.data = true, nil
		} else {
			r.data = append(r.data, p[:n]...)
		}
	}
	if err == io.EOF && !r.large && r.commit != nil {
		r.commit(r.data)
		r.commit = nil
	}
	return n, err
}
