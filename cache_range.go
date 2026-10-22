package tlsforge

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"
)

func strongETag(h fhttp.Header) string {
	tag := cacheValue(h, "ETag")
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return ""
	}
	return tag
}

func contentRange(h fhttp.Header) (first, last, total int, ok bool) {
	s := cacheValue(h, "Content-Range")
	if !strings.HasPrefix(s, "bytes ") {
		return
	}
	span, size, found := strings.Cut(strings.TrimPrefix(s, "bytes "), "/")
	lo, hi, dash := strings.Cut(span, "-")
	if !found || !dash {
		return
	}
	a, e1 := strconv.ParseUint(lo, 10, 31)
	b, e2 := strconv.ParseUint(hi, 10, 31)
	n, e3 := strconv.ParseUint(size, 10, 31)
	if e1 != nil || e2 != nil || e3 != nil || a > b || b >= n {
		return
	}
	return int(a), int(b), int(n), true
}

// Only one satisfiable byte range of a complete, unencoded 200 entry is
// synthesized locally. Multipart and malformed ranges use the origin path.
func (e *cachedResponse) rangeResponse(req *fhttp.Request) *fhttp.Response {
	if e.status != 200 || e.partialTotal != 0 || cacheValue(e.header, "Content-Encoding") != "" || len(e.body) == 0 {
		return nil
	}
	value := cacheValue(req.Header, "Range")
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") {
		return nil
	}
	lo, hi, ok := strings.Cut(strings.TrimPrefix(value, "bytes="), "-")
	if !ok {
		return nil
	}
	first, last := 0, len(e.body)-1
	if lo == "" {
		n, err := strconv.ParseUint(hi, 10, 31)
		if err != nil || n == 0 {
			return nil
		}
		first = max(0, len(e.body)-int(n))
	} else {
		n, err := strconv.ParseUint(lo, 10, 31)
		if err != nil || n >= uint64(len(e.body)) {
			return nil
		}
		first = int(n)
		if hi != "" {
			n, err = strconv.ParseUint(hi, 10, 31)
			if err != nil || n < uint64(first) {
				return nil
			}
			last = min(last, int(n))
		}
	}
	res := e.response(req)
	res.StatusCode, res.Status = 206, "206 Partial Content"
	res.ContentLength = int64(last - first + 1)
	res.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(e.body)))
	res.Header.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
	if req.Method != "HEAD" {
		res.Body = io.NopCloser(bytes.NewReader(e.body[first : last+1]))
	}
	return res
}

func (c *responseCache) forget(key string, entry *cachedResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, old := range c.entries[key] {
		if old == entry {
			c.bytes -= len(old.body)
			delete(c.entries, key)
			break
		}
	}
}

// A prefix never answers a full GET. First validate it, then fetch the missing
// interval with If-Range. Only exact ranges with the same strong validator may
// be combined (RFC 9111 section 3.4). A changed entity returned as 200 replaces
// the old prefix; malformed or truncated 206 data never enters the cache.
func (c *responseCache) completePrefix(key string, req *fhttp.Request, e *cachedResponse, next fhttp.RoundTripper) (*fhttp.Response, error) {
	tag := strongETag(e.header)
	validate := conditionalRequest(req, "Range", fmt.Sprintf("bytes=0-%d", len(e.body)-1))
	validate = conditionalRequest(validate, "If-None-Match", tag)
	res, err := next.RoundTrip(validate)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == 304 && (cacheValue(res.Header, "ETag") == "" || strongETag(res.Header) == tag) {
		_ = res.Body.Close()
		tail := conditionalRequest(req, "Range", fmt.Sprintf("bytes=%d-%d", len(e.body), e.partialTotal-1))
		tail = conditionalRequest(tail, "If-Range", tag)
		res, err = next.RoundTrip(tail)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == 206 {
			first, last, total, valid := contentRange(res.Header)
			valid = valid && first == len(e.body) && last+1 == e.partialTotal && total == e.partialTotal &&
				strongETag(res.Header) == tag && cacheValue(res.Header, "Content-Encoding") == ""
			if valid {
				body, readErr := io.ReadAll(io.LimitReader(res.Body, int64(e.partialTotal-len(e.body)+1)))
				closeErr := res.Body.Close()
				if readErr != nil || closeErr != nil || len(body) != e.partialTotal-len(e.body) {
					c.forget(key, e)
					if readErr != nil {
						return nil, readErr
					}
					return nil, io.ErrUnexpectedEOF
				}
				body = append(bytes.Clone(e.body), body...)
				res.StatusCode, res.Status = 200, "200 OK"
				res.Header.Del("Content-Range")
				res.ContentLength = int64(len(body))
				res.Header.Set("Content-Length", strconv.Itoa(len(body)))
				res.Body, res.Request = io.NopCloser(bytes.NewReader(body)), req
				c.store(key, req.Header, res, body)
				return res, nil
			}
		}
	}
	c.forget(key, e)
	if res.StatusCode != 200 {
		_ = res.Body.Close()
		res, err = next.RoundTrip(req)
		if err != nil {
			return nil, err
		}
	}
	if res.StatusCode == 200 {
		res.Body = &cacheBody{ReadCloser: res.Body, commit: func(body []byte) { c.store(key, req.Header, res, body) }}
	}
	return res, nil
}
