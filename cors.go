package tlsforge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// What CORS asks of fetch() and an XHR in cors mode to another origin, as the
// Fetch standard has it and Chrome 155 was measured doing it
// (testdata/chrome155-requests.json): a request CORS would not let through
// unasked goes after a preflight, an OPTIONS that asks whether it may, and not
// at all when the answer is no; a preflight's yes is kept for as long as it
// says; and the answer to the request itself is the page's only when it names
// the page's origin, and, for one that carried credentials, allows them.

// ErrCORS is what an error wraps when CORS stopped a request in a browser
// context: a preflight that did not allow it, which nothing more followed, or
// an answer that was not the page's, which is not returned. errors.Is tells
// one from a failure to send or receive.
var ErrCORS = errors.New("CORS")

func corsError(format string, args ...any) error {
	return fmt.Errorf("tlsforge: %w: "+format, append([]any{ErrCORS}, args...)...)
}

// corsSafelistedMethod reports a method CORS lets through without asking.
func corsSafelistedMethod(method string) bool {
	return method == fhttp.MethodGet || method == fhttp.MethodHead || method == fhttp.MethodPost
}

// maxSafelistedValues is how many bytes of safelisted header values CORS lets
// through unasked: past it, every header is asked about.
const maxSafelistedValues = 1024

// unsafeHeaderNames are the names of a script's headers a preflight asks
// about, in lower case, sorted, once each: those CORS does not let through,
// and every one when the values of the rest come to more than 1024 bytes.
func unsafeHeaderNames(header Header) []string {
	var unsafe, safe []string
	size := 0
	for _, f := range header {
		name := strings.ToLower(f.Name)
		if corsSafelisted(f.Name, f.Value) {
			safe, size = append(safe, name), size+len(f.Value)
		} else {
			unsafe = append(unsafe, name)
		}
	}
	if size > maxSafelistedValues {
		unsafe = append(unsafe, safe...)
	}
	slices.Sort(unsafe)
	return slices.Compact(unsafe)
}

// needsPreflight reports a request that goes after a preflight: one in cors
// mode to another origin, with a method or a header CORS asks about.
func (r *browserRequest) needsPreflight() bool {
	return r.cors && (!corsSafelistedMethod(r.method) || len(unsafeHeaderNames(r.script)) > 0)
}

// preflightOrder is the order of a preflight's headers in Chrome 155, as
// measured: no client hints and no cookies.
var preflightOrder = []string{"accept", "access-control-request-method", "access-control-request-headers", "origin",
	"user-agent", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "referer", "accept-encoding",
	"accept-language", "priority"}

// preflightHeader is the headers of the preflight of a request to target.
func (r *browserRequest) preflightHeader(target origin, base Header) Header {
	values := r.values(target, base)
	values["accept"] = acceptAnything
	values["access-control-request-method"] = r.method
	if unsafe := unsafeHeaderNames(r.script); len(unsafe) > 0 {
		values["access-control-request-headers"] = strings.Join(unsafe, ",")
	}
	var out Header
	for _, name := range preflightOrder {
		if value, ok := values[name]; ok {
			out = append(out, profile.Field{Name: name, Value: value})
		}
	}
	return out
}

// corsCheck is whether an answer is the page's, as the Fetch standard's CORS
// check has it: Access-Control-Allow-Origin, said once, names the page's
// origin, or is "*" for a request without credentials; and for one with them,
// Access-Control-Allow-Credentials is "true".
func (r *browserRequest) corsCheck(header fhttp.Header) error {
	allowed := header.Values("Access-Control-Allow-Origin")
	switch {
	case len(allowed) != 1:
		return fmt.Errorf("Access-Control-Allow-Origin is said %d times, not once", len(allowed))
	case r.credentials != credentialsAll && allowed[0] == "*":
		return nil
	case allowed[0] != r.from.String():
		return fmt.Errorf("Access-Control-Allow-Origin is %q, not %q", allowed[0], r.from.String())
	case r.credentials != credentialsAll:
		return nil
	case header.Get("Access-Control-Allow-Credentials") != "true":
		return fmt.Errorf("credentials were sent, and Access-Control-Allow-Credentials is not \"true\"")
	}
	return nil
}

// allowance is what a preflight's answer allows: methods and header names, as
// it lists them, for how long.
type allowance struct {
	methods, headers []string
	maxAge           time.Duration
}

// defaultPreflightAge is how long a preflight's answer is kept when it says
// nothing of it; maxPreflightAge the longest Chrome keeps one whatever it says.
const (
	defaultPreflightAge = 5 * time.Second
	maxPreflightAge     = 2 * time.Hour
)

// checkPreflight is what a preflight's answer allows the request, or why it
// does not: a status that is not 2xx, a CORS check that fails, a method or a
// header it does not list. "*" stands for any method or header but
// Authorization, for a request without credentials.
func (r *browserRequest) checkPreflight(res *fhttp.Response) (allowance, error) {
	var a allowance
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return a, fmt.Errorf("it was answered %d", res.StatusCode)
	}
	if err := r.corsCheck(res.Header); err != nil {
		return a, err
	}
	var err error
	if a.methods, err = tokenList(res.Header, "Access-Control-Allow-Methods"); err != nil {
		return a, err
	}
	if a.headers, err = tokenList(res.Header, "Access-Control-Allow-Headers"); err != nil {
		return a, err
	}
	wildcard := r.credentials != credentialsAll
	if !corsSafelistedMethod(r.method) && !slices.Contains(a.methods, r.method) &&
		(!wildcard || !slices.Contains(a.methods, "*")) {
		return a, fmt.Errorf("Access-Control-Allow-Methods does not allow %s", r.method)
	}
	for _, name := range unsafeHeaderNames(r.script) {
		listed := slices.ContainsFunc(a.headers, func(h string) bool { return strings.EqualFold(h, name) })
		if !listed && (!wildcard || name == "authorization" || !slices.Contains(a.headers, "*")) {
			return a, fmt.Errorf("Access-Control-Allow-Headers does not allow %s", name)
		}
	}
	a.maxAge = defaultPreflightAge
	if seconds, err := strconv.ParseUint(res.Header.Get("Access-Control-Max-Age"), 10, 63); err == nil {
		a.maxAge = time.Duration(min(seconds, uint64(maxPreflightAge/time.Second))) * time.Second
	}
	return a, nil
}

// tokenList is the comma-separated tokens a header lists, every field of it,
// or an error for one that is not a token: the answer of a server that does
// not say what it allows the way CORS reads it.
func tokenList(header fhttp.Header, name string) ([]string, error) {
	var out []string
	for _, value := range header.Values(name) {
		for _, item := range strings.Split(value, ",") {
			item = strings.Trim(item, " \t")
			if item == "" {
				continue
			}
			if strings.ContainsFunc(item, func(r rune) bool { return !tokenByte(r) }) {
				return nil, fmt.Errorf("%s lists %q, which is not a token", name, item)
			}
			out = append(out, item)
		}
	}
	return out, nil
}

// tokenByte reports a byte HTTP lets a token have.
func tokenByte(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)
}

// preflightCache is what preflights allowed in a session, until when: by the
// page's origin, the URL, whether credentials went, and the method or header
// name allowed. Every client of a session, made Fresh, shares it; another
// session has its own.
type preflightCache struct {
	mu      sync.Mutex
	allowed map[preflightKey]time.Time
	now     func() time.Time
}

type preflightKey struct {
	origin, url string
	credentials bool
	method      string
	header      string
}

func newPreflightCache() *preflightCache {
	return &preflightCache{allowed: map[preflightKey]time.Time{}, now: time.Now}
}

// key is the cache's key for a request to a URL, of a method or a header.
func (r *browserRequest) key(target, method, header string) preflightKey {
	return preflightKey{r.from.String(), target, r.credentials == credentialsAll, method, header}
}

// allows reports a request a cached preflight lets through: its method, and
// every header it would ask about, each allowed by name or by a wildcard a
// request without credentials can use.
func (c *preflightCache) allows(r *browserRequest, target string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	live := func(k preflightKey) bool {
		until, ok := c.allowed[k]
		return ok && now.Before(until)
	}
	wildcard := r.credentials != credentialsAll
	if !corsSafelistedMethod(r.method) && !live(r.key(target, r.method, "")) &&
		(!wildcard || !live(r.key(target, "*", ""))) {
		return false
	}
	for _, name := range unsafeHeaderNames(r.script) {
		if !live(r.key(target, "", name)) && (!wildcard || name == "authorization" || !live(r.key(target, "", "*"))) {
			return false
		}
	}
	return true
}

// keep files what a preflight allowed.
func (c *preflightCache) keep(r *browserRequest, target string, a allowance) {
	c.mu.Lock()
	defer c.mu.Unlock()
	until := c.now().Add(a.maxAge)
	for _, method := range a.methods {
		c.allowed[r.key(target, method, "")] = until
	}
	for _, header := range a.headers {
		c.allowed[r.key(target, "", strings.ToLower(header))] = until
	}
}

// preflightContextKey marks a preflight's context, so that its redirect is not
// followed: a preflight answered with one fails.
type preflightContextKey struct{}

// preflight asks, before a request in cors mode, whether it may be sent: an
// OPTIONS of the same URL, on the transport the request goes out on, with
// Chrome's headers and no cookies. What it allows is kept in the session's
// cache; an answer that does not allow the request is an error, and the
// request is not sent.
//
// base is the request's context before its own layouts were hung on it, so
// that what the preflight's connection is told is the preflight's.
func (c *Client) preflight(base context.Context, inner *fhttp.Request, r *browserRequest, transport tls_client.HttpClient,
	log *requestLog) error {
	target := inner.URL.String()
	u := *inner.URL
	ask := (&fhttp.Request{Method: fhttp.MethodOptions, URL: &u, Host: inner.Host, Proto: "HTTP/1.1", ProtoMajor: 1,
		ProtoMinor: 1}).WithContext(context.WithValue(base, preflightContextKey{}, true))
	field := r.preflightHeader(originOf(inner.URL), c.headers)
	ask.Header = browserLayout(field, preflightOrder, inner.URL.Host)
	if order := c.profile.HTTP2.PseudoHeaderOrder; len(order) > 0 {
		ask.Header[fhttp.PHeaderOrderKey] = order
	}
	http1 := browserHTTP1Layout(field, nil, preflightOrder, c.profile.HTTP1, c.http1Headers, inner.URL.Host)
	ask = withProtocolLayouts(ask, &protocolLayouts{http1: http1, http2: cloneHeaderLayout(ask.Header),
		managed: managedHeaderNames(ask.Header, http1)})
	withPort(ask)
	if c.jar != nil {
		c.jar.restrict(ask.URL, sendRule{none: true})
		defer c.jar.release(ask.URL)
	}
	res, err := transport.Do(ask)
	if err != nil {
		return transportError(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxDrain))
	_ = res.Body.Close()
	allowed, err := r.checkPreflight(res)
	if log != nil {
		log.preflight(target, res.StatusCode, err)
	}
	if err != nil {
		return corsError("the preflight of %s %s from %s refused it: %v", r.method, target, r.from, err)
	}
	c.preflights.keep(r, target, allowed)
	return nil
}

// maxDrain is how much of a preflight's body is read so that its connection
// can carry the request: a preflight's answer has none worth keeping.
const maxDrain = 64 << 10
