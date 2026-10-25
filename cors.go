package tlsforge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	http2 "github.com/igor-lemon/fhttp/http2"
	tls_client "github.com/igor-lemon/tls-client"

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

// needsPreflight reports a hop that goes after a preflight: one CORS answers
// for, with a method or a header CORS asks about.
func (r *browserRequest) needsPreflight(h hop) bool {
	return h.cors && (!corsSafelistedMethod(h.method) || len(unsafeHeaderNames(h.script)) > 0)
}

// preflightHeader is the headers of the preflight of a hop: its own
// Sec-Fetch-Site, which goes by the URL it asks about alone, and the hop's
// Origin, which a request CORS answers always carries.
func (r *browserRequest) preflightHeader(h hop, base Header) Header {
	h.site = relation(r.from, h.to)
	values := r.values(h, base)
	values["accept"] = r.runtimeBehavior().Text("headers.accept_preflight")
	values["access-control-request-method"] = h.method
	if unsafe := unsafeHeaderNames(h.script); len(unsafe) > 0 {
		values["access-control-request-headers"] = strings.Join(unsafe, ",")
	}
	var out Header
	for _, name := range r.runtimeBehavior().Strings("headers.preflight_order") {
		if value, ok := values[name]; ok {
			out = append(out, profile.Field{Name: name, Value: value})
		}
	}
	return out
}

// corsCheck is whether an answer is the page's, as the Fetch standard's CORS
// check has it: Access-Control-Allow-Origin, said once, names the origin the
// request carried, serialized, or is "*" for a request without credentials;
// and for one with them, Access-Control-Allow-Credentials is "true".
func (r *browserRequest) corsCheck(header fhttp.Header, serialized string) error {
	allowed := header.Values("Access-Control-Allow-Origin")
	switch {
	case len(allowed) != 1:
		return fmt.Errorf("Access-Control-Allow-Origin is said %d times, not once", len(allowed))
	case r.credentials != credentialsAll && allowed[0] == "*":
		return nil
	case allowed[0] != serialized:
		return fmt.Errorf("Access-Control-Allow-Origin is %q, not %q", allowed[0], serialized)
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

// checkPreflight is what a preflight's answer allows the request, or why it
// does not: a status that is not 2xx, a CORS check that fails, a method or a
// header it does not list. "*" stands for any method or header but
// Authorization, for a request without credentials.
func (r *browserRequest) checkPreflight(res *fhttp.Response, h hop) (allowance, error) {
	var a allowance
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return a, fmt.Errorf("it was answered %d", res.StatusCode)
	}
	if err := r.corsCheck(res.Header, h.serialized(r)); err != nil {
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
	if !corsSafelistedMethod(h.method) && !slices.Contains(a.methods, h.method) &&
		(!wildcard || !slices.Contains(a.methods, "*")) {
		return a, fmt.Errorf("Access-Control-Allow-Methods does not allow %s", h.method)
	}
	for _, name := range unsafeHeaderNames(h.script) {
		listed := slices.ContainsFunc(a.headers, func(h string) bool { return strings.EqualFold(h, name) })
		if !listed && (!wildcard || name == "authorization" || !slices.Contains(a.headers, "*")) {
			return a, fmt.Errorf("Access-Control-Allow-Headers does not allow %s", name)
		}
	}
	a.maxAge = time.Duration(r.runtimeBehavior().Uint("http.preflight_default_age_seconds")) * time.Second
	if seconds, err := strconv.ParseUint(res.Header.Get("Access-Control-Max-Age"), 10, 63); err == nil {
		a.maxAge = time.Duration(min(seconds, r.runtimeBehavior().Uint("http.preflight_max_age_seconds"))) * time.Second
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

// key is the cache's key for a request carrying origin to a URL, of a method
// or a header.
func (r *browserRequest) key(origin, target, method, header string) preflightKey {
	return preflightKey{origin, target, r.credentials == credentialsAll, method, header}
}

// allows reports a hop a cached preflight lets through: its method, and every
// header it would ask about, each allowed by name or by a wildcard a request
// without credentials can use, for the origin it carries.
func (c *preflightCache) allows(r *browserRequest, h hop, target string) bool {
	origin := h.serialized(r)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	live := func(k preflightKey) bool {
		until, ok := c.allowed[k]
		return ok && now.Before(until)
	}
	wildcard := r.credentials != credentialsAll
	if !corsSafelistedMethod(h.method) && !live(r.key(origin, target, h.method, "")) &&
		(!wildcard || !live(r.key(origin, target, "*", ""))) {
		return false
	}
	for _, name := range unsafeHeaderNames(h.script) {
		if !live(r.key(origin, target, "", name)) &&
			(!wildcard || name == "authorization" || !live(r.key(origin, target, "", "*"))) {
			return false
		}
	}
	return true
}

// keep files what a preflight allowed a hop.
func (c *preflightCache) keep(r *browserRequest, h hop, target string, a allowance) {
	c.mu.Lock()
	defer c.mu.Unlock()
	origin := h.serialized(r)
	until := c.now().Add(a.maxAge)
	// Chrome caches one latest preflight result for this origin/URL and
	// credentials scope. A narrower replacement grant must not inherit
	// methods or headers allowed by an earlier result.
	for key := range c.allowed {
		if key.origin == origin && key.url == target && key.credentials == (r.credentials == credentialsAll) {
			delete(c.allowed, key)
		}
	}
	for _, method := range a.methods {
		c.allowed[r.key(origin, target, method, "")] = until
	}
	for _, header := range a.headers {
		c.allowed[r.key(origin, target, "", strings.ToLower(header))] = until
	}
}

// preflightContextKey marks a preflight's context, so that its redirect is not
// followed: a preflight answered with one fails.
type preflightContextKey struct{}

// preflight asks, before a request in cors mode, whether it may be sent: an
// OPTIONS of the same URL with Chrome's headers and no credentials, on bare,
// the connections of the page's site for requests that carry none, where
// Chrome sends it whatever the request carries. What it allows is kept in the session's cache; an answer
// that does not allow the request is an error, and the request is not sent.
//
// base is the request's context before its own layouts went on it, which
// are not the preflight's.
func (c *Client) preflight(base context.Context, inner *fhttp.Request, r *browserRequest, h hop,
	bare tls_client.HttpClient, log *requestLog) error {
	shown := shownURL(inner)
	target := shown.String()
	u := *inner.URL
	var conn net.Conn
	// A preflight carries no credentials, and keeps none of the cookies its
	// answer sets, as Chrome's.
	asked := fhttp.WithResponseCookies(context.WithValue(base, preflightContextKey{}, true), keepsNone)
	ask := (&fhttp.Request{Method: fhttp.MethodOptions, URL: &u, Host: inner.Host, Proto: "HTTP/1.1", ProtoMajor: 1,
		ProtoMinor: 1}).WithContext(keepingConn(asked, &conn))
	ask = c.browserLayouts(r.preflightHeader(h, c.headers), nil, nil, c.behavior().Strings("headers.preflight_order"), shown.Host).wear(ask)
	withPort(ask)
	if c.session.jar != nil {
		c.session.jar.restrict(ask.URL, sendRule{none: true})
		defer c.session.jar.release(ask.URL)
	}
	res, err := bare.Do(ask)
	if err == nil && res.StatusCode == fhttp.StatusMisdirectedRequest {
		// Asked once more, as Chrome asks again, on a connection of its
		// host's own.
		letGo(res, conn)
		if log != nil {
			log.misdirected(target)
		}
		again := ask.Clone(http2.WithCoalescing(ask.Context(), false))
		// The URL the jar was told about, which Clone copies.
		again.URL = ask.URL
		res, err = bare.Do(again)
	}
	if err != nil {
		return transportError(err)
	}
	c.leave("preflight", res, maxDrain)
	allowed, err := r.checkPreflight(res, h)
	if log != nil {
		log.preflight(target, res.StatusCode, err)
	}
	if err != nil {
		return corsError("the preflight of %s %s from %s refused it: %v", h.method, target, h.serialized(r), err)
	}
	c.session.preflights.keep(r, h, target, allowed)
	return nil
}

// keepsNone keeps none of the cookies an answer sets.
func keepsNone(*fhttp.Response) bool { return false }

// maxDrain is how much of the body of an answer a request goes on from is
// read, so that its connection can carry what comes next, where the profile
// does not say otherwise (leave): such an answer has none worth keeping.
const maxDrain = 64 << 10
