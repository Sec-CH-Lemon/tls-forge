// Package tlsforge is an HTTP client whose TLS and HTTP/2 fingerprints are a
// real browser's.
//
// The problem it solves is narrow and specific. Go's crypto/tls — like Node's
// OpenSSL binding, like Python's ssl — offers no control over extension order,
// GREASE values or the extension set, and those are exactly what JA3 and JA4
// hash. Chrome uses BoringSSL and sends something no stock TLS stack can
// produce. A request that claims to be Chrome in its User-Agent and is
// demonstrably not Chrome in its handshake is not a slightly imperfect
// disguise; it is a contradiction, and it is trivially detectable.
//
// This package sends the browser's bytes. The profiles are not written by hand
// from documentation: they are captured from a browser running on your own
// machine (`tls-forge capture`) and verified against it (`tls-forge compare`),
// which is why the claim can be checked rather than believed.
//
//	client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
//	if err != nil { return err }
//	defer client.Close()
//
//	res, err := client.Get("https://tls.browserleaks.com/json")
//
// # Scope
//
// This is a network-layer tool. It makes a request look like it came from a
// browser; it does not run JavaScript, execute challenges, or solve CAPTCHAs.
// Use it where you are permitted to make the requests you are making.
package tlsforge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tls_client "github.com/bogdanfinn/tls-client"
	"golang.org/x/net/publicsuffix"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// Client is an HTTP client wearing one browser's fingerprint.
//
// One client is one identity: one TLS fingerprint, one cookie jar, one exit IP.
// Rotating any of those means a new client, which is deliberate — a jar shared
// between two fingerprints describes a browser that changed its TLS stack
// mid-session.
//
// A Client is safe for concurrent use.
type Client struct {
	inner   tls_client.HttpClient
	profile *profile.Profile
	jar     fhttp.CookieJar
	headers Header
	closed  atomic.Bool
	maxBody int64
	// warm is the session this client was handed, filed into the jar against
	// each request's own URL.
	//
	// Not at construction: the jar files a cookie under the URL it is given, and
	// a URL synthesised from a domain has no port, which a jar keyed by host and
	// port then never matches. The request knows the URL exactly.
	warm       []Cookie
	warmMu     sync.Mutex
	warmSeeded map[warmCookieKey]struct{}
}

type warmCookieKey struct {
	index int
	host  string
}

// DefaultMaxResponseBody bounds the decompressed body retained in memory.
const DefaultMaxResponseBody int64 = 64 << 20

// ErrResponseTooLarge reports that a decompressed response exceeded its
// configured in-memory limit.
var ErrResponseTooLarge = errors.New("tlsforge: response body exceeds the configured limit")

var newDefaultCookieJar = func() (fhttp.CookieJar, error) {
	return cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}

// Request is one HTTP request.
type Request struct {
	// Context cancels this request. Nil means context.Background.
	Context context.Context
	// Method defaults to GET.
	Method string
	URL    string
	// Header is layered over the profile's headers, keeping the profile's order
	// for names it already has.
	Header Header
	Body   []byte
	// Cookies are added to the jar before the request.
	//
	// Through the jar rather than through a Cookie header on purpose: setting
	// the header by hand REPLACES whatever the jar holds, so cookies the server
	// set earlier in the session would silently vanish from this request — which
	// no real browser would ever do.
	Cookies []Cookie
}

// Cookie is one cookie to seed the jar with.
//
// Domain, Secure and HttpOnly matter for a session warmed elsewhere: a cookie
// the server set for a parent domain has to go back to the whole of it, and one
// marked Secure has to keep saying so. An empty Domain means the host being
// asked, which is what a cookie given as a bare name and value means.
type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	Expires  time.Time
}

// Response is one HTTP response, with the body already read and decompressed.
type Response struct {
	Status int
	// URL is the final URL, after redirects.
	URL     string
	Header  map[string][]string
	Body    []byte
	Cookies []string
}

// Text returns the body as a string.
func (r *Response) Text() string { return string(r.Body) }

// OK reports a 2xx status.
func (r *Response) OK() bool { return r.Status >= 200 && r.Status < 300 }

// New builds a client. Without options it uses the default profile.
func New(opts ...Option) (*Client, error) {
	cfg := defaults()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("tlsforge: nil client option")
		}
		opt(&cfg)
	}
	if cfg.timeout <= 0 {
		return nil, fmt.Errorf("tlsforge: timeout must be positive")
	}
	if cfg.maxResponseBody <= 0 || cfg.maxResponseBody == math.MaxInt64 {
		return nil, fmt.Errorf("tlsforge: maximum response body must be positive and bounded")
	}

	prof := cfg.profile
	if cfg.profileValueSet && prof == nil {
		return nil, fmt.Errorf("tlsforge: profile value cannot be nil")
	}
	if !cfg.profileValueSet {
		var err error
		if prof, err = profile.Get(cfg.profileName); err != nil {
			return nil, err
		}
	}
	prof = prof.Clone()
	clientProfile, err := prof.ClientProfile()
	if err != nil {
		return nil, err
	}

	// A nil jar reaches the transport as nil, which then keeps no cookies at
	// all. That is what WithoutCookieJar asks for.
	jar := cfg.jar
	if jar == nil && !cfg.noJar {
		jar, err = newDefaultCookieJar()
		if err != nil {
			return nil, fmt.Errorf("tlsforge: cookie jar: %w", err)
		}
	}
	milliseconds := cfg.timeout.Milliseconds()
	if milliseconds == 0 {
		milliseconds = 1
	}
	// tls-client accepts an int. Bound this consistently on every architecture
	// instead of allowing a timeout on 64-bit that wraps on a 32-bit build.
	if milliseconds > math.MaxInt32 {
		return nil, fmt.Errorf("tlsforge: timeout is too large")
	}

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutMilliseconds(int(milliseconds)),
		tls_client.WithClientProfile(clientProfile),
		tls_client.WithCookieJar(jar),
		// Six idle connections per host, which is Chrome's own limit for
		// HTTP/1.1 and six times the transport's default of one.
		//
		// It matters twice. Above the default, a request beyond the second
		// closes its connection when it finishes and the next one dials again,
		// which was measured at 1726 connections for 3000 requests over eight
		// workers. That is slow, it exhausts local ports on a long run, and a
		// fresh handshake per request is the very signal this library exists to
		// avoid. HTTP/2 multiplexes and never sees any of it: the same 3000
		// requests went over two connections.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{
			MaxIdleConnsPerHost: 6,
		}),
	}
	shuffleExtensions := prof.ShufflesExtensions()
	if cfg.shuffleExtensions != nil {
		shuffleExtensions = *cfg.shuffleExtensions
	}
	if shuffleExtensions {
		// Chrome randomises its extension order on every connection, so a client
		// that always sends the same order is distinguishable from Chrome even
		// with Chrome's exact extension set. Measured against a real browser:
		// three consecutive connections produced three different JA3 hashes and
		// one JA4. GREASE and padding stay put, as they do in Chrome.
		options = append(options, tls_client.WithRandomTLSExtensionOrder())
	}
	if !cfg.followRedirects {
		options = append(options, tls_client.WithNotFollowRedirects())
	}
	if cfg.proxy != "" {
		options = append(options, tls_client.WithProxyUrl(cfg.proxy))
	}
	if cfg.insecureSkipVerify {
		options = append(options, tls_client.WithInsecureSkipVerify())
	}
	for _, opt := range cfg.extra {
		if opt == nil {
			return nil, fmt.Errorf("tlsforge: nil transport option")
		}
	}
	options = append(options, cfg.extra...)

	inner, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}

	headers := Header(nil)
	for _, f := range prof.Headers {
		headers = append(headers, f)
	}
	headers = headers.Merge(cfg.headers)

	return &Client{inner: inner, profile: prof, jar: jar, headers: headers,
		warm: cfg.cookies, warmSeeded: map[warmCookieKey]struct{}{},
		maxBody: cfg.maxResponseBody}, nil
}

// Profile returns the profile this client wears.
func (c *Client) Profile() *profile.Profile { return c.profile.Clone() }

// Headers returns the default headers, in order.
func (c *Client) Headers() Header { return c.headers.Clone() }

// Get fetches a URL with the profile's headers.
func (c *Client) Get(url string) (*Response, error) {
	return c.Do(&Request{URL: url})
}

// Do performs a request.
func (c *Client) Do(req *Request) (*Response, error) {
	if c.closed.Load() {
		return nil, fmt.Errorf("tlsforge: this client is closed; construct a new one")
	}
	if req == nil || req.URL == "" {
		return nil, fmt.Errorf("tlsforge: request needs a URL")
	}
	method := req.Method
	if method == "" {
		method = fhttp.MethodGet
	}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	inner, err := fhttp.NewRequest(method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}
	if req.Context != nil {
		inner = inner.WithContext(req.Context)
	}

	// The URL fhttp already parsed, rather than a second parse of the same
	// string: two parsers agreeing is not something to verify at runtime, and a
	// second parse is a second chance to disagree about what the request is for.
	parsed := inner.URL
	// The warmed session, filed against this request's URL once. Re-seeding it on
	// every request would overwrite a value the server had refreshed in the jar
	// with the stale value loaded at construction.
	c.seedWarmCookies(parsed)
	c.seedCookies(parsed, req.Cookies)

	headers := c.headers.Merge(req.Header)
	// HTTP/1.1 keeps the spelling in this map on the wire; HTTP/2 lower-cases it
	// during HPACK encoding. Canonical spelling therefore fixes forced HTTP/1.1
	// without changing an HTTP/2 fingerprint.
	inner.Header = fhttp.Header{}
	order := []string{"host"}
	seen := map[string]bool{"host": true}
	inner.Header["Host"] = []string{parsed.Host}
	for _, f := range headers {
		name := strings.ToLower(f.Name)
		wireName := textproto.CanonicalMIMEHeaderKey(name)
		if name == "host" {
			// A caller's Host replaces the one taken from the URL rather than
			// following it. Appending produced two Host lines, which RFC 7230
			// requires a server to answer with 400 — and which is a request
			// smuggling primitive whenever a proxy and an origin in front of
			// the same request pick different ones.
			//
			// Host is the one name this can happen to: every other repeated
			// value arrives through Merge, which already decided that repeats
			// are wanted, while this one is seeded from the URL before the loop.
			inner.Header[wireName] = []string{f.Value}
			continue
		}
		inner.Header[wireName] = append(inner.Header[wireName], f.Value)
		if !seen[name] {
			order = append(order, name)
			seen[name] = true
		}
	}
	inner.Header[fhttp.HeaderOrderKey] = order
	if order := c.profile.HTTP2.PseudoHeaderOrder; len(order) > 0 {
		inner.Header[fhttp.PHeaderOrderKey] = order
	}

	res, err := c.inner.Do(inner)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	read, err := io.ReadAll(io.LimitReader(res.Body, c.maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("tlsforge: reading body: %w", err)
	}
	if int64(len(read)) > c.maxBody {
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, c.maxBody)
	}

	out := &Response{
		Status: res.StatusCode,
		URL:    req.URL,
		Body:   read,
		Header: map[string][]string{},
	}
	cookieURL := parsed
	if res.Request != nil && res.Request.URL != nil {
		out.URL = res.Request.URL.String()
		cookieURL = res.Request.URL
	}
	for name, values := range res.Header {
		out.Header[strings.ToLower(name)] = values
	}
	if c.jar != nil {
		for _, cookie := range c.jar.Cookies(cookieURL) {
			out.Cookies = append(out.Cookies, cookie.Name+"="+cookie.Value)
		}
	}
	return out, nil
}

// seedWarmCookies files the part of a warmed session that belongs to this host
// into the jar, once. A cookie with no domain belongs to whichever host is being
// asked, so it is seeded once per distinct host; a domain cookie is seeded once
// in total and the jar then applies its domain scope.
func (c *Client) seedWarmCookies(u *url.URL) {
	if len(c.warm) == 0 || c.jar == nil {
		return
	}

	host := strings.ToLower(u.Hostname())
	c.warmMu.Lock()
	defer c.warmMu.Unlock()

	ready := make([]Cookie, 0, len(c.warm))
	for i, cookie := range c.warm {
		domain := strings.ToLower(strings.TrimPrefix(cookie.Domain, "."))
		if domain != "" && domain != host && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		key := warmCookieKey{index: i}
		if domain == "" {
			key.host = host
		}
		if _, seeded := c.warmSeeded[key]; seeded {
			continue
		}
		c.warmSeeded[key] = struct{}{}
		ready = append(ready, cookie)
	}
	c.seedCookies(u, ready)
}

// CookiesFor returns what the jar holds for a URL, which is how a warmed
// session is read back out and written down.
func (c *Client) CookiesFor(rawURL string) ([]Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}
	if c.jar == nil {
		return nil, nil
	}
	held := c.jar.Cookies(u)
	out := make([]Cookie, 0, len(held))
	for _, cookie := range held {
		out = append(out, Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
			Expires:  cookie.Expires,
		})
	}
	return out, nil
}

func (c *Client) seedCookies(u *url.URL, cookies []Cookie) {
	if len(cookies) == 0 || c.jar == nil {
		return
	}
	jarCookies := make([]*fhttp.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		domain := cookie.Domain
		// RFC 6265 does not permit a Domain attribute on an IP address. A
		// browser-exported cookie often spells the request IP there anyway; treat
		// the matching value as the host-only cookie it represents.
		if net.ParseIP(strings.TrimPrefix(domain, ".")) != nil &&
			strings.TrimPrefix(domain, ".") == u.Hostname() {
			domain = ""
		}
		jarCookies = append(jarCookies, &fhttp.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     path,
			Domain:   domain,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
			Expires:  cookie.Expires,
		})
	}
	c.jar.SetCookies(u, jarCookies)
}

// Cookies returns the jar's cookies for a URL.
func (c *Client) Cookies(rawURL string) ([]Cookie, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}
	if c.jar == nil {
		return nil, nil
	}
	var out []Cookie
	for _, cookie := range c.jar.Cookies(parsed) {
		out = append(out, Cookie{
			Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain, Path: cookie.Path,
			Secure: cookie.Secure, HTTPOnly: cookie.HttpOnly, Expires: cookie.Expires,
		})
	}
	return out, nil
}

// Close releases the client's connections. A closed client must not be reused.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.inner.CloseIdleConnections()
	return nil
}

// Timeout is the default request deadline.
const Timeout = 30 * time.Second
