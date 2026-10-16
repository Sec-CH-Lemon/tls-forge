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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"github.com/bogdanfinn/fhttp/http2"
	fhttptrace "github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"golang.org/x/net/publicsuffix"

	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
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
	inner tls_client.HttpClient
	// options are what inner was built with, but for how it dials, which is
	// the client's own, and the client profile, which is clientProfile: Fresh
	// builds another with them.
	options       func(log *slog.Logger, built profiles.ClientProfile) []tls_client.HttpClientOption
	clientProfile profiles.ClientProfile
	// script is the transport requests of fetch() and an XHR go out on, made
	// when one first does: see scriptClient.
	scriptMu sync.Mutex
	script   tls_client.HttpClient
	// preflights is what CORS preflights allowed in the session: every
	// client made Fresh from this one shares it.
	preflights *preflightCache
	profile    *profile.Profile
	// jar is nil when the client keeps no cookies.
	jar     *keptJar
	headers Header
	// http1Headers begins with the shared profile headers, then applies values
	// measured only on HTTP/1.1. It stays separate so Connection can never leak
	// into HPACK merely because the same client also talks to an h1 origin.
	http1Headers Header
	closed       atomic.Bool
	maxBody      int64
	// warm is the session this client was handed, filed into the jar against
	// each request's own URL.
	//
	// Not at construction: the jar files a cookie under the URL it is given, and
	// a URL synthesised from a domain has no port, which a jar keyed by host and
	// port then never matches. The request knows the URL exactly.
	warm *warmSession

	// id is the client's number in the process, and log what it writes down
	// what it does to, with that number; nil writes nothing. logger is the one
	// it was given, which a client made Fresh numbers itself in, and requests
	// numbers the requests it is not told the purpose of.
	id       uint64
	log      *slog.Logger
	logger   *slog.Logger
	requests atomic.Uint64
	// proxy is the proxy every connection goes through, which what is logged
	// is cleaned of.
	proxy string
}

// warmSession is a session a client was handed, with which of its cookies have
// been filed already. Every client made Fresh from one shares it, so a cookie
// is filed once whichever of them asks first, and a value the server has since
// replaced in the jar is not put back.
type warmSession struct {
	cookies []Cookie
	mu      sync.Mutex
	seeded  map[warmCookieKey]struct{}
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
	// Trace, when set, is told each step this request takes on the wire.
	//
	// On the request rather than on the client, because a client is shared: two
	// requests through one connection are still two things to follow.
	Trace *Trace
	// Logger, when set, is what this request's steps are written to instead of
	// the client's logger, so that what the request is for goes with every one
	// of them: which item of a list, which try. See WithLogger.
	Logger *slog.Logger
	// Browser, when set, says what in a browser this request stands for, and
	// it goes out as Chrome sends that request: see BrowserContext. Nil sends
	// it as a navigation typed into the address bar, as it always was.
	Browser *BrowserContext
}

// Cookie is one cookie, as a jar holds it and as a session is written down.
//
// Domain, Secure and HttpOnly matter for a session warmed elsewhere: a cookie
// the server set for a parent domain has to go back to the whole of it, and one
// marked Secure has to keep saying so. An empty Domain means the host being
// asked, which is what a cookie given as a bare name and value means.
type Cookie struct {
	Name   string
	Value  string
	Domain string
	// HostOnly says the cookie goes to the host of Domain alone, as one set
	// without a Domain attribute does, and not to its subdomains. A cookie
	// seeded with it is filed for that host only, and not for any other.
	HostOnly bool
	Path     string
	Secure   bool
	HTTPOnly bool
	// Expires is when a persistent cookie expires; zero is a session cookie,
	// which lasts as long as the client.
	Expires time.Time
	// SameSite is the attribute as the server set it: "strict", "lax", "none",
	// or empty when it named none. Kept so that a session written down and
	// read back says what the server said.
	SameSite string
}

// Response is one HTTP response, with the body already read and decoded.
type Response struct {
	Status int
	// URL is the final URL, after redirects.
	URL string
	// Header describes Body. When Body was decoded from a content coding,
	// Content-Encoding and Content-Length are left out of it: they said what
	// came over the wire, and a caller that passed them on with Body would be
	// telling the next reader to decode it again.
	Header map[string][]string
	Body   []byte
	// Encoding is the content codings Body was decoded from, as a
	// Content-Encoding field would list them ("gzip", "gzip, br"), or empty
	// when Body is the bytes as they came. A body in a coding Chrome does not
	// know is not decoded, and keeps its Content-Encoding in Header.
	Encoding string
	Cookies  []string
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
	given := cfg.jar
	if given == nil && !cfg.noJar {
		given, err = newDefaultCookieJar()
		if err != nil {
			return nil, fmt.Errorf("tlsforge: cookie jar: %w", err)
		}
	}
	var jar *keptJar
	// An interface holding a nil *keptJar is not nil to the transport, which
	// would call it: only a jar that exists is handed over.
	var transportJar fhttp.CookieJar
	if given != nil {
		jar = newKeptJar(given)
		transportJar = jar
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
		tls_client.WithCookieJar(transportJar),
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
			// Bodies are decoded here rather than by the transport, which decodes
			// some wrongly and adds an Accept-Encoding of its own: see
			// encoding.go. A caller's WithTransportOption that sets transport
			// options replaces these, and the transport decodes again.
			DisableCompression: true,
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
	if len(cfg.proxyHeader) > 0 {
		asked := fhttp.Header{}
		for _, field := range cfg.proxyHeader {
			asked.Add(field.Name, field.Value)
		}
		options = append(options, tls_client.WithConnectHeaders(asked))
	}
	if cfg.insecureSkipVerify {
		options = append(options, tls_client.WithInsecureSkipVerify())
	}
	if cfg.noResumption {
		options = append(options, tls_client.WithDisableSessionTickets())
	}
	if cfg.followRedirects {
		// Redirects are new requests. Their Context carries both layouts, but the
		// GotConn hook must close over the new request rather than the first hop.
		// For every profile and not only those with an HTTP/1.1 layout to
		// prepare, so that the chain is bounded and traced the same way whichever
		// one is worn.
		options = append(options, tls_client.WithCustomRedirectFunc(followRedirect))
	}
	for _, opt := range cfg.extra {
		if opt == nil {
			return nil, fmt.Errorf("tlsforge: nil transport option")
		}
	}
	// How it dials comes last but for the caller's own, and is made for each
	// client, so that every one logs its connections as itself.
	built := func(log *slog.Logger, profile profiles.ClientProfile) []tls_client.HttpClientOption {
		out := append([]tls_client.HttpClientOption{tls_client.WithClientProfile(profile)}, options...)
		out = append(out, dialOptions(cfg.proxy, len(cfg.extra) == 0, log)...)
		return append(out, cfg.extra...)
	}

	id, log := newClientLog(cfg.logger)
	inner, err := newInnerClient(tls_client.NewNoopLogger(), built(log, clientProfile)...)
	if err != nil {
		// A proxy the transport cannot read is quoted back whole, password and
		// all, by url.Parse and by the transport alike.
		return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, cfg.proxy))
	}

	headers := Header(nil)
	for _, f := range prof.Headers {
		headers = append(headers, f)
	}
	headers = headers.Merge(cfg.headers)
	http1Headers := profileHTTP1Headers(prof)
	http1Headers = http1Headers.Merge(cfg.headers)

	client := &Client{inner: inner, options: built, clientProfile: clientProfile, profile: prof, jar: jar,
		preflights:   newPreflightCache(),
		headers:      headers,
		http1Headers: http1Headers,
		warm:         &warmSession{cookies: cfg.cookies, seeded: map[warmCookieKey]struct{}{}},
		maxBody:      cfg.maxResponseBody,
		id:           id, log: log, logger: cfg.logger, proxy: cfg.proxy}
	if log != nil {
		client.describe(cfg, shuffleExtensions, clientProfile)
	}
	return client, nil
}

// newClientLog numbers a client, and is the log it writes to under that
// number, or nil when it was given none.
func newClientLog(logger *slog.Logger) (uint64, *slog.Logger) {
	id := clientCount.Add(1)
	if logger == nil {
		return id, nil
	}
	return id, logger.With("client", id)
}

// newInnerClient is tls_client.NewHttpClient, named so a test can make it
// fail where nothing else would.
var newInnerClient = tls_client.NewHttpClient

// Fresh is a client of the same session that opens connections of its own:
// the same profile, header fields, cookie jar and warmed cookies, with a
// transport and a TLS session cache of its own. Nothing it sends goes out on a
// connection of this client's, or of any other client made Fresh, and its
// handshakes resume none of their TLS sessions, which would tell a server two
// connections were one visitor. Through a proxy that hands every connection an
// address, what it sends comes out of an address of its own.
//
// Each must be closed when it is done with. Closing one leaves this client,
// and the session they share, as they were.
func (c *Client) Fresh() (*Client, error) {
	if c.closed.Load() {
		return nil, fmt.Errorf("tlsforge: this client is closed; construct a new one")
	}
	id, log := newClientLog(c.logger)
	inner, err := newInnerClient(tls_client.NewNoopLogger(), c.options(log, c.clientProfile)...)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, c.proxy))
	}
	if log != nil {
		log.Debug("fresh client", "from", c.id)
	}
	return &Client{inner: inner, options: c.options, clientProfile: c.clientProfile, profile: c.profile, jar: c.jar,
		preflights:   c.preflights,
		headers:      c.headers,
		http1Headers: c.http1Headers, warm: c.warm, maxBody: c.maxBody,
		id: id, log: log, logger: c.logger, proxy: c.proxy}, nil
}

func profileHTTP1Headers(prof *profile.Profile) Header {
	shared := append(Header(nil), prof.Headers...)
	if prof.HTTP1 == nil {
		return shared
	}
	resolved := shared.Merge(Header(prof.HTTP1.Headers))
	var out Header
	for _, wireName := range prof.HTTP1.HeaderOrder {
		if strings.EqualFold(wireName, "host") {
			continue
		}
		for _, value := range resolved.Values(wireName) {
			out = append(out, profile.Field{Name: strings.ToLower(wireName), Value: value})
		}
	}
	return out
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
//
// An error says nothing of the password of the client's proxy, nor of any
// other URL it quotes, since it is printed by whoever gets it; what it wraps is
// underneath, for errors.Is and errors.As.
func (c *Client) Do(req *Request) (*Response, error) {
	r := c.requestLog(req)
	res, err := c.do(req, r)
	if r != nil {
		r.ended(res, err)
	}
	return res, redact.Err(err, c.proxy)
}

// requestLog is the log a request is written down in: its own logger's, or
// the client's with the request's number, or nil when there is neither.
func (c *Client) requestLog(req *Request) *requestLog {
	log := c.log
	switch {
	case req != nil && req.Logger != nil:
		log = req.Logger.With("client", c.id)
	case log != nil:
		log = log.With("request", c.requests.Add(1))
	default:
		return nil
	}
	return newRequestLog(log, c.proxy, "prepare")
}

func (c *Client) do(req *Request, r *requestLog) (*Response, error) {
	if r != nil && req != nil {
		r.start(cmp.Or(req.Method, fhttp.MethodGet), req.URL, len(req.Body))
	}
	if c.closed.Load() {
		return nil, fmt.Errorf("tlsforge: this client is closed; construct a new one")
	}
	inner, browser, err := c.parse(req)
	if err != nil {
		return nil, err
	}
	method := inner.Method
	if req.Context != nil {
		inner = inner.WithContext(req.Context)
	}
	if req.Trace != nil {
		inner = inner.WithContext(req.Trace.attach(inner.Context()))
	}
	if r != nil {
		inner = inner.WithContext(r.attach(inner.Context()))
	}

	// The URL fhttp already parsed, rather than a second parse of the same
	// string: two parsers agreeing is not something to verify at runtime, and a
	// second parse is a second chance to disagree about what the request is for.
	parsed := inner.URL
	transport := c.inner
	if browser != nil && (browser.kind == KindFetch || browser.kind == KindXHR) {
		if transport, err = c.scriptClient(); err != nil {
			return nil, err
		}
	}
	// The warmed session, filed against this request's URL once. Re-seeding it on
	// every request would overwrite a value the server had refreshed in the jar
	// with the stale value loaded at construction.
	c.seedWarmCookies(parsed)
	c.seedCookies(parsed, req.Cookies)

	var http1 fhttp.Header
	switch {
	case browser != nil:
		field := browser.header(parsed, c.headers)
		order := browser.wireOrder()
		inner.Header = browserLayout(field, order, parsed.Host)
		http1 = browserHTTP1Layout(field, browser.script, order, c.profile.HTTP1, c.http1Headers, parsed.Host)
	default:
		headers := c.headers.Merge(req.Header)
		inner.Header = legacyHeaderLayout(headers, parsed.Host)
		switch {
		case c.profile.HTTP1 != nil:
			http1 = measuredHTTP1Layout(c.http1Headers.Merge(req.Header), c.profile.HTTP1, parsed.Host)
		case !headers.Has("user-agent"):
			// The one field the two protocols cannot be told the same way: an
			// HTTP/1.1 connection gets a layout of its own even where nothing
			// else differs.
			http1 = cloneHeaderLayout(inner.Header)
		}
	}
	if order := c.profile.HTTP2.PseudoHeaderOrder; len(order) > 0 {
		inner.Header[fhttp.PHeaderOrderKey] = order
	}
	quietUserAgent(inner.Header, http2UserAgent)
	unlaid := inner.Context()
	if http1 != nil {
		quietUserAgent(http1, http1UserAgent)
		layouts := &protocolLayouts{
			http1:   http1,
			http2:   cloneHeaderLayout(inner.Header),
			managed: managedHeaderNames(inner.Header, http1),
		}
		inner = withProtocolLayouts(inner, layouts)
	}

	if browser != nil && browser.needsPreflight() && !c.preflights.allows(browser, inner.URL.String()) {
		if err := c.preflight(unlaid, inner, browser, transport, r); err != nil {
			return nil, err
		}
	}
	if browser != nil && c.jar != nil {
		// By the URL the transport will ask the jar about: the request's own,
		// which every WithContext above copied anew.
		c.jar.restrict(inner.URL, browser.cookies(originOf(inner.URL)))
		defer c.jar.release(inner.URL)
	}
	if r != nil {
		r.step("connect")
	}
	withPort(inner)
	res, err := transport.Do(inner)
	if err != nil {
		return nil, transportError(err)
	}
	defer func() { _ = res.Body.Close() }()
	if r != nil {
		r.answered(res)
	}
	if browser != nil && browser.cors {
		if err := browser.corsCheck(res.Header); err != nil {
			return nil, corsError("the answer of %s %s did not allow %s: %v", browser.method, shownURL(res.Request),
				browser.from, err)
		}
	}

	answered := method
	if res.Request != nil {
		// The method of the request that was answered, which a redirect can
		// have changed.
		answered = res.Request.Method
	}
	read, encoding, err := readBody(res, answered, c.maxBody)
	if err != nil {
		return nil, err
	}

	out := &Response{
		Status:   res.StatusCode,
		URL:      req.URL,
		Body:     read,
		Encoding: encoding,
		Header:   map[string][]string{},
	}
	cookieURL := parsed
	if res.Request != nil && res.Request.URL != nil {
		out.URL = shownURL(res.Request).String()
		cookieURL = res.Request.URL
	}
	for name, values := range res.Header {
		lower := strings.ToLower(name)
		if encoding != "" && (lower == "content-encoding" || lower == "content-length") {
			continue
		}
		out.Header[lower] = values
	}
	if c.jar != nil {
		// What the jar holds for the URL, whatever this request carried.
		for _, cookie := range c.jar.inner.Cookies(cookieURL) {
			out.Cookies = append(out.Cookies, cookie.Name+"="+cookie.Value)
		}
	}
	return out, nil
}

// Validate reports why a request could not be sent as it is, without sending
// it: no URL, one the transport cannot read, a method it cannot send, or a
// browser context that is incomplete, names what does not exist, asks for what
// a page cannot send, or that this client's profile cannot send. What Do
// would refuse before sending anything, it refuses; a nil error is no promise
// of an answer.
func (c *Client) Validate(req *Request) error {
	_, _, err := c.parse(req)
	return err
}

// parse is a request as the transport will send it, and its browser context
// resolved against it, the method normalized as the context says; or why it
// cannot be sent.
func (c *Client) parse(req *Request) (*fhttp.Request, *browserRequest, error) {
	if req == nil || req.URL == "" {
		return nil, nil, fmt.Errorf("tlsforge: request needs a URL")
	}
	method := cmp.Or(req.Method, fhttp.MethodGet)
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	inner, err := fhttp.NewRequest(method, req.URL, body)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsforge: %w", err)
	}
	if req.Browser == nil {
		return inner, nil, nil
	}
	browser, err := c.resolveBrowser(req, method, inner.URL)
	if err != nil {
		return nil, nil, err
	}
	inner.Method = browser.method
	return inner, browser, nil
}

// resolveBrowser is a request's browser context resolved against it, or why
// it cannot be sent as one: the layouts are Chromium's, measured on Chrome,
// and are filled in with the profile's own header values.
func (c *Client) resolveBrowser(req *Request, method string, target *url.URL) (*browserRequest, error) {
	switch {
	case !c.profile.Chromium():
		return nil, errContext("is measured on Chrome; profile %q is not of a Chromium browser", c.profile.Name)
	case !c.headers.Has("user-agent"):
		return nil, errContext("needs the profile's headers, and profile %q has none to send", c.profile.Name)
	}
	return req.Browser.resolve(method, target, req.Header, req.Body)
}

// legacyHeaderLayout is the compatibility path for profiles captured before
// HTTP/1.1 was measured. Its canonical spelling is intentionally the old
// behaviour: adding a schema field must not make an existing profile fail a
// request it used to send.
func legacyHeaderLayout(headers Header, host string) fhttp.Header {
	out := fhttp.Header{}
	order := []string{"host"}
	seen := map[string]bool{"host": true}
	out["Host"] = []string{host}
	for _, field := range headers {
		name := strings.ToLower(field.Name)
		wireName := textproto.CanonicalMIMEHeaderKey(name)
		if name == "host" {
			out[wireName] = []string{field.Value}
			continue
		}
		out[wireName] = append(out[wireName], field.Value)
		if !seen[name] {
			order = append(order, name)
			seen[name] = true
		}
	}
	out[fhttp.HeaderOrderKey] = order
	return out
}

func measuredHTTP1Layout(headers Header, measured *profile.HTTP1, host string) fhttp.Header {
	values := make(map[string][]string)
	for _, field := range headers {
		name := strings.ToLower(field.Name)
		values[name] = append(values[name], field.Value)
	}
	if hosts := values["host"]; len(hosts) > 0 {
		host = hosts[len(hosts)-1]
	}

	out := fhttp.Header{}
	order := make([]string, 0, len(measured.HeaderOrder)+len(headers))
	seen := make(map[string]bool)
	for _, wireName := range measured.HeaderOrder {
		name := strings.ToLower(wireName)
		var fieldValues []string
		if name == "host" {
			fieldValues = []string{host}
		} else {
			fieldValues = values[name]
		}
		if len(fieldValues) == 0 {
			continue
		}
		out[wireName] = append([]string(nil), fieldValues...)
		order = append(order, name)
		seen[name] = true
	}
	for _, field := range headers {
		name := strings.ToLower(field.Name)
		if seen[name] || name == "host" {
			continue
		}
		wireName := textproto.CanonicalMIMEHeaderKey(name)
		out[wireName] = append([]string(nil), values[name]...)
		order = append(order, name)
		seen[name] = true
	}
	out[fhttp.HeaderOrderKey] = order
	return out
}

// quietUserAgent keeps the transport from naming itself. fhttp gives a request
// that carries no User-Agent its own, "Go-http-client", which says what is
// talking more plainly than any handshake could hide it; and a request can come
// without one, from a profile out of the transport's catalogue, which knows a
// handshake and no headers, or from a hand-written one.
//
// Each protocol is told it is named and empty in the one way its writer takes
// as that: HTTP/2 by an empty value, which it leaves out, and HTTP/1.1 by the
// field with no values at all, since an empty value is a line of its own there
// and no values is no line. Neither reads the other's way: HTTP/2 passes over a
// field with no values before it notices the name, and HTTP/1.1 writes
// "User-Agent: " for an empty one.
func quietUserAgent(header fhttp.Header, empty []string) {
	for name := range header {
		if strings.EqualFold(name, "user-agent") {
			return
		}
	}
	header["User-Agent"] = empty
}

// How each protocol's writer is told a request names no user agent.
var (
	http2UserAgent = []string{""}
	http1UserAgent = []string{}
)

type protocolLayouts struct {
	http1   fhttp.Header
	http2   fhttp.Header
	managed map[string]bool
}

type protocolLayoutsKey struct{}

func managedHeaderNames(layouts ...fhttp.Header) map[string]bool {
	out := make(map[string]bool)
	for _, layout := range layouts {
		for name := range layout {
			out[strings.ToLower(name)] = true
		}
	}
	return out
}

func withProtocolLayouts(req *fhttp.Request, layouts *protocolLayouts) *fhttp.Request {
	ctx := context.WithValue(req.Context(), protocolLayoutsKey{}, layouts)
	target := req
	trace := &fhttptrace.ClientTrace{GotConn: func(info fhttptrace.GotConnInfo) {
		if connectionUsesHTTP1(target.URL, info.Conn) {
			applyHeaderLayout(target.Header, layouts.http1, layouts.managed)
		}
	}}
	return req.WithContext(fhttptrace.WithClientTrace(ctx, trace))
}

// maxRedirects is how many redirects one request follows before it gives up.
//
// Ten is what the transport allows when it is left alone, and it has to be
// said again here because a redirect policy of one's own replaces that check
// rather than adding to it. The policy that prepares the HTTP/1.1 layout let
// everything through, so two pages redirecting to each other were followed
// until the request's deadline: measured against a local server, 54,600
// requests in five seconds.
const maxRedirects = 10

// followRedirect is the policy for every redirect: where the chain stops, who
// is told about the hop, and which header layout the next request wears.
func followRedirect(req *fhttp.Request, via []*fhttp.Request) error {
	if req.Context().Value(preflightContextKey{}) != nil {
		// A preflight answered with a redirect is refused, not followed.
		return fhttp.ErrUseLastResponse
	}
	// The transport sets Response on every request it builds to follow a
	// redirect, to the response that sent it there.
	r := requestLogOf(req.Context())
	if len(via) >= maxRedirects {
		if r != nil {
			r.stopped(len(via), req.Response.StatusCode, shownURL(req).String())
		}
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if t, _ := req.Context().Value(traceKey{}).(*Trace); t != nil {
		t.redirect(req.Response.StatusCode, shownURL(req).String())
	}
	if r != nil {
		r.redirect(len(via), req.Response.StatusCode, shownURL(req).String(), req.Response.Header)
	}
	withPort(req)
	return prepareRedirectLayout(req, via)
}

func prepareRedirectLayout(req *fhttp.Request, _ []*fhttp.Request) error {
	layouts, _ := req.Context().Value(protocolLayoutsKey{}).(*protocolLayouts)
	if layouts == nil {
		return nil
	}
	// fhttp has already copied only the headers that are safe for this redirect.
	// Replaying the first hop's complete HTTP/1 block here would undo that
	// decision: on a cross-origin redirect it reintroduced Authorization, Cookie
	// and the old Host after fhttp had deliberately removed them.
	host := req.URL.Host
	if req.Host != "" {
		// fhttp sets Request.Host only when an explicitly overridden host is being
		// preserved across a relative redirect. An absolute redirect never reaches
		// this branch, so a source origin cannot lend its Host to another one.
		host = req.Host
	}
	http1 := redirectHTTP1Layout(layouts.http1, layouts.http2, req.Header, host)
	redirect := &protocolLayouts{
		http1:   http1,
		http2:   cloneHeaderLayout(req.Header),
		managed: managedHeaderNames(req.Header, http1),
	}
	prepared := withProtocolLayouts(req, redirect)
	*req = *prepared
	return nil
}

// redirectHTTP1Layout keeps the measured spelling and HTTP/1-only fields from
// the first layout while applying the redirect policy reflected in current.
// original is the HTTP/2-shaped block before the first request was sent; it is
// the baseline fhttp copies on every hop.
func redirectHTTP1Layout(http1, original, current fhttp.Header, host string) fhttp.Header {
	out := cloneHeaderLayout(http1)
	before := headerValues(original)
	now := headerValues(current)

	beforeNames := make([]string, 0, len(before))
	for name := range before {
		beforeNames = append(beforeNames, name)
	}
	slices.Sort(beforeNames)
	for _, name := range beforeNames {
		if name == "host" {
			continue
		}
		values := before[name]
		redirected, kept := now[name]
		if !kept {
			deleteHeader(out, name)
			continue
		}
		// An unchanged shared field keeps its HTTP/1-specific captured value.
		// A changed field (Referer and adjusted explicit cookies are the usual
		// examples) must use the value computed for this hop.
		if !slices.Equal(redirected, values) {
			setHeader(out, name, redirected)
		}
	}
	nowNames := make([]string, 0, len(now))
	for name := range now {
		nowNames = append(nowNames, name)
	}
	slices.Sort(nowNames)
	for _, name := range nowNames {
		if name == "host" || headerLayoutKey(name) {
			continue
		}
		if _, existed := before[name]; !existed {
			setHeader(out, name, now[name])
		}
	}
	setHeader(out, "host", []string{host})
	return out
}

func cloneHeaderLayout(header fhttp.Header) fhttp.Header {
	out := make(fhttp.Header, len(header))
	for name, values := range header {
		out[name] = copyValues(values)
	}
	return out
}

// copyValues copies a field's values, and keeps a field with none as one with
// none rather than as nil: to fhttp a nil field is one that is not there, and an
// HTTP/1.1 request without a User-Agent field is one fhttp gives its own.
func copyValues(values []string) []string {
	return append(make([]string, 0, len(values)), values...)
}

func headerValues(header fhttp.Header) map[string][]string {
	out := make(map[string][]string, len(header))
	for name, values := range header {
		lower := strings.ToLower(name)
		if headerLayoutKey(lower) {
			continue
		}
		out[lower] = append(out[lower], values...)
	}
	return out
}

func headerLayoutKey(name string) bool {
	return strings.EqualFold(name, fhttp.HeaderOrderKey) ||
		strings.EqualFold(name, fhttp.PHeaderOrderKey)
}

func deleteHeader(header fhttp.Header, lower string) {
	for name := range header {
		if strings.EqualFold(name, lower) {
			delete(header, name)
		}
	}
	order := header[fhttp.HeaderOrderKey]
	kept := order[:0]
	for _, name := range order {
		if !strings.EqualFold(name, lower) {
			kept = append(kept, name)
		}
	}
	header[fhttp.HeaderOrderKey] = kept
}

func setHeader(header fhttp.Header, lower string, values []string) {
	wireName := ""
	for name := range header {
		if strings.EqualFold(name, lower) && !headerLayoutKey(name) {
			wireName = name
			break
		}
	}
	if wireName == "" {
		wireName = textproto.CanonicalMIMEHeaderKey(lower)
		header[fhttp.HeaderOrderKey] = append(header[fhttp.HeaderOrderKey], lower)
	}
	header[wireName] = append([]string(nil), values...)
}

func connectionUsesHTTP1(target *url.URL, conn net.Conn) bool {
	if target.Scheme == "http" {
		return true
	}
	state, ok := conn.(connectionStater)
	if !ok {
		// An unknown TLS wrapper must not perturb HTTP/2, the core fingerprint.
		return false
	}
	negotiated := state.ConnectionState().NegotiatedProtocol
	return negotiated == "" || negotiated == "http/1.1"
}

func applyHeaderLayout(target, layout fhttp.Header, managed map[string]bool) {
	for name := range target {
		if managed[strings.ToLower(name)] {
			delete(target, name)
		}
	}
	for name, values := range layout {
		target[name] = copyValues(values)
	}
}

// seedWarmCookies files the part of a warmed session that belongs to this host
// into the jar, once. A cookie with no domain belongs to whichever host is being
// asked, so it is seeded once per distinct host; a domain cookie is seeded once
// in total and the jar then applies its domain scope.
func (c *Client) seedWarmCookies(u *url.URL) {
	warm := c.warm
	if len(warm.cookies) == 0 || c.jar == nil {
		return
	}

	host := strings.ToLower(u.Hostname())
	warm.mu.Lock()
	defer warm.mu.Unlock()

	ready := make([]Cookie, 0, len(warm.cookies))
	for i, cookie := range warm.cookies {
		domain := strings.ToLower(strings.TrimPrefix(cookie.Domain, "."))
		if domain != "" && domain != host && (cookie.HostOnly || !strings.HasSuffix(host, "."+domain)) {
			continue
		}
		key := warmCookieKey{index: i}
		if domain == "" {
			key.host = host
		}
		if _, seeded := warm.seeded[key]; seeded {
			continue
		}
		warm.seeded[key] = struct{}{}
		ready = append(ready, cookie)
	}
	c.seedCookies(u, ready)
}

// CookiesFor returns what the jar would send to a URL, each cookie with its
// scope, its lifetime and its SameSite.
func (c *Client) CookiesFor(rawURL string) ([]Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}
	if c.jar == nil {
		return nil, nil
	}
	return c.jar.forURL(u), nil
}

// Cookies returns the jar's cookies for a URL. It is CookiesFor by its older
// name.
func (c *Client) Cookies(rawURL string) ([]Cookie, error) { return c.CookiesFor(rawURL) }

// AllCookies returns every cookie the jar holds, for every host, which is how
// a warmed session is written down whole: a cookie a redirect's host set is in
// it as well as those of the URLs that were asked for. Each comes with its
// scope, its lifetime and its SameSite, sorted by domain, path and name.
//
// A cookie set through another client that shares the jar, given with
// WithCookieJar, is listed by that client and not by this one.
func (c *Client) AllCookies() []Cookie {
	if c.jar == nil {
		return nil
	}
	return c.jar.all()
}

// seedCookies files cookies in the jar against u, each as what it is: a
// cookie its host's alone under that host and under no other, a domain's under
// the domain, a session cookie without an expiry.
func (c *Client) seedCookies(u *url.URL, cookies []Cookie) {
	if len(cookies) == 0 || c.jar == nil {
		return
	}
	host := strings.ToLower(u.Hostname())
	jarCookies := make([]*fhttp.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		domain := strings.ToLower(strings.TrimPrefix(cookie.Domain, "."))
		// RFC 6265 does not permit a Domain attribute on an IP address. A
		// browser-exported cookie often spells the request IP there anyway; the
		// matching value is the host-only cookie it represents.
		if cookie.HostOnly || domain == "" || (net.ParseIP(domain) != nil && domain == host) {
			if domain != "" && domain != host {
				continue
			}
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
			SameSite: sameSiteMode(cookie.SameSite),
		})
	}
	c.jar.SetCookies(u, jarCookies)
}

// CloseIdleConnections closes the connections the client holds open between
// requests, so that the next request opens one of its own: one that resumes
// the TLS session of the last, when the profile's browser resumes and the site
// issued a ticket, as a browser's new connection does. The client stays open.
func (c *Client) CloseIdleConnections() {
	c.inner.CloseIdleConnections()
	c.closeScript()
	if c.log != nil {
		c.log.Debug("idle connections closed")
	}
}

// Close releases the client's connections. A closed client must not be reused.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.inner.CloseIdleConnections()
	c.closeScript()
	if c.log != nil {
		c.log.Debug("client closed")
	}
	return nil
}

// closeScript closes the idle connections of the transport of fetch() and an
// XHR, when there is one.
func (c *Client) closeScript() {
	c.scriptMu.Lock()
	defer c.scriptMu.Unlock()
	if c.script != nil {
		c.script.CloseIdleConnections()
	}
}

// scriptClient is the transport a request of fetch() or an XHR goes out on,
// made when one first does: the client's own, but for the priority on each
// request's HEADERS frame, which Chrome gives such a request (weight 220)
// where it gives a page its highest (256). The transport puts one priority on
// every request it sends, so these go out on connections of their own, with
// TLS sessions of their own.
func (c *Client) scriptClient() (tls_client.HttpClient, error) {
	c.scriptMu.Lock()
	defer c.scriptMu.Unlock()
	if c.script == nil {
		built := withHeaderPriority(c.clientProfile, scriptHeaderPriority)
		script, err := newInnerClient(tls_client.NewNoopLogger(), c.options(c.log, built)...)
		if err != nil {
			return nil, fmt.Errorf("tlsforge: %w", redact.Err(err, c.proxy))
		}
		c.script = script
	}
	return c.script, nil
}

// withHeaderPriority is a client profile with another priority on the
// HEADERS frame of every request.
func withHeaderPriority(p profiles.ClientProfile, priority http2.PriorityParam) profiles.ClientProfile {
	return profiles.NewClientProfile(p.GetClientHelloId(), p.GetSettings(), p.GetSettingsOrder(),
		p.GetPseudoHeaderOrder(), p.GetConnectionFlow(), p.GetPriorities(), &priority, p.GetStreamID(),
		p.GetAllowHTTP(), p.GetHttp3Settings(), p.GetHttp3SettingsOrder(), p.GetHttp3PriorityParam(),
		p.GetHttp3PseudoHeaderOrder(), p.GetHttp3SendGreaseFrames())
}

// scriptHeaderPriority is the priority Chrome 155 puts on the HEADERS frame of
// fetch(), an XHR and a CORS preflight: exclusive, on no stream (on a
// connection of their own), weight 220 (219 on the wire), as measured in
// testdata/chrome155-requests.json, where a page's is 256.
var scriptHeaderPriority = http2.PriorityParam{Exclusive: true, Weight: 219}

// Timeout is the default request deadline.
const Timeout = 30 * time.Second
