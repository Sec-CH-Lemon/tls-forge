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
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
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
	// transports are how its requests reach the network, its own; session
	// is what its identity keeps across them, which every client made Fresh
	// from this one shares.
	transports *transports
	session    *session
	profile    *profile.Profile
	headers    Header
	// http1Headers begins with the shared profile headers, then applies values
	// measured only on HTTP/1.1. It stays separate so Connection can never leak
	// into HPACK merely because the same client also talks to an h1 origin.
	http1Headers Header
	closed       atomic.Bool
	maxBody      int64

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
	t, err := newTransports(built, clientProfile, log, cfg.proxy)
	if err != nil {
		return nil, err
	}

	headers := Header(nil)
	for _, f := range prof.Headers {
		headers = append(headers, f)
	}
	headers = headers.Merge(cfg.headers)
	http1Headers := profileHTTP1Headers(prof)
	http1Headers = http1Headers.Merge(cfg.headers)

	// The warmed cookies are filed into the jar against each request's own URL,
	// not here: the jar files a cookie under the URL it is given, and a URL
	// synthesised from a domain has no port, which a jar keyed by host and port
	// then never matches. The request knows the URL exactly.
	client := &Client{transports: t, session: newSession(jar, cfg.cookies), profile: prof, headers: headers,
		http1Headers: http1Headers, maxBody: cfg.maxResponseBody,
		id: id, log: log, logger: cfg.logger, proxy: cfg.proxy}
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
	t, err := c.transports.fresh(log)
	if err != nil {
		return nil, err
	}
	if log != nil {
		log.Debug("fresh client", "from", c.id)
	}
	return &Client{transports: t, session: c.session, profile: c.profile, headers: c.headers,
		http1Headers: c.http1Headers, maxBody: c.maxBody,
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
	// The URL fhttp already parsed, rather than a second parse of the same
	// string: two parsers agreeing is not something to verify at runtime, and a
	// second parse is a second chance to disagree about what the request is for.
	parsed := inner.URL
	transport := c.transports.page
	if browser != nil && browser.scripted() {
		if transport, err = c.transports.forScript(); err != nil {
			return nil, err
		}
	}
	// The warmed session, filed against this request's URL once. Re-seeding it on
	// every request would overwrite a value the server had refreshed in the jar
	// with the stale value loaded at construction.
	c.session.seedWarm(parsed)
	c.session.seed(parsed, req.Cookies)

	res, ch, err := c.send(req, inner, browser, transport, r, false)
	if errors.Is(err, errCriticalHints) {
		// Chrome starts the navigation again, once, where it began. The
		// request was read once already, so it reads the same again.
		inner, _, _ = c.parse(req)
		res, ch, err = c.send(req, inner, browser, transport, r, true)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if browser != nil && ch.last.cors {
		serialized := ch.last.serialized(browser)
		if err := browser.corsCheck(res.Header, serialized); err != nil {
			return nil, corsError("the answer of %s %s did not allow %s: %v", ch.last.method,
				shownURL(res.Request).Redacted(), serialized, err)
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
	if c.session.jar != nil {
		// What the jar holds for the URL, whatever this request carried.
		for _, cookie := range c.session.jar.inner.Cookies(cookieURL) {
			out.Cookies = append(out.Cookies, cookie.Name+"="+cookie.Value)
		}
	}
	return out, nil
}

// errCriticalHints is how a navigation ends whose answer names, in
// Critical-CH, client hints its origin asked for that it did not carry:
// Chrome starts it again for them, once.
var errCriticalHints = errors.New("tlsforge: the page needs client hints it was not sent")

// send sends inner, the request req asks for, as its browser context says,
// and follows its redirects: the first request of a navigation started again
// for its critical client hints when restarted. It returns the answer, the
// chain that came to it, or why there is none.
func (c *Client) send(req *Request, inner *fhttp.Request, browser *browserRequest, transport tls_client.HttpClient,
	r *requestLog, restarted bool) (*fhttp.Response, *chain, error) {
	if req.Context != nil {
		inner = inner.WithContext(req.Context)
	}
	if req.Trace != nil {
		inner = inner.WithContext(req.Trace.attach(inner.Context()))
	}
	if r != nil {
		inner = inner.WithContext(r.attach(inner.Context()))
	}
	parsed := inner.URL
	ch := &chain{client: c, transport: transport, log: r, browser: browser, urls: []*url.URL{parsed},
		restarted: restarted}
	// A URL's credentials go only where a 401 asks for them; the transport
	// would send them at once.
	user := parsed.User
	parsed.User = nil
	var blocks *layouts
	switch {
	case browser != nil:
		first := browser.first(parsed)
		first.hints = c.hintsOf(browser, first)
		first.restarted = restarted
		first.authorization = ch.arrive(first.method, parsed, user, ch.authenticates(first))
		ch.last, ch.policy = first, browser.policy
		if first.referrer != "" {
			ch.referrer, _ = url.Parse(first.referrer)
		}
		blocks = c.browserLayouts(browser.header(first, c.headers), first.script, browser.wireOrder(first), parsed.Host)
	default:
		headers := c.headers.Merge(req.Header)
		ch.given, ch.own = headers.Values("referer"), headers.Has("authorization")
		blocks = c.layoutsAsGiven(headers, req.Header, parsed.Host)
		if value := ch.arrive(inner.Method, parsed, user, ch.authenticates(ch.last)); value != "" {
			blocks = blocks.authorized(value)
		}
		ch.laid = blocks
	}
	ch.ours = ch.sent != nil
	ch.base = inner.Context()
	inner = blocks.wear(inner)
	inner = inner.WithContext(context.WithValue(inner.Context(), chainKey{}, ch))

	defer ch.release()
	if browser != nil {
		if browser.needsPreflight(ch.last) && !c.session.preflights.allows(browser, ch.last, inner.URL.String()) {
			if err := c.preflight(ch.base, inner, browser, ch.last, transport, r); err != nil {
				return nil, nil, err
			}
		}
		// By the URL the transport will ask the jar about: the request's own,
		// which every WithContext above copied anew.
		ch.rule(inner.URL, browser.cookies(ch.last))
	}
	if r != nil {
		r.step("connect")
	}
	withPort(inner)
	res, err := transport.Do(inner)
	for err == nil {
		if r != nil {
			r.answered(res)
		}
		value, ok, failed := ch.challenged(res)
		if failed != nil || ok {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxDrain))
			_ = res.Body.Close()
		}
		if failed != nil {
			return nil, nil, failed
		}
		if !ok {
			break
		}
		retry := ch.again(res.Request, value)
		if r != nil {
			r.step("connect")
		}
		withPort(retry)
		res, err = transport.Do(retry)
	}
	if err != nil {
		return nil, nil, transportError(err)
	}
	if browser != nil && !browser.scripted() {
		// What the origin asked for, said on the answer to a navigation.
		ch.remember(originOf(res.Request.URL), res.Header)
		if ch.restart(shownURL(res.Request), res.Header, ch.last) {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxDrain))
			_ = res.Body.Close()
			return nil, nil, errCriticalHints
		}
	}
	return res, ch, nil
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

// followRedirect is the policy for every redirect: where the chain stops, who
// is told about the hop, and which header layout the next request wears.
func followRedirect(req *fhttp.Request, via []*fhttp.Request) error {
	if req.Context().Value(preflightContextKey{}) != nil {
		// A preflight answered with a redirect is refused, not followed.
		return fhttp.ErrUseLastResponse
	}
	// The transport sets Response on every request it builds to follow a
	// redirect, to the response that sent it there. The count goes on across
	// a challenge answered, which is no redirect, as Chrome's does.
	r := requestLogOf(req.Context())
	ch, _ := req.Context().Value(chainKey{}).(*chain)
	ch.redirects++
	if ch.redirects >= maxRedirects {
		if r != nil {
			r.stopped(ch.redirects, req.Response.StatusCode, shownURL(req).String())
		}
		return fmt.Errorf("the %dth redirect was not followed", maxRedirects)
	}
	if t, _ := req.Context().Value(traceKey{}).(*Trace); t != nil {
		t.redirect(req.Response.StatusCode, shownURL(req).String())
	}
	if r != nil {
		r.redirect(ch.redirects, req.Response.StatusCode, shownURL(req).String(), req.Response.Header)
	}
	withPort(req)
	return ch.follow(req, via)
}

// CookiesFor returns what the jar would send to a URL, each cookie with its
// scope, its lifetime and its SameSite.
func (c *Client) CookiesFor(rawURL string) ([]Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}
	return c.session.cookiesFor(u), nil
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
func (c *Client) AllCookies() []Cookie { return c.session.all() }

// CloseIdleConnections closes the connections the client holds open between
// requests, so that the next request opens one of its own: one that resumes
// the TLS session of the last, when the profile's browser resumes and the site
// issued a ticket, as a browser's new connection does. The client stays open.
func (c *Client) CloseIdleConnections() {
	c.transports.closeIdle()
	if c.log != nil {
		c.log.Debug("idle connections closed")
	}
}

// Close releases the client's connections. A closed client must not be reused.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.transports.closeIdle()
	if c.log != nil {
		c.log.Debug("client closed")
	}
	return nil
}

// Timeout is the default request deadline.
const Timeout = 30 * time.Second
