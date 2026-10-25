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

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/cookiejar"
	http2 "github.com/igor-lemon/fhttp/http2"
	tls_client "github.com/igor-lemon/tls-client"
	"golang.org/x/net/publicsuffix"

	"github.com/Sec-CH-Lemon/tls-forge/internal/conntap"
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
	// given are the fields the client was given (WithHeaders), which a request
	// without a browser context sent as a typed navigation carries in their
	// slots (typed.go).
	given Header
	// http1Headers begins with the shared profile headers, then applies values
	// measured only on HTTP/1.1. It stays separate so Connection can never leak
	// into HPACK merely because the same client also talks to an h1 origin.
	http1Headers Header
	closed       atomic.Bool
	maxBody      int64
	// timeout is how long a request may take, all of it.
	timeout time.Duration

	// withheld is what of the profile's headers a request without a browser
	// context sends only to a URL that is potentially trustworthy, less what
	// the client was given; nil for none.
	withheld *withholding

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
	// upgrades is how a request to plain http learns that the name's HTTPS
	// records send it to https (dns.https_upgrade), or nil: through a proxy
	// and with transport options of the caller's, the names are not looked
	// up here.
	upgrades *resolving
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
	// URL is an http or https URL, read as Chrome reads one: the request goes
	// out for it as Chrome writes it (CanonicalURL), and one Chrome sends
	// nothing for is refused before anything is sent.
	URL string
	// Header is layered over the profile's headers, keeping the profile's order
	// for names it already has. A Cookie in it goes with the jar's cookies, as
	// net/http adds a jar's to a request's own: every cookie it names first,
	// then those the jar holds for the URL, over HTTP/1.1 and HTTP/2 alike.
	Header Header
	// Body nil means no body. A non-nil empty slice is an explicit zero-byte
	// upload; framing is derived from this distinction and the selected profile.
	Body []byte
	// Cookies are added to the jar before the request.
	//
	// Through the jar rather than through a Cookie header on purpose: a cookie
	// in the jar goes on every request it belongs to and gives way to the value
	// the server sets next, as a browser's does, while one in the header goes
	// with this request alone, beside the jar's, so a name in both goes twice —
	// which no real browser would ever do.
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
	// Reload sends the request as Chrome sends it again when the page it
	// opened is reloaded (Ctrl+R): the navigation, typed or from a page, or
	// the form, to the URL of that page, its Response's URL. It asks for the
	// page afresh (Cache-Control), says the person asked (Sec-Fetch-User),
	// carries what the page's answer set, its cookies and the client hints it
	// asked for, and goes on a connection the client still holds to the site,
	// as Chrome's goes on the one the page came on; a form's POST goes with
	// its body again, in the order Chrome posts it again in. A script's
	// request opens no page and is not reloaded: Ctrl+R reloads its page.
	Reload bool
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
	// URL is the final URL, after redirects, as Chrome writes it.
	URL string
	// Method is the method of the request this answers: the request's own,
	// or GET where a redirect made a POST one, as Chrome follows it.
	Method string
	// Header in a browser context preserves received representation metadata,
	// as Fetch does even after decoding Body. Encoding says what was decoded.
	// Without a browser context Header describes the decoded Body, so a proxy
	// can forward it without instructing its reader to decode it again.
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
	if err := prof.ValidateEngine(); err != nil {
		return nil, err
	}
	prof = prof.Clone()
	prof.Behavior = prof.RuntimeBehavior().Clone()
	shuffleExtensions := prof.ShufflesExtensions()
	if cfg.shuffleExtensions != nil {
		shuffleExtensions = *cfg.shuffleExtensions
	}
	// Chrome draws the order of its TLS extensions for every connection, so
	// a client that always sends one order is told from Chrome even with its
	// exact extensions; the profile draws it, every order as likely as any
	// other, as Chrome does.
	clientProfile, err := prof.ClientProfileShuffled(shuffleExtensions)
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
		jar.behavior = prof.RuntimeBehavior().Clone()
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

	// One writer for every connection of the client and of every client
	// Fresh makes of it, to sites and to a proxy alike.
	keys := keyLogOf(cfg.keyLog)
	dnsServer, err := dnsServerOf(cfg.dnsServer)
	if err != nil {
		return nil, err
	}
	// How long an idle connection is kept: the profile's for each protocol,
	// else one for both. A browser's HTTP/1.1 socket pool reaps an idle
	// socket when a socket is next asked of it ("on-request"), not by a timer.
	idleTimeout := policyDuration(prof.RuntimeBehavior(), "http.idle_connection_timeout_ms")
	if prof.RuntimeBehavior().Has("h1.idle_connection_timeout_ms") {
		idleTimeout = policyDuration(prof.RuntimeBehavior(), "h1.idle_connection_timeout_ms")
	}
	transportOptions := &tls_client.TransportOptions{
		MaxIdleConnsPerHost:   prof.RuntimeBehavior().Int("h1.max_idle_connections"),
		IdleConnTimeout:       &idleTimeout,
		IdleConnReapOnRequest: prof.RuntimeBehavior().Text("h1.idle_reap") == "on-request",
		DisableCompression:    true,
		KeyLogWriter:          keys,
	}
	if prof.RuntimeBehavior().Has("h2.idle_connection_timeout_ms") {
		http2Idle := policyDuration(prof.RuntimeBehavior(), "h2.idle_connection_timeout_ms")
		transportOptions.HTTP2IdleConnTimeout = &http2Idle
	}
	if prof.RuntimeBehavior().Has("h1.response_header_bytes") {
		// The profile bounds an HTTP/1 response head at 256 KiB, including the
		// status line and delimiters, and holds at most six HTTP/1 connections
		// in a host's pool. HTTP/2 keeps its own multiplexing/field-list rules.
		transportOptions.MaxResponseHeaderBytes = int64(prof.RuntimeBehavior().Uint("h1.response_header_bytes"))
		transportOptions.MaxConnsPerHost = prof.RuntimeBehavior().Int("h1.max_connections")
	}
	options := []tls_client.HttpClientOption{
		// A request ends with its context, which do gives the timeout as its
		// deadline: the transport sets none of its own on each of the
		// requests one asks for, and bounds each dial with it.
		tls_client.WithTimeoutMilliseconds(int(milliseconds)),
		tls_client.WithoutRequestTimeout(),
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
		// Bodies are decoded here (encoding.go); an explicit caller-supplied
		// transport-options value replaces all these defaults.
		tls_client.WithTransportOptions(transportOptions),
	}
	if transportShuffles(prof, shuffleExtensions) {
		options = append(options, tls_client.WithRandomTLSExtensionOrder())
	}
	if !cfg.followRedirects {
		options = append(options, tls_client.WithNotFollowRedirects())
	}
	if len(cfg.proxyHeader) > 0 || prof.RuntimeBehavior().Flag("proxy.profile_tls") {
		asked := fhttp.Header{}
		if prof.RuntimeBehavior().Flag("proxy.profile_tls") {
			ua := Header(prof.Headers).Merge(cfg.headers).Get("user-agent")
			if !cfg.proxyHeader.Has("user-agent") {
				asked.Set("User-Agent", ua)
			}
			if !cfg.proxyHeader.Has("proxy-connection") {
				asked.Set("Proxy-Connection", prof.RuntimeBehavior().Text("proxy.connection_value"))
			}
			asked[fhttp.HeaderOrderKey] = prof.RuntimeBehavior().Strings("proxy.connect_header_order")
		}
		for _, field := range cfg.proxyHeader {
			asked.Add(field.Name, field.Value)
		}
		options = append(options, tls_client.WithConnectHeaders(asked))
	}
	if cfg.insecureSkipVerify {
		options = append(options, tls_client.WithInsecureSkipVerify())
	}
	if cfg.noResumption || !prof.RuntimeBehavior().Flag("tls.resumption") {
		options = append(options, tls_client.WithDisableSessionTickets())
	}
	if cfg.followRedirects {
		// Redirects are new requests, which fhttp makes with the first's
		// context, its layouts in it, and no HeaderFor: followRedirect dresses
		// each. For every profile and not only those with an HTTP/1.1 layout
		// to prepare, so that the chain is bounded and traced the same way
		// whichever one is worn.
		options = append(options, tls_client.WithCustomRedirectFunc(followRedirect))
	}
	for _, opt := range cfg.extra {
		if opt == nil {
			return nil, fmt.Errorf("tlsforge: nil transport option")
		}
	}
	// How it dials comes last but for what each transport is given of its own
	// and the caller's own.
	// One resolving for every connection of the client and of every client
	// Fresh makes of it: what it keeps of the HTTPS records, the host cache.
	res := newResolving(dnsServer, prof.RuntimeBehavior())
	// What the session knows of QUIC, as a profile's network session does:
	// whether it worked, where it broke, each server's RTT.
	quic := tls_client.NewQUICState()
	built := func(proxyPool *proxyH2Pool, site func() string, own ...tls_client.HttpClientOption) []tls_client.HttpClientOption {
		out := append([]tls_client.HttpClientOption{tls_client.WithLockedClientProfile(clientProfile, fmt.Sprintf("profile %q engine_major %d (running engine major %d)", prof.Name, *prof.EngineMajor, EngineMajor()))}, options...)
		h3 := &tls_client.HTTP3FromDNS{Endpoint: res.quicEndpoint, State: quic, Key: site}
		out = append(out, dialOptions(cfg.proxy, len(cfg.extra) == 0, keys, keepAliveOf(prof.RuntimeBehavior()),
			res, h3, proxyIdentity{profile: prof, pool: proxyPool})...)
		return append(append(out, own...), cfg.extra...)
	}

	id, log := newClientLog(cfg.logger)
	t, err := newTransports(built, cfg.proxy, prof.RuntimeBehavior())
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
	client := &Client{transports: t, session: newSession(jar, cfg.cookies, prof.RuntimeBehavior()), profile: prof, headers: headers,
		given: cfg.headers.Clone(), http1Headers: http1Headers, withheld: withheldOf(prof, cfg.headers), maxBody: cfg.maxResponseBody, timeout: cfg.timeout,
		id: id, log: log, logger: cfg.logger, proxy: cfg.proxy}
	if prof.RuntimeBehavior().Flag("dns.https_upgrade") && cfg.proxy == "" && len(cfg.extra) == 0 {
		client.upgrades = res
	}
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
	if err := c.profile.ValidateEngine(); err != nil {
		return nil, err
	}
	if c.closed.Load() {
		return nil, fmt.Errorf("tlsforge: this client is closed; construct a new one")
	}
	id, log := newClientLog(c.logger)
	t, err := c.transports.fresh()
	if err != nil {
		return nil, err
	}
	if log != nil {
		log.Debug("fresh client", "from", c.id)
	}
	return &Client{transports: t, session: c.session, profile: c.profile, headers: c.headers,
		given: c.given, http1Headers: c.http1Headers, withheld: c.withheld, maxBody: c.maxBody, timeout: c.timeout,
		id: id, log: log, logger: c.logger, proxy: c.proxy, upgrades: c.upgrades}, nil
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
	if err := c.profile.ValidateEngine(); err != nil {
		return nil, err
	}
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
	// The warmed session, filed against this request's URL once. Re-seeding it on
	// every request would overwrite a value the server had refreshed in the jar
	// with the stale value loaded at construction.
	c.session.seedWarm(parsed)
	c.session.seed(parsed, req.Cookies)
	// A request asks the pool for a connection: what is idle too long goes,
	// but at its own address, whose round trip cleans up once it has asked
	// whether there is a connection, as Chromium's main job asks its socket
	// group before its socket request cleans up.
	c.transports.reapIdle(dialAddress(parsed))

	// One deadline for all of the request: its preflight, each hop, each
	// answer to a 401 or a 421, its start again for client hints, and its
	// body. Sent each alone, each had the whole timeout again.
	ctx, cancel := context.WithTimeout(cmp.Or(req.Context, context.Background()), c.timeout)
	defer cancel()
	res, ch, err := c.send(ctx, req, inner, browser, r, false)
	if errors.Is(err, errCriticalHints) {
		// Chrome starts the navigation again, once, where it began. The
		// request was read once already, so it reads the same again.
		inner, _, _ = c.parse(req)
		res, ch, err = c.send(ctx, req, inner, browser, r, true)
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
	read, encoding, err := readBody(res, answered, c.maxBody, c.behavior())
	if err != nil {
		return nil, err
	}

	out := &Response{
		Status:   res.StatusCode,
		URL:      req.URL,
		Method:   answered,
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
		if !browser.explicit() && encoding != "" && (lower == "content-encoding" || lower == "content-length") {
			continue
		}
		out.Header[lower] = values
	}
	if browser.explicit() {
		for name, values := range res.FramingHeader {
			out.Header[strings.ToLower(name)] = values
		}
	}
	if c.session.jar != nil {
		// What the jar holds for the URL, whatever this request carried.
		for _, cookie := range c.session.jar.inner.Cookies(jarURL(cookieURL)) {
			out.Cookies = append(out.Cookies, cookie.Name+"="+cookie.Value)
		}
	}
	return out, nil
}

// errCriticalHints is how a navigation ends whose answer names, in
// Critical-CH, client hints its origin asked for that it did not carry:
// Chrome starts it again for them, once.
var errCriticalHints = errors.New("tlsforge: the page needs client hints it was not sent")

// send sends inner, the request req asks for, in ctx, as its browser context
// says, and follows its redirects: the first request of a navigation started
// again for its critical client hints when restarted. It returns the answer,
// the chain that came to it, or why there is none.
func (c *Client) send(ctx context.Context, req *Request, inner *fhttp.Request, browser *browserRequest, r *requestLog,
	restarted bool) (*fhttp.Response, *chain, error) {
	inner = inner.WithContext(ctx)
	if req.Trace != nil {
		inner = inner.WithContext(req.Trace.attach(inner.Context()))
	}
	if r != nil {
		inner = inner.WithContext(r.attach(inner.Context()))
	}
	if tap := conntap.From(ctx); tap != nil {
		inner = inner.WithContext(watched(inner.Context(), tap))
	}
	parsed := inner.URL
	ch := &chain{client: c, log: r, browser: browser, urls: []*url.URL{parsed}, restarted: restarted}
	// A URL's credentials go only where a 401 asks for them; the transport
	// would send them at once.
	user := parsed.User
	parsed.User = nil
	var blocks *layouts
	switch {
	case browser != nil:
		first := browser.first(parsed)
		if !browser.sent {
			first.hints = c.hintsOf(browser, first)
		}
		first.restarted = restarted
		first.authorization = ch.arrive(first.method, parsed, user, ch.authenticates(first))
		ch.last, ch.policy = first, browser.policy
		if first.referrer != "" {
			ch.referrer, _ = url.Parse(first.referrer)
		}
		blocks = ch.layoutsOf(first, parsed.Host)
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
	switch {
	case browser != nil && browser.sent:
		// The priority of its urgency, as Chrome gives what the browser sent.
		if priority, ok := c.sentFramePriority(browser, ch.last); ok {
			inner = inner.WithContext(http2.WithHeaderPriority(inner.Context(), priority))
		}
	case browser != nil && browser.scripted():
		// With a priority of their own, as Chrome sends them: the preflight,
		// the hops of its redirects and its answer to a 401 too.
		inner = inner.WithContext(http2.WithHeaderPriority(inner.Context(), priorityFrom(c.behavior(), "headers.script_priority")))
	}
	// A request that carries no credentials goes out on connections of its
	// own, as Chrome sends one, and each top-level site has its own; each hop
	// of its redirects goes out on those of its own site and credentials, and
	// its answer to a 401 or a 421 on those of the hop it answers, whichever
	// client follows them: the first hop's.
	if err := ch.goOn(parsed); err != nil {
		return nil, nil, err
	}
	transport := ch.on
	ch.base = inner.Context()
	inner = blocks.wear(inner)
	inner = inner.WithContext(ch.in(inner.Context()))

	defer ch.release()
	if browser != nil {
		if browser.needsPreflight(ch.last) && !c.session.preflights.allows(browser, ch.last, inner.URL.String()) {
			if err := c.preflight(ch.base, inner, browser, ch.last, ch.site.bare, r); err != nil {
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
		ch.took()
		if r != nil {
			r.answered(res)
		}
		if ch.misdirected(res) {
			if r != nil {
				r.misdirected(shownURL(res.Request).String())
			}
			res, err = transport.Do(ch.remade(res.Request))
			continue
		}
		value, ok, failed := ch.challenged(res)
		if failed != nil {
			c.leave("dropped", res, maxDrain)
			return nil, nil, failed
		}
		if !ok {
			break
		}
		c.leave("auth", res, maxDrain)
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
	if browser != nil && !browser.scripted() && !browser.sent {
		// What the origin asked for, said on the answer to a navigation.
		ch.remember(originOf(res.Request.URL), res.Header)
		if ch.restart(shownURL(res.Request), res.Header, ch.last) {
			c.leave("restart", res, maxDrain)
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
	target, err := requestURL(req.URL, nil, c.behavior())
	if err != nil {
		return nil, nil, fmt.Errorf("tlsforge: %q %w", req.URL, err)
	}
	method := cmp.Or(req.Method, fhttp.MethodGet)
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	inner, err := fhttp.NewRequest(method, target.String(), body)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsforge: %w", err)
	}
	var browser *browserRequest
	switch {
	case req.Browser != nil:
		browser, err = c.resolveBrowser(req, method, inner.URL)
	case !c.typedWithoutContext():
		if req.Reload {
			return nil, nil, fmt.Errorf("tlsforge: profile %q sends a request without a browser context as "+
				"it is given, which opens no page to reload", c.profile.Name)
		}
		return inner, nil, nil
	default:
		browser, err = c.typedNavigation(req, method, inner.URL)
	}
	if err == nil && req.Reload {
		err = browser.reloads()
	}
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
	case !c.behavior().Flag("headers.browser_context"):
		return nil, errContext("profile %q does not enable browser_context", c.profile.Name)
	case !c.headers.Has("user-agent"):
		return nil, errContext("needs the profile's headers, and profile %q has none to send", c.profile.Name)
	}
	r, err := req.Browser.resolve(method, target, req.Header, req.Body, c.behavior())
	if err == nil && r.sent {
		c.asProfile(r)
	}
	return r, err
}

// transportShuffles reports whether the transport draws the order of a
// client's TLS extensions: for a bare base of its catalogue, whose handshake
// is its own, when shuffle says. A profile with a handshake of its own draws
// it itself (profile.ClientProfileShuffled), and the transport's draw, which
// passes over a swap with GREASE, would be a second one.
func transportShuffles(prof *profile.Profile, shuffle bool) bool {
	return shuffle && prof.BareBase()
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
	if ch.browser != nil && ch.browser.sent {
		// A browser follows the redirects of what it sent itself, with its
		// own cookies and Sec-Fetch-* for each hop: it is answered with them.
		return fhttp.ErrUseLastResponse
	}
	// The request goes on from the redirect, followed or not, without its
	// body, which is let go of before anything the hop asks.
	ch.client.leave("dropped", req.Response, -1)
	if err := locate(req, via[len(via)-1]); err != nil {
		return err
	}
	ch.redirects++
	limit := ch.client.behavior().Int("http.redirects_navigation")
	if ch.browser != nil && (ch.browser.kind == KindFetch || ch.browser.kind == KindXHR) {
		limit = ch.client.behavior().Int("http.redirects_fetch")
	}
	if ch.redirects > limit {
		if r != nil {
			r.stopped(ch.redirects, req.Response.StatusCode, shownURL(req).String())
		}
		return fmt.Errorf("the %s redirect was not followed", ordinal(limit+1))
	}
	if t, _ := req.Context().Value(traceKey{}).(*Trace); t != nil {
		t.redirect(req.Response.StatusCode, shownURL(req).String())
	}
	if r != nil {
		r.redirect(ch.redirects, req.Response.StatusCode, shownURL(req).String(), req.Response.Header)
	}
	withPort(req)
	// A hop goes out as one of its own, which Chrome sends with IP pooling on
	// whatever the hop before it was sent with: the transport makes it with
	// the context of the request it was given, a hop sent again for a 421.
	// Before it is dressed, since the URL the jar is told about is the copy
	// WithContext makes.
	*req = *req.WithContext(http2.WithCoalescing(req.Context(), true))
	if err := ch.follow(req, via); err != nil {
		return err
	}
	return ch.goOn(req.URL)
}

// CookiesFor returns what the jar would send to a URL, each cookie with its
// scope, its lifetime and its SameSite.
func (c *Client) CookiesFor(rawURL string) ([]Cookie, error) {
	p, err := parseURL(rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %q %w", rawURL, err)
	}
	return c.session.cookiesFor(p.url()), nil
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
// issued a ticket, as a browser's new connection does. Those it still reads an
// answer it went on from on are let go of first, and closed. The client stays
// open.
func (c *Client) CloseIdleConnections() {
	c.transports.closeIdle()
	if c.log != nil {
		c.log.Debug("idle connections closed")
	}
}

// Close releases the client's connections, those it reads an answer it went
// on from in the background on too. A closed client must not be reused.
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
