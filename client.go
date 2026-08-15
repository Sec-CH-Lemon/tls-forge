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
//	res, err := client.Get("https://example.com")
//
// # Scope
//
// This is a network-layer tool. It makes a request look like it came from a
// browser; it does not run JavaScript, execute challenges, or solve CAPTCHAs.
// Use it where you are permitted to make the requests you are making.
package tlsforge

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

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
	jar     tls_client.CookieJar
	headers Header
}

// Request is one HTTP request.
type Request struct {
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

// Cookie is a name/value pair to seed the jar with.
type Cookie struct {
	Name  string
	Value string
	Path  string
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
		opt(&cfg)
	}

	prof := cfg.profile
	if prof == nil {
		var err error
		if prof, err = profile.Get(cfg.profileName); err != nil {
			return nil, err
		}
	}
	clientProfile, err := prof.ClientProfile()
	if err != nil {
		return nil, err
	}

	jar := cfg.jar
	if jar == nil {
		jar = tls_client.NewCookieJar()
	}

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeout(int(cfg.timeout.Seconds())),
		tls_client.WithClientProfile(clientProfile),
		tls_client.WithCookieJar(jar),
	}
	if cfg.shuffleExtensions {
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

	return &Client{inner: inner, profile: prof, jar: jar, headers: headers}, nil
}

// Profile returns the profile this client wears.
func (c *Client) Profile() *profile.Profile { return c.profile }

// Headers returns the default headers, in order.
func (c *Client) Headers() Header { return c.headers.Clone() }

// Get fetches a URL with the profile's headers.
func (c *Client) Get(url string) (*Response, error) {
	return c.Do(&Request{URL: url})
}

// Do performs a request.
func (c *Client) Do(req *Request) (*Response, error) {
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

	// The URL fhttp already parsed, rather than a second parse of the same
	// string: two parsers agreeing is not something to verify at runtime, and a
	// second parse is a second chance to disagree about what the request is for.
	parsed := inner.URL
	c.seedCookies(parsed, req.Cookies)

	headers := c.headers.Merge(req.Header)
	// Assigned directly rather than through Set, which would canonicalise the
	// names to Sec-Ch-Ua form. HPACK requires lower case, and the order key is
	// matched lower-cased, so the map and the order list have to agree.
	inner.Header = fhttp.Header{}
	for _, f := range headers {
		inner.Header[f.Name] = []string{f.Value}
	}
	inner.Header[fhttp.HeaderOrderKey] = headers.Names()
	if order := c.profile.HTTP2.PseudoHeaderOrder; len(order) > 0 {
		inner.Header[fhttp.PHeaderOrderKey] = order
	}

	res, err := c.inner.Do(inner)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: %w", err)
	}
	defer res.Body.Close()

	read, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: reading body: %w", err)
	}

	out := &Response{
		Status: res.StatusCode,
		URL:    req.URL,
		Body:   read,
		Header: map[string][]string{},
	}
	if res.Request != nil && res.Request.URL != nil {
		out.URL = res.Request.URL.String()
	}
	for name, values := range res.Header {
		out.Header[strings.ToLower(name)] = values
	}
	for _, cookie := range c.jar.Cookies(parsed) {
		out.Cookies = append(out.Cookies, cookie.Name+"="+cookie.Value)
	}
	return out, nil
}

func (c *Client) seedCookies(u *url.URL, cookies []Cookie) {
	if len(cookies) == 0 {
		return
	}
	jarCookies := make([]*fhttp.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		jarCookies = append(jarCookies, &fhttp.Cookie{
			Name: cookie.Name, Value: cookie.Value, Path: path, Domain: u.Hostname(),
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
	var out []Cookie
	for _, cookie := range c.jar.Cookies(parsed) {
		out = append(out, Cookie{Name: cookie.Name, Value: cookie.Value, Path: cookie.Path})
	}
	return out, nil
}

// Close releases the client's connections. A closed client must not be reused.
func (c *Client) Close() error {
	c.inner.CloseIdleConnections()
	return nil
}

// Timeout is the default request deadline.
const Timeout = 30 * time.Second
