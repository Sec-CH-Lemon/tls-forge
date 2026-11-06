# Go package `tlsforge`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```text title="Go package tlsforge"
package tlsforge // import "github.com/Sec-CH-Lemon/tls-forge"

Package tlsforge is an HTTP client whose TLS and HTTP/2 fingerprints are a real
browser's.

The problem it solves is narrow and specific. Go's crypto/tls — like Node's
OpenSSL binding, like Python's ssl — offers no control over extension order,
GREASE values or the extension set, and those are exactly what JA3 and JA4 hash.
Chrome uses BoringSSL and sends something no stock TLS stack can produce.
A request that claims to be Chrome in its User-Agent and is demonstrably
not Chrome in its handshake is not a slightly imperfect disguise; it is a
contradiction, and it is trivially detectable.

A profile combines captured browser fields with explicit rules for values
that change across requests and connections. `tls-forge capture` measures a
browser and `tls-forge compare` checks selected fields in a local scenario.
A match there is not proof of full browser equivalence across platforms,
protocols or connection states.

    client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
    if err != nil { return err }
    defer client.Close()

    res, err := client.Get("https://tls.browserleaks.com/json")

# Scope

This is a network-layer tool. It models selected browser request behaviour;
it does not run JavaScript, execute challenges, or solve CAPTCHAs. Use it where
you are permitted to make the requests you are making.

CONSTANTS

const (
	ModeHeadless = "headless"
	ModeWindow   = "with a window"
	ModeManual   = "opened by a person"
)
    How a browser was run, for Measurement.Mode.

const DefaultMaxResponseBody int64 = 64 << 20
    DefaultMaxResponseBody bounds the decompressed body retained in memory.

const DefaultProfile = "chrome"
    DefaultProfile is used when no profile is named. It is a Chrome measured
    from a real browser, not an approximation of one.

const LevelTrace = slog.Level(-8)
    LevelTrace is the most a client says, below slog.LevelDebug: the ClientHello
    every connection sent, and every certificate a server showed.

const Timeout = 30 * time.Second
    Timeout is the default request deadline.


VARIABLES

var ErrCORS = errors.New("CORS")
    ErrCORS is what an error wraps when CORS stopped a request in a browser
    context: a preflight that did not allow it, which nothing more followed,
    or an answer that was not the page's, which is not returned. errors.Is tells
    one from a failure to send or receive.

var ErrMixedContent = errors.New("mixed content")
    ErrMixedContent is what an error wraps when a page over https would make a
    request Chrome does not send, to a URL that is not potentially trustworthy:
    plain http to a name that is not localhost or under .localhost, nor a
    loopback address. Chrome blocks fetch() and an XHR there, on the first
    request or a redirect's; a form it submits there, or posts there again after
    a 307 or a 308, only once the person using it says to go on past a warning.
    Nothing is sent to that URL. A navigation is never stopped, nor anything
    from a page that is not over https, http://localhost's too.

var ErrNeedsContext = errors.New("needs a browser context")
    ErrNeedsContext is a request without a browser context that a navigation
    typed into the address bar cannot be: one by another method than GET,
    or with a body. Chrome sends such a request only from a page, as a form,
    fetch() or an XHR: a browser context says which, and from which page.

var ErrResponseTooLarge = errors.New("tlsforge: response body exceeds the configured limit")
    ErrResponseTooLarge reports that a decompressed response exceeded its
    configured in-memory limit.


FUNCTIONS

func CanonicalURL(raw string) (string, error)
    CanonicalURL is raw as tls-forge sends a request for it, as Chrome does:
    the http or https URL Chrome's URL parser makes of it, its credentials kept,
    which no request sends before a server asks for them. The error says why
    there is none: raw is not an http or https URL, Chrome sends nothing to its
    port, or its path holds a percent sign that escapes nothing, which Chrome
    sends as it is and tls-forge cannot yet. It unwraps to the reason alone,
    said as of the URL.

func EngineMajor() int
    EngineMajor is the exact profile compatibility major.

func MeasureBrowser(ctx context.Context, opts MeasureOptions) (*capture.Capture, error)
    MeasureBrowser launches a browser, points it at a local server and returns
    what it sent.

    The window that opens shows the result and can be closed; the browser runs
    with a throwaway profile directory, so nothing touches the user's own.

func MeasureBrowserAt(ctx context.Context, server *echo.Server, opts MeasureOptions) (*capture.Capture, error)
    MeasureBrowserAt measures a browser against a server the caller already has,
    which is how a comparison puts both sides on one instrument.

func MeasureSelf(ctx context.Context, opts ...Option) (*capture.Capture, error)
    MeasureSelf returns what THIS library sends, measured the same way.

func MeasureSelfAt(ctx context.Context, server *echo.Server, opts ...Option) (*capture.Capture, error)
    MeasureSelfAt measures this library against a server the caller already has.

func MeasureVisitorAt(ctx context.Context, server *echo.Server) (*capture.Capture, error)
    MeasureVisitorAt waits for a browser a person opens a server's page in,
    and returns what it sent: Firefox, Safari, a phone's, none of which this
    library can launch. The server is one started with echo.WithManual(true),
    whose page walks the person through the visit that is measured; the browser
    is measured over HTTP/2 alone.

func OwnPage(rawURL string) (string, error)
    OwnPage is the page a request to rawURL is sent from when no other is named:
    the root of the URL's own origin, its port said where it is not the scheme's
    own ("https://www.example.com/", "https://[::1]:8443/"); or why rawURL does
    not read.

func Version() string
    Version is the actual compiled engine version.


TYPES

type BrowserContext struct {
	// Kind is what sends the request.
	Kind RequestKind
	// Initiator is the URL of the page that sends it. Empty for a navigation
	// is one typed into the address bar; a form, fetch() and an XHR need one.
	Initiator string
	// ReferrerPolicy is that page's referrer policy, as a Referrer-Policy
	// header names one. Empty is Chrome's default,
	// strict-origin-when-cross-origin.
	ReferrerPolicy string
	// Mode is fetch()'s request mode: cors, the default, no-cors or
	// same-origin. Only for fetch().
	Mode string
	// Credentials is fetch()'s credentials mode: same-origin, the default,
	// include or omit. An XHR takes same-origin, its default, or include,
	// which is withCredentials.
	Credentials string
	// Clicked says a person's click on the page sent the request: the link
	// they clicked, or the button of the form they submitted, which Chrome
	// says in Sec-Fetch-User. Without it the page's script navigated or
	// submitted the form, and the request says nothing of a person. Only a
	// navigation from a page and a form are clicked: one typed into the
	// address bar is the person's already, and a script's request is no
	// navigation for Chrome to say it of.
	Clicked bool
	// Sent says the request's Header is what a browser sent for it, as an
	// intercepting proxy is given a browser's request (sent.go): it goes with
	// those fields and no others, in Chrome's order for its kind, the
	// profile's own in place of the browser's for the user agent, the client
	// hints the profile has values of, Accept-Language and Accept-Encoding. A
	// page's subresource is sent as fetch() is in its mode, which goes the
	// same. What a browser works out is not worked out again: no Origin,
	// Referer or Sec-Fetch-* of tls-forge's, no client hints it was not sent,
	// no preflight, no check of CORS, no answer to a 401 and no start again
	// for critical hints, which the browser does itself; nor are its answers
	// kept, which it keeps itself.
	Sent bool
}
    BrowserContext says what in a browser a request stands for: what sends it,
    from which page, under which policy. A request in one goes out as Chrome
    sends that request: the headers of its kind in Chrome's order and with
    Chrome's values, Sec-Fetch-* for where it goes, Origin and Referer as the
    page would give them, and only the cookies such a request carries.

    A Request without one goes out as it always has: as a navigation typed into
    the address bar, with the profile's headers, and whatever the caller adds.
    What a context cannot be sent as yet is refused before anything is sent.

type Client struct {
	// Has unexported fields.
}
    Client is an HTTP client wearing one browser's fingerprint.

    Shipped profiles give each Do call a fresh browser instance. Redirects and
    internal protocol retries share that call's state. A profile may explicitly
    select client scope for a workflow that owns a persistent browser session.

    A Client is safe for concurrent use.

func New(opts ...Option) (*Client, error)
    New builds a client. Without options it uses the default profile.

func (c *Client) AllCookies() []Cookie
    AllCookies returns every cookie the jar holds, for every host, which is how
    a warmed session is written down whole: a cookie a redirect's host set is
    in it as well as those of the URLs that were asked for. Each comes with its
    scope, its lifetime and its SameSite, sorted by domain, path and name.

    A cookie set through another client that shares the jar, given with
    WithCookieJar, is listed by that client and not by this one.

func (c *Client) Close() error
    Close releases the client's connections, those it reads an answer it went on
    from in the background on too. A closed client must not be reused.

func (c *Client) CloseIdleConnections()
    CloseIdleConnections closes the connections the client holds open between
    requests, so that the next request opens one of its own: one that resumes
    the TLS session of the last, when the profile's browser resumes and the site
    issued a ticket, as a browser's new connection does. Those it still reads
    an answer it went on from on are let go of first, and closed. A site with
    a request still going keeps its connections until that request is done,
    and then closes those idle by then: one is not closed under a reader.
    The client stays open.

func (c *Client) Cookies(rawURL string) ([]Cookie, error)
    Cookies returns the jar's cookies for a URL. It is CookiesFor by its older
    name.

func (c *Client) CookiesFor(rawURL string) ([]Cookie, error)
    CookiesFor returns what the jar would send to a URL, each cookie with its
    scope, its lifetime and its SameSite.

func (c *Client) Do(req *Request) (*Response, error)
    Do performs a request.

    An error says nothing of the password of the client's proxy, nor of any
    other URL it quotes, since it is printed by whoever gets it; what it wraps
    is underneath, for errors.Is and errors.As.

func (c *Client) Fresh() (*Client, error)
    Fresh constructs an independent client with the same explicit inputs.
    Received cookies, cache, authentication, DNS/QUIC learning, connections
    and TLS sessions are never shared. The returned client must be closed
    separately. An opaque caller-owned cookie jar cannot be cloned and is
    rejected.

func (c *Client) Get(url string) (*Response, error)
    Get fetches a URL with the profile's headers.

func (c *Client) Headers() Header
    Headers returns the default headers, in order.

func (c *Client) Profile() *profile.Profile
    Profile returns the profile this client wears.

func (c *Client) Validate(req *Request) error
    Validate reports why a request could not be sent as it is, without sending
    it: no URL, one the transport cannot read, a method it cannot send,
    or a browser context that is incomplete, names what does not exist,
    asks for what a page cannot send, or that this client's profile cannot send.
    What Do would refuse before sending anything, it refuses; a nil error is no
    promise of an answer.

type Comparison struct {
	Browser *capture.Capture `json:"browser"`
	Client  *capture.Capture `json:"client"`
	TLS     fingerprint.Report
	HTTP1   fingerprint.Report
	HTTP2   fingerprint.Report

	// Measured is what the comparison was made of, and Manifest the rule each
	// field was compared by: together, what a match covers.
	Measured Measurement        `json:"measured"`
	Manifest []fingerprint.Rule `json:"manifest"`
}
    Comparison is the result of measuring both sides.

func Compare(browserCapture, clientCapture *capture.Capture) (*Comparison, error)
    Compare diffs two measurements that were taken earlier, which is how a
    capture saved to disk is checked against today's client.

func CompareToBrowser(ctx context.Context, measure MeasureOptions, opts ...Option) (*Comparison, error)
    CompareToBrowser measures a browser and this library on one server and diffs
    them.

    This is the function behind `tls-forge compare`, and the answer to "is
    the impersonation still good?" after a browser update — which is when it
    silently stops being true.

func CompareVisitorAt(ctx context.Context, server *echo.Server, opts ...Option) (*Comparison, error)
    CompareVisitorAt measures a visiting browser and this library on one server
    and diffs them, over TLS and HTTP/2: the browser is not measured over
    HTTP/1.1, so this library's HTTP/1.1 has nothing to be held to, and is left
    out rather than reported as a difference.

func (c *Comparison) OK() bool
    OK reports a client that matches the browser on every field compared,
    with nothing left that could not be compared: of the hellos and the first
    requests measured, which says nothing of later connections and requests.

func (c *Comparison) String() string

type ConnInfo struct {
	// Reused reports a connection that had carried a request before, so that
	// nothing was looked up, dialled or negotiated for this one.
	Reused bool
	// RemoteAddr is the other end of the socket, which is the proxy when there
	// is a proxy.
	RemoteAddr string
	// TLSVersion, CipherSuite and ALPN are what the handshake settled on, by
	// name. All three are empty over plain HTTP, and ALPN is empty as well
	// when the server negotiated no protocol.
	TLSVersion  string
	CipherSuite string
	ALPN        string
	// Resumed reports a handshake that picked up an earlier session.
	Resumed bool
	// ProxyHeader is what an HTTP or HTTPS proxy answered when it opened the
	// tunnel the connection goes through: the header fields of its reply to
	// CONNECT, in lower case. Some proxies say there where the tunnel comes
	// out, which nothing else a request can see of itself does. Nil without
	// such a proxy, and for a SOCKS proxy, whose answer has no header fields.
	ProxyHeader Header
	// Tunnel is the number of that tunnel, the same for every request that
	// goes out on it and for no other tunnel, and 0 without one. Two requests
	// with the same number came out of the same place.
	Tunnel uint64
}
    ConnInfo is the connection a request went out on.

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
    Cookie is one cookie, as a jar holds it and as a session is written down.

    Domain, Secure and HttpOnly matter for a session warmed elsewhere: a cookie
    the server set for a parent domain has to go back to the whole of it,
    and one marked Secure has to keep saying so. An empty Domain means the host
    being asked, which is what a cookie given as a bare name and value means.

type Header []profile.Field
    Header is an ordered list of headers.

    A list rather than a map because header order is fingerprinted. Go's
    net/http.Header is a map, and a map has no order — which is why libraries
    built on it emit headers alphabetically or at random, and why a client with
    a perfect TLS handshake can still be spotted from its first request.

func NewHeader(pairs ...string) Header
    NewHeader builds a header from alternating name/value pairs. An odd number
    of arguments drops the last one rather than panicking: this is convenience
    syntax, not a place to lose a request over. Names retain their spelling
    for a script's HTTP/1.1 fields. All lookups remain case-insensitive and the
    HTTP/2 writer lowercases names.

func (h *Header) Add(name, value string)
    Add appends another value for a header. Unlike Set it deliberately keeps an
    existing value; repeated Via and X-Forwarded-For fields are distinct fields
    on the wire, and the cookies of repeated Cookie fields all go, in the one
    Cookie a request sends, so the proxy must not drop any of them.

func (h Header) Clone() Header
    Clone returns an independent copy.

func (h *Header) Del(name string)
    Del removes a header.

func (h Header) Get(name string) string
    Get returns the first value for a name, matched case-insensitively.

func (h Header) Has(name string) bool
    Has reports whether a name is present, including with an empty value.

func (h Header) Merge(overrides Header) Header
    Merge layers overrides onto a base, keeping the base's ordering for names it
    already has and appending the rest.

    This is how a per-request header meets a browser profile: a caller setting
    `referer` gets the browser's order with referer in the browser's slot,
    not a browser-shaped list with one header bolted onto the end.

func (h Header) Names() []string
    Names lists the header names in order.

func (h *Header) Set(name, value string)
    Set replaces a header IN PLACE, keeping its position, or appends it.

    Keeping the position is the point. A Set that deleted and re-appended
    would move the header to the end of the list and change the fingerprint,
    so overriding one value of a browser profile would silently stop looking
    like that browser.

func (h Header) Values(name string) []string
    Values returns every value for a name, in wire order.

type MeasureOptions struct {
	// Browser names an installed browser ("chrome", "chromium", "edge",
	// "brave") or is a path to an executable. Empty searches for one.
	Browser string

	// Headless runs without a window.
	//
	// Chrome's modern headless was measured to send the identical handshake:
	// same JA4, same HTTP/2 fingerprint, same header order. It is still not the
	// default, because the browser being impersonated is a headed one, and
	// "identical when last measured" is a fact about the past.
	Headless bool

	// Timeout bounds the whole measurement. Zero means two minutes, which is
	// generous on purpose: it includes a cold browser start.
	Timeout time.Duration

	// BrowserArgs are extra flags for the browser, appended last so they win.
	//
	// For the machine rather than for the measurement. `--no-sandbox` is the one
	// a CI runner needs: Ubuntu 24.04 restricts the unprivileged user namespaces
	// Chrome's sandbox is built on, and a Windows runner denies the sandbox
	// access to the executable in its tool cache. In both, Chrome starts, never
	// loads the page, and the measurement times out having launched a browser
	// that was never going to answer. Process isolation is not TLS, so the
	// capture is the same capture — but nothing here checks that, and a flag
	// that did change what goes on the wire would quietly make this a
	// measurement of something else.
	BrowserArgs []string
}
    MeasureOptions controls a browser measurement.

type Measurement struct {
	// Browser is the browser's build, as navigator.userAgentData says it, or
	// its user agent when that says nothing.
	Browser string `json:"browser,omitempty"`
	// Platform is its operating system and machine, as navigator says them.
	Platform string `json:"platform,omitempty"`
	// Mode is how it was run: headless, with a window, or opened by a person;
	// empty for captures compared after the fact.
	Mode string `json:"mode,omitempty"`
	// Scenario is what was compared, protocol by protocol.
	Scenario []string `json:"scenario"`
}
    Measurement is what a comparison was made of: the browser, as it says it is,
    how it was run, and which of its requests were compared. The captures beside
    it hold what was sent, as it went.

type NetworkContext = networkquality.Context
    NetworkContext describes actual metadata, separately from browser persona or
    estimates.

type Option func(*config)
    Option configures a Client.

func WithCookieJar(jar fhttp.CookieJar) Option
    WithCookieJar supplies a jar, which is how a session is shared between
    clients or restored from disk. The client wraps it to keep what a jar does
    not say of its cookies, so AllCookies lists the cookies set through this
    client, and a jar that does not report a cookie's domain and path when asked
    for it is listed by AllCookies as holding none.

func WithCookies(cookies []Cookie) Option
    WithCookies starts a client with a session already warmed.

    On the client rather than on a request, because a jar is an identity:
    two warmed sessions seeded into one client describe a browser that was two
    people at once.

func WithDNSServer(address string) Option
    WithDNSServer has the client ask the DNS server at address (host:port,
    or a host and port 53) for the names it connects to, the addresses and,
    as the profile says (dns.https_records), the HTTPS records whose ECH configs
    a connection offers and whose ALPN may send it over HTTP/3 (dns.https_h3),
    instead of the machine's servers. It is for a direct connection, which the
    client dials itself: through a proxy the names are the proxy's to look up,
    and transport options a caller gives with WithTransportOption replace the
    dialer it would ask with.

func WithFixedExtensionOrder() Option
    WithFixedExtensionOrder stops shuffling the TLS extension order.

    Shuffling is on by default because Chrome shuffles. Turn it off to
    impersonate a client that does NOT — Firefox and Safari send a stable order,
    and against those a shuffling client is the anomaly.

func WithHeaders(h Header) Option
    WithHeaders layers default headers over the profile's, for every request.

func WithInsecureSkipVerify() Option
    WithInsecureSkipVerify disables certificate verification.

    This exists for one honest use: talking to the local echo server, whose
    certificate is generated per run and signs nothing. Anywhere else it removes
    the guarantee that you are talking to who you think you are — and a tool for
    looking like a browser has no business being easier to intercept than one.

func WithKeyLogWriter(w io.Writer) Option
    WithKeyLogWriter has the client write the TLS secrets of every connection
    it makes, to the sites it asks and to an HTTPS proxy, to w, in the NSS
    key log format browsers write to the file SSLKEYLOGFILE names: given them,
    Wireshark reads a capture of the client's traffic as plainly as the client
    wrote it. So can anybody else who has them: they are for looking into a run,
    never for keeping, and a file of them wants the mode 0600.

    Each line goes to w in a write of its own, never two at once, of this client
    or of any other, so w need not be safe for concurrent use. A write that
    fails fails the handshake it was for, as crypto/tls's KeyLogWriter does.
    Transport options a caller gives with WithTransportOption replace the ones
    the secrets go with, for the connections to sites, which then write none;
    an HTTPS proxy's still do.

func WithLogger(log *slog.Logger) Option
    WithLogger has the client write down what it does, as it does it:
    each step of every request, from the lookup of a name to the end of the
    answer's body, and the connections they go out on, through a proxy or not.
    Debug says the steps, LevelTrace adds the ClientHello of every connection
    and the certificates its server showed, and Info is a line for each request
    and each answer. Secrets stay out of it: a proxy's password, and the values
    of cookies and credentials.

    A request's own Logger, when it has one, is written to instead, so that what
    the request is for can be said with every record of it.

func WithMaxResponseBody(bytes int64) Option
    WithMaxResponseBody limits the decompressed response retained in memory.
    The client returns ErrResponseTooLarge when the limit is exceeded.

func WithNetworkContext(network NetworkContext) Option
    WithNetworkContext supplies actual network metadata to an estimated profile.
    It never supplies precomputed RTT or throughput, and snapshots the optional
    signal.

func WithProfile(name string) Option
    WithProfile selects a profile by name — a measured one such as "chrome",
    or any entry from the tls-client catalogue. See profile.Names.

func WithProfileValue(p *profile.Profile) Option
    WithProfileValue uses a profile directly, which is how a freshly captured
    one is used without registering it.

func WithProxy(proxyURL string) Option
    WithProxy routes requests through a proxy: http://, https://, socks5:// or
    socks5h://, with optional user:pass credentials.

func WithProxyHeader(header Header) Option
    WithProxyHeader adds header fields to the CONNECT that opens every tunnel
    through an HTTP or HTTPS proxy: for a proxy that says more about the tunnel
    when it is asked to, as SOAX does with Respond-With. They go to the proxy
    and no further, and a SOCKS proxy is sent none.

func WithRandomExtensionOrder() Option
    WithRandomExtensionOrder explicitly enables per-connection extension
    shuffling. Profiles select the browser's behaviour automatically; this is
    for a custom Chromium profile whose name and user agent do not reveal its
    family.

func WithTimeout(d time.Duration) Option
    WithTimeout sets the per-request deadline.

func WithTransportOption(opts ...tls_client.HttpClientOption) Option
    WithTransportOption is an escape hatch for explicit client-scope profiles.
    Request scope rejects opaque callbacks before transport construction, since
    they can hide shared jars or connections. Use JSON for isolated requests.
    It passes an option through to the underlying tls-client, for the cases this
    API does not cover.

    An escape hatch, on purpose: the alternative is either a wrapper for every
    option the dependency has — a list that goes stale — or a hard stop for
    callers who need one of them.

    The options are given after tls-forge's own, so one that sets what tls-forge
    sets replaces it, except profile selection: a raw WithClientProfile
    override is rejected; use WithProfile/WithProfileValue with engine_major.
    What tls-forge did with other options goes too: the transport options
    (tls_client.WithTransportOptions) take six idle connections per host and the
    decoding of bodies with them, a redirect policy takes Chrome's, a cookie
    jar the client's, and a proxy given here rather than with WithProxy is the
    transport's to dial, without tls-forge's tunnel records and exit header
    fields. Any of them leaves a client without a proxy dialing the transport's
    way, so that the connections HTTP/2 dials apart from a request go unlogged.
    GO.md, «Transport options», says it all.

func WithoutCookieJar() Option
    WithoutCookieJar stops the client from keeping cookies of its own.

    One case needs this and it is not an optimisation. A proxy forwards whatever
    Cookie header its caller sent, and a jar underneath would add a second one
    from its own store, leaving the caller's session and the proxy's quietly
    diverging. Whoever holds the session should be the only one holding it.

func WithoutRedirects() Option
    WithoutRedirects returns the 3xx instead of following it.

func WithoutSessionResumption() Option
    WithoutSessionResumption keeps no TLS session to resume, so that every
    connection is the cold handshake of a browser's first contact. Without it
    a profile whose browser resumes does as the browser does: a new connection
    to a site that issued a ticket resumes that session, with pre_shared_key,
    and a different JA4.

type Request struct {
	// Network identifies the current actual network epoch. Nil uses the configured
	// input or the profile's explicit unavailable-input contract.
	Network *NetworkContext
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
	// With request scope, no state from an earlier call is retained; select
	// explicit client scope for a reload within a persistent browser.
	Reload bool

	// Has unexported fields.
}
    Request is one HTTP request.

func (req Request) FromItsOwnPage() Request
    FromItsOwnPage is req sent as the script of a page of its URL's own origin,
    the origin's root (OwnPage), sends it by XMLHttpRequest, when req says
    nothing of what sends it (no browser context) and is no navigation typed
    into the address bar, which a GET is: a POST, PUT, PATCH, DELETE or HEAD
    as an ordinary XHR of the site. A request in a browser context, a GET (one
    with a body too) and one whose URL does not read come back as they are,
    for Do to send or refuse as ever.

func (req Request) Reloaded(res *Response) Request
    Reloaded is the request Chrome sends when the page req opened, res its
    answer, is reloaded (Ctrl+R): req again with Reload, to the URL res is at,
    where a redirect may have taken it, and by the method res answers. A form
    posted that a redirect made a GET is reloaded as that GET, a navigation
    from the form's page without the form's body, as Chrome reloads the page it
    ended on; one posted to the end is posted again. res nil, no answer, reloads
    req's own URL. A script's request opens no page and comes back as it is,
    for the page's script to send it again.

type RequestError struct {
	// Has unexported fields.
}
    RequestError retains an isolated browser's cookie snapshot after a failed
    request. It preserves the original error through Unwrap. The snapshot is
    available only to explicit callers and never seeds another browser.

func (e *RequestError) AllCookies() []Cookie
    AllCookies returns an independent snapshot of the failed browser's jar.

func (e *RequestError) Error() string

func (e *RequestError) Unwrap() error

type RequestKind string
    RequestKind is what in a browser sends a request.

const (
	// KindNavigation is a page loaded at the top: typed into the address bar
	// when it has no initiator, or reached from a page, by a link or by its
	// script setting location, when it has one.
	KindNavigation RequestKind = "navigation"
	// KindForm is a form submitted from a page, by GET or POST.
	KindForm RequestKind = "form"
	// KindFetch is a page's script calling fetch().
	KindFetch RequestKind = "fetch"
	// KindXHR is a page's script sending an XMLHttpRequest.
	KindXHR RequestKind = "xhr"
)
    The kinds of request a browser context can say a request is.

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
	// Has unexported fields.
}
    Response is one HTTP response, with the body already read and decoded.

func (r *Response) AllCookies() []Cookie
    AllCookies returns this response's browser-instance cookie snapshot.
    Reading it does not seed a later request or expose another instance's jar.

func (r *Response) OK() bool
    OK reports a 2xx status.

func (r *Response) Text() string
    Text returns the body as a string.

type Trace struct {
	// DNSStart and DNSDone surround the lookup of a name. A request to a
	// literal address has neither, and nor has one that found a connection
	// already open.
	DNSStart func(host string)
	DNSDone  func(addrs []string, err error)

	// ConnectStart and ConnectDone surround one TCP dial: to the proxy when
	// there is one, because that is where the socket goes. A host with several
	// addresses is dialled more than once, and those dials can overlap.
	ConnectStart func(network, addr string)
	ConnectDone  func(network, addr string, err error)

	// GotConn is called when a connection is ready to carry the request, with
	// its handshake done if it has one.
	GotConn func(ConnInfo)

	// WroteRequest is called when the request has been written, with the
	// header fields in the order they went onto the wire. The pseudo-headers
	// and the jar's Cookie are among them: this is the request as the server
	// saw it rather than as it was asked for.
	WroteRequest func(sent Header, err error)

	// FirstByte is called when the first byte of the response arrives.
	FirstByte func()

	// Redirect is called when a response is a redirect that is about to be
	// followed, with the status that said so and the URL it leads to.
	Redirect func(status int, location string)
}
    Trace is told what a request does on the wire, while it does it.

    A response says how a request ended. It does not say whether a name was
    looked up or a connection was already open, which address answered,
    what the handshake settled on, or in what order the headers actually left,
    and those are the questions a request that went wrong raises. One that
    failed has no response to ask at all.

    Every hook is optional. They are called from whichever goroutine is doing
    the work, so two can run at once, and one can still be called after Do has
    returned: a dial that lost a race reports in when it gets round to it.
    A redirected request calls them again for every hop.
```
