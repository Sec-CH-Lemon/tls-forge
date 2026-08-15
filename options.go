package tlsforge

import (
	"time"

	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// DefaultProfile is used when no profile is named. It is a Chrome measured from
// a real browser, not an approximation of one.
const DefaultProfile = "chrome"

type config struct {
	profile            *profile.Profile
	profileName        string
	proxy              string
	timeout            time.Duration
	headers            Header
	jar                tls_client.CookieJar
	followRedirects    bool
	insecureSkipVerify bool
	shuffleExtensions  bool
	extra              []tls_client.HttpClientOption
}

func defaults() config {
	return config{
		profileName:     DefaultProfile,
		timeout:         Timeout,
		followRedirects: true,
		// On by default because the browser being impersonated does it. See the
		// note where the option is applied.
		shuffleExtensions: true,
	}
}

// Option configures a Client.
type Option func(*config)

// WithProfile selects a profile by name — a measured one such as "chrome", or
// any entry from the tls-client catalogue. See profile.Names.
func WithProfile(name string) Option {
	return func(c *config) { c.profileName = name }
}

// WithProfileValue uses a profile directly, which is how a freshly captured one
// is used without registering it.
func WithProfileValue(p *profile.Profile) Option {
	return func(c *config) { c.profile = p }
}

// WithProxy routes requests through a proxy: http://, https://, socks5:// or
// socks5h://, with optional user:pass credentials.
func WithProxy(proxyURL string) Option {
	return func(c *config) { c.proxy = proxyURL }
}

// WithTimeout sets the per-request deadline.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithHeaders layers default headers over the profile's, for every request.
func WithHeaders(h Header) Option {
	return func(c *config) { c.headers = c.headers.Merge(h) }
}

// WithCookieJar supplies a jar, which is how a session is shared between
// clients or restored from disk.
func WithCookieJar(jar tls_client.CookieJar) Option {
	return func(c *config) { c.jar = jar }
}

// WithoutRedirects returns the 3xx instead of following it.
func WithoutRedirects() Option {
	return func(c *config) { c.followRedirects = false }
}

// WithInsecureSkipVerify disables certificate verification.
//
// This exists for one honest use: talking to the local echo server, whose
// certificate is generated per run and signs nothing. Anywhere else it removes
// the guarantee that you are talking to who you think you are — and a tool for
// looking like a browser has no business being easier to intercept than one.
func WithInsecureSkipVerify() Option {
	return func(c *config) { c.insecureSkipVerify = true }
}

// WithFixedExtensionOrder stops shuffling the TLS extension order.
//
// Shuffling is on by default because Chrome shuffles. Turn it off to impersonate
// a client that does NOT — Firefox and Safari send a stable order, and against
// those a shuffling client is the anomaly.
func WithFixedExtensionOrder() Option {
	return func(c *config) { c.shuffleExtensions = false }
}

// WithTransportOption passes an option through to the underlying tls-client,
// for the cases this API does not cover.
//
// An escape hatch, on purpose: the alternative is either a wrapper for every
// option the dependency has — a list that goes stale — or a hard stop for
// callers who need one of them.
func WithTransportOption(opts ...tls_client.HttpClientOption) Option {
	return func(c *config) { c.extra = append(c.extra, opts...) }
}
