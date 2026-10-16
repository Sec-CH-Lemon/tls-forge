package tlsforge

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// A cookie jar answers one question, what goes to this URL, and says of each
// cookie its name, value, domain, path and expiry. It does not say whether the
// cookie is its host's alone or its domain's, nor whether it lasts past the
// session, and those are what a session written down and read back has to
// keep: without them a host's cookie came back as its domain's and went to
// every subdomain, and a session cookie came back expiring in the year 9999,
// which is how the jar spells "never" to itself.
//
// So the jar a client is given is wrapped, and every cookie set through it is
// filed beside it under the identity RFC 6265 gives it, its name, domain and
// path, with what the jar would not say. What the wrapper knows is also what
// lets a client list every cookie it holds, rather than only those of a URL.

// keptJar is a jar with what it does not say of its cookies kept beside it.
type keptJar struct {
	inner fhttp.CookieJar
	mu    sync.Mutex
	kept  map[cookieKey]cookieFacts
	// rules are what a request in a browser context lets through, by the URL
	// the transport asks the jar about for it: its own, for each hop.
	rules sync.Map
}

// cookieKey is a cookie's identity in a jar: a second cookie of the same name,
// domain and path replaces the first.
type cookieKey struct{ name, domain, path string }

// cookieFacts are what the jar does not say of a cookie.
type cookieFacts struct {
	hostOnly   bool
	persistent bool
	sameSite   fhttp.SameSite
	// created is when the cookie was first set: one set again over it keeps
	// the first's, as RFC 6265 has a browser keep it.
	created time.Time
}

// maxCookieLifetime is the longest Chrome keeps a cookie: a later Expires or a
// longer Max-Age is cut to 400 days, as RFC 6265bis has every browser do. Cut
// here too, so that a cookie lives as long as it would in the browser, and a
// Max-Age of centuries cannot overflow the jar's arithmetic into a date that
// cannot be written down.
const maxCookieLifetime = 400 * 24 * time.Hour

// jarSessionEnd is the expiry the transport's jar gives a session cookie, which
// is how one is told apart when the wrapper never saw it set.
var jarSessionEnd = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

func newKeptJar(inner fhttp.CookieJar) *keptJar {
	return &keptJar{inner: inner, kept: map[cookieKey]cookieFacts{}}
}

// SetCookies files the cookies in the jar, each cut to Chrome's lifetime, and
// keeps what the jar will not say of them.
func (j *keptJar) SetCookies(u *url.URL, cookies []*fhttp.Cookie) {
	now := time.Now()
	capped := make([]*fhttp.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c != nil {
			capped = append(capped, capLifetime(c, now))
		}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.inner.SetCookies(u, capped)
	for _, c := range capped {
		key, hostOnly, filed := jarKeyOf(u, c)
		switch {
		case !filed:
		case c.MaxAge < 0 || (c.MaxAge == 0 && !c.Expires.IsZero() && !c.Expires.After(now)):
			delete(j.kept, key)
		default:
			created := now
			if before, known := j.kept[key]; known {
				created = before.created
			}
			j.kept[key] = cookieFacts{
				hostOnly:   hostOnly,
				persistent: c.MaxAge > 0 || !c.Expires.IsZero(),
				sameSite:   c.SameSite,
				created:    created,
			}
		}
	}
}

// Cookies is the jar's own answer, what goes to a URL, less what a request in
// a browser context does not carry, when u is that request's.
func (j *keptJar) Cookies(u *url.URL) []*fhttp.Cookie {
	held := j.inner.Cookies(u)
	ruled, ok := j.rules.Load(u)
	if !ok {
		return held
	}
	rule := ruled.(sendRule)
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	kept := held[:0:0]
	for _, c := range held {
		facts, known := j.kept[cookieKey{c.Name, c.Domain, c.Path}]
		if rule.allows(facts, known, now) {
			kept = append(kept, c)
		}
	}
	return kept
}

// restrict has the jar answer the transport, when it asks about u, with what
// a request in a browser context carries; release forgets it.
func (j *keptJar) restrict(u *url.URL, rule sendRule) { j.rules.Store(u, rule) }
func (j *keptJar) release(u *url.URL)                 { j.rules.Delete(u) }

// sendRule is which cookies a request in a browser context carries.
type sendRule struct {
	// none carries none: fetch() with credentials omitted, or kept to its
	// own origin and going to another.
	none bool
	// crossSite goes to another site than its initiator's.
	crossSite bool
	// topLevel loads a page at the top: a navigation or a form.
	topLevel bool
	// safe is a GET or a HEAD.
	safe bool
}

// laxAllowingUnsafe is how long after it was set a cookie that named no
// SameSite still goes with a page's POST to it from another site: Chrome's
// two minutes, measured in testdata/chrome155-requests.json.
const laxAllowingUnsafe = 2 * time.Minute

// allows reports a cookie a request carries, by its SameSite: to its own site
// any; to another, one of SameSite=None, one of Lax when a page is loaded by
// GET, and one that named none, which is Lax, also when a page is posted to
// within two minutes of its being set. A cookie the wrapper never saw set
// named none, as far as it knows, and was not set lately.
func (rule sendRule) allows(facts cookieFacts, known bool, now time.Time) bool {
	switch {
	case rule.none:
		return false
	case !rule.crossSite:
		return true
	}
	switch facts.sameSite {
	case fhttp.SameSiteNoneMode:
		return true
	case fhttp.SameSiteStrictMode:
		return false
	case fhttp.SameSiteLaxMode:
		return rule.topLevel && rule.safe
	}
	return rule.topLevel && (rule.safe || known && now.Sub(facts.created) < laxAllowingUnsafe)
}

// forURL is what goes to a URL, with what the jar does not say of each cookie.
func (j *keptJar) forURL(u *url.URL) []Cookie {
	held := j.inner.Cookies(u)
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Cookie, 0, len(held))
	for _, c := range held {
		facts, known := j.kept[cookieKey{c.Name, c.Domain, c.Path}]
		out = append(out, asCookie(c, facts, known))
	}
	return out
}

// all is every cookie the jar holds that was set through this wrapper, asked
// of the jar at the place each was filed, so that one that has expired or been
// replaced since is the jar's answer rather than the wrapper's memory. What the
// jar no longer holds is forgotten. Sorted by domain, path and name, so that a
// session written down twice reads the same.
func (j *keptJar) all() []Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	places := map[[2]string]bool{}
	for key := range j.kept {
		places[[2]string{key.domain, key.path}] = true
	}
	found := map[cookieKey]Cookie{}
	for place := range places {
		for _, c := range j.inner.Cookies(placeURL(place[0], place[1])) {
			key := cookieKey{c.Name, c.Domain, c.Path}
			if facts, known := j.kept[key]; known {
				found[key] = asCookie(c, facts, true)
			}
		}
	}
	for key := range j.kept {
		if _, held := found[key]; !held {
			delete(j.kept, key)
		}
	}
	out := make([]Cookie, 0, len(found))
	for _, c := range found {
		out = append(out, c)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Domain != out[b].Domain {
			return out[a].Domain < out[b].Domain
		}
		if out[a].Path != out[b].Path {
			return out[a].Path < out[b].Path
		}
		return out[a].Name < out[b].Name
	})
	return out
}

// placeURL is a URL the jar answers with the cookies filed under a domain and
// path: over https, so that Secure ones come too, and with a port, which the
// jar takes off a host the same way whatever it is.
func placeURL(domain, path string) *url.URL {
	host := domain
	if !strings.HasPrefix(domain, "[") {
		host = net.JoinHostPort(domain, "443")
	}
	return &url.URL{Scheme: "https", Host: host, Path: path}
}

// asCookie is a cookie of the jar's with what it does not say. A cookie the
// wrapper never saw set, through a jar shared with somebody else, is taken for
// its domain's, as every cookie used to be, and for a session's when its
// expiry is the jar's own word for never.
func asCookie(c *fhttp.Cookie, facts cookieFacts, known bool) Cookie {
	out := Cookie{
		Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
		Secure: c.Secure, HTTPOnly: c.HttpOnly, Expires: c.Expires,
	}
	switch {
	case known:
		out.HostOnly = facts.hostOnly
		out.SameSite = sameSiteName(facts.sameSite)
		if !facts.persistent {
			out.Expires = time.Time{}
		}
	case c.Expires.Equal(jarSessionEnd):
		out.Expires = time.Time{}
	}
	return out
}

// capLifetime is a cookie with Chrome's lifetime at most, as a copy: the
// transport's own cookie is not changed under it.
func capLifetime(c *fhttp.Cookie, now time.Time) *fhttp.Cookie {
	out := *c
	if longest := int(maxCookieLifetime / time.Second); out.MaxAge > longest {
		out.MaxAge = longest
	}
	if limit := now.Add(maxCookieLifetime); out.MaxAge == 0 && out.Expires.After(limit) {
		out.Expires = limit
	}
	return &out
}

// jarKeyOf is where the jar files a cookie set from u, and whether for the
// host alone, by the rules of RFC 6265 the transport's jar follows; filed is
// false for a cookie it refuses. A cookie without a Domain is its host's; one
// whose Domain is a public suffix is its host's when the host is that suffix
// and refused otherwise; a Domain on an address, or one the host is not in,
// is refused.
func jarKeyOf(u *url.URL, c *fhttp.Cookie) (key cookieKey, hostOnly, filed bool) {
	host, ok := canonicalHost(u.Host)
	if !ok {
		return cookieKey{}, false, false
	}
	key = cookieKey{name: c.Name, path: c.Path}
	if key.path == "" || key.path[0] != '/' {
		key.path = defaultCookiePath(u.Path)
	}
	if c.Domain == "" {
		key.domain = host
		return key, true, true
	}
	if net.ParseIP(host) != nil {
		return key, false, false
	}
	domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
	if domain == "" || domain[0] == '.' || domain[len(domain)-1] == '.' {
		return key, false, false
	}
	if suffix := publicsuffix.List.PublicSuffix(domain); suffix != "" && !strings.HasSuffix(domain, "."+suffix) {
		if host != domain {
			return key, false, false
		}
		key.domain = host
		return key, true, true
	}
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return key, false, false
	}
	key.domain = domain
	return key, false, true
}

// canonicalHost is a host as the jar files it: in lower case, without its
// port or a trailing dot, and in punycode.
func canonicalHost(host string) (string, bool) {
	host = strings.ToLower(host)
	if hasPort(host) {
		var err error
		if host, _, err = net.SplitHostPort(host); err != nil {
			return "", false
		}
	}
	host = strings.TrimSuffix(host, ".")
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			ascii, err := idna.Punycode.ToASCII(host)
			return ascii, err == nil
		}
	}
	return host, true
}

// hasPort says a host carries a port, an IPv6 address only in brackets.
func hasPort(host string) bool {
	switch strings.Count(host, ":") {
	case 0:
		return false
	case 1:
		return true
	}
	return host[0] == '[' && strings.Contains(host, "]:")
}

// defaultCookiePath is the path a cookie set without one is filed under: the
// directory of the path it was set from (RFC 6265, 5.1.4).
func defaultCookiePath(path string) string {
	if path == "" || path[0] != '/' {
		return "/"
	}
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "/"
}

// sameSiteName is a SameSite attribute as a cookie file spells it, and
// sameSiteMode the other way: "strict", "lax", "none", or nothing for a cookie
// that named none.
func sameSiteName(mode fhttp.SameSite) string {
	switch mode {
	case fhttp.SameSiteStrictMode:
		return "strict"
	case fhttp.SameSiteLaxMode:
		return "lax"
	case fhttp.SameSiteNoneMode:
		return "none"
	}
	return ""
}

func sameSiteMode(name string) fhttp.SameSite {
	switch strings.ToLower(name) {
	case "strict":
		return fhttp.SameSiteStrictMode
	case "lax":
		return fhttp.SameSiteLaxMode
	case "none":
		return fhttp.SameSiteNoneMode
	}
	return 0
}
