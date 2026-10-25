package tlsforge

import (
	"github.com/igor-lemon/utls/behavior"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
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
	inner    fhttp.CookieJar
	mu       sync.Mutex
	kept     map[cookieKey]cookieFacts
	chrome   bool // Deprecated fixture compatibility; new clients carry explicit policy.
	behavior behavior.Policy
	serial   uint64
	// rules are what a request in a browser context lets through, by the URL
	// the transport asks the jar about for it: its own, for each hop.
	rules sync.Map
	// Partitioned cookies never enter the ordinary jar. Each top-level
	// schemeful site owns a separate store, including replacement/expiry.
	partitions map[string]*keptJar
}

// cookieKey is a cookie's identity in a jar: a second cookie of the same name,
// domain and path replaces the first.
type cookieKey struct{ name, domain, path string }

// cookieFacts are what the jar does not say of a cookie, and whether it is
// Secure, which a cookie set from an origin that is not secure leaves alone.
type cookieFacts struct {
	hostOnly   bool
	persistent bool
	secure     bool
	sameSite   fhttp.SameSite
	// created is when the cookie was first set: one set again over it keeps
	// the first's, as RFC 6265 has a browser keep it.
	created time.Time
	value   string
	order   uint64
}

// maxCookieLifetime is the longest Chrome keeps a cookie: a later Expires or a
// longer Max-Age is cut to 400 days, as RFC 6265bis has every browser do. Cut
// here too, so that a cookie lives as long as it would in the browser, and a
// Max-Age of centuries cannot overflow the jar's arithmetic into a date that
// cannot be written down.
var maxCookieLifetime = time.Duration(legacyPolicy().Uint("cookie.max_age_seconds")) * time.Second

// jarSessionEnd is the expiry the transport's jar gives a session cookie, which
// is how one is told apart when the wrapper never saw it set.
var jarSessionEnd = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

func newKeptJar(inner fhttp.CookieJar) *keptJar {
	return &keptJar{inner: inner, kept: map[cookieKey]cookieFacts{}}
}

// SetCookies files the cookies an answer from u sets that Chrome would keep:
// those a server may set (accepts), and of an answer to a request in a
// browser context, whose rule u is ruled by, those the request may set
// (sendRule.keeps). Each is filed as file files it.
func (j *keptJar) SetCookies(u *url.URL, cookies []*fhttp.Cookie) {
	var rule sendRule
	if ruled, ok := j.rules.Load(u); ok {
		rule = ruled.(sendRule)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	kept := make([]*fhttp.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil {
			continue
		}
		if partitionedCookie(c) {
			if !c.Secure || rule.none || !rule.keeps(c) {
				continue
			}
			key := rule.partition
			if key == "" {
				key = originOf(u).site()
			}
			if j.partitions == nil {
				j.partitions = map[string]*keptJar{}
			}
			part := j.partitions[key]
			if part == nil {
				inner, err := newDefaultCookieJar()
				if err != nil {
					continue
				}
				part = newKeptJar(inner)
				part.chrome = j.chrome
				part.behavior = j.behavior
				j.partitions[key] = part
			}
			copy := *c
			copy.Unparsed = nil
			for _, attr := range c.Unparsed {
				name, _, _ := strings.Cut(attr, "=")
				if !strings.EqualFold(strings.TrimSpace(name), "partitioned") {
					copy.Unparsed = append(copy.Unparsed, attr)
				}
			}
			part.SetCookies(u, []*fhttp.Cookie{&copy})
			continue
		}
		if c = withinLimits(c, j.cookiePolicy()); rule.keeps(c) && j.accepts(u, c) {
			// Chrome accepts an exact IP Domain as a host-only cookie. The
			// underlying RFC jar rejects every IP Domain, so file the equivalent
			// host-only form; a different IP is still rejected by that jar.
			if host, ok := canonicalHost(u.Host); j.cookiePolicy().Flag("cookie.ip_domain_host_only") && ok && net.ParseIP(host) != nil && c.Domain == host {
				copy := *c
				copy.Domain = ""
				c = &copy
			}
			kept = append(kept, c)
		}
	}
	j.fileLocked(u, kept)
}

// file files cookies the caller gave in the jar as they are, not held to
// what a server may set: each cut to Chrome's lifetime, with what the jar
// will not say of it kept.
func (j *keptJar) file(u *url.URL, cookies []*fhttp.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.fileLocked(u, cookies)
}

func (j *keptJar) fileLocked(u *url.URL, cookies []*fhttp.Cookie) {
	now := time.Now()
	capped := make([]*fhttp.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c != nil {
			capped = append(capped, capLifetime(c, now, j.cookiePolicy()))
		}
	}
	j.inner.SetCookies(cookiePathURL(u), capped)
	for _, c := range capped {
		key, hostOnly, filed := jarKeyOf(u, c)
		switch {
		case !filed:
		case c.MaxAge < 0 || (c.MaxAge == 0 && !c.Expires.IsZero() && !c.Expires.After(now)):
			delete(j.kept, key)
		default:
			created := now
			j.serial++
			order := j.serial
			if before, known := j.kept[key]; known && (!j.cookiePolicy().Flag("cookie.reset_order_on_value_change") || before.value == c.Value) {
				created = before.created
				order = before.order
			}
			j.kept[key] = cookieFacts{
				hostOnly:   hostOnly,
				persistent: c.MaxAge > 0 || !c.Expires.IsZero(),
				secure:     c.Secure,
				sameSite:   c.SameSite,
				created:    created,
				value:      c.Value,
				order:      order,
			}
		}
	}
}

// Cookies is the jar's own answer, what goes to a URL, less what a request in
// a browser context does not carry, when u is that request's.
func (j *keptJar) Cookies(u *url.URL) []*fhttp.Cookie {
	held := j.inner.Cookies(jarURL(u))
	ruled, ok := j.rules.Load(u)
	var rule sendRule
	if ok {
		rule = ruled.(sendRule)
	}
	partition := rule.partition
	if partition == "" {
		partition = originOf(u).site()
	}
	j.mu.Lock()
	part := j.partitions[partition]
	j.mu.Unlock()
	var partitioned []*fhttp.Cookie
	if part != nil {
		part.restrict(u, rule)
		partitioned = part.Cookies(u)
		part.release(u)
	}
	if !ok {
		j.mu.Lock()
		j.sortCookies(held)
		j.mu.Unlock()
		return append(held, partitioned...)
	}
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	kept := held[:0:0]
	for _, c := range held {
		facts, known := j.kept[cookieKey{c.Name, c.Domain, c.Path}]
		if rule.allows(facts, known, now, j.cookiePolicy()) {
			kept = append(kept, c)
		}
	}
	j.sortCookies(kept)
	return append(kept, partitioned...)
}

// Chrome preserves creation order for an identical value (including an expiry
// refresh), but a changed value receives a new place among equal-length paths.
// The wrapped RFC jar always retains the old order, so use our measured facts.
// The caller holds j.mu; non-Chrome jars retain their original ordering.
func (j *keptJar) sortCookies(cookies []*fhttp.Cookie) {
	if !j.cookiePolicy().Flag("cookie.reset_order_on_value_change") {
		return
	}
	order := func(c *fhttp.Cookie) uint64 {
		if f, ok := j.kept[cookieKey{c.Name, c.Domain, c.Path}]; ok {
			return f.order
		}
		return ^uint64(0)
	}
	sort.SliceStable(cookies, func(a, b int) bool {
		if len(cookies[a].Path) != len(cookies[b].Path) {
			return len(cookies[a].Path) > len(cookies[b].Path)
		}
		return order(cookies[a]) < order(cookies[b])
	})
}

func partitionedCookie(c *fhttp.Cookie) bool {
	for _, attr := range c.Unparsed {
		name, _, _ := strings.Cut(attr, "=")
		if strings.EqualFold(strings.TrimSpace(name), "partitioned") {
			return true
		}
	}
	return false
}

// restrict has the jar answer the transport, when it asks about u, with what
// a request in a browser context carries; release forgets it.
func (j *keptJar) restrict(u *url.URL, rule sendRule) { j.rules.Store(u, rule) }
func (j *keptJar) release(u *url.URL)                 { j.rules.Delete(u) }

// sendRule is which cookies a request in a browser context carries.
type sendRule struct {
	partition string
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

// allows reports a cookie a request carries, by its SameSite: to its own site
// any; to another, one of SameSite=None, one of Lax when a page is loaded by
// GET, and one that named none, which is Lax, also when a page is posted to
// within two minutes of its being set. A cookie the wrapper never saw set
// named none, as far as it knows, and was not set lately.
func (rule sendRule) allows(facts cookieFacts, known bool, now time.Time, policies ...behavior.Policy) bool {
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
	return rule.topLevel && (rule.safe || known && now.Sub(facts.created) < time.Duration(policyArgument(policies).Uint("cookie.lax_unsafe_age_seconds"))*time.Second)
}

// keeps reports a cookie an answer sets that is filed, by its SameSite: any
// from a request to its page's site, or one that loads a page at the top,
// and from a script's request to another site, one of SameSite=None alone, as
// Chrome keeps them (the set-cookie-samesite-* scenarios of
// testdata/chrome155-requests.json). A redirect that went through another
// site changes nothing: the hop's own URL decides. A request without a
// browser context has the zero rule, and files any.
func (rule sendRule) keeps(c *fhttp.Cookie) bool {
	return !rule.crossSite || rule.topLevel || c.SameSite == fhttp.SameSiteNoneMode
}

// withinLimits is c without a Path or a Domain longer than Chrome reads, as a
// copy: the cookie is filed under the default path, or as its host's.
func withinLimits(c *fhttp.Cookie, policies ...behavior.Policy) *fhttp.Cookie {
	pol := policyArgument(policies)
	if !pol.Has("cookie.max_attribute_bytes") {
		return c
	}
	maxAttributeSize := pol.Int("cookie.max_attribute_bytes")
	if len(c.Path) <= maxAttributeSize && len(c.Domain) <= maxAttributeSize {
		return c
	}
	out := *c
	if len(out.Path) > maxAttributeSize {
		out.Path = ""
	}
	if len(out.Domain) > maxAttributeSize {
		out.Domain = ""
	}
	return &out
}

// accepts reports a cookie an answer from u sets that Chrome files, as it
// was measured to (the set-cookie-prefixes, -insecure-origin,
// -insecure-localhost, -leave-secure-alone and -size scenarios): at most
// maxCookieSize bytes of name and value; Secure from a secure origin alone
// (https, or the machine itself), and so SameSite=None; a prefix, in any
// case, kept: __Secure- Secure, __Host- Secure with Path=/ and no Domain,
// __Http- Secure and HttpOnly, __Host-Http- all of those; and none without
// Secure, from an origin that is not secure, of the name of a Secure cookie
// it would shadow. The jar itself refuses a Domain that is a public suffix,
// another site's, or ends in a dot. j.mu is held.
func (j *keptJar) accepts(u *url.URL, c *fhttp.Cookie) bool {
	secure := trustworthy(originOf(u))
	name := strings.ToLower(c.Name)
	switch {
	case j.cookiePolicy().Has("cookie.max_pair_bytes") && len(c.Name)+len(c.Value) > j.cookiePolicy().Int("cookie.max_pair_bytes"):
		return false
	case c.Secure && !secure, c.SameSite == fhttp.SameSiteNoneMode && !c.Secure:
		return false
	case strings.HasPrefix(name, "__secure-") && !c.Secure:
		return false
	case strings.HasPrefix(name, "__host-") && (!c.Secure || c.Domain != "" || c.Path != "/"):
		return false
	case (strings.HasPrefix(name, "__http-") || strings.HasPrefix(name, "__host-http-")) && (!c.Secure || !c.HttpOnly):
		return false
	}
	return c.Secure || secure || !j.shadowsSecure(u, c)
}

// shadowsSecure reports a cookie of the name of a Secure cookie the jar
// holds whose domain domain-matches its, or is domain-matched by it, and
// whose path its own is within: which a cookie without Secure set from an
// origin that is not secure leaves alone (RFC 6265bis 5.7). j.mu is held.
func (j *keptJar) shadowsSecure(u *url.URL, c *fhttp.Cookie) bool {
	// One the jar refuses has no domain to match, and shadows nothing.
	key, _, _ := jarKeyOf(u, c)
	for held, facts := range j.kept {
		if held.name != c.Name || !facts.secure || !domainMatches(held.domain, key.domain) || !pathWithin(key.path, held.path) {
			continue
		}
		// What the wrapper filed may since have gone from the jar.
		for _, still := range j.inner.Cookies(&url.URL{Scheme: "https", Host: held.domain, Path: held.path}) {
			if still.Name == c.Name {
				return true
			}
		}
	}
	return false
}

// domainMatches reports two domains of which one is the other or under it.
func domainMatches(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// pathWithin reports a path that path-matches another, as RFC 6265 has it:
// the same, or under it.
func pathWithin(path, under string) bool {
	return path == under || strings.HasPrefix(path, under) && (strings.HasSuffix(under, "/") || path[len(under)] == '/')
}

// jarURL is the URL the transport's jar is asked about for u: one over https
// for plain http to the machine itself, which Chrome deems a secure origin and
// sends Secure cookies to (measured: set-cookie-insecure-localhost).
func jarURL(u *url.URL) *url.URL {
	u = cookiePathURL(u)
	if u.Scheme != "http" || !trustworthy(originOf(u)) {
		return u
	}
	https := *u
	https.Scheme = "https"
	return &https
}

// The underlying jar compares URL.Path verbatim. Cookie path matching uses the
// serialized request path, including percent escapes, rather than url.URL's
// decoded Path. Only URL inputs are adapted: a Set-Cookie Path is already the
// literal stored value and must not be decoded or escaped again.
func cookiePathURL(u *url.URL) *url.URL {
	path := u.EscapedPath()
	if path == u.Path {
		return u
	}
	copy := *u
	copy.Path, copy.RawPath = path, ""
	return &copy
}

// forURL is what goes to a URL, with what the jar does not say of each cookie.
func (j *keptJar) forURL(u *url.URL) []Cookie {
	held := j.inner.Cookies(jarURL(u))
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
func capLifetime(c *fhttp.Cookie, now time.Time, policies ...behavior.Policy) *fhttp.Cookie {
	pol := policyArgument(policies)
	if !pol.Has("cookie.max_age_seconds") {
		out := *c
		return &out
	}
	maxCookieLifetime := time.Duration(pol.Uint("cookie.max_age_seconds")) * time.Second
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
		key.path = defaultCookiePath(u.EscapedPath())
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

func (j *keptJar) cookiePolicy() behavior.Policy {
	if j.behavior != nil {
		return j.behavior
	}
	p := legacyPolicy()
	if !j.chrome {
		p["cookie.raw_fields"] = []byte("false")
		p["cookie.ip_domain_host_only"] = []byte("false")
		p["cookie.reset_order_on_value_change"] = []byte("false")
	}
	return p
}
