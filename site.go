package tlsforge

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// What a browser compares two URLs by, as the Fetch and HTML standards have
// it: their origins (scheme, host, port), their sites (scheme and registrable
// domain), and whether a URL is one a secure page may be sent to without
// being downgraded.

// origin is a URL's origin: scheme, host in its ASCII form, and port, the
// scheme's own when it names none.
type origin struct{ scheme, host, port string }

// originOf is the origin of an http or https URL.
func originOf(u *url.URL) origin {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	return origin{scheme, asciiHost(u.Hostname()), port}
}

// defaultPort is the port a scheme means when a URL names none.
func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

// asciiHost is a host as a browser writes it: in lower case and, when it is a
// name, in its ASCII form, IDNA's. One IDNA refuses is kept as it was, lowered:
// the request goes out with it all the same, and the comparison stays honest.
func asciiHost(host string) string {
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return host
	}
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		return ascii
	}
	return host
}

// String is the origin serialized as an Origin header carries it: scheme,
// host, and the port when it is not the scheme's own.
func (o origin) String() string {
	host := o.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if o.port == defaultPort(o.scheme) {
		return o.scheme + "://" + host
	}
	return o.scheme + "://" + host + ":" + o.port
}

// site is an origin's schemeful site: its scheme and registrable domain, the
// host itself for an IP address or a host with no registrable domain.
func (o origin) site() string {
	domain := o.host
	if net.ParseIP(o.host) == nil {
		if registrable, err := publicsuffix.EffectiveTLDPlusOne(o.host); err == nil {
			domain = registrable
		}
	}
	return o.scheme + "://" + domain
}

// relation is how a request's URL stands to the origin that made it, as
// Sec-Fetch-Site says it.
func relation(from, to origin) string {
	switch {
	case from == to:
		return "same-origin"
	case from.site() == to.site():
		return "same-site"
	}
	return "cross-site"
}

// trustworthy reports a URL a browser deems potentially trustworthy: https,
// or http to the machine itself, by loopback address or a localhost name.
// Only to such a URL does Chrome send client hints and Sec-Fetch-*, and going
// from one to a URL that is not is a downgrade.
func trustworthy(o origin) bool {
	if o.scheme == "https" {
		return true
	}
	if ip := net.ParseIP(o.host); ip != nil {
		return ip.IsLoopback()
	}
	return o.host == "localhost" || strings.HasSuffix(o.host, ".localhost")
}

// Referrer policies, as a page names them in a Referrer-Policy header or a
// <meta name="referrer">.
const (
	policyNoReferrer                  = "no-referrer"
	policyNoReferrerWhenDowngrade     = "no-referrer-when-downgrade"
	policyOrigin                      = "origin"
	policyOriginWhenCrossOrigin       = "origin-when-cross-origin"
	policySameOrigin                  = "same-origin"
	policyStrictOrigin                = "strict-origin"
	policyStrictOriginWhenCrossOrigin = "strict-origin-when-cross-origin"
	policyUnsafeURL                   = "unsafe-url"
)

// referrerPolicies are the policies a browser context may name.
var referrerPolicies = []string{
	policyNoReferrer, policyNoReferrerWhenDowngrade, policyOrigin, policyOriginWhenCrossOrigin,
	policySameOrigin, policyStrictOrigin, policyStrictOriginWhenCrossOrigin, policyUnsafeURL,
}

// maxReferrerLength is the longest Referer a browser sends whole: a longer
// one is cut to its origin.
const maxReferrerLength = 4096

// referrerFor is the Referer a request to target carries from a page at
// source under a policy, as the Referrer Policy standard determines it: the
// page's URL without its fragment or credentials, its origin alone, or
// nothing. Empty means no Referer.
func referrerFor(source *url.URL, target origin, policy string) string {
	from := originOf(source)
	full := strippedURL(source)
	originOnly := from.String() + "/"
	if len(full) > maxReferrerLength {
		full = originOnly
	}
	sameOrigin := from == target
	downgrade := trustworthy(from) && !trustworthy(target)
	switch policy {
	case policyNoReferrer:
		return ""
	case policyUnsafeURL:
		return full
	case policyOrigin:
		return originOnly
	case policyStrictOrigin:
		if downgrade {
			return ""
		}
		return originOnly
	case policySameOrigin:
		if sameOrigin {
			return full
		}
		return ""
	case policyOriginWhenCrossOrigin:
		if sameOrigin {
			return full
		}
		return originOnly
	case policyNoReferrerWhenDowngrade:
		if downgrade {
			return ""
		}
		return full
	}
	// strict-origin-when-cross-origin, the default.
	switch {
	case sameOrigin:
		return full
	case downgrade:
		return ""
	}
	return originOnly
}

// strippedURL is a URL as a Referer carries it: without its credentials or
// fragment, its origin serialized as an Origin header would be, and a path of
// "/" when it has none.
func strippedURL(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	stripped := originOf(u).String() + path
	if u.RawQuery != "" || u.ForceQuery {
		stripped += "?" + u.RawQuery
	}
	return stripped
}
