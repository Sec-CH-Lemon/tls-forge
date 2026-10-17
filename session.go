package tlsforge

import (
	"net"
	"net/url"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
)

// session is what one identity keeps across its requests: its cookies, the
// cookies it was warmed with, the client hints each origin asked it for, and
// what CORS preflights allowed. Every client made Fresh from another shares
// its session and has transports of its own (transports), and a request's
// browser context is neither: it is what one page asks.
type session struct {
	// jar is nil when the client keeps no cookies.
	jar   *keptJar
	warm  *warmSession
	hints *hintStore
	// preflights is what CORS preflights allowed in the session.
	preflights *preflightCache
}

// newSession is a session keeping cookies in jar, nil for none, warmed with
// cookies.
func newSession(jar *keptJar, cookies []Cookie) *session {
	return &session{jar: jar, warm: &warmSession{cookies: cookies, seeded: map[warmCookieKey]struct{}{}},
		hints: newHintStore(), preflights: newPreflightCache()}
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

// seedWarm files the part of the warmed cookies that belongs to this host into
// the jar, once. A cookie with no domain belongs to whichever host is being
// asked, so it is seeded once per distinct host; a domain cookie is seeded once
// in total and the jar then applies its domain scope.
func (s *session) seedWarm(u *url.URL) {
	warm := s.warm
	if len(warm.cookies) == 0 || s.jar == nil {
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
	s.seed(u, ready)
}

// seed files cookies in the jar against u, each as what it is: a cookie its
// host's alone under that host and under no other, a domain's under the
// domain, a session cookie without an expiry.
func (s *session) seed(u *url.URL, cookies []Cookie) {
	if len(cookies) == 0 || s.jar == nil {
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
	s.jar.SetCookies(u, jarCookies)
}

// cookiesFor is what the jar would send to u, nothing when there is none.
func (s *session) cookiesFor(u *url.URL) []Cookie {
	if s.jar == nil {
		return nil
	}
	return s.jar.forURL(u)
}

// all is every cookie the jar holds, nothing when there is none.
func (s *session) all() []Cookie {
	if s.jar == nil {
		return nil
	}
	return s.jar.all()
}
