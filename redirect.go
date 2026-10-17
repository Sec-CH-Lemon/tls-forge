package tlsforge

import (
	"context"
	"net/url"
	"slices"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

// How a redirect is followed, as Chrome 155 was measured following one
// (testdata/chrome155-requests.json): the method a status leaves and the body
// with it, no Referer the request was not given, Authorization only within
// its origin, an Origin that crosses origins said as "null", a page's client
// hints after Sec-Fetch-Dest, and no credentials a Location names sent
// unasked; and for a request in a browser context, every hop worked out again
// from what the hops before it say.

// maxRedirects is the most requests one chain of redirects makes: Chrome
// 155, measured on a chain that does not end, made 20 and did not follow the
// 20th redirect, as the Fetch standard's count of 20 has it. A redirect policy
// of one's own replaces the transport's check rather than adding to it, and
// one that let everything through followed two pages redirecting to each
// other until the request's deadline: 54,600 requests in five seconds.
const maxRedirects = 20

// chain is what a request carries from hop to hop of its redirects, kept in
// its context for followRedirect.
type chain struct {
	client    *Client
	transport tls_client.HttpClient
	log       *requestLog
	// base is the request's context before its layouts were hung on it, which
	// a hop's preflight is made in.
	base context.Context
	// bodyless is a chain whose body a redirect has dropped, and every hop
	// after it goes without one, whatever its status.
	bodyless bool
	// browser is the request's browser context, nil for a request without;
	// last is its latest hop, policy its referrer policy as the redirects so
	// far left it, referrer what the next Referer is worked out from, nil once
	// there is none, and urls every URL asked.
	browser  *browserRequest
	last     hop
	policy   string
	referrer *url.URL
	urls     []*url.URL
	// given is the Referer a request without a browser context was given,
	// which every hop of it keeps, and crossed is such a chain that has gone
	// to another origin: Authorization is gone, and Origin is "null".
	given   []string
	crossed bool
	// ruled are the URLs the jar was told a rule for.
	ruled []*url.URL
}

type chainKey struct{}

// rule has the jar answer the transport, when it asks about u, with what the
// hop carries; release forgets every one when the request is over.
func (ch *chain) rule(u *url.URL, rule sendRule) {
	if ch.client.jar == nil {
		return
	}
	ch.client.jar.restrict(u, rule)
	ch.ruled = append(ch.ruled, u)
}

// remember keeps what the answer to a navigation from origin o asked for with
// Accept-CH, and writes it down.
func (ch *chain) remember(o origin, header fhttp.Header) {
	if asked, said := ch.client.hints.remember(o, header); said && ch.log != nil {
		ch.log.hintsAsked(o, asked)
	}
}

func (ch *chain) release() {
	for _, u := range ch.ruled {
		ch.client.jar.release(u)
	}
}

// follow makes req, the request a redirect leads to, the one Chrome sends.
func (ch *chain) follow(req *fhttp.Request, via []*fhttp.Request) error {
	previous := via[len(via)-1]
	crossed := originOf(previous.URL) != originOf(req.URL)
	dropped := ch.method(req, via)
	if ch.browser == nil {
		ch.followAsIs(req, crossed)
		return nil
	}
	return ch.followInContext(req, previous, crossed, dropped)
}

// method sets the method and body of a redirect's request as the Fetch
// standard has them, where the transport's differ: 301 and 302 make a GET of
// a POST alone, 303 of all but HEAD, and each drops the body for good; 307
// and 308 keep both. The transport makes a GET of every method but GET and
// HEAD on the first three, and sends the first request's body again after a
// 307 or 308 even once it was dropped. It reports a hop that dropped the
// body.
func (ch *chain) method(req *fhttp.Request, via []*fhttp.Request) bool {
	was := via[len(via)-1].Method
	status := req.Response.StatusCode
	drops := (status == fhttp.StatusMovedPermanently || status == fhttp.StatusFound) && was == fhttp.MethodPost ||
		status == fhttp.StatusSeeOther && was != fhttp.MethodGet && was != fhttp.MethodHead
	req.Method = was
	if drops {
		req.Method = fhttp.MethodGet
		ch.bodyless = true
	}
	req.Body, req.GetBody, req.ContentLength = nil, nil, 0
	if first := via[0]; !ch.bodyless && first.GetBody != nil {
		// GetBody of a request made from bytes, which cannot fail.
		req.Body, _ = first.GetBody()
		req.GetBody, req.ContentLength = first.GetBody, first.ContentLength
	}
	return drops
}

// bodyHeaders are what describes a body, and goes when a redirect drops it.
var bodyHeaders = []string{"content-type", "content-encoding", "content-language", "content-location"}

// followAsIs is a redirect of a request without a browser context: the hop
// the transport made, but for what Chrome sends otherwise. The transport
// copies the first request's headers onto every hop, so what a redirect took
// away is taken away again on each.
func (ch *chain) followAsIs(req *fhttp.Request, crossed bool) {
	// Chrome follows a Location with credentials in it, and sends them only
	// when the server asks; the transport would send them at once.
	req.URL.User = nil
	// fhttp keeps a Referer the request has, where net/http puts its own in
	// its place: it is said again, so that neither way changes it.
	if len(ch.given) > 0 {
		setHeader(req.Header, "referer", ch.given)
	} else {
		deleteHeader(req.Header, "referer")
	}
	ch.crossed = ch.crossed || crossed
	if ch.crossed {
		deleteHeader(req.Header, "authorization")
		if req.Header.Get("Origin") != "" {
			setHeader(req.Header, "origin", []string{"null"})
		}
	}
	if ch.bodyless {
		// With the body goes what describes it, and the Origin Chrome's
		// network stack drops with them.
		for _, name := range bodyHeaders {
			deleteHeader(req.Header, name)
		}
		deleteHeader(req.Header, "origin")
	}
	// Only Chromium sends client hints, so no other browser's order changes.
	req.Header[fhttp.HeaderOrderKey] = hintsAfterDest(req.Header[fhttp.HeaderOrderKey])
	prepareRedirectLayout(req)
	if layouts, _ := req.Context().Value(protocolLayoutsKey{}).(*protocolLayouts); layouts != nil {
		layouts.http1[fhttp.HeaderOrderKey] = hintsAfterDest(layouts.http1[fhttp.HeaderOrderKey])
	}
}

// clientHints are the hints Chrome sends of its own, which a redirect moves.
var clientHints = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}

// hintsAfterDest is an order of header names with the client hints moved to
// just after Sec-Fetch-Dest, where Chrome sends them after a redirect, and as
// it was when it has no Sec-Fetch-Dest.
func hintsAfterDest(order []string) []string {
	at := -1
	var rest, hints []string
	for _, name := range order {
		if isClientHint(name) {
			hints = append(hints, name)
			continue
		}
		rest = append(rest, name)
		if strings.EqualFold(name, "sec-fetch-dest") {
			at = len(rest)
		}
	}
	if at < 0 {
		return order
	}
	return slices.Concat(rest[:at], hints, rest[at:])
}

func isClientHint(name string) bool {
	return slices.ContainsFunc(clientHints, func(hint string) bool { return strings.EqualFold(name, hint) })
}

// followInContext is a redirect of a request in a browser context: its next
// hop worked out from the ones before, asked about first where CORS asks
// about it, at the URL it now goes to, and the request dressed as Chrome sends
// that hop.
func (ch *chain) followInContext(req, previous *fhttp.Request, crossed, dropped bool) error {
	h, err := ch.next(req, previous, crossed, dropped)
	if err != nil {
		return err
	}
	// Chrome sends credentials a Location names only when the server asks.
	req.URL.User = nil
	r := ch.browser
	if r.needsPreflight(h) && !ch.client.preflights.allows(r, h, shownURL(req).String()) {
		if err := ch.client.preflight(ch.base, req, r, h, ch.transport, ch.log); err != nil {
			return err
		}
	}
	ch.dress(req, h)
	ch.last = h
	return nil
}

// next is the hop req makes after the ones before, or why Chrome would not
// make it. CORS has to allow the redirect itself of a request it answers
// for, and Chrome refuses some outright. Across origins Authorization goes,
// and the Origin is "null" from then on; the Referer is worked out from the
// one before, under the policy the redirect may have set, and Sec-Fetch-Site
// from every URL asked.
func (ch *chain) next(req, previous *fhttp.Request, crossed, dropped bool) (hop, error) {
	r, last, shown := ch.browser, ch.last, shownURL(req)
	if last.cors {
		if err := r.corsCheck(req.Response.Header, last.serialized(r)); err != nil {
			return hop{}, corsError("the redirect of %s %s to %s did not allow %s: %v", last.method,
				shownURL(previous).Redacted(), shown.Redacted(), last.serialized(r), err)
		}
	}
	h := hop{to: originOf(req.URL), method: req.Method, redirected: true, script: last.script}
	if err := r.mayFollow(shown, h.to, last); err != nil {
		return hop{}, err
	}
	h.cors = last.cors || r.scripted() && r.mode == modeCORS && h.to != r.from
	switch {
	case h.cors:
		// The Fetch standard's tainted origin, which Chrome keeps for CORS: a
		// hop to another origin from one that is not the page's.
		h.tainted = last.tainted || crossed && originOf(previous.URL) != r.from
	default:
		// And for the rest, as its network stack does: any hop to another
		// origin.
		h.tainted = last.tainted || crossed
	}
	if crossed {
		h.script = h.script.without("authorization")
	}
	if dropped {
		h.script = h.script.without(bodyHeaders...)
	}
	if !r.scripted() {
		// A redirect a navigation was answered with may ask for hints too.
		ch.remember(originOf(previous.URL), req.Response.Header)
	}
	h.hints = ch.client.hintsOf(r, h)
	ch.urls = append(ch.urls, req.URL)
	h.site = r.chainSite(ch.urls)
	if policy := redirectPolicy(req.Response.Header); policy != "" {
		ch.policy = policy
	}
	if ch.referrer != nil {
		h.referrer = referrerFor(ch.referrer, h.to, ch.policy)
		ch.referrer = nil
		if h.referrer != "" {
			ch.referrer, _ = url.Parse(h.referrer)
		}
	}
	h.origin = r.originHeader(h)
	// An Origin the hop before went without, or one the network stack
	// dropped with the body and CORS gave back.
	h.lateOrigin = last.lateOrigin || h.origin != "" && (last.origin == "" || dropped)
	return h, nil
}

// dress gives req the headers of hop h in Chrome's order over each protocol,
// and has the jar give it the cookies h carries.
func (ch *chain) dress(req *fhttp.Request, h hop) {
	r, host := ch.browser, shownURL(req).Host
	field := r.header(h, ch.client.headers)
	order := r.wireOrder(h)
	req.Header = browserLayout(field, order, host)
	if pseudo := ch.client.profile.HTTP2.PseudoHeaderOrder; len(pseudo) > 0 {
		req.Header[fhttp.PHeaderOrderKey] = pseudo
	}
	http1 := browserHTTP1Layout(field, h.script, order, ch.client.profile.HTTP1, ch.client.http1Headers, host)
	*req = *withProtocolLayouts(req, &protocolLayouts{http1: http1, http2: cloneHeaderLayout(req.Header),
		managed: managedHeaderNames(req.Header, http1)})
	ch.rule(req.URL, r.cookies(h))
}

// mayFollow is why Chrome would not let a page's request follow a redirect to
// u, of origin to, after the hop last: fetch() in same-origin mode leaves the
// page's origin; or u has credentials in it, which fetch() is not let follow
// but to the page's own origin with the page's own credentials, and a request
// in cors mode not once CORS answers for it, its origin is tainted or u is of
// another origin than the page.
func (r *browserRequest) mayFollow(u *url.URL, to origin, last hop) error {
	switch {
	case r.mode == modeSameOrigin && to != r.from:
		return corsError("fetch() in same-origin mode follows no redirect to another origin: %s", u.Redacted())
	case u.User == nil:
		return nil
	case r.kind == KindFetch && (to != r.from || u.User.Username() != r.initiator.User.Username() ||
		password(u.User) != password(r.initiator.User)):
		return corsError("fetch() follows no redirect to a URL with credentials in it: %s", u.Redacted())
	case r.mode == modeCORS && (last.cors || last.tainted || to != r.from):
		return corsError("%s follows no redirect to a URL with credentials in it across origins: %s",
			r.kindName(), u.Redacted())
	}
	return nil
}

// password is the password of credentials, empty for none.
func password(user *url.Userinfo) string {
	p, _ := user.Password()
	return p
}

// redirectPolicy is the referrer policy a redirect's answer sets for the hops
// after it, as Chrome reads Referrer-Policy there: of a comma-separated list,
// over every field, the last that names a policy, in any case of ASCII; empty
// when none does.
func redirectPolicy(header fhttp.Header) string {
	tokens := strings.Split(strings.Join(header.Values("Referrer-Policy"), ","), ",")
	for _, token := range slices.Backward(tokens) {
		token = strings.Map(lowerASCII, strings.Trim(token, " \t\n\v\f\r"))
		if slices.Contains(referrerPolicies, token) {
			return token
		}
	}
	return ""
}

// lowerASCII is a rune in lower case if it is an ASCII capital, as it is
// otherwise.
func lowerASCII(r rune) rune {
	if 'A' <= r && r <= 'Z' {
		return r + 'a' - 'A'
	}
	return r
}

// serialized is the origin a hop's request carries, said as an Origin header
// says it: "null" once it has gone across origins.
func (h hop) serialized(r *browserRequest) string {
	if h.tainted {
		return "null"
	}
	return r.from.String()
}

// chainSite is Sec-Fetch-Site for a request that asked every URL of urls:
// same-origin when each was the page's origin, same-site when each was its
// site, cross-site otherwise; none for a navigation typed into the address
// bar, wherever it went.
func (r *browserRequest) chainSite(urls []*url.URL) string {
	if r.initiator == nil {
		return "none"
	}
	site := "same-origin"
	for _, u := range urls {
		switch relation(r.from, originOf(u)) {
		case "cross-site":
			return "cross-site"
		case "same-site":
			site = "same-site"
		}
	}
	return site
}
