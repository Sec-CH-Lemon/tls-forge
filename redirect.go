package tlsforge

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"
	http2 "github.com/igor-lemon/fhttp/http2"
	fhttptrace "github.com/igor-lemon/fhttp/httptrace"
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
	client *Client
	log    *requestLog
	// base is the request's context before its layouts were hung on it, which
	// a hop's preflight is made in; site are the connections of the latest
	// hop's top-level site, which its preflight goes out on, and on the pool
	// of them of its kind, with credentials or without, the hop goes out, and
	// its answer to a 401 or a 421.
	base context.Context
	site *site
	on   pool
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
	// restarted is a navigation started again for its critical client
	// hints, which is not started again for them twice.
	restarted bool
	// ruled are the URLs the jar was told a rule for.
	ruled []*url.URL

	// own is a request without a browser context that has an Authorization
	// of its own, which tls-forge neither adds to nor answers for.
	own bool
	// credentials are what the URL of the latest hop carried, taken off it
	// before it is sent, and embedded whether a challenge was answered with
	// them; sent is the Authorization tls-forge gave the latest hop, nil for
	// none, and restarts how many times it was sent again with one; ours is
	// the request the transport makes hops of carrying one, which it copies
	// onto them.
	credentials *url.Userinfo
	embedded    bool
	sent        *sentAuth
	restarts    int
	ours        bool
	// redirects are the redirects followed so far, those after a challenge
	// answered too.
	redirects int
	// laid are the layouts the latest hop of a request without a browser
	// context wears, which one sent again for a challenge is made from.
	laid *layouts
	// resent is the latest hop sent again for a 421 (Misdirected Request),
	// which Chrome does once a hop; conn is the connection the latest request
	// of the chain went out on.
	resent bool
	conn   net.Conn
}

// sentAuth is the Authorization tls-forge gave a hop: the challenge it
// answered, the credentials, and where they were from: the URL, the realm, or
// what was kept for the directory, sent unasked.
type sentAuth struct {
	challenge   challenge
	credentials credentials
	from        string
}

type chainKey struct{}

// in is ctx for a request of the chain: the chain in it, the connection the
// request goes out on kept, and the jar given the cookies of each answer but
// a 421 its hop is sent again for; once its hop was sent again for a 421, it
// goes out on no connection shared with another host, as Chrome sends what is
// left of a hop with IP pooling off.
func (ch *chain) in(ctx context.Context) context.Context {
	ctx = keepingConn(context.WithValue(ctx, chainKey{}, ch), &ch.conn)
	ctx = fhttp.WithResponseCookies(ctx, ch.keeps)
	return http2.WithCoalescing(ctx, !ch.resent)
}

// keeps reports whether the jar keeps the cookies res sets: not those of a
// 421 its hop is sent again for, which Chrome's network stack never hands
// over.
func (ch *chain) keeps(res *fhttp.Response) bool {
	return res.StatusCode != fhttp.StatusMisdirectedRequest || ch.resent
}

// keepingConn is ctx with a hook that keeps in conn the connection a request
// made with it goes out on.
func keepingConn(ctx context.Context, conn *net.Conn) context.Context {
	return fhttptrace.WithClientTrace(ctx, &fhttptrace.ClientTrace{
		GotConn: func(info fhttptrace.GotConnInfo) { *conn = info.Conn },
	})
}

// goOn has the latest hop, to u, go out on the connections of its own
// top-level site, and on those of them of its kind, with credentials or
// without, as Chrome sends each hop of a redirect
// (testdata/chrome155-connections.json): a navigation's or a form's to another
// site on that site's, and back on the first's; one that leaves a request
// without credentials on those of requests that carry none, which it stays
// on. A script's hops go out on its page's site's.
func (ch *chain) goOn(u *url.URL) error {
	s, err := ch.client.transports.siteOf(topSite(ch.browser, u))
	if err != nil {
		return err
	}
	ch.site, ch.on = s, s.carrying(ch.browser == nil || !ch.browser.cookies(ch.last).none)
	return nil
}

// rule has the jar answer the transport, when it asks about u, with what the
// hop carries; release forgets every one when the request is over.
func (ch *chain) rule(u *url.URL, rule sendRule) {
	if ch.client.session.jar == nil {
		return
	}
	ch.client.session.jar.restrict(u, rule)
	ch.ruled = append(ch.ruled, u)
}

// remember keeps what the answer to a navigation from origin o asked for with
// Accept-CH, and writes it down.
func (ch *chain) remember(o origin, header fhttp.Header) {
	if asked, said := ch.client.session.hints.remember(o, header); said && ch.log != nil {
		ch.log.hintsAsked(o, asked)
	}
}

// restart reports an answer, from u, to a navigation's GET that names in
// Critical-CH a client hint its origin asks for, which the profile has a value
// for and the request that got it did not carry, as Chrome starts the
// navigation again for, once; and writes it down.
func (ch *chain) restart(u *url.URL, header fhttp.Header, sent hop) bool {
	if ch.restarted || sent.method != fhttp.MethodGet {
		return false
	}
	critical := askedHints(header.Values("Critical-CH"))
	var missing []string
	for _, hint := range ch.client.hintsOf(ch.browser, sent) {
		if slices.Contains(critical, hint.Name) && !sent.hints.Has(hint.Name) {
			missing = append(missing, hint.Name)
		}
	}
	if missing == nil {
		return false
	}
	if ch.log != nil {
		ch.log.restarted(u.Redacted(), missing)
	}
	return true
}

func (ch *chain) release() {
	for _, u := range ch.ruled {
		ch.client.session.jar.release(u)
	}
}

// authenticates reports whether HTTP authentication goes with a hop: not with
// a request that has an Authorization of its own, nor, in a browser context,
// with one CORS answers for or one that carries no credentials.
func (ch *chain) authenticates(h hop) bool {
	if ch.browser == nil {
		return !ch.own
	}
	return !h.script.Has("authorization") && !h.cors && !ch.browser.cookies(h).none
}

// arrive begins the hop to u, a request of method: user, the credentials its
// URL carried, are kept, none sent; and it is the Authorization the session
// sends unasked to where it goes, worked out from the challenge kept for the
// directory, nothing for a URL that carries credentials, nor where allowed
// says none goes.
func (ch *chain) arrive(method string, u *url.URL, user *url.Userinfo, allowed bool) string {
	ch.credentials, ch.embedded, ch.sent, ch.restarts, ch.resent = user, false, nil, 0, false
	if _, carried := credentialsOf(user); carried || !allowed {
		return ""
	}
	cache := ch.client.session.auth
	k, ok := cache.forPath(originOf(u), requestPath(u))
	if !ok {
		return ""
	}
	// A challenge kept as it said a nonce was out of date may not be read.
	c, ok := ch.client.challengeOf(k.field)
	if !ok {
		return ""
	}
	ch.sent = &sentAuth{challenge: c, credentials: k.credentials, from: "path"}
	if ch.log != nil {
		ch.log.authorized(u.Redacted(), c, k.count)
	}
	return c.answer(k.credentials, method, u.RequestURI(), k.count, cache.draw)
}

// challenged is the Authorization to send res's request again with, when res
// is a 401 Chrome answers: in the scheme of the best challenge it offers,
// Basic or Digest, with the credentials of the request's URL if they were not
// sent yet, or with those the session keeps for the realm and scheme. What
// the 401 says of an answer the hop was sent comes first: the credentials it
// turns down are forgotten, and so are those it asks for another realm in
// place of, unless they were sent unasked; and a challenge that says the
// Digest nonce answered was out of date is kept in place of the one answered,
// the URL's credentials free to answer it again. A hop answered
// maxRestarts-1 times is answered no more: the request fails, as Chrome's
// does.
func (ch *chain) challenged(res *fhttp.Response) (string, bool, error) {
	if res.StatusCode != fhttp.StatusUnauthorized || !ch.authenticates(ch.last) {
		return "", false, nil
	}
	fields := res.Header.Values("WWW-Authenticate")
	u := shownURL(res.Request)
	at, cache := originOf(u), ch.client.session.auth
	if sent := ch.sent; sent != nil {
		said, field := sent.challenge.respond(fields)
		if ch.log != nil {
			ch.log.answeredAgain(u.Redacted(), sent.challenge, said)
		}
		switch {
		case said == outOfDate && cache.renew(at, sent.challenge.realm, sent.challenge.scheme, field):
			if sent.from == "url" {
				// They answer the new nonce, as they did the one before.
				ch.embedded = false
			}
		case said == otherRealm && sent.from == "path":
			// What is kept for the realm sent unasked stays.
		default:
			cache.drop(at, sent.challenge.realm, sent.challenge.scheme, sent.credentials)
		}
	}
	best, ok := ch.client.bestChallenge(fields)
	if !ok || best.scheme != "basic" && best.scheme != "digest" {
		return "", false, nil
	}
	cred, embedded := credentialsOf(ch.credentials)
	from := "url"
	switch {
	case embedded && !ch.embedded:
		ch.embedded = true
	default:
		if cred, ok = cache.forRealm(at, best.realm, best.scheme); !ok {
			return "", false, nil
		}
		from = "realm"
	}
	if ch.restarts++; ch.restarts == maxRestarts {
		return "", false, fmt.Errorf("tlsforge: %s %s asked for authentication again after %d answers, and Chrome answers it no more",
			res.Request.Method, u.Redacted(), maxRestarts-1)
	}
	cache.keep(at, best, cred, requestPath(u))
	ch.sent = &sentAuth{challenge: best, credentials: cred, from: from}
	if ch.log != nil {
		ch.log.authenticated(u.Redacted(), best, from)
	}
	return best.answer(cred, res.Request.Method, res.Request.URL.RequestURI(), 1, cache.draw), true, nil
}

// again is res's request, the latest hop, sent again with Authorization said
// as value: its body too, its headers as Chrome's network stack restarts it.
func (ch *chain) again(sent *fhttp.Request, value string) *fhttp.Request {
	ch.ours = true
	if ch.browser != nil {
		ch.last.authorization = value
	} else {
		ch.laid = ch.laid.authorized(value)
	}
	return ch.remade(sent)
}

// misdirected reports a 421 (Misdirected Request) Chrome sends its request
// again for: the first of its hop's, as HttpNetworkTransaction sends one
// again once, the rest of the hop with IP pooling off. Such an answer is let
// go of as Chrome lets go of it: its body unread, and over HTTP/1.1 the
// connection it came on closed, where a body read to its end would leave it to
// the next request.
func (ch *chain) misdirected(res *fhttp.Response) bool {
	if res.StatusCode != fhttp.StatusMisdirectedRequest || ch.resent {
		return false
	}
	letGo(res, ch.conn)
	ch.resent = true
	return true
}

// letGo lets go of a 421 a request is sent again for, which came on conn.
func letGo(res *fhttp.Response, conn net.Conn) {
	_ = res.Body.Close()
	if res.ProtoMajor < 2 {
		_ = conn.Close()
	}
}

// remade is sent, the latest hop, made again to be sent as it is laid out
// now: its body too. Its context goes on before it is dressed, the jar told
// about the URL it is sent with, which every WithContext copies anew.
func (ch *chain) remade(sent *fhttp.Request) *fhttp.Request {
	u := *sent.URL
	retry := (&fhttp.Request{Method: sent.Method, URL: &u, Host: sent.Host, Proto: "HTTP/1.1", ProtoMajor: 1,
		ProtoMinor: 1, ContentLength: sent.ContentLength, GetBody: sent.GetBody}).WithContext(ch.in(ch.base))
	if sent.GetBody != nil {
		// GetBody of a request made from bytes, which cannot fail.
		retry.Body, _ = sent.GetBody()
	}
	if ch.browser != nil {
		ch.dress(retry, ch.last)
		return retry
	}
	return ch.laid.wear(retry)
}

// redirected are the credentials of the URL a redirect leads req to, taken
// off it: its own, or, when its Location is relative, those of the URL it is
// relative to, as resolving one keeps them.
func (ch *chain) redirected(req *fhttp.Request) *url.Userinfo {
	user := req.URL.User
	req.URL.User = nil
	if user == nil && relativeLocation(req.Response.Header.Get("Location")) {
		user = ch.credentials
	}
	return user
}

// relativeLocation reports a Location that names neither a scheme nor a host,
// read as the transport reads it.
func relativeLocation(location string) bool {
	u, err := url.Parse(location)
	return err == nil && u.Scheme == "" && u.Host == ""
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
	user := ch.redirected(req)
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
	if ch.ours {
		// The Authorization tls-forge gave the request the transport copied
		// this one from: each hop has its own, or none.
		deleteHeader(req.Header, "authorization")
	}
	hop := newLayouts(req.Header, nil)
	if first := layoutsOn(req); first != nil {
		hop = first.redirected(req)
		hop.http1[fhttp.HeaderOrderKey] = hintsAfterDest(hop.http1[fhttp.HeaderOrderKey])
	}
	if value := ch.arrive(req.Method, shownURL(req), user, ch.authenticates(ch.last)); value != "" {
		hop = hop.authorized(value)
	}
	ch.laid = hop
	*req = *hop.wear(req)
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
	user := ch.redirected(req)
	h.authorization = ch.arrive(h.method, shownURL(req), user, ch.authenticates(h))
	r := ch.browser
	if r.needsPreflight(h) && !ch.client.session.preflights.allows(r, h, shownURL(req).String()) {
		if err := ch.client.preflight(ch.base, req, r, h, ch.site.bare, ch.log); err != nil {
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
		// A redirect a navigation was answered with may ask for hints too,
		// and say it needs them.
		ch.remember(originOf(previous.URL), req.Response.Header)
		if ch.restart(shownURL(previous), req.Response.Header, last) {
			return hop{}, errCriticalHints
		}
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
	r := ch.browser
	*req = *ch.client.browserLayouts(r.header(h, ch.client.headers), h.script, r.wireOrder(h), shownURL(req).Host).wear(req)
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
