package tlsforge

import (
	"context"
	"github.com/igor-lemon/utls/behavior"
	"net/textproto"
	"slices"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// layouts are the header blocks of one request, made before it is sent: as it
// goes over HTTP/2, and as it goes over HTTP/1.1 where that differs. Which
// protocol a request goes over is known only once its connection's handshake
// is over: ALPN is encrypted in TLS 1.3, and tls-client picks the protocol
// inside its round tripper. So a request wears its HTTP/2 block, and the
// transport asks it for the header to write once it knows (Request.HeaderFor,
// of tls-forge's fork of fhttp), which over HTTP/1.1 is the other (wear).
type layouts struct {
	behavior behavior.Policy
	http2    fhttp.Header
	// http1 is nil when the request goes the same over both.
	http1 fhttp.Header
	// managed are the names either block has, which the change takes away
	// before it puts the HTTP/1.1 block in, so that a field fhttp added in
	// between stays: never the Cookie, to which fhttp's client adds the jar's
	// cookies (newLayouts).
	managed map[string]bool
	// withheld is what of the blocks goes only to a URL that is potentially
	// trustworthy, which wear leaves out of what is written to any other; nil
	// for nothing.
	withheld *withholding
	// asked, for a page's request in a browser context, is the HTTP/2 block
	// to write in place of http2 once its connection is known, when the
	// connection's ALPS asks for client hints the request does not carry
	// (chain.alpsBlock): nil for none, and nil when it is nil.
	asked func() fhttp.Header
}

type layoutsKey struct{}

// newLayouts are the layouts of the blocks http2 and http1, nil for none; each
// tells its protocol's writer that the request names no user agent where it
// names none (quietUserAgent). The pseudo-headers are the transport's to
// order, as its client profile says: the profile's, or the one a transport
// option gave. Both protocols write the Cookie fhttp's client leaves on the
// request: the request's own with the jar's cookies after it, added once the
// request is laid out, as net/http's client adds them. So the HTTP/1.1 block
// names the Cookie's slot and carries none, and the change takes none away.
func newLayouts(http2, http1 fhttp.Header) *layouts {
	quietUserAgent(http2, http2UserAgent)
	l := &layouts{http2: http2}
	if http1 != nil {
		quietUserAgent(http1, http1UserAgent)
		deleteFields(http1, "cookie")
		l.http1, l.managed = http1, managedHeaderNames(http2, http1)
		delete(l.managed, "cookie")
	}
	return l
}

// layoutsAsGiven are the layouts of a request without a browser context:
// headers, the profile's with the request's own (given) laid over them, in
// the profile's order over HTTP/2; over HTTP/1.1 in the order and spelling the
// profile measured, with its HTTP/1.1 values, or as over HTTP/2 when it
// measured none and the request names no user agent. A Chromium profile's
// layouts name the Cookie where Chrome writes it (cookieSlot); only Chromium
// was measured, so another browser's Cookie goes where the transport puts a
// name its order does not have: last. A Cookie of the request's own goes as
// one (ownCookie), the jar's cookies after it.
func (c *Client) layoutsAsGiven(headers, given Header, host string) *layouts {
	http2 := legacyHeaderLayout(headers, host)
	ownCookie(http2)
	var http1 fhttp.Header
	switch {
	case c.profile.HTTP1 != nil:
		http1 = measuredHTTP1Layout(c.http1Headers.Merge(given), c.profile.HTTP1, host)
	case !headers.Has("user-agent"):
		// The one field the two protocols cannot be told the same way: an
		// HTTP/1.1 connection gets a layout of its own even where nothing
		// else differs.
		http1 = cloneHeaderLayout(http2)
	}
	if c.behavior().Flag("headers.cookie_slot") {
		cookieSlot(http2, c.behavior())
		cookieSlot(http1, c.behavior())
	}
	l := newLayouts(http2, http1)
	l.behavior = c.behavior()
	l.withheld = c.withheld.without(given)
	return l
}

// withholding is what of a request without a browser context goes only to a
// URL that is potentially trustworthy (trustworthy): https, or http to the
// machine itself. Chrome tells no other its client hints or where its requests
// come from (Sec-Fetch-*), and offers it neither Brotli nor zstd, a navigation
// typed or redirected there as any other (testdata/chrome155-requests.json:
// nav-direct-plain, and the hops of the redir-nav-direct-* scenarios between
// plain http, https and http://localhost). Only the profile's is withheld: a
// field the client or the request was given goes as given.
type withholding struct {
	encodings []string
	// names are the lower-case names of the client hints and Sec-Fetch-*.
	names []string
	// encoding is whether the Accept-Encoding is the profile's.
	encoding bool
}

// withheldOf is what of prof's headers, over either protocol, goes only to a
// potentially trustworthy URL, but what given names; nil for nothing. Only
// Chromium was measured: another browser's profile withholds nothing.
func withheldOf(prof *profile.Profile, given Header) *withholding {
	if !prof.RuntimeBehavior().Flag("headers.withhold_untrusted") {
		return nil
	}
	fields := append(Header(nil), prof.Headers...)
	if prof.HTTP1 != nil {
		fields = append(fields, prof.HTTP1.Headers...)
	}
	w := &withholding{encodings: prof.RuntimeBehavior().Strings("headers.untrusted_drop_codings")}
	for _, f := range fields {
		name := strings.ToLower(f.Name)
		switch {
		case given.Has(name) || slices.Contains(w.names, name):
		case hasPrefixIn(name, prof.RuntimeBehavior().Strings("headers.untrusted_prefixes")):
			w.names = append(w.names, name)
		case name == "accept-encoding":
			w.encoding = true
		}
	}
	if len(w.names) == 0 && !w.encoding {
		return nil
	}
	return w
}

// without is w less what given names, a request's own headers; nil for
// nothing.
func (w *withholding) without(given Header) *withholding {
	if w == nil || len(given) == 0 {
		return w
	}
	out := &withholding{encodings: w.encodings, encoding: w.encoding && !given.Has("accept-encoding")}
	for _, name := range w.names {
		if !given.Has(name) {
			out.names = append(out.names, name)
		}
	}
	if len(out.names) == 0 && !out.encoding {
		return nil
	}
	return out
}

// from takes what w withholds out of header, a block to be written to a URL
// that is not potentially trustworthy: the fields it names, their slots left in
// the order, and Brotli and zstd out of the Accept-Encoding, which goes when
// it offers nothing else.
func (w *withholding) from(header fhttp.Header) {
	for _, name := range w.names {
		deleteFields(header, name)
	}
	if !w.encoding {
		return
	}
	for name, values := range header {
		if !strings.EqualFold(name, "accept-encoding") {
			continue
		}
		if offered := withoutCodings(strings.Join(values, ", "), w.droppedCodings()...); offered != "" {
			header[name] = []string{offered}
		} else {
			delete(header, name)
		}
	}
}

// cookieSlot names the Cookie in block's order where Chrome writes it: right
// after Accept-Language, the last header its network stack adds before the
// cookies, and so before the Priority its HTTP/2 writer adds after them all,
// as every request with cookies was measured (testdata/chrome155-requests.json);
// last when block has no Accept-Language. The transport adds the jar's Cookie
// once a request is laid out, and writes a name its order does not have after
// every name it does: after Priority. A Cookie the request was given goes in
// the same slot, the jar's cookies after it. A request the same over both
// protocols has no HTTP/1.1 block: nil is left as it is.
func cookieSlot(block fhttp.Header, policies ...behavior.Policy) {
	if block == nil {
		return
	}
	order := slices.DeleteFunc(block[fhttp.HeaderOrderKey], func(name string) bool {
		return strings.EqualFold(name, "cookie")
	})
	at := len(order)
	if i := slices.IndexFunc(order, func(name string) bool {
		return strings.EqualFold(name, policyArgument(policies).Text("headers.cookie_after"))
	}); i >= 0 {
		at = i + 1
	}
	block[fhttp.HeaderOrderKey] = slices.Insert(order, at, "cookie")
}

// ownCookie says the Cookie block, a request's HTTP/2 block, was given as a
// browser says its cookies: one field, its pairs in their order, each without
// the spaces around it and none empty, joined by "; " (RFC 6265, 4.2.1). The
// transport's client adds the jar's cookies to a Cookie's first field and
// drops the rest, and the transport writes each pair a field of its own over
// HTTP/2 and the field one line over HTTP/1.1: so every cookie given goes,
// before the jar's, the same over both. A Cookie with no pair is none, its
// slot left to the jar's.
func ownCookie(block fhttp.Header) {
	var pairs []string
	for _, value := range block["Cookie"] {
		for _, pair := range strings.Split(value, ";") {
			if pair = textproto.TrimString(pair); pair != "" {
				pairs = append(pairs, pair)
			}
		}
	}
	if len(pairs) == 0 {
		delete(block, "Cookie")
		return
	}
	block["Cookie"] = []string{strings.Join(pairs, "; ")}
}

// browserLayouts are the layouts of a request in a browser context: field, its
// headers, in order over HTTP/2 and as Chrome writes them over HTTP/1.1,
// script being those a script set, and spelt those it was given that go over
// HTTP/1.1 as given. A Cookie it was given goes as one, the jar's cookies after
// it (ownCookie).
func (c *Client) browserLayouts(field, script, spelt Header, order []string, host string) *layouts {
	http2 := browserLayout(field, order, host)
	ownCookie(http2)
	l := newLayouts(http2,
		browserHTTP1Layout(field, script, spelt, order, c.profile.HTTP1, c.http1Headers, host, c.behavior()))
	l.behavior = c.behavior()
	return l
}

// redirected are the layouts of req, a redirect's request, made from l, the
// first request's: req wears the HTTP/2 block fhttp gave it, and the HTTP/1.1
// block keeps the first's spelling and the fields only HTTP/1.1 has, with the
// changes the redirect made (redirectHTTP1Layout).
func (l *layouts) redirected(req *fhttp.Request) *layouts {
	// fhttp has already copied only the headers that are safe for this redirect.
	// Replaying the first hop's complete HTTP/1 block here would undo that
	// decision: on a cross-origin redirect it reintroduced Authorization, Cookie
	// and the old Host after fhttp had deliberately removed them.
	host := req.URL.Host
	if req.Host != "" {
		// Request.Host is set when fhttp keeps a Host the first request was
		// given across a relative redirect, or when withPort moved a port-less
		// http URL's host there. Neither is ever the source's on a redirect to
		// another origin, so a source origin cannot lend its Host to another.
		host = req.Host
	}
	out := newLayouts(req.Header, redirectHTTP1Layout(l.http1, l.http2, req.Header, host))
	out.behavior = l.behavior
	return out
}

// authorized are l with Authorization said as value in both blocks, where
// Chrome's network stack adds it: after the Content-Length and Cache-Control
// that lead a request, Host and Connection leading HTTP/1.1's, and before
// every other header. One tls-forge gave them before is replaced.
func (l *layouts) authorized(value string) *layouts {
	var http1 fhttp.Header
	if l.http1 != nil {
		http1 = withAuthorization(l.http1, value, l.runtimeBehavior())
	}
	out := newLayouts(withAuthorization(l.http2, value, l.runtimeBehavior()), http1)
	out.withheld = l.withheld
	out.behavior = l.behavior
	return out
}

// withAuthorization is a copy of block with Authorization said as value, in
// its slot.
func withAuthorization(block fhttp.Header, value string, policies ...behavior.Policy) fhttp.Header {
	leadAuthorization := policyArgument(policies).Strings("headers.authorization_leading")
	out := cloneHeaderLayout(block)
	deleteHeader(out, "authorization")
	order := out[fhttp.HeaderOrderKey]
	at := 0
	for at < len(order) && slices.Contains(leadAuthorization, strings.ToLower(order[at])) {
		at++
	}
	out[fhttp.HeaderOrderKey] = slices.Insert(order, at, "authorization")
	out["Authorization"] = []string{value}
	return out
}

// wear is req wearing l: the HTTP/2 block, and over HTTP/1.1 the HTTP/1.1
// block, which the transport asks for once it knows (HeaderFor). To a URL that
// is not potentially trustworthy either is written without what l withholds,
// while the block req wears stays whole: fhttp makes a redirect's request with
// a copy of it, and a hop to a URL that is gets what was withheld back. l goes
// on req's context too, for a redirect's request to make its own from
// (layoutsOn), since fhttp makes it with the first request's context. A
// request that goes the same over both wears its one block, and nothing more
// where it withholds nothing. Each wears a copy, which the client and the
// transport add to (the jar's Cookie, Host): l stays as it was made, for a
// request sent again for a challenge to be made from (chain.laid). Over HTTP/2
// a page's request is written with the block its connection's ALPS asks for,
// where it asks for one (asked).
func (l *layouts) wear(req *fhttp.Request) *fhttp.Request {
	req.Header = cloneHeaderLayout(l.http2)
	withheld := l.withheld
	if withheld != nil && trustworthy(originOf(req.URL)) {
		withheld = nil
	}
	if l.http1 == nil && withheld == nil && l.asked == nil {
		return req
	}
	req.HeaderFor = func(protocol string, header fhttp.Header) fhttp.Header {
		http1 := protocol == fhttp.ProtocolHTTP1 && l.http1 != nil
		var asked fhttp.Header
		if protocol == fhttp.ProtocolHTTP2 && l.asked != nil {
			asked = l.asked()
		}
		if !http1 && withheld == nil && asked == nil {
			return nil
		}
		// The header as the client left it, what it added kept: the Cookie
		// it wrote the jar's cookies into, after the request's own.
		written := cloneHeaderLayout(header)
		switch {
		case http1:
			applyHeaderLayout(written, l.http1, l.managed)
		case asked != nil:
			// The asked block has no Cookie of its own: the one written is the
			// client's, the request's own with the jar's after it.
			managed := managedHeaderNames(l.http2, asked)
			delete(managed, "cookie")
			applyHeaderLayout(written, asked, managed)
		}
		if withheld != nil {
			withheld.from(written)
		}
		return written
	}
	if l.http1 == nil {
		return req
	}
	return req.WithContext(context.WithValue(req.Context(), layoutsKey{}, l))
}

// layoutsOn are the layouts req's context carries, nil for none.
func layoutsOn(req *fhttp.Request) *layouts {
	l, _ := req.Context().Value(layoutsKey{}).(*layouts)
	return l
}

// legacyHeaderLayout is the compatibility path for profiles captured before
// HTTP/1.1 was measured. Its canonical spelling is intentionally the old
// behaviour: adding a schema field must not make an existing profile fail a
// request it used to send.
func legacyHeaderLayout(headers Header, host string) fhttp.Header {
	out := fhttp.Header{}
	order := []string{"host"}
	seen := map[string]bool{"host": true}
	out["Host"] = []string{host}
	for _, field := range headers {
		name := strings.ToLower(field.Name)
		wireName := textproto.CanonicalMIMEHeaderKey(name)
		if name == "host" {
			out[wireName] = []string{field.Value}
			continue
		}
		out[wireName] = append(out[wireName], field.Value)
		if !seen[name] {
			order = append(order, name)
			seen[name] = true
		}
	}
	out[fhttp.HeaderOrderKey] = order
	return out
}

func measuredHTTP1Layout(headers Header, measured *profile.HTTP1, host string) fhttp.Header {
	values := make(map[string][]string)
	for _, field := range headers {
		name := strings.ToLower(field.Name)
		values[name] = append(values[name], field.Value)
	}
	if hosts := values["host"]; len(hosts) > 0 {
		host = hosts[len(hosts)-1]
	}

	out := fhttp.Header{}
	order := make([]string, 0, len(measured.HeaderOrder)+len(headers))
	seen := make(map[string]bool)
	for _, wireName := range measured.HeaderOrder {
		name := strings.ToLower(wireName)
		var fieldValues []string
		if name == "host" {
			fieldValues = []string{host}
		} else {
			fieldValues = values[name]
		}
		if len(fieldValues) == 0 {
			continue
		}
		out[wireName] = append([]string(nil), fieldValues...)
		order = append(order, name)
		seen[name] = true
	}
	for _, field := range headers {
		name := strings.ToLower(field.Name)
		if seen[name] || name == "host" {
			continue
		}
		wireName := textproto.CanonicalMIMEHeaderKey(name)
		out[wireName] = append([]string(nil), values[name]...)
		order = append(order, name)
		seen[name] = true
	}
	out[fhttp.HeaderOrderKey] = order
	return out
}

// quietUserAgent keeps the transport from naming itself. fhttp gives a request
// that carries no User-Agent its own, "Go-http-client", which says what is
// talking more plainly than any handshake could hide it; and a request can come
// without one, from a profile out of the transport's catalogue, which knows a
// handshake and no headers, or from a hand-written one.
//
// Each protocol is told it is named and empty in the one way its writer takes
// as that: HTTP/2 by an empty value, which it leaves out, and HTTP/1.1 by the
// field with no values at all, since an empty value is a line of its own there
// and no values is no line. Neither reads the other's way: HTTP/2 passes over a
// field with no values before it notices the name, and HTTP/1.1 writes
// "User-Agent: " for an empty one.
func quietUserAgent(header fhttp.Header, empty []string) {
	for name := range header {
		if strings.EqualFold(name, "user-agent") {
			return
		}
	}
	header["User-Agent"] = empty
}

// How each protocol's writer is told a request names no user agent.
var (
	http2UserAgent = []string{""}
	http1UserAgent = []string{}
)

func managedHeaderNames(layouts ...fhttp.Header) map[string]bool {
	out := make(map[string]bool)
	for _, layout := range layouts {
		for name := range layout {
			out[strings.ToLower(name)] = true
		}
	}
	return out
}

// redirectHTTP1Layout keeps the measured spelling and HTTP/1-only fields from
// the first layout while applying the redirect policy reflected in current.
// original is the HTTP/2-shaped block before the first request was sent; it is
// the baseline fhttp copies on every hop.
func redirectHTTP1Layout(http1, original, current fhttp.Header, host string) fhttp.Header {
	out := cloneHeaderLayout(http1)
	before := headerValues(original)
	now := headerValues(current)

	beforeNames := make([]string, 0, len(before))
	for name := range before {
		beforeNames = append(beforeNames, name)
	}
	slices.Sort(beforeNames)
	for _, name := range beforeNames {
		if name == "host" || name == "cookie" {
			// The hop's Host is its own, and its Cookie is the one fhttp's
			// client leaves on it (newLayouts): the request's own, which fhttp
			// sends on to its host alone, and the jar's, in the slot the order
			// keeps, as the order fhttp copies onto the hop keeps it over
			// HTTP/2.
			continue
		}
		values := before[name]
		redirected, kept := now[name]
		if !kept {
			deleteHeader(out, name)
			continue
		}
		// An unchanged shared field keeps its HTTP/1-specific captured value.
		// A changed field (Referer, or an Origin that became "null", are the
		// usual examples) must use the value computed for this hop.
		if !slices.Equal(redirected, values) {
			setHeader(out, name, redirected)
		}
	}
	nowNames := make([]string, 0, len(now))
	for name := range now {
		nowNames = append(nowNames, name)
	}
	slices.Sort(nowNames)
	for _, name := range nowNames {
		if name == "host" || headerLayoutKey(name) {
			continue
		}
		if _, existed := before[name]; !existed {
			setHeader(out, name, now[name])
		}
	}
	setHeader(out, "host", []string{host})
	return out
}

func cloneHeaderLayout(header fhttp.Header) fhttp.Header {
	out := make(fhttp.Header, len(header))
	for name, values := range header {
		out[name] = copyValues(values)
	}
	return out
}

// copyValues copies a field's values, and keeps a field with none as one with
// none rather than as nil: to fhttp a nil field is one that is not there, and an
// HTTP/1.1 request without a User-Agent field is one fhttp gives its own.
func copyValues(values []string) []string {
	return append(make([]string, 0, len(values)), values...)
}

func headerValues(header fhttp.Header) map[string][]string {
	out := make(map[string][]string, len(header))
	for name, values := range header {
		lower := strings.ToLower(name)
		if headerLayoutKey(lower) {
			continue
		}
		out[lower] = append(out[lower], values...)
	}
	return out
}

func headerLayoutKey(name string) bool {
	return strings.EqualFold(name, fhttp.HeaderOrderKey) ||
		strings.EqualFold(name, fhttp.PHeaderOrderKey)
}

func deleteHeader(header fhttp.Header, lower string) {
	deleteFields(header, lower)
	order := header[fhttp.HeaderOrderKey]
	kept := order[:0]
	for _, name := range order {
		if !strings.EqualFold(name, lower) {
			kept = append(kept, name)
		}
	}
	header[fhttp.HeaderOrderKey] = kept
}

// deleteFields removes a header's fields, its name left in the order.
func deleteFields(header fhttp.Header, lower string) {
	for name := range header {
		if strings.EqualFold(name, lower) {
			delete(header, name)
		}
	}
}

func setHeader(header fhttp.Header, lower string, values []string) {
	wireName := ""
	for name := range header {
		if strings.EqualFold(name, lower) && !headerLayoutKey(name) {
			wireName = name
			break
		}
	}
	if wireName == "" {
		wireName = textproto.CanonicalMIMEHeaderKey(lower)
		header[fhttp.HeaderOrderKey] = append(header[fhttp.HeaderOrderKey], lower)
	}
	header[wireName] = append([]string(nil), values...)
}

func applyHeaderLayout(target, layout fhttp.Header, managed map[string]bool) {
	for name := range target {
		if managed[strings.ToLower(name)] {
			delete(target, name)
		}
	}
	for name, values := range layout {
		target[name] = copyValues(values)
	}
}

// browserLayout is the HTTP/2 header block of a request in a browser context:
// its headers in their order, the transport's own in their slots.
func browserLayout(h Header, order []string, host string) fhttp.Header {
	out := fhttp.Header{"Host": {host}}
	for _, f := range h {
		name := textproto.CanonicalMIMEHeaderKey(f.Name)
		out[name] = append(out[name], f.Value)
	}
	out[fhttp.HeaderOrderKey] = append([]string{"host"}, order...)
	return out
}

// browserHTTP1Layout is the same request over HTTP/1.1, as Chrome writes it:
// Host and Connection first, no generated Priority (a script's survives, and
// one the request was given), and each name spelt as the profile measured it,
// a script's as the script gave it, one of spelt as first given, a client hint
// in lower case, and any other as HTTP spells it.
func browserHTTP1Layout(h, script, spelt Header, order []string, measured *profile.HTTP1, http1 Header, host string, policies ...behavior.Policy) fhttp.Header {
	pol := policyArgument(policies)
	spelling := map[string]string{}
	if measured != nil {
		for _, wire := range measured.HeaderOrder {
			spelling[strings.ToLower(wire)] = wire
		}
	}
	for i, f := range spelt {
		// As DevTools gives Chrome the extra headers it writes: the first
		// spelling of a name.
		if lower := strings.ToLower(f.Name); !spelt[:i].Has(lower) {
			spelling[lower] = f.Name
		}
	}
	for _, f := range script {
		if strings.EqualFold(f.Name, "range") && !script.Has("if-range") {
			// A lone Range is reconstructed by the network stack, including
			// its HTTP/1 spelling. With If-Range both remain renderer fields.
			continue
		}
		// The script's first spelling survives even when it is all lower
		// case (fresh Chrome H1 oracle,chrome155-script-headers.json).
		spelling[strings.ToLower(f.Name)] = f.Name
	}
	spell := func(name string) string {
		lower := strings.ToLower(name)
		switch wire, known := spelling[lower]; {
		case known:
			return wire
		case strings.HasPrefix(lower, "sec-ch-") || slices.Contains(pol.Strings("headers.client_hint_order"), lower):
			// Chrome writes every client hint in lower case, the device's
			// under their old names too.
			return lower
		}
		return textproto.CanonicalMIMEHeaderKey(lower)
	}
	connection := http1.Get("connection")
	if connection == "" {
		connection = pol.Text("headers.h1_connection_default")
	}
	out := fhttp.Header{spell("host"): {host}}
	if connection != "" {
		out[spell("connection")] = []string{connection}
	}
	wireOrder := pol.Strings("headers.h1_prefix")
	keepPriority := script.Has("priority") || spelt.Has("priority") || pol.Flag("headers.h1_generated_priority")
	for _, name := range order {
		if !strings.EqualFold(name, "priority") || keepPriority {
			wireOrder = append(wireOrder, name)
		}
	}
	for _, f := range h {
		if !strings.EqualFold(f.Name, "priority") || keepPriority {
			name := spell(f.Name)
			out[name] = append(out[name], f.Value)
		}
	}
	out[fhttp.HeaderOrderKey] = wireOrder
	return out
}

func (l *layouts) runtimeBehavior() behavior.Policy {
	if l.behavior != nil {
		return l.behavior
	}
	return legacyPolicy()
}
func (w *withholding) droppedCodings() []string {
	if w.encodings != nil {
		return w.encodings
	}
	return legacyPolicy().Strings("headers.untrusted_drop_codings")
}
