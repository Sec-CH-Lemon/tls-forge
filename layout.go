package tlsforge

import (
	"context"
	"net"
	"net/textproto"
	"net/url"
	"slices"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttptrace "github.com/bogdanfinn/fhttp/httptrace"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// layouts are the header blocks of one request, made before it is sent: as it
// goes over HTTP/2, and as it goes over HTTP/1.1 where that differs. fhttp
// writes whatever block a request has, over whichever protocol its connection
// speaks, and which that is is known only once the connection's handshake is
// over: ALPN is encrypted in TLS 1.3, and tls-client picks the protocol inside
// its round tripper. The one place fhttp calls between the two is the trace's
// GotConn. So a request wears its HTTP/2 block, and a connection that speaks
// HTTP/1.1 changes it for the other there (wear), the only place anything
// changes a request's headers once the transport has it. Choosing the block
// anywhere else needs a transport that asks for one once it knows the
// protocol, which fhttp is not.
type layouts struct {
	http2 fhttp.Header
	// http1 is nil when the request goes the same over both.
	http1 fhttp.Header
	// managed are the names either block has, which the change takes away
	// before it puts the HTTP/1.1 block in, so that a field fhttp added in
	// between, as the jar's Cookie, stays.
	managed map[string]bool
}

type layoutsKey struct{}

// newLayouts are the layouts of the blocks http2, given the pseudo-header
// order pseudo when there is one, and http1, nil for none; each tells its
// protocol's writer that the request names no user agent where it names none
// (quietUserAgent).
func newLayouts(http2, http1 fhttp.Header, pseudo []string) *layouts {
	if len(pseudo) > 0 {
		http2[fhttp.PHeaderOrderKey] = pseudo
	}
	quietUserAgent(http2, http2UserAgent)
	l := &layouts{http2: http2}
	if http1 != nil {
		quietUserAgent(http1, http1UserAgent)
		l.http1, l.managed = http1, managedHeaderNames(http2, http1)
	}
	return l
}

// layoutsAsGiven are the layouts of a request without a browser context:
// headers, the profile's with the request's own (given) laid over them, in
// the profile's order over HTTP/2; over HTTP/1.1 in the order and spelling the
// profile measured, with its HTTP/1.1 values, or as over HTTP/2 when it
// measured none and the request names no user agent.
func (c *Client) layoutsAsGiven(headers, given Header, host string) *layouts {
	http2 := legacyHeaderLayout(headers, host)
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
	return newLayouts(http2, http1, c.profile.HTTP2.PseudoHeaderOrder)
}

// browserLayouts are the layouts of a request in a browser context: field, its
// headers, in order over HTTP/2 and as Chrome writes them over HTTP/1.1,
// script being those a script set.
func (c *Client) browserLayouts(field, script Header, order []string, host string) *layouts {
	return newLayouts(browserLayout(field, order, host),
		browserHTTP1Layout(field, script, order, c.profile.HTTP1, c.http1Headers, host),
		c.profile.HTTP2.PseudoHeaderOrder)
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
	return newLayouts(req.Header, redirectHTTP1Layout(l.http1, l.http2, req.Header, host), nil)
}

// wear is req wearing l: the HTTP/2 block, which a connection that speaks
// HTTP/1.1 changes for the HTTP/1.1 block when the request gets it. l goes on
// req's context too, for a redirect's request to make its own from
// (layoutsOn), since fhttp makes it with the first request's context. A
// request that goes the same over both wears its one block, and nothing more.
func (l *layouts) wear(req *fhttp.Request) *fhttp.Request {
	if l.http1 == nil {
		req.Header = l.http2
		return req
	}
	// The request's own copy, which the hook changes in place: the request the
	// transport writes is a copy of req (WithContext below, and fhttp's own)
	// that shares the map, not the struct. l.http2 stays as it was made.
	header := cloneHeaderLayout(l.http2)
	req.Header = header
	target := req.URL
	got := func(info fhttptrace.GotConnInfo) {
		if connectionUsesHTTP1(target, info.Conn) {
			applyHeaderLayout(header, l.http1, l.managed)
		}
	}
	ctx := context.WithValue(req.Context(), layoutsKey{}, l)
	return req.WithContext(fhttptrace.WithClientTrace(ctx, &fhttptrace.ClientTrace{GotConn: got}))
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
		if name == "host" {
			continue
		}
		values := before[name]
		redirected, kept := now[name]
		if !kept {
			deleteHeader(out, name)
			continue
		}
		// An unchanged shared field keeps its HTTP/1-specific captured value.
		// A changed field (Referer and adjusted explicit cookies are the usual
		// examples) must use the value computed for this hop.
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
	for name := range header {
		if strings.EqualFold(name, lower) {
			delete(header, name)
		}
	}
	order := header[fhttp.HeaderOrderKey]
	kept := order[:0]
	for _, name := range order {
		if !strings.EqualFold(name, lower) {
			kept = append(kept, name)
		}
	}
	header[fhttp.HeaderOrderKey] = kept
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

func connectionUsesHTTP1(target *url.URL, conn net.Conn) bool {
	if target.Scheme == "http" {
		return true
	}
	state, ok := conn.(connectionStater)
	if !ok {
		// An unknown TLS wrapper must not perturb HTTP/2, the core fingerprint.
		return false
	}
	negotiated := state.ConnectionState().NegotiatedProtocol
	return negotiated == "" || negotiated == "http/1.1"
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
// Host and Connection first, no Priority, and each name spelt as the profile
// measured it, a script's as the script gave it, a client hint in lower case,
// and any other as HTTP spells it.
func browserHTTP1Layout(h, script Header, order []string, measured *profile.HTTP1, http1 Header, host string) fhttp.Header {
	spelling := map[string]string{}
	if measured != nil {
		for _, wire := range measured.HeaderOrder {
			spelling[strings.ToLower(wire)] = wire
		}
	}
	for _, f := range script {
		// As a script spelt it; in lower case, as NewHeader gives every name,
		// as a script writes it, which is as HTTP spells it.
		if f.Name != strings.ToLower(f.Name) {
			spelling[strings.ToLower(f.Name)] = f.Name
		}
	}
	spell := func(name string) string {
		lower := strings.ToLower(name)
		switch wire, known := spelling[lower]; {
		case known:
			return wire
		case strings.HasPrefix(lower, "sec-ch-") || slices.Contains(profile.ClientHintOrder, lower):
			// Chrome writes every client hint in lower case, the device's
			// under their old names too.
			return lower
		}
		return textproto.CanonicalMIMEHeaderKey(lower)
	}
	connection := http1.Get("connection")
	if connection == "" {
		connection = "keep-alive"
	}
	out := fhttp.Header{spell("host"): {host}, spell("connection"): {connection}}
	wireOrder := []string{"host", "connection"}
	for _, name := range order {
		if name != "priority" {
			wireOrder = append(wireOrder, name)
		}
	}
	for _, f := range h {
		if !strings.EqualFold(f.Name, "priority") {
			name := spell(f.Name)
			out[name] = append(out[name], f.Value)
		}
	}
	out[fhttp.HeaderOrderKey] = wireOrder
	return out
}
