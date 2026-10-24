package tlsforge

import (
	"slices"
	"strconv"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"
	http2 "github.com/igor-lemon/fhttp/http2"
)

// A request a browser sent (BrowserContext.Sent), as an intercepting proxy is
// given one: the browser said what it is with its fields, Sec-Fetch-* among
// them, and it goes with them, in Chrome's order for its kind: a field in the
// slot Chrome writes it in (navigationOrder and the rest, scriptOrder), one
// Chrome has no slot of its own for where @given stands, and a script's own
// in the renderer's map. The profile is the browser the handshake says, so the
// user agent, the client hints it has values of, Accept-Language and
// Accept-Encoding are its own; the rest is the browser's.

// resolveSent checks a browser's request against what its kind can be, and
// keeps its fields.
func (b *BrowserContext) resolveSent(r *browserRequest, header Header, body []byte) error {
	r.sent = true
	switch b.Kind {
	case KindNavigation:
		switch {
		case r.method != fhttp.MethodGet:
			return errContext("a navigation is a GET, not a %s: a form posts", r.method)
		case body != nil:
			return errContext("a navigation sends no body")
		}
	case KindForm:
		if r.initiator == nil {
			return errContext("a form is submitted from a page: name it as the initiator")
		}
		switch r.method {
		case fhttp.MethodGet:
			if body != nil {
				return errContext("a form sent by GET has its fields in the URL, not a body")
			}
		case fhttp.MethodPost:
			r.posted, r.contentType = true, header.Get("content-type")
		default:
			return errContext("a form is sent by GET or POST, not %s", r.method)
		}
	case KindFetch, KindXHR:
		if err := b.resolveScriptOf(r, body); err != nil {
			return err
		}
		// What the renderer gave it, which its map orders, and what the
		// network stack adds after, each in its slot: the Origin too but of
		// what the renderer itself asks of another origin, a font among them
		// (headers.renderer_origin_dests), whose Origin is the renderer's.
		stack := r.stackNames()
		if slices.Contains(r.runtimeBehavior().Strings("headers.renderer_origin_dests"),
			strings.ToLower(strings.TrimSpace(header.Get("sec-fetch-dest")))) {
			stack = slices.DeleteFunc(stack, func(name string) bool { return name == "origin" })
		}
		var script Header
		for _, f := range header {
			if !slices.Contains(stack, strings.ToLower(f.Name)) {
				script = append(script, f)
			}
		}
		r.script = scriptHeaders(script)
		header = header.without(script.Names()...)
	default:
		return errContext("kind %q is not navigation, form, fetch or xhr", b.Kind)
	}
	r.given = header
	return nil
}

// stackNames are the fields of a script's request that Chrome's network stack
// writes, in slots after the renderer's map (scriptOrder): Content-Length,
// Accept, Origin, Sec-Fetch-* and those after them; but Range, which a script
// gives the renderer.
func (r *browserRequest) stackNames() []string {
	pol := r.runtimeBehavior()
	names := slices.Concat(pol.Strings("headers.script_leading"), []string{"accept", "origin"},
		pol.Strings("headers.script_metadata"), pol.Strings("headers.script_trailing"))
	return slices.DeleteFunc(names, func(name string) bool { return name == "range" })
}

// asProfile has the fields of r, a request a browser sent, say the profile's
// for what the profile says itself: no user agent, Accept-Language or
// Accept-Encoding of the browser's, whose come from the profile (values), and
// the profile's value of each client hint it has one of.
func (c *Client) asProfile(r *browserRequest) {
	own := c.behavior().Strings("headers.browser_base_fields")
	hints := Header(c.profile.ClientHints)
	said := func(h Header) Header {
		var out Header
		for _, f := range h.without(own...) {
			if value := hints.Get(f.Name); value != "" {
				f.Value = value
			}
			out = append(out, f)
		}
		return out
	}
	r.given, r.script = said(r.given), said(r.script)
}

// sentPriority is the Priority Chrome writes over HTTP/2 for hop h of a
// request a browser sent without one, as it sends none over HTTP/1.1, the
// protocol a browser speaks to a proxy: by what the request is for
// (Sec-Fetch-Dest), as the profile says (headers.sent_priority), as Chrome 155
// was measured writing it (a document's and a frame's "u=0, i", a style
// sheet's and a font's "u=0", an image's "i", a script's none, fetch()'s and
// an XHR's "u=1, i"); "" for none.
func (r *browserRequest) sentPriority(h hop) string {
	dest := strings.ToLower(strings.TrimSpace(h.given.Get("sec-fetch-dest")))
	for _, entry := range r.runtimeBehavior().Strings("headers.sent_priority") {
		if of, value, _ := strings.Cut(entry, "="); of == dest {
			return value
		}
	}
	return ""
}

// urgencyOf is the urgency a Priority field says (RFC 9218): 3 unless its u
// says another, from 0 to 7.
func urgencyOf(value string) int {
	for _, member := range strings.Split(value, ",") {
		key, said, _ := strings.Cut(strings.TrimSpace(member), "=")
		if n, err := strconv.Atoi(said); key == "u" && err == nil && n >= 0 && n <= 7 {
			return n
		}
	}
	return 3
}

// sentFramePriority is the priority of the HEADERS frame of hop h of a
// request a browser sent, as Chrome gives one of its urgency
// (h2.urgency_weights), exclusive as the profile's own; false when the profile
// says no weights.
func (c *Client) sentFramePriority(r *browserRequest, h hop) (http2.PriorityParam, bool) {
	weights := c.behavior().Numbers("h2.urgency_weights")
	if len(weights) == 0 {
		return http2.PriorityParam{}, false
	}
	value := r.sentPriority(h)
	if h.given.Has("priority") {
		value = h.given.Get("priority")
	}
	exclusive := c.profile.HTTP2.HeaderPriority != nil && c.profile.HTTP2.HeaderPriority.Exclusive
	return http2.PriorityParam{Weight: uint8(weights[urgencyOf(value)]), Exclusive: exclusive}, true
}
