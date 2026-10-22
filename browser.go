package tlsforge

import (
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"net/url"
	"slices"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// RequestKind is what in a browser sends a request.
type RequestKind string

// The kinds of request a browser context can say a request is.
const (
	// KindNavigation is a page loaded at the top: typed into the address bar
	// when it has no initiator, or reached from a page, by a link or by its
	// script setting location, when it has one.
	KindNavigation RequestKind = "navigation"
	// KindForm is a form submitted from a page, by GET or POST.
	KindForm RequestKind = "form"
	// KindFetch is a page's script calling fetch().
	KindFetch RequestKind = "fetch"
	// KindXHR is a page's script sending an XMLHttpRequest.
	KindXHR RequestKind = "xhr"
)

// BrowserContext says what in a browser a request stands for: what sends it,
// from which page, under which policy. A request in one goes out as Chrome
// sends that request: the headers of its kind in Chrome's order and with
// Chrome's values, Sec-Fetch-* for where it goes, Origin and Referer as the
// page would give them, and only the cookies such a request carries.
//
// A Request without one goes out as it always has: as a navigation typed into
// the address bar, with the profile's headers, and whatever the caller adds.
// What a context cannot be sent as yet is refused before anything is sent.
type BrowserContext struct {
	// Kind is what sends the request.
	Kind RequestKind
	// Initiator is the URL of the page that sends it. Empty for a navigation
	// is one typed into the address bar; a form, fetch() and an XHR need one.
	Initiator string
	// ReferrerPolicy is that page's referrer policy, as a Referrer-Policy
	// header names one. Empty is Chrome's default,
	// strict-origin-when-cross-origin.
	ReferrerPolicy string
	// Mode is fetch()'s request mode: cors, the default, no-cors or
	// same-origin. Only for fetch().
	Mode string
	// Credentials is fetch()'s credentials mode: same-origin, the default,
	// include or omit. An XHR takes same-origin, its default, or include,
	// which is withCredentials.
	Credentials string
}

// Modes of fetch() and its credentials, as fetch() names them.
const (
	modeCORS        = "cors"
	modeNoCORS      = "no-cors"
	modeSameOrigin  = "same-origin"
	credentialsSame = "same-origin"
	credentialsAll  = "include"
	credentialsNone = "omit"
	modeNavigate    = "navigate"
	destDocument    = "document"
	destEmpty       = "empty"
	formEncoded     = "application/x-www-form-urlencoded"
	formMultipart   = "multipart/form-data"
	formText        = "text/plain"
)

// browserRequest is a request in a browser context, as resolved against the
// URL it goes to: what its headers are computed from.
type browserRequest struct {
	behavior    behavior.Policy
	kind        RequestKind
	method      string
	initiator   *url.URL
	from        origin
	policy      string
	mode        string
	credentials string
	// contentType is a form's, from its encoding.
	contentType string
	// script are the headers fetch() or an XHR was given, as given.
	script Header
	// cors is a request CORS answers: fetch() or an XHR in cors mode to
	// another origin.
	cors bool
	// posted is a form sent by POST: its redirects keep its Cache-Control.
	posted bool
}

// hop is one request of a chain of redirects, the first included, as what is
// worked out for it stands: where it goes and how it stands to the page, the
// Referer and the Origin it carries, its method, and whether it follows a
// redirect, after which Chrome sends a page's client hints later.
type hop struct {
	behavior   behavior.Policy
	to         origin
	site       string
	referrer   string
	origin     string
	method     string
	redirected bool
	// script are the headers fetch() or an XHR was given that the hop still
	// carries: a redirect to another origin drops Authorization, and one that
	// drops the body the headers that describe it.
	script Header
	// cors is a request CORS answers from this hop on; tainted is one whose
	// Origin has gone across origins, and is "null" from here on.
	cors, tainted bool
	// lateOrigin is an Origin a redirect gave a script's request that the
	// hop before it went without, which Chrome sends after Sec-Fetch-*, there
	// from then on.
	lateOrigin bool
	// hints are the client hints the hop carries beyond the three Chrome
	// sends unasked, with the profile's values, in Chrome's order.
	hints Header
	// restarted is the first request of a navigation started again for its
	// critical client hints, which Chrome sends after Accept.
	restarted bool
	// alps are the client hints the ALPS of the connection a page's hop went
	// out on asked its origin for that it did not carry, with the profile's
	// values, in Chrome's order: the hop goes again with them after Accept
	// (alpsOrder), and is sent so again for a 401 or a 421, as Chrome's
	// request, started again with them, is.
	alps Header
	// authorization is the Authorization tls-forge gives the hop: a
	// challenge answered, or what the session keeps for where it goes.
	authorization string
}

// first is the first request of a chain: to target, as the page sends it.
func (r *browserRequest) first(target *url.URL) hop {
	h := hop{behavior: r.behavior, to: originOf(target), method: r.method, cors: r.cors, script: r.script}
	if r.initiator == nil {
		h.site = "none"
		return h
	}
	h.site = relation(r.from, h.to)
	h.referrer = referrerFor(r.initiator, h.to, r.policy)
	h.origin = r.originHeader(h)
	return h
}

// scripted reports a request a page's script makes: fetch() or an XHR.
func (r *browserRequest) scripted() bool {
	return r.kind == KindFetch || r.kind == KindXHR
}

// kindName is what a script's request is called: fetch() or an XHR.
func (r *browserRequest) kindName() string {
	if r.kind == KindXHR {
		return "an XHR"
	}
	return "fetch()"
}

// errContext is what is wrong with a browser context, said before anything is
// sent.
func errContext(format string, args ...any) error {
	return fmt.Errorf("tlsforge: browser context: "+format, args...)
}

// resolve checks a browser context against the request it is for, and is the
// request it makes: an error, before anything is sent, for a context that is
// incomplete, names what does not exist, or asks for what a browser would not
// send or tls-forge does not send as one yet.
func (b *BrowserContext) resolve(method string, target *url.URL, header Header, body []byte, policies ...behavior.Policy) (*browserRequest, error) {
	r := &browserRequest{behavior: policyArgument(policies), kind: b.Kind, method: normalizedMethod(method), policy: b.ReferrerPolicy}
	if r.policy == "" {
		r.policy = r.behavior.Text("headers.default_referrer_policy")
	}
	if !slices.Contains(referrerPolicies, r.policy) {
		return nil, errContext("referrer policy %q is not one of %s", b.ReferrerPolicy, strings.Join(referrerPolicies, ", "))
	}
	if b.Initiator != "" {
		// The page's URL as Chrome made it, which its Referer is written from.
		initiator, err := parseURL(b.Initiator, nil)
		if err == nil {
			err = initiator.uncarried()
		}
		if err != nil {
			return nil, errContext("initiator %q %v", b.Initiator, err)
		}
		r.initiator = initiator.url()
		r.from = originOf(r.initiator)
	}
	if err := b.resolveKind(r, target, header, body); err != nil {
		return nil, err
	}
	if err := r.mixed(target, r.method, true); err != nil {
		return nil, err
	}
	return r, nil
}

func (b *BrowserContext) resolveKind(r *browserRequest, target *url.URL, header Header, body []byte) error {
	switch b.Kind {
	case KindNavigation:
		if r.method != fhttp.MethodGet {
			return errContext("a navigation is a GET, not a %s: a form posts", r.method)
		}
		if len(body) > 0 {
			return errContext("a navigation sends no body")
		}
		return b.onlyFetch(header, "a navigation")
	case KindForm:
		return b.resolveForm(r, header, body)
	case KindFetch, KindXHR:
		return b.resolveScript(r, target, header, body)
	}
	return errContext("kind %q is not navigation, form, fetch or xhr", b.Kind)
}

// onlyFetch refuses what only fetch() and an XHR are given: a mode,
// credentials and headers of their own.
func (b *BrowserContext) onlyFetch(header Header, what string) error {
	switch {
	case b.Mode != "":
		return errContext("%s has no mode: only fetch() has one", what)
	case b.Credentials != "":
		return errContext("%s has no credentials mode: only fetch() and an XHR have one", what)
	case len(header) > 0:
		return errContext("%s sends the headers the browser gives it, not %s", what, strings.ToLower(header[0].Name))
	}
	return nil
}

func (b *BrowserContext) resolveForm(r *browserRequest, header Header, body []byte) error {
	if r.initiator == nil {
		return errContext("a form is submitted from a page: name it as the initiator")
	}
	var given Header
	for _, f := range header {
		if !strings.EqualFold(f.Name, "content-type") {
			given = append(given, f)
		}
	}
	if err := b.onlyFetch(given, "a form"); err != nil {
		return err
	}
	switch r.method {
	case fhttp.MethodGet:
		if len(body) > 0 || header.Has("content-type") {
			return errContext("a form sent by GET has its fields in the URL, not a body")
		}
	case fhttp.MethodPost:
		r.posted = true
		r.contentType = header.Get("content-type")
		if r.contentType == "" {
			r.contentType = formEncoded
		}
		if !formEncoding(r.contentType) {
			return errContext("a form is encoded as %s, %s with its boundary or %s, not %q",
				formEncoded, formMultipart, formText, r.contentType)
		}
	default:
		return errContext("a form is sent by GET or POST, not %s", r.method)
	}
	return nil
}

// formEncoding reports a Content-Type a form can be encoded in: as Chrome
// sends it, the multipart one with the boundary it chose.
func formEncoding(contentType string) bool {
	switch contentType {
	case formEncoded, formText:
		return true
	}
	boundary, ok := strings.CutPrefix(contentType, formMultipart+"; boundary=")
	return ok && boundary != "" && !strings.ContainsAny(boundary, " \t\";")
}

func (b *BrowserContext) resolveScript(r *browserRequest, target *url.URL, header Header, body []byte) error {
	what := r.kindName()
	if r.initiator == nil {
		return errContext("%s is sent by a page's script: name the page as the initiator", what)
	}
	r.mode, r.credentials = b.Mode, b.Credentials
	if r.mode == "" {
		r.mode = modeCORS
	}
	if r.credentials == "" {
		r.credentials = credentialsSame
	}
	switch {
	case b.Kind == KindXHR && b.Mode != "":
		return errContext("an XHR has no mode: only fetch() has one")
	case b.Kind == KindXHR && r.credentials != credentialsSame && r.credentials != credentialsAll:
		return errContext("an XHR's credentials are same-origin or include, which is withCredentials, not %q",
			b.Credentials)
	case !slices.Contains([]string{modeCORS, modeNoCORS, modeSameOrigin}, r.mode):
		return errContext("mode %q is not cors, no-cors or same-origin", b.Mode)
	case !slices.Contains([]string{credentialsSame, credentialsAll, credentialsNone}, r.credentials):
		return errContext("credentials %q is not same-origin, include or omit", b.Credentials)
	case forbiddenMethod(r.method):
		return errContext("%s cannot send %s", what, r.method)
	case (r.method == fhttp.MethodGet || r.method == fhttp.MethodHead) && len(body) > 0:
		return errContext("%s sends no body with %s", what, r.method)
	}
	for _, f := range header {
		if forbiddenHeader(f.Name) {
			return errContext("%s cannot set %s: the browser sets it", what, strings.ToLower(f.Name))
		}
	}
	r.script = scriptHeaders(header)
	to := originOf(target)
	switch {
	case b.Kind == KindFetch && target.User != nil:
		return errContext("fetch() is given no URL with credentials in it, as a Request cannot be")
	case r.mode == modeSameOrigin && to != r.from:
		return errContext("%s in same-origin mode cannot go to another origin", what)
	case r.mode == modeNoCORS && !noCORSSafe(r.method, header):
		return errContext("%s in no-cors mode sends GET, HEAD or POST with only the headers CORS lets through", what)
	}
	r.cors = r.mode == modeCORS && to != r.from
	return nil
}

// normalizedMethod is a method as fetch() sends it: the six it knows in
// capitals, whatever case they were given in, and any other as given.
func normalizedMethod(method string) string {
	switch upper := strings.ToUpper(method); upper {
	case "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT":
		return upper
	}
	return method
}

// forbiddenMethod reports a method fetch() and an XHR refuse.
func forbiddenMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "CONNECT", "TRACE", "TRACK":
		return true
	}
	return false
}

// forbiddenHeader reports a header a page's script cannot set: the Fetch
// standard's forbidden request headers, and User-Agent, which Chrome does not
// let a script change either.
func forbiddenHeader(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "proxy-") || strings.HasPrefix(lower, "sec-") {
		return true
	}
	switch lower {
	case "accept-charset", "accept-encoding", "access-control-request-headers", "access-control-request-method",
		"connection", "content-length", "cookie", "cookie2", "date", "dnt", "expect", "host", "keep-alive",
		"origin", "referer", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade", "via", "user-agent",
		"x-http-method", "x-http-method-override", "x-method-override":
		return true
	}
	return false
}

// noCORSSafe reports a method and headers a no-cors request can have: GET,
// HEAD or POST, with headers CORS lets through without asking.
func noCORSSafe(method string, header Header) bool {
	switch method {
	case fhttp.MethodGet, fhttp.MethodHead, fhttp.MethodPost:
	default:
		return false
	}
	for _, f := range header {
		if !corsSafelisted(f.Name, f.Value) {
			return false
		}
	}
	return true
}

// corsSafelisted reports a header CORS lets through without a preflight, as
// the Fetch standard lists them.
func corsSafelisted(name, value string) bool {
	if len(value) > 128 {
		return false
	}
	switch strings.ToLower(name) {
	case "accept":
		return !strings.ContainsFunc(value, corsUnsafeByte)
	case "accept-language", "content-language":
		return !strings.ContainsFunc(value, func(r rune) bool { return !corsLanguageByte(r) })
	case "content-type":
		if strings.ContainsFunc(value, corsUnsafeByte) {
			return false
		}
		essence, _, _ := strings.Cut(value, ";")
		switch strings.ToLower(strings.TrimSpace(essence)) {
		case formEncoded, formMultipart, formText:
			return true
		}
	}
	return false
}

// corsLanguageByte is a byte a safelisted Accept-Language or Content-Language
// may have.
func corsLanguageByte(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune(" *,-.;=", r)
}

// corsUnsafeByte is a byte the Fetch standard keeps out of a safelisted
// Accept or Content-Type.
func corsUnsafeByte(r rune) bool {
	return r < 0x20 && r != '\t' || r == 0x7f || strings.ContainsRune("\"():<>?@[\\]{}", r)
}

// Slots that stand for several headers: where in a request of fetch() or an
// XHR the headers its script gave go; where in a page's the client hints go,
// the three Chrome sends unasked and those an origin asked for, in Chrome's
// order (profile.ClientHintOrder); where in a script's those asked for go; and
// where in a page's those a connection's ALPS asked for that it did not carry.
const (
	slotHints     = "\x00hints"
	slotALPSHints = "\x00ALPS hints"
)

// The headers of each kind of request, in the order Chrome 155 sends them, as
// measured (testdata/chrome155-requests.json). A request has a header of a
// slot only when it has a value for it. Authorization, which Chrome's network
// stack adds, goes after the Content-Length and Cache-Control it adds and
// before the rest.
var (
	navigationOrder = slotList(legacyPolicy().Strings("headers.navigation_order"))
	formOrder       = slotList(legacyPolicy().Strings("headers.form_order"))
	// restartedOrder is the first request of a navigation started again for
	// its critical client hints.
	restartedOrder = slotList(legacyPolicy().Strings("headers.restarted_order"))
	// redirectedOrder is a navigation's or a form's after a redirect.
	redirectedOrder = slotList(legacyPolicy().Strings("headers.redirected_order"))
)

// order is a request's slots, in Chrome's order: a page's after a redirect
// has its client hints after Sec-Fetch-Dest, and one a connection's ALPS asked
// hints of those after Accept (alpsOrder).
func (r *browserRequest) order(h hop) []string {
	if r.scripted() {
		return scriptOrder(h)
	}
	order := slotList(r.runtimeBehavior().Strings("headers.navigation_order"))
	switch {
	case h.redirected:
		order = slotList(r.runtimeBehavior().Strings("headers.redirected_order"))
	case h.restarted:
		order = slotList(r.runtimeBehavior().Strings("headers.restarted_order"))
	case r.posted:
		order = slotList(r.runtimeBehavior().Strings("headers.form_order"))
	}
	if len(h.alps) > 0 {
		return alpsOrder(order, h.redirected, r.runtimeBehavior())
	}
	return order
}

// alpsOrder is order, a page's request's, for one Chrome starts again with the
// client hints a connection's ALPS asked for (slotALPSHints), as it was
// measured doing it (testdata/chrome155-alps.json): they go after the headers
// its browser gives the request, which end with Accept, or with the client
// hints that follow Accept; and a request after a redirect, whose hints its
// browser gave last and its network stack's Sec-Fetch-* follow, has its hints
// after Accept too, those asked after them.
func alpsOrder(order []string, redirected bool, policies ...behavior.Policy) []string {
	anchor := policyArgument(policies).Text("headers.alps_after")
	out := slices.Clone(order)
	if redirected {
		out = slices.DeleteFunc(out, func(slot string) bool { return slot == slotHints })
		out = slices.Insert(out, slices.Index(out, anchor)+1, slotHints)
	}
	at := slices.Index(out, anchor) + 1
	if at < len(out) && out[at] == slotHints {
		at++
	}
	return slices.Insert(out, at, slotALPSHints)
}

// scriptOrder starts with the renderer's actual case-folding header-map order.
// Headers the network stack adds follow it; a redirect can give Origin late.
func scriptOrder(h hop) []string {
	out := h.runtimeBehavior().Strings("headers.script_leading")
	if h.script.Has("range") && h.script.Has("if-range") && !h.script.Has("cache-control") {
		out = append(out, "cache-control")
	}
	if !h.script.Has("authorization") {
		out = append(out, "authorization")
	}
	renderer := h
	if h.script.Has("range") && !h.script.Has("if-range") {
		renderer.script = h.script.without("range")
	}
	out = append(out, scriptHeaderOrder(renderer)...)
	if !h.script.Has("accept") {
		out = append(out, "accept")
	}
	if !h.lateOrigin {
		out = append(out, "origin")
	}
	out = append(out, h.runtimeBehavior().Strings("headers.script_metadata")...)
	if h.lateOrigin {
		out = append(out, "origin")
	}
	// A script-owned field already has its renderer slot. The network stack
	// must not append the same name again in its default slot.
	for _, name := range h.runtimeBehavior().Strings("headers.script_trailing") {
		if name == "range" && !h.script.Has(name) {
			continue
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// header is the request's headers to target, in Chrome's order: the
// profile's values where the browser's are the same for every request, and
// the rest worked out for this one. The transport adds Content-Length and the
// cookies, in their slots; Host and Connection are HTTP/1.1's own.
func (r *browserRequest) header(h hop, base Header) Header {
	values := r.values(h, base)
	scriptNames := map[string]string{}
	for _, f := range h.script {
		name := strings.ToLower(f.Name)
		values[name] = f.Value
		scriptNames[name] = f.Name
	}
	var out Header
	for _, slot := range r.order(h) {
		for _, name := range slotNames(slot, h) {
			if value, ok := values[name]; ok {
				wireName := name
				if original, ok := scriptNames[name]; ok {
					wireName = original
				}
				out = append(out, profile.Field{Name: wireName, Value: value})
			}
		}
	}
	return out
}

// slotNames are the header names a slot of a hop stands for: those of its
// client hints in Chrome's order, those a connection's ALPS asked for aside,
// which have a slot of their own; or itself.
func slotNames(slot string, h hop) []string {
	switch slot {
	case slotHints:
		if len(h.alps) > 0 {
			return slices.DeleteFunc(h.runtimeBehavior().Strings("headers.client_hint_order"), h.alps.Has)
		}
		return h.runtimeBehavior().Strings("headers.client_hint_order")
	case slotALPSHints:
		return h.alps.Names()
	}
	return []string{slot}
}

// values are the request's header values by name, where it has one.
func (r *browserRequest) values(h hop, base Header) map[string]string {
	to := h.to
	values := map[string]string{}
	for _, name := range r.runtimeBehavior().Strings("headers.browser_base_fields") {
		if base.Has(name) {
			values[name] = base.Get(name)
		}
	}
	script := r.scripted()
	if script {
		values["accept"] = r.runtimeBehavior().Text("headers.accept_fetch")
		values["priority"] = r.runtimeBehavior().Text("headers.priority_fetch")
		values["sec-fetch-mode"] = r.mode
		values["sec-fetch-dest"] = destEmpty
	} else {
		for _, name := range []string{"accept", "upgrade-insecure-requests", "priority"} {
			if base.Has(name) {
				values[name] = base.Get(name)
			}
		}
		values["sec-fetch-mode"] = modeNavigate
		values["sec-fetch-dest"] = destDocument
	}
	if r.posted {
		values["cache-control"] = r.runtimeBehavior().Text("headers.form_cache_control")
		if h.method == fhttp.MethodPost {
			values["content-type"] = r.contentType
		}
	}
	if script && h.script.Has("range") {
		values["accept-encoding"] = r.runtimeBehavior().Text("headers.range_accept_encoding")
		if h.script.Has("if-range") {
			values["cache-control"] = r.runtimeBehavior().Text("headers.range_cache_control")
		}
	}
	values["sec-fetch-site"] = h.site
	if r.initiator == nil {
		values["sec-fetch-user"] = r.runtimeBehavior().Text("headers.navigation_fetch_user")
	}
	if h.referrer != "" {
		values["referer"] = h.referrer
	}
	if h.origin != "" {
		values["origin"] = h.origin
	}
	if script && r.credentials == credentialsAll && relation(r.from, to) == "cross-site" {
		// A script's credentialed request to another site than its page's
		// says so; one a redirect took through another site back to the
		// page's does not, though Sec-Fetch-Site says cross-site.
		values["sec-fetch-storage-access"] = r.runtimeBehavior().Text("headers.storage_access")
	}
	for _, hint := range slices.Concat(h.hints, h.alps) {
		values[hint.Name] = hint.Value
	}
	if h.authorization != "" {
		values["authorization"] = h.authorization
	}
	if !trustworthy(to) {
		// A page that is not potentially trustworthy is told neither the
		// client's hints nor where its requests come from, and is offered
		// neither Brotli nor zstd.
		for name := range values {
			if hasPrefixIn(name, r.runtimeBehavior().Strings("headers.untrusted_prefixes")) {
				delete(values, name)
			}
		}
		if offered, ok := values["accept-encoding"]; ok {
			values["accept-encoding"] = withoutCodings(offered, r.runtimeBehavior().Strings("headers.untrusted_drop_codings")...)
		}
	}
	for _, f := range h.script {
		// What a script set in place of what the browser would have.
		delete(values, strings.ToLower(f.Name))
	}
	return values
}

// originHeader is the Origin a request carries, as the Fetch standard
// appends one: the initiator's origin for a request that CORS answers, and,
// for one that is neither GET nor HEAD, that origin or "null" as the
// referrer policy says. Empty is none.
//
// Across origins a redirect taints it: Chrome then sends "null", lest a page
// that posted to another site be posted back to as from itself.
func (r *browserRequest) originHeader(h hop) string {
	serialized := r.from.String()
	if h.tainted {
		serialized = "null"
	}
	if h.cors {
		return serialized
	}
	to := h.to
	cors := r.scripted() && r.mode == modeCORS
	if h.method == fhttp.MethodGet || h.method == fhttp.MethodHead {
		return ""
	}
	if !cors {
		switch r.policy {
		case policyNoReferrer:
			return "null"
		case policyNoReferrerWhenDowngrade, policyStrictOrigin, policyStrictOriginWhenCrossOrigin:
			if r.from.scheme == "https" && to.scheme != "https" {
				return "null"
			}
		case policySameOrigin:
			if r.from != to {
				return "null"
			}
		}
	}
	return serialized
}

// withoutCodings is an Accept-Encoding value without some of its codings.
func withoutCodings(value string, codings ...string) string {
	var kept []string
	for _, coding := range strings.Split(value, ",") {
		coding = strings.TrimSpace(coding)
		name, _, _ := strings.Cut(coding, ";")
		if coding != "" && !slices.Contains(codings, strings.TrimSpace(name)) {
			kept = append(kept, coding)
		}
	}
	return strings.Join(kept, ", ")
}

// wireOrder is the order the transport writes the request's headers in, as
// lower-case names: every slot of its kind, so that Content-Length and the
// cookies the transport adds itself go where Chrome puts them, and the
// script's headers in theirs.
func (r *browserRequest) wireOrder(h hop) []string {
	var out []string
	for _, slot := range r.order(h) {
		out = append(out, slotNames(slot, h)...)
	}
	return out
}

// cookies are which of its cookies a request carries on a hop. SameSite goes
// by the page and the hop's URL alone, as Chrome's does: a redirect through
// another site does not make a request cross-site, as measured. A request
// kept to its own origin carries none from the first hop that leaves the
// page's origin on, back at it too: what it got is no longer the page's own
// (cors, or opaque in no-cors mode), as Chrome sends it. Its Sec-Fetch-Site
// says the same: same-origin while every URL of the chain was the page's.
func (r *browserRequest) cookies(h hop) sendRule {
	rule := sendRule{
		topLevel: r.kind == KindNavigation || r.kind == KindForm,
		safe:     h.method == fhttp.MethodGet || h.method == fhttp.MethodHead,
	}
	if r.initiator != nil {
		rule.crossSite = relation(r.from, h.to) == "cross-site"
	}
	switch {
	case r.credentials == credentialsNone:
		rule.none = true
	case r.credentials == credentialsSame && h.site != "same-origin":
		rule.none = true
	}
	return rule
}

func (r *browserRequest) runtimeBehavior() behavior.Policy {
	if r.behavior != nil {
		return r.behavior
	}
	return legacyPolicy()
}
func (h hop) runtimeBehavior() behavior.Policy {
	if h.behavior != nil {
		return h.behavior
	}
	return legacyPolicy()
}

func slotList(in []string) []string {
	for i, n := range in {
		switch n {
		case "@hints":
			in[i] = slotHints
		case "@alps-hints":
			in[i] = slotALPSHints
		}
	}
	return in
}
