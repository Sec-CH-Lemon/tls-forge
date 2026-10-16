package tlsforge

import (
	"fmt"
	"net/textproto"
	"net/url"
	"slices"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
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
	modeCORS         = "cors"
	modeNoCORS       = "no-cors"
	modeSameOrigin   = "same-origin"
	credentialsSame  = "same-origin"
	credentialsAll   = "include"
	credentialsNone  = "omit"
	modeNavigate     = "navigate"
	destDocument     = "document"
	destEmpty        = "empty"
	priorityDocument = "u=0, i"
	priorityFetch    = "u=1, i"
	acceptAnything   = "*/*"
	formEncoded      = "application/x-www-form-urlencoded"
	formMultipart    = "multipart/form-data"
	formText         = "text/plain"
)

// browserRequest is a request in a browser context, as resolved against the
// URL it goes to: what its headers are computed from.
type browserRequest struct {
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
func (b *BrowserContext) resolve(method string, target *url.URL, header Header, body []byte) (*browserRequest, error) {
	r := &browserRequest{kind: b.Kind, method: normalizedMethod(method), policy: b.ReferrerPolicy}
	if r.policy == "" {
		r.policy = policyStrictOriginWhenCrossOrigin
	}
	if !slices.Contains(referrerPolicies, r.policy) {
		return nil, errContext("referrer policy %q is not one of %s", b.ReferrerPolicy, strings.Join(referrerPolicies, ", "))
	}
	if b.Initiator != "" {
		initiator, err := url.Parse(b.Initiator)
		if err != nil || (initiator.Scheme != "http" && initiator.Scheme != "https") || initiator.Host == "" {
			return nil, errContext("initiator %q is not an http or https URL", b.Initiator)
		}
		r.initiator, r.from = initiator, originOf(initiator)
	}
	if err := b.resolveKind(r, target, header, body); err != nil {
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
		return errContext("%s sends the headers the browser gives it, not %s", what, header[0].Name)
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
	what := "fetch()"
	if b.Kind == KindXHR {
		what = "an XHR"
	}
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
			return errContext("%s cannot set %s: the browser sets it", what, f.Name)
		}
	}
	r.script = header
	to := originOf(target)
	switch {
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

// slotScript is where in a request of fetch() or an XHR the headers its
// script gave go.
const slotScript = "\x00script"

// The headers of each kind of request, in the order Chrome 155 sends them, as
// measured (testdata/chrome155-requests.json). A request has a header of a
// slot only when it has a value for it.
var (
	navigationOrder = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
		"user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer",
		"accept-encoding", "accept-language", "cookie", "priority"}
	formOrder = []string{"content-length", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "content-type", "user-agent", "origin", "accept", "sec-fetch-site",
		"sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"}
	scriptOrder = []string{"content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", slotScript,
		"sec-ch-ua-mobile", "accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
		"sec-fetch-storage-access", "referer", "accept-encoding", "accept-language", "cookie", "priority"}
)

// order is the request's slots, in Chrome's order.
func (r *browserRequest) order() []string {
	switch {
	case r.kind == KindFetch || r.kind == KindXHR:
		return scriptOrder
	case r.kind == KindForm && r.method == fhttp.MethodPost:
		return formOrder
	}
	return navigationOrder
}

// header is the request's headers to target, in Chrome's order: the
// profile's values where the browser's are the same for every request, and
// the rest worked out for this one. The transport adds Content-Length and the
// cookies, in their slots; Host and Connection are HTTP/1.1's own.
func (r *browserRequest) header(target *url.URL, base Header) Header {
	to := originOf(target)
	values := r.values(to, base)
	var out Header
	for _, name := range r.order() {
		if name == slotScript {
			out = append(out, r.script...)
			continue
		}
		if value, ok := values[name]; ok {
			out = append(out, profile.Field{Name: name, Value: value})
		}
	}
	return out
}

// values are the request's header values by name, where it has one.
func (r *browserRequest) values(to origin, base Header) map[string]string {
	values := map[string]string{}
	for _, name := range []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent",
		"accept-language", "accept-encoding"} {
		if base.Has(name) {
			values[name] = base.Get(name)
		}
	}
	script := r.kind == KindFetch || r.kind == KindXHR
	if script {
		values["accept"] = acceptAnything
		values["priority"] = priorityFetch
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
	if r.kind == KindForm && r.method == fhttp.MethodPost {
		values["cache-control"] = "max-age=0"
		values["content-type"] = r.contentType
	}
	if r.initiator == nil {
		values["sec-fetch-site"], values["sec-fetch-user"] = "none", "?1"
	} else {
		values["sec-fetch-site"] = relation(r.from, to)
		if referrer := referrerFor(r.initiator, to, r.policy); referrer != "" {
			values["referer"] = referrer
		}
		if serialized := r.originHeader(to); serialized != "" {
			values["origin"] = serialized
		}
	}
	if script && r.credentials == credentialsAll && values["sec-fetch-site"] == "cross-site" {
		values["sec-fetch-storage-access"] = "active"
	}
	if !trustworthy(to) {
		// A page that is not potentially trustworthy is told neither the
		// client's hints nor where its requests come from, and is offered
		// neither Brotli nor zstd.
		for name := range values {
			if strings.HasPrefix(name, "sec-ch-") || strings.HasPrefix(name, "sec-fetch-") {
				delete(values, name)
			}
		}
		if offered, ok := values["accept-encoding"]; ok {
			values["accept-encoding"] = withoutCodings(offered, "br", "zstd")
		}
	}
	for _, f := range r.script {
		// What a script set in place of what the browser would have.
		delete(values, strings.ToLower(f.Name))
	}
	return values
}

// originHeader is the Origin a request carries, as the Fetch standard
// appends one: the initiator's origin for a request that CORS answers, and,
// for one that is neither GET nor HEAD, that origin or "null" as the
// referrer policy says. Empty is none.
func (r *browserRequest) originHeader(to origin) string {
	if r.cors {
		return r.from.String()
	}
	cors := (r.kind == KindFetch || r.kind == KindXHR) && r.mode == modeCORS
	if r.method == fhttp.MethodGet || r.method == fhttp.MethodHead {
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
	return r.from.String()
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
func (r *browserRequest) wireOrder() []string {
	var out []string
	for _, name := range r.order() {
		if name != slotScript {
			out = append(out, name)
			continue
		}
		for _, f := range r.script {
			out = append(out, strings.ToLower(f.Name))
		}
	}
	return out
}

// cookies are which of its cookies the request carries to a URL of origin to.
func (r *browserRequest) cookies(to origin) sendRule {
	rule := sendRule{
		topLevel: r.kind == KindNavigation || r.kind == KindForm,
		safe:     r.method == fhttp.MethodGet || r.method == fhttp.MethodHead,
	}
	if r.initiator != nil {
		rule.crossSite = relation(r.from, to) == "cross-site"
	}
	switch {
	case r.credentials == credentialsNone:
		rule.none = true
	case r.credentials == credentialsSame && r.from != to:
		rule.none = true
	}
	return rule
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
		case strings.HasPrefix(lower, "sec-ch-"):
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
