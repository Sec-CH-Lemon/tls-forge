package profile

import (
	"fmt"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"golang.org/x/net/http/httpguts"
)

// perRequest names the headers a profile must NOT carry.
//
// They describe one navigation rather than one browser, and replaying them is
// how a perfectly-fingerprinted client gives itself away at the next layer up:
//
//	cookie          belongs to the jar; a captured one pins a dead session
//	host/:authority derived from the URL being fetched
//	content-*       describe a body this request may not have
//	referer/origin  describe where the captured click came from, not this one
//	cache-control   present only because the capture navigation was a reload;
//	pragma          an ordinary visit sends neither
//
// The sec-fetch-* family is deliberately NOT here. Those describe the KIND of
// request — a document navigation — which is exactly what a profile is for; a
// caller fetching a subresource overrides them.
var perRequest = map[string]bool{
	"cookie":         true,
	"host":           true,
	"content-length": true,
	"content-type":   true,
	"referer":        true,
	"origin":         true,
	"cache-control":  true,
	"pragma":         true,
}

// FromCapture turns a browser measurement into a reusable profile.
//
// Exactly one explicit, executable policy basis is required. Only observed
// fields replace it; unmeasured generation, protocol and lifecycle policies
// remain inherited data. Names, User-Agent and brands never select policy here.
// The variadic signature keeps old callers source-compatible, but omission is
// an error rather than an implicit legacy/browser preset.
func FromCapture(name string, c *capture.Capture, basis ...*Profile) (*Profile, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("profile: name is required")
	}
	if c == nil {
		return nil, fmt.Errorf("profile: nil capture")
	}
	if len(c.RawClientHello) == 0 {
		return nil, fmt.Errorf("profile: capture has no ClientHello")
	}
	// Parsing here rather than trusting the capture: a profile built from bytes
	// that do not parse would fail later, on the first request, somewhere far
	// from the mistake.
	hello, err := c.Hello()
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	// What the capture says of the hello, when it says anything, is checked
	// against the hello: one that says otherwise is not one capture, whichever
	// of the two is wrong. A capture that rendered its hello gave its JA4.
	_, resumed := hello.Extension(fingerprint.ExtPreSharedKey)
	if c.TLS.JA4 != "" && (c.TLS.JA4 != hello.JA4() || c.TLS.Resumed != resumed) {
		return nil, fmt.Errorf("profile: the capture says JA4 %s, session_resumed %v, and its ClientHello "+
			"%s, %v: it is not one capture", c.TLS.JA4, c.TLS.Resumed, hello.JA4(), resumed)
	}
	// Read from the bytes, the capture's word aside: a pre_shared_key, whether
	// it parses or not, is a resumed connection's.
	if resumed {
		return nil, fmt.Errorf("profile: capture is from a RESUMED connection; " +
			"its pre_shared_key makes it a different fingerprint from the same browser's " +
			"first contact. Capture again against a server that does not issue tickets")
	}
	// A browser names no server to an address (RFC 6066), and a profile is the
	// hello as it came: one taken at an address would name none to any site,
	// which no browser does.
	if _, named := hello.Extension(fingerprint.ExtServerName); !named {
		return nil, fmt.Errorf("profile: the capture's ClientHello names no server (no server_name), as a " +
			"browser's does at an address: a profile of it would name none to any site. Capture at a name")
	}

	if c.HTTP2 == nil {
		return nil, fmt.Errorf("profile: capture has no HTTP/2 data; a reusable browser profile needs pseudo headers")
	}
	if len(basis) != 1 || basis[0] == nil {
		return nil, fmt.Errorf("profile: capture requires one explicit policy basis (FromCapture(name, capture, basis))")
	}
	if err := basis[0].Validate(); err != nil {
		return nil, fmt.Errorf("profile: invalid capture policy basis: %w", err)
	}
	if basis[0].Schema != Schema || basis[0].PerConnection == nil {
		return nil, fmt.Errorf("profile: capture policy basis requires schema %d and explicit per_connection generation rules", Schema)
	}
	if basis[0].BareBase() {
		return nil, fmt.Errorf("profile: capture policy basis must be a full explicit profile, not a catalogue preset")
	}
	p := basis[0].Clone()
	p.Schema, p.Name, p.Base, p.source = Schema, name, "", ""
	p.ClientHello = append([]byte(nil), c.RawClientHello...)
	if agent := c.UserAgent(); agent != "" {
		p.UserAgent = agent
	}

	if len(c.HTTP2.PseudoHeaderOrder) > 0 {
		p.HTTP2.ConnectionFlow = c.HTTP2.WindowUpdate
		p.HTTP2.PseudoHeaderOrder = append([]string(nil), pseudoNames(c.HTTP2)...)
		p.HTTP2.Settings = make([]Setting, 0, len(c.HTTP2.Settings))
		p.HTTP2.Priorities = nil
		p.HTTP2.HeaderPriority = nil
		for _, s := range c.HTTP2.Settings {
			p.HTTP2.Settings = append(p.HTTP2.Settings, Setting{ID: s.ID, Value: s.Value})
		}
		for _, pr := range c.HTTP2.Priorities {
			p.HTTP2.Priorities = append(p.HTTP2.Priorities, Priority{
				StreamID: pr.StreamID, Exclusive: pr.Exclusive, DependsOn: pr.DependsOn, Weight: pr.Weight,
			})
		}
		if pr := c.HTTP2.HeaderPriority; pr != nil {
			p.HTTP2.HeaderPriority = &Priority{
				StreamID: pr.StreamID, Exclusive: pr.Exclusive, DependsOn: pr.DependsOn, Weight: pr.Weight,
			}
		}
	}
	if len(c.HTTP2.Headers) > 0 {
		p.Headers = nil
	}
	for _, h := range c.HTTP2.Headers {
		name := strings.ToLower(h.Name)
		if strings.HasPrefix(name, ":") || perRequest[name] {
			continue
		}
		p.Headers = append(p.Headers, Field{Name: name, Value: h.Value})
	}
	if c.HTTP1 != nil {
		p.HTTP1 = http1FromCapture(c.HTTP1, p.Headers)
	}

	// Merge only observed UA/persona hints. Context/device/network values stay
	// with the explicit basis until their generation is separately measured.
	observed := capturedPersonaHints(c)
	for _, field := range observed {
		found := false
		for i := range p.ClientHints {
			if p.ClientHints[i].Name == field.Name {
				p.ClientHints[i] = field
				found = true
				break
			}
		}
		if !found {
			p.ClientHints = append(p.ClientHints, field)
		}
	}
	// Finite observations do not establish a complete draw distribution. Keep
	// the basis's generation rules; refuse measured variation they cannot model.
	drawn, err := DrawnOf(c)
	if err != nil {
		return nil, err
	}
	if drawn != nil {
		if drawn.Order && (p.PerConnection == nil || !p.PerConnection.ShufflesExtensions) {
			return nil, fmt.Errorf("profile: capture extension-order variation requires an explicit basis generation rule")
		}
		if len(drawn.ECH) > 1 && (p.PerConnection == nil || len(p.PerConnection.ECHPayloadLengths) < 2) {
			return nil, fmt.Errorf("profile: capture ECH-length variation requires an explicit basis generation rule")
		}
		if p.PerConnection != nil && len(p.PerConnection.ECHPayloadLengths) > 0 {
			for _, length := range drawn.ECH {
				matched := false
				for _, allowed := range p.PerConnection.ECHPayloadLengths {
					if length == int(allowed)+echTag {
						matched = true
						break
					}
				}
				if !matched {
					return nil, fmt.Errorf("profile: capture ECH length %d is outside the explicit basis generation rule", length)
				}
			}
		}
	}
	return p, nil
}

// clientHintsSent are the client hints a browser sent its page when the page
// asked for every one, as it sent them, in Chrome's order, those it sends
// unasked aside (its headers say them) and any no header could carry again:
// what it sends a server that asks, measured, which a capture that kept them
// has the profile say over what it gave JavaScript. None of a browser that
// sent the unasked alone.
func clientHintsSent(sent []capture.HeaderField) []Field {
	var out []Field
	for _, name := range AskedClientHints() {
		for _, h := range sent {
			if strings.EqualFold(h.Name, name) && h.Value != "" && httpguts.ValidHeaderFieldValue(h.Value) {
				out = append(out, Field{Name: name, Value: h.Value})
				break
			}
		}
	}
	return out
}

// clientHintsOf are the client hints of the user agent its browser sends when
// a server asks for them, as it gave them to JavaScript: the high-entropy
// values of navigator.userAgentData, written as Structured Fields, as Chrome
// writes them. None for a browser that gave none: the full version list is
// what getHighEntropyValues gives every Chromium, and nothing else.
func clientHintsOf(n *capture.Navigator) []Field {
	if n == nil || len(n.FullVersionList) == 0 {
		return nil
	}
	brands := make([]string, len(n.FullVersionList))
	for i, b := range n.FullVersionList {
		brands[i] = sfString(b.Brand) + ";v=" + sfString(b.Version)
	}
	wow64 := "?0"
	if n.WOW64 {
		wow64 = "?1"
	}
	hints := []Field{
		{Name: "sec-ch-ua-full-version", Value: sfString(n.UAFullVersion)},
		{Name: "sec-ch-ua-arch", Value: sfString(n.Architecture)},
		{Name: "sec-ch-ua-platform-version", Value: sfString(n.PlatformVersion)},
		{Name: "sec-ch-ua-model", Value: sfString(n.Model)},
		{Name: "sec-ch-ua-bitness", Value: sfString(n.Bitness)},
		{Name: "sec-ch-ua-wow64", Value: wow64},
		{Name: "sec-ch-ua-full-version-list", Value: strings.Join(brands, ", ")},
	}
	if len(n.FormFactors) > 0 {
		factors := make([]string, len(n.FormFactors))
		for i, factor := range n.FormFactors {
			factors[i] = sfString(factor)
		}
		hints = append(hints, Field{Name: "sec-ch-ua-form-factors", Value: strings.Join(factors, ", ")})
	}
	return hints
}

// sfString is a Structured Field string (RFC 8941): in double quotes, with a
// backslash before a double quote or a backslash.
func sfString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func http1FromCapture(measured *capture.HTTP1, shared []Field) *HTTP1 {
	if measured == nil || len(measured.Headers) == 0 {
		return nil
	}
	sharedValues := fieldValues(shared)
	type group struct {
		fields []Field
	}
	groups := make(map[string]*group)
	var order []string
	for i, header := range measured.Headers {
		name := strings.ToLower(header.Name)
		if perRequest[name] && name != "host" {
			continue
		}
		wireName := header.Name
		if i < len(measured.HeaderNames) && measured.HeaderNames[i] != "" {
			wireName = measured.HeaderNames[i]
		}
		g := groups[name]
		if g == nil {
			g = &group{}
			groups[name] = g
			order = append(order, wireName)
		}
		if name != "host" {
			g.fields = append(g.fields, Field{Name: wireName, Value: header.Value})
		}
	}
	if len(order) == 0 {
		return nil
	}

	http1 := &HTTP1{HeaderOrder: order}
	for _, wireName := range order {
		name := strings.ToLower(wireName)
		g := groups[name]
		if sameFieldValues(g.fields, sharedValues[name]) {
			continue
		}
		http1.Headers = append(http1.Headers, g.fields...)
	}
	return http1
}

func fieldValues(fields []Field) map[string][]string {
	out := make(map[string][]string)
	for _, field := range fields {
		name := strings.ToLower(field.Name)
		out[name] = append(out[name], field.Value)
	}
	return out
}

func sameFieldValues(fields []Field, values []string) bool {
	if len(fields) != len(values) {
		return false
	}
	for i, field := range fields {
		if field.Value != values[i] {
			return false
		}
	}
	return true
}

// pseudoNames recovers the full pseudo-header names from the capture's
// single-letter rendering.
func pseudoNames(h *capture.HTTP2) []string {
	names := map[string]string{"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}
	out := make([]string, 0, len(h.PseudoHeaderOrder))
	for _, letter := range h.PseudoHeaderOrder {
		if full, ok := names[letter]; ok {
			out = append(out, full)
		}
	}
	return out
}

// capturedPersonaHints keeps only values actually supplied by the capture.
// Wire UA hints override navigator values; network/device context is not frozen.
func capturedPersonaHints(c *capture.Capture) []Field {
	var out []Field
	if n := c.Navigator; n != nil {
		known := map[string]bool{"sec-ch-ua-full-version": n.UAFullVersion != "", "sec-ch-ua-arch": n.Architecture != "", "sec-ch-ua-platform-version": n.PlatformVersion != "", "sec-ch-ua-model": n.Model != "", "sec-ch-ua-bitness": n.Bitness != "", "sec-ch-ua-wow64": n.WOW64, "sec-ch-ua-full-version-list": len(n.FullVersionList) > 0, "sec-ch-ua-form-factors": len(n.FormFactors) > 0}
		for _, f := range clientHintsOf(n) {
			if known[f.Name] {
				out = append(out, f)
			}
		}
	}
	for _, f := range clientHintsSent(c.ClientHints) {
		if strings.HasPrefix(f.Name, "sec-ch-ua-") {
			out = append(out, f)
		}
	}
	return out
}
