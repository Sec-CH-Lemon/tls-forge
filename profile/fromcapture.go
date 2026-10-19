package profile

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
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
// This is the function that makes the library's claim checkable rather than
// asserted: nothing in the resulting profile was written by hand, so nothing in
// it can be a plausible guess about what a browser sends.
func FromCapture(name string, c *capture.Capture) (*Profile, error) {
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

	p := &Profile{
		Schema:      Schema,
		Name:        name,
		UserAgent:   c.UserAgent(),
		ClientHello: append([]byte(nil), c.RawClientHello...),
	}
	if c.HTTP2 == nil {
		return nil, fmt.Errorf("profile: capture has no HTTP/2 data; a reusable browser profile needs pseudo headers")
	}

	if c.HTTP2 != nil {
		p.HTTP2 = HTTP2{
			ConnectionFlow:    c.HTTP2.WindowUpdate,
			PseudoHeaderOrder: append([]string(nil), pseudoNames(c.HTTP2)...),
			Settings:          make([]Setting, 0, len(c.HTTP2.Settings)),
		}
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
		for _, h := range c.HTTP2.Headers {
			name := strings.ToLower(h.Name)
			if strings.HasPrefix(name, ":") || perRequest[name] {
				continue
			}
			p.Headers = append(p.Headers, Field{Name: name, Value: h.Value})
		}
	}
	if c.HTTP1 != nil {
		p.HTTP1 = http1FromCapture(c.HTTP1, p.Headers)
	}

	if c.Navigator != nil && c.Navigator.UserAgent != "" {
		p.UserAgent = c.Navigator.UserAgent
	}
	p.ClientHints = clientHintsOf(c.Navigator)
	p.PerConnection = perConnectionOf(p)
	if c.Navigator != nil && len(c.Navigator.Brands) > 0 {
		p.PerConnection = &PerConnection{}
		if slices.ContainsFunc(c.Navigator.Brands, func(b capture.Brand) bool { return b.Brand == "Chromium" }) {
			p.PerConnection = chromiumPerConnection()
		}
	}
	return p, nil
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

// perConnectionOf is what a profile's browser draws for every connection, as
// far as its name and user agent tell: Chromium's draws on every platform but
// iOS, and nothing else's is known. A capture whose browser names its brands
// says it better: only a Chromium browser counts Chromium among them, and
// none on iOS has them to give.
func perConnectionOf(p *Profile) *PerConnection {
	if p.chromium() {
		return chromiumPerConnection()
	}
	return &PerConnection{}
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
