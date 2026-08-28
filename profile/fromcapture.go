package profile

import (
	"fmt"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
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
	if _, err := c.Hello(); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}

	p := &Profile{
		Name:        name,
		UserAgent:   c.UserAgent(),
		ClientHello: append([]byte(nil), c.RawClientHello...),
	}

	if c.TLS.Resumed {
		return nil, fmt.Errorf("profile: capture is from a RESUMED connection; " +
			"its pre_shared_key makes it a different fingerprint from the same browser's " +
			"first contact. Capture again against a server that does not issue tickets")
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
	return p, nil
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
