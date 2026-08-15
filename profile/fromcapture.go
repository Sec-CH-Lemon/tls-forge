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
		ClientHello: c.RawClientHello,
	}

	if c.TLS.Resumed {
		return nil, fmt.Errorf("profile: capture is from a RESUMED connection; " +
			"its pre_shared_key makes it a different fingerprint from the same browser's " +
			"first contact. Capture again against a server that does not issue tickets")
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

	if c.Navigator != nil && c.Navigator.UserAgent != "" {
		p.UserAgent = c.Navigator.UserAgent
	}
	return p, nil
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
