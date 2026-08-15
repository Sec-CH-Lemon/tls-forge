package fingerprint

import (
	"fmt"
	"strings"
)

// Setting is one entry of an HTTP/2 SETTINGS frame, kept in the order it was
// sent. Two clients can send the same settings in a different order, and the
// order is fingerprinted, so a map would throw away the signal.
type Setting struct {
	ID    uint16
	Value uint32
}

// Priority is a standalone PRIORITY frame. Chrome stopped sending these when it
// moved to the `priority` header, so their PRESENCE is a signal in itself.
type Priority struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}

// HeaderField is one HPACK-decoded header, in wire order, pseudo-headers
// included.
type HeaderField struct {
	Name  string
	Value string
}

// HTTP2 is everything a server sees a client do on a fresh HTTP/2 connection
// before the first response is written.
type HTTP2 struct {
	Settings     []Setting
	WindowUpdate uint32
	Priorities   []Priority
	Headers      []HeaderField

	// HeaderPriority is the priority carried ON the HEADERS frame, which is a
	// different thing from a standalone PRIORITY frame and is set by a different
	// knob in every library that lets you set it at all. Chrome sends one
	// (exclusive, depends on stream 0, weight 255 on the wire); most HTTP
	// clients send none.
	HeaderPriority *Priority
}

// Akamai returns the Akamai HTTP/2 fingerprint, e.g.
//
//	1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
//
// The four fields are the SETTINGS in order, the connection-level WINDOW_UPDATE
// increment, the PRIORITY frames, and the order of the pseudo-headers. It
// complements the TLS fingerprint rather than duplicating it: a client can copy
// a ClientHello byte for byte and still give itself away one layer up by
// sending :path before :scheme.
func (h *HTTP2) Akamai() string {
	settings := make([]string, len(h.Settings))
	for i, s := range h.Settings {
		settings[i] = fmt.Sprintf("%d:%d", s.ID, s.Value)
	}

	// "00" rather than "0" for a missing WINDOW_UPDATE is what the original
	// implementation writes, and the value is compared as a string against logs
	// produced by it.
	window := "00"
	if h.WindowUpdate != 0 {
		window = fmt.Sprintf("%d", h.WindowUpdate)
	}

	priorities := "0"
	if len(h.Priorities) > 0 {
		parts := make([]string, len(h.Priorities))
		for i, p := range h.Priorities {
			exclusive := 0
			if p.Exclusive {
				exclusive = 1
			}
			parts[i] = fmt.Sprintf("%d:%d:%d:%d", p.StreamID, exclusive, p.DependsOn, p.Weight)
		}
		priorities = strings.Join(parts, ",")
	}

	return strings.Join([]string{
		strings.Join(settings, ";"),
		window,
		priorities,
		strings.Join(h.PseudoHeaderOrder(), ","),
	}, "|")
}

// PseudoHeaderOrder returns the pseudo-headers as single letters in the order
// sent: m, a, s, p for :method, :authority, :scheme, :path.
func (h *HTTP2) PseudoHeaderOrder() []string {
	var out []string
	for _, f := range h.Headers {
		if !strings.HasPrefix(f.Name, ":") || len(f.Name) < 2 {
			continue
		}
		out = append(out, f.Name[1:2])
	}
	return out
}

// HeaderOrder returns the ordinary header names in the order sent.
//
// This is a fingerprint in its own right and one of the easiest to get wrong,
// because most HTTP libraries store headers in a map and emit them sorted or at
// random. A client whose TLS is perfect and whose headers arrive alphabetically
// has announced itself.
func (h *HTTP2) HeaderOrder() []string {
	var out []string
	for _, f := range h.Headers {
		if strings.HasPrefix(f.Name, ":") {
			continue
		}
		out = append(out, f.Name)
	}
	return out
}

// Header returns the first value sent for a name, matched case-insensitively.
func (h *HTTP2) Header(name string) (string, bool) {
	for _, f := range h.Headers {
		if strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}
