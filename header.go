package tlsforge

import (
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// Header is an ordered list of headers.
//
// A list rather than a map because header order is fingerprinted. Go's
// net/http.Header is a map, and a map has no order — which is why libraries
// built on it emit headers alphabetically or at random, and why a client with a
// perfect TLS handshake can still be spotted from its first request.
type Header []profile.Field

// NewHeader builds a header from alternating name/value pairs. An odd number of
// arguments drops the last one rather than panicking: this is convenience
// syntax, not a place to lose a request over.
func NewHeader(pairs ...string) Header {
	h := make(Header, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		h = append(h, profile.Field{Name: strings.ToLower(pairs[i]), Value: pairs[i+1]})
	}
	return h
}

// Get returns the first value for a name, matched case-insensitively.
func (h Header) Get(name string) string {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return f.Value
		}
	}
	return ""
}

// Has reports whether a name is present, including with an empty value.
func (h Header) Has(name string) bool {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return true
		}
	}
	return false
}

// Set replaces a header IN PLACE, keeping its position, or appends it.
//
// Keeping the position is the point. A Set that deleted and re-appended would
// move the header to the end of the list and change the fingerprint, so
// overriding one value of a browser profile would silently stop looking like
// that browser.
func (h *Header) Set(name, value string) {
	name = strings.ToLower(name)
	for i := range *h {
		if strings.EqualFold((*h)[i].Name, name) {
			(*h)[i].Value = value
			return
		}
	}
	*h = append(*h, profile.Field{Name: name, Value: value})
}

// Del removes a header.
func (h *Header) Del(name string) {
	out := (*h)[:0]
	for _, f := range *h {
		if !strings.EqualFold(f.Name, name) {
			out = append(out, f)
		}
	}
	*h = out
}

// Names lists the header names in order.
func (h Header) Names() []string {
	out := make([]string, len(h))
	for i, f := range h {
		out[i] = f.Name
	}
	return out
}

// Clone returns an independent copy.
func (h Header) Clone() Header {
	return append(Header(nil), h...)
}

// Merge layers overrides onto a base, keeping the base's ordering for names it
// already has and appending the rest.
//
// This is how a per-request header meets a browser profile: a caller setting
// `referer` gets the browser's order with referer in the browser's slot, not a
// browser-shaped list with one header bolted onto the end.
func (h Header) Merge(overrides Header) Header {
	out := h.Clone()
	for _, f := range overrides {
		out.Set(f.Name, f.Value)
	}
	return out
}
