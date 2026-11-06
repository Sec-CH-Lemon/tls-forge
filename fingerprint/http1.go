package fingerprint

import "strings"

// HTTP1 is the request line, without its target, and the ordered header block
// as they appeared on the wire.
type HTTP1 struct {
	Method  string
	Proto   string
	Headers []HeaderField
	// Layout is how the request was written where a server reads it alike
	// (capture.HTTP1.Layout); nil when it was not recorded.
	Layout []string
}

// HTTP1Fields is everything in an HTTP/1.1 request fingerprint.
//
// Host's position and spelling are fingerprinted, but its value belongs to the
// destination and differs between two measurements by construction, as does
// the target of the request line.
func HTTP1Fields(h *HTTP1) []Field {
	return []Field{
		scalar("http1_request", strings.TrimSpace(h.Method+" "+h.Proto)),
		{Name: "http1_header_order", Values: http1HeaderOrder(h.Headers)},
		{Name: "http1_header_values", Values: http1HeaderStrings(h.Headers)},
		http1Layout(h.Layout),
	}
}

// http1Layout is the layout field: not checked when it was not recorded.
func http1Layout(layout []string) Field {
	if layout == nil {
		return Field{Name: "http1_layout", Values: []string{"(not recorded)"}, Missing: true}
	}
	return Field{Name: "http1_layout", Values: layout}
}

func http1HeaderOrder(headers []HeaderField) []string {
	out := make([]string, len(headers))
	for i, header := range headers {
		out[i] = header.Name
	}
	return out
}

func http1HeaderStrings(headers []HeaderField) []string {
	out := make([]string, 0, len(headers))
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "host") {
			out = append(out, header.Name+": "+header.Value)
		}
	}
	return out
}
