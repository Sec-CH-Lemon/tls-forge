package echo

import (
	"slices"

	"github.com/Sec-CH-Lemon/tls-forge/v3/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v3/profile"
)

// clientHints are the client hints Chrome sends, in the order it sends them
// (profile.ClientHintOrder, measured on Chrome 155). unaskedHints it sends to
// every server; the rest only to one that asks.
var clientHints = profile.DefaultHintOrder()

// unaskedHints are the client hints Chrome sends unasked.
var unaskedHints = profile.DefaultUnaskedHints()

// askedHints are the client hints the capture page asks for: every one a
// server has to ask for.
func askedHints() []string {
	return slices.DeleteFunc(slices.Clone(clientHints), func(name string) bool {
		return slices.Contains(unaskedHints, name)
	})
}

// clientHintsIn are the client hints among a request's headers, keyed by
// names in lower case, in the order Chrome sends them.
func clientHintsIn(headers map[string]string) []capture.HeaderField {
	var out []capture.HeaderField
	for _, name := range clientHints {
		if value, ok := headers[name]; ok {
			out = append(out, capture.HeaderField{Name: name, Value: value})
		}
	}
	return out
}
