package echo

import (
	"slices"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

// clientHints are the client hints Chrome sends, in the order it sends them
// (profile.ClientHintOrder, measured on Chrome 155). unaskedHints it sends to
// every server; the rest only to one that asks.
var clientHints = []string{
	"device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr", "viewport-width", "sec-ch-viewport-width",
	"sec-ch-viewport-height", "rtt", "downlink", "ect",
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch", "sec-ch-ua-platform",
	"sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-bitness", "sec-ch-ua-wow64",
	"sec-ch-ua-full-version-list", "sec-ch-ua-form-factors",
	"sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency",
}

// unaskedHints are the client hints Chrome sends unasked.
var unaskedHints = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}

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
