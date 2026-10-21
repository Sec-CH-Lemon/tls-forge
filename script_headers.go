package tlsforge

import (
	"slices"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/internal/chromehash"
)

// scriptHeaders is a browser API's header list: repeated names share the first
// name's spelling, values are trimmed and combined in the caller's order.
// A low-level Request without Browser keeps its original Header semantics.
func scriptHeaders(given Header) Header {
	var out Header
	for _, f := range given {
		value := strings.Trim(f.Value, " \t\r\n")
		at := -1
		for i, old := range out {
			if strings.EqualFold(old.Name, f.Name) {
				at = i
				break
			}
		}
		if at < 0 {
			f.Value = value
			out = append(out, f)
		} else {
			out[at].Value += ", " + value
		}
	}
	return out
}

// scriptHeaderOrder models the renderer map rather than assigning a slot to
// one known custom name. A half-full table doubles; quadratic probes resolve
// collisions, and rehashing visits old buckets in their iteration order.
func scriptHeaderOrder(h hop) []string {
	names := h.script.Names()
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	slices.Sort(names) // Fetch's case-insensitive header list is name-ordered.
	if h.to.scheme == "" || trustworthy(h.to) {
		for _, name := range rendererHintInsertionOrder {
			if h.hints.Has(name) || slices.Contains(defaultRendererHints, name) {
				names = append(names, name)
			}
		}
	}
	names = append(names, "user-agent")
	table := make([]string, 8)
	count := 0
	insert := func(table []string, name string) bool {
		index := int(chromehash.Hash(name)) & (len(table) - 1)
		for probe := 1; table[index] != ""; probe++ {
			if strings.EqualFold(table[index], name) {
				return false
			}
			index = (index + probe) & (len(table) - 1)
		}
		table[index] = name
		return true
	}
	for _, name := range names {
		if insert(table, name) {
			count++
			if count*2 >= len(table) {
				old := table
				table = make([]string, len(old)*2)
				for _, name := range old {
					if name != "" {
						insert(table, name)
					}
				}
			}
		}
	}
	out := make([]string, 0, count)
	for _, name := range table {
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// Construction order, not the profile's observed bucket iteration order.
// Blink FrameFetchContext::AddClientHintsIfNecessary inserts these fields
// before the network service supplies Accept and Sec-Fetch-*.
var rendererHintInsertionOrder = []string{
	"device-memory", "sec-ch-device-memory", "rtt", "downlink", "ect",
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform",
	"sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-full-version",
	"sec-ch-ua-full-version-list", "sec-ch-ua-bitness", "sec-ch-ua-wow64",
	"sec-ch-ua-form-factors", "save-data", "sec-ch-prefers-reduced-transparency",
	"sec-ch-prefers-reduced-motion", "sec-ch-prefers-color-scheme", "dpr",
	"sec-ch-dpr", "viewport-width", "sec-ch-viewport-width", "viewport-height",
	"sec-ch-viewport-height", "width", "sec-ch-width",
}

var defaultRendererHints = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}
