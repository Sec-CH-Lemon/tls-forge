package fingerprint

// IsGREASE reports whether a value is one of the sixteen reserved GREASE
// values, which all have the form 0xNaNa: both bytes equal, low nibble 0xa.
//
// GREASE is the random noise TLS clients sprinkle through their ClientHello to
// keep middleboxes honest (RFC 8701). Chrome picks fresh values on every single
// connection, so anything derived from them differs from the same browser to
// itself — which is why every fingerprint in this package drops them before
// hashing. Forgetting to do that is the classic way to produce a "fingerprint"
// that never matches twice.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0x00ff
}

// withoutGREASE returns the values that carry meaning, in their original order.
//
// The result is always a fresh slice: callers sort it (JA4 does), and sorting a
// slice that aliased the parsed ClientHello would scramble the record of what
// the client actually sent — which the structural diff still needs.
func withoutGREASE(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
