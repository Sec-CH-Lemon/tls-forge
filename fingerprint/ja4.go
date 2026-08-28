package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// A JA4 section with nothing in it hashes to this rather than to the SHA-256 of
// the empty string, per the specification.
const emptySection = "000000000000"

// ja4 truncates every hash to twelve hex characters.
const ja4HashLen = 12

// JA4 returns the FoxIO JA4 TLS fingerprint, e.g.
//
//	t13d1516h2_8daaf6152771_806a8c22fdea
//
// Unlike JA3 it sorts the cipher and extension lists before hashing, so it is
// stable for a browser that shuffles its extension order — which is every
// modern Chrome. This is the fingerprint to compare.
//
// One property worth knowing before comparing anything: a client's JA4 changes
// when the connection is RESUMED, because resumption adds pre_shared_key to the
// extension set. Real Chrome 151 sends t13d1516h2_…_806a8c22fdea cold and
// t13d1517h2_…_a87ad97598a9 on a resumed connection. Both are that browser.
// Compare like with like.
func (c *ClientHello) JA4() string {
	a, b, d := c.ja4Parts()
	return a + "_" + b + "_" + d
}

// JA4Raw returns the un-hashed form, `ja4_r`, whose whole point is that a
// mismatch can be read: two JA4s that differ tell you nothing about why, two
// JA4Raws differ at a cipher or an extension you can name.
func (c *ClientHello) JA4Raw() string {
	a, _, _ := c.ja4Parts()
	return strings.Join([]string{a, c.ja4Ciphers(), c.ja4ExtensionInput()}, "_")
}

func (c *ClientHello) ja4Parts() (a, b, d string) {
	ciphers := c.ja4Ciphers()
	exts := c.ja4ExtensionInput()

	b = emptySection
	if ciphers != "" {
		b = truncatedSHA256(ciphers)
	}
	// The extension section hashes the extensions and, when present, the
	// signature algorithms joined by an underscore. FoxIO specifies no trailing
	// underscore when the signature list is absent.
	d = emptySection
	if exts != "" {
		d = truncatedSHA256(exts)
	}
	return c.ja4Prefix(), b, d
}

// ja4Prefix builds the human-readable head: transport, version, SNI, counts and
// ALPN.
func (c *ClientHello) ja4Prefix() string {
	sni := 'i'
	if _, ok := c.ServerName(); ok {
		sni = 'd'
	}
	return fmt.Sprintf("t%s%c%s%s%s",
		ja4Version(c.negotiableVersion()),
		sni,
		countTo99(len(withoutGREASE(c.CipherSuites))),
		countTo99(len(withoutGREASE(c.ExtensionTypes()))),
		ja4ALPN(c.ALPN()),
	)
}

// negotiableVersion is the highest version the client would actually accept:
// supported_versions when present, since a TLS 1.3 client still writes 1.2 in
// the legacy field to get past middleboxes.
func (c *ClientHello) negotiableVersion() uint16 {
	best := uint16(0)
	for _, v := range withoutGREASE(c.SupportedVersions()) {
		if v > best {
			best = v
		}
	}
	if best != 0 {
		return best
	}
	return c.LegacyVersion
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

// ja4ALPN is the first and last character of the first advertised protocol:
// "h2" for HTTP/2, "h1" for "http/1.1" — first char and last char, not a
// substring.
func ja4ALPN(protocols []string) string {
	if len(protocols) == 0 || protocols[0] == "" {
		return "00"
	}
	first := protocols[0]
	head, tail := first[0], first[len(first)-1]
	// A protocol whose ends are not printable ASCII is rendered as hex instead,
	// so the fingerprint stays a fixed-width, log-safe token.
	if !isAlphanumeric(head) || !isAlphanumeric(tail) {
		encoded := hex.EncodeToString([]byte{head, tail})
		return string(encoded[0]) + string(encoded[len(encoded)-1])
	}
	return string(head) + string(tail)
}

func isAlphanumeric(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// countTo99 renders a count as exactly two digits, saturating rather than
// overflowing the field.
func countTo99(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func (c *ClientHello) ja4Ciphers() string {
	return joinHexSorted(withoutGREASE(c.CipherSuites))
}

// ja4Extensions excludes SNI and ALPN from the hashed list — they are already
// represented in the readable prefix, and SNI is per-destination rather than
// per-client, so hashing it would give every host its own fingerprint. They are
// still COUNTED in the prefix.
func (c *ClientHello) ja4Extensions() string {
	kept := make([]uint16, 0, len(c.Extensions))
	for _, typ := range withoutGREASE(c.ExtensionTypes()) {
		if typ == ExtServerName || typ == ExtALPN {
			continue
		}
		kept = append(kept, typ)
	}
	return joinHexSorted(kept)
}

// ja4SignatureAlgorithms keeps wire order. This is the one list JA4 does not
// sort, because it is a preference order and clients differ in it.
func (c *ClientHello) ja4SignatureAlgorithms() string {
	return joinHex(withoutGREASE(c.SignatureAlgorithms()))
}

func (c *ClientHello) ja4ExtensionInput() string {
	exts := c.ja4Extensions()
	if sigs := c.ja4SignatureAlgorithms(); sigs != "" {
		return exts + "_" + sigs
	}
	return exts
}

func joinHexSorted(values []uint16) string {
	sorted := append([]uint16(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return joinHex(sorted)
}

func joinHex(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:ja4HashLen]
}
