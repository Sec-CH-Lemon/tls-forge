package fingerprint

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3 returns the JA3 string: version, ciphers, extensions, curves and point
// formats, decimal, GREASE removed.
//
// A warning that belongs next to the function rather than in a document: JA3 is
// not usable for Chrome. Chrome shuffles its extension order on every
// connection, and JA3 hashes that order, so the same browser produces a
// different JA3 for every request it makes. It is implemented here because
// plenty of services still log it and because a JA3 that is stable across
// connections is itself evidence of a client that is NOT Chrome — but never
// compare two JA3s and conclude anything from their differing.
//
// Use JA4, which sorts before hashing for exactly this reason.
func (c *ClientHello) JA3() string {
	fields := []string{
		strconv.Itoa(int(c.LegacyVersion)),
		joinDecimal(withoutGREASE(c.CipherSuites)),
		joinDecimal(withoutGREASE(c.ExtensionTypes())),
		joinDecimal(withoutGREASE(c.SupportedGroups())),
		joinDecimalBytes(c.ECPointFormats()),
	}
	return strings.Join(fields, ",")
}

// JA3Hash returns the MD5 of the JA3 string, which is the form services log.
func (c *ClientHello) JA3Hash() string {
	sum := md5.Sum([]byte(c.JA3()))
	return hex.EncodeToString(sum[:])
}

func joinDecimal(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinDecimalBytes(values []uint8) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}
