package fingerprint

import (
	"bytes"
	"fmt"
	"strings"
)

// What a comparison holds two hellos to beyond their lists: the shape of what
// is drawn afresh for every connection, and the contents of each extension.
//
// A hello is mostly values that are the same on every connection of one
// browser build, and a few that are drawn for each: GREASE, the random, the
// session id, the keys, the ECH payload. The first are compared as they are.
// The second cannot be, since the browser would not match itself, and cannot
// be left out either, since where they go and how long they are does not
// change: so their shape is compared instead. What no rule here describes is
// said to be not checked, rather than taken to match.

// Extensions another field of the comparison reads, value by value.
var readByAField = map[uint16]bool{
	ExtSupportedGroups:        true,
	ExtECPointFormats:         true,
	ExtSignatureAlgorithms:    true,
	ExtALPN:                   true,
	ExtCompressCertificate:    true,
	ExtSupportedVersions:      true,
	ExtPSKKeyExchangeModes:    true,
	ExtKeyShare:               true,
	ExtApplicationSettings:    true,
	ExtApplicationSettingsOld: true,
	ExtTrustAnchors:           true,
	ExtEncryptedClientHello:   true,
	ExtPreSharedKey:           true,
}

// Extensions whose contents are not the client's to choose: server_name is the
// site's, and padding is as long as the rest of the hello leaves it. Whether
// they are sent is compared with the extensions; what is in them is not.
var notTheClients = map[uint16]bool{
	ExtServerName: true,
	ExtPadding:    true,
}

// Extensions known to carry the same bytes on every connection of one build:
// compared byte for byte, in extension_contents.
var sameEveryTime = map[uint16]bool{
	ExtStatusRequest:        true,
	17:                      true, // status_request_v2
	ExtSCT:                  true,
	22:                      true, // encrypt_then_mac
	ExtExtendedMasterSecret: true,
	28:                      true, // record_size_limit
	34:                      true, // delegated_credentials
	ExtSessionTicket:        true,
	42:                      true, // early_data
	49:                      true, // post_handshake_auth
	50:                      true, // signature_algorithms_cert
	30031:                   true, // channel_id
	ExtRenegotiationInfo:    true,
}

// unknownExtension is one no rule describes: neither read by a field, nor
// known to be the same every time, nor known not to be the client's.
func unknownExtension(typ uint16) bool {
	return !IsGREASE(typ) && !readByAField[typ] && !notTheClients[typ] && !sameEveryTime[typ]
}

// extensionContents are the extensions known to be the same every time, each
// as "name: contents in hex", in no order: the order is the browser's to
// shuffle.
func extensionContents(hello *ClientHello) []string {
	var out []string
	for _, ext := range hello.Extensions {
		if sameEveryTime[ext.Type] {
			out = append(out, ExtensionName(ext.Type)+": "+hexOrEmpty(ext.Data))
		}
	}
	return out
}

// uncheckedExtensions are the extensions both hellos send that no rule
// describes and whose contents differ: a new extension may carry random bytes
// as well as a difference, and which it is cannot be told from two hellos.
// Contents that are the same on both sides are a match whatever they are.
func uncheckedExtensions(reference, candidate *ClientHello) []Difference {
	var out []Difference
	for _, ext := range reference.Extensions {
		if !unknownExtension(ext.Type) {
			continue
		}
		theirs, ok := candidate.Extension(ext.Type)
		if !ok || bytes.Equal(ext.Data, theirs) {
			continue
		}
		out = append(out, Difference{
			Field:     "contents of " + ExtensionName(ext.Type),
			Reference: hexOrEmpty(ext.Data),
			Candidate: hexOrEmpty(theirs),
		})
	}
	return out
}

func hexOrEmpty(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}
	return fmt.Sprintf("%x", data)
}

// greaseLayout is where a hello puts GREASE (RFC 8701), and how. The values
// are drawn for every connection; where they go, how long the contents of a
// GREASE extension or key share are, and which of them are one value are not.
// Chrome puts one first in each list it greases, and two extensions, first and
// last, before a pre_shared_key, which has to be last: the first empty, the
// second a single byte, never the same value as the first. Its key share's
// GREASE group is the one in supported_groups.
func greaseLayout(hello *ClientHello) []string {
	var out []string
	greased := func(list string, values []uint16) []uint16 {
		var found []uint16
		for i, v := range values {
			if IsGREASE(v) {
				out = append(out, list+" "+position(i, len(values)))
				found = append(found, v)
			}
		}
		return found
	}
	greased("cipher_suites", hello.CipherSuites)

	extensions := hello.Extensions
	if n := len(extensions); n > 0 && extensions[n-1].Type == ExtPreSharedKey {
		extensions = extensions[:n-1]
	}
	var values []uint16
	for i, ext := range extensions {
		if IsGREASE(ext.Type) {
			out = append(out, fmt.Sprintf("extensions %s, %s", position(i, len(extensions)), size(len(ext.Data))))
			values = append(values, ext.Type)
		}
	}
	if len(values) > 1 {
		if distinct(values) {
			out = append(out, "extensions each a value of their own")
		} else {
			out = append(out, "extensions a value twice")
		}
	}

	groups := greased("supported_groups", hello.SupportedGroups())
	shares := hello.KeyShares()
	var shared []uint16
	for i, share := range shares {
		if IsGREASE(share.Group) {
			out = append(out, fmt.Sprintf("key_share %s, key %s", position(i, len(shares)), size(share.Length)))
			shared = append(shared, share.Group)
		}
	}
	if len(groups) > 0 && len(shared) > 0 {
		if groups[0] == shared[0] {
			out = append(out, "key_share the group of supported_groups")
		} else {
			out = append(out, "key_share a group supported_groups does not have")
		}
	}
	greased("supported_versions", hello.SupportedVersions())
	greased("signature_algorithms", hello.SignatureAlgorithms())
	return out
}

// position is where an entry is in a list of n: first, last, or its number.
func position(i, n int) string {
	switch i {
	case 0:
		return "first"
	case n - 1:
		return "last"
	default:
		return fmt.Sprintf("%d of %d", i+1, n)
	}
}

func size(n int) string {
	switch n {
	case 0:
		return "empty"
	case 1:
		return "1 byte"
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

func distinct(values []uint16) bool {
	seen := map[uint16]bool{}
	for _, v := range values {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

// keyShareLengths are the key shares other than GREASE, each with how long its
// key is: the keys are fresh for every connection, their lengths are the
// group's.
func keyShareLengths(hello *ClientHello) []string {
	var out []string
	for _, share := range hello.KeyShares() {
		if !IsGREASE(share.Group) {
			out = append(out, GroupName(share.Group)+": "+size(share.Length))
		}
	}
	return out
}

var hpkeKDFs = map[uint16]string{1: "HKDF-SHA256", 2: "HKDF-SHA384", 3: "HKDF-SHA512"}

var hpkeAEADs = map[uint16]string{1: "AES-128-GCM", 2: "AES-256-GCM", 3: "ChaCha20-Poly1305"}

func hpkeName(names map[uint16]string, id uint16) string {
	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}

// echShape is what stays the same of a GREASE encrypted_client_hello from one
// connection to the next, its cipher suite and the length of its key, and the
// length of its payload, which does not: Chrome draws it for each.
func echShape(hello *ClientHello) (fixed, payload string) {
	ech, ok := hello.EncryptedClientHello()
	if ok {
		return fmt.Sprintf("%s, %s, key %s", hpkeName(hpkeKDFs, ech.KDF), hpkeName(hpkeAEADs, ech.AEAD),
			size(ech.EncLength)), fmt.Sprint(ech.PayloadLength)
	}
	if data, present := hello.Extension(ExtEncryptedClientHello); present {
		return "unreadable, " + size(len(data)), "(none)"
	}
	return "(none)", "(none)"
}

// pskShape is pre_shared_key without its tickets and binders: how many
// identities, and how long each binder is.
func pskShape(hello *ClientHello) string {
	psk, ok := hello.PreSharedKey()
	if ok {
		noun := "identities"
		if psk.Identities == 1 {
			noun = "identity"
		}
		if len(psk.Binders) == 0 {
			return fmt.Sprintf("%d %s, no binder", psk.Identities, noun)
		}
		binders := make([]string, len(psk.Binders))
		for i, binder := range psk.Binders {
			binders[i] = fmt.Sprint(binder)
		}
		return fmt.Sprintf("%d %s, binders of %s bytes", psk.Identities, noun, strings.Join(binders, ", "))
	}
	if data, present := hello.Extension(ExtPreSharedKey); present {
		return "unreadable, " + size(len(data))
	}
	return "(none)"
}
