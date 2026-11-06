package fingerprint

import "golang.org/x/crypto/cryptobyte"

// framing are the extensions whose bytes do not read whole as their grammar
// has them: a list with bytes past it, or one cut short. The fields that read
// them read what they can, so without this a byte a client adds where the
// browser has none would match. server_name is held to one host_name here,
// the name itself aside, the site's.
func framing(hello *ClientHello) []string {
	var out []string
	for _, ext := range hello.Extensions {
		if grammar, ok := grammars[ext.Type]; ok && !readsWhole(ext.Data, grammar) {
			out = append(out, ExtensionName(ext.Type))
		}
	}
	return out
}

// grammar reads one extension's body, and says whether it read as one.
type grammar func(*cryptobyte.String) bool

// grammars are the extensions' a field reads, and server_name's.
var grammars = map[uint16]grammar{
	ExtServerName:          oneHostName,
	ExtSupportedGroups:     list16(twoBytes),
	ExtSignatureAlgorithms: list16(twoBytes),
	ExtSupportedVersions:   list8(twoBytes),
	ExtCompressCertificate: list8(twoBytes),
	ExtECPointFormats:      list8(oneByte),
	ExtPSKKeyExchangeModes: list8(oneByte),
	ExtALPN:                list16(protocolName),
	ExtALPS:                list16(protocolName),
	ExtALPSOld:             list16(protocolName),
	ExtKeyShare:            list16(keyShareEntry),
	ExtTrustAnchors:        list16(protocolName),
}

// readsWhole says whether data is what g reads and nothing more.
func readsWhole(data []byte, g grammar) bool {
	s := cryptobyte.String(data)
	return g(&s) && s.Empty()
}

// list16 and list8 read a list behind a length of two bytes or one, each of
// its entries read whole by item.
func list16(item grammar) grammar {
	return func(s *cryptobyte.String) bool {
		var body cryptobyte.String
		return s.ReadUint16LengthPrefixed(&body) && entries(body, item)
	}
}

func list8(item grammar) grammar {
	return func(s *cryptobyte.String) bool {
		var body cryptobyte.String
		return s.ReadUint8LengthPrefixed(&body) && entries(body, item)
	}
}

func entries(body cryptobyte.String, item grammar) bool {
	for !body.Empty() {
		if !item(&body) {
			return false
		}
	}
	return true
}

func oneByte(s *cryptobyte.String) bool {
	var v uint8
	return s.ReadUint8(&v)
}

func twoBytes(s *cryptobyte.String) bool {
	var v uint16
	return s.ReadUint16(&v)
}

// protocolName is an ALPN protocol's, or a trust anchor's ID: bytes behind a
// length of one byte.
func protocolName(s *cryptobyte.String) bool {
	var name cryptobyte.String
	return s.ReadUint8LengthPrefixed(&name)
}

// oneHostName is server_name's list of one entry: the host_name type, and
// its name.
func oneHostName(s *cryptobyte.String) bool {
	var list, name cryptobyte.String
	var kind uint8
	return s.ReadUint16LengthPrefixed(&list) && list.ReadUint8(&kind) && kind == 0 &&
		list.ReadUint16LengthPrefixed(&name) && list.Empty()
}

func keyShareEntry(s *cryptobyte.String) bool {
	var group uint16
	var key cryptobyte.String
	return s.ReadUint16(&group) && s.ReadUint16LengthPrefixed(&key)
}
