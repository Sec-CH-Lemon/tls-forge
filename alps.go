package tlsforge

import (
	"encoding/binary"
	"net"

	utls "github.com/igor-lemon/utls"
	"golang.org/x/crypto/cryptobyte"
)

// Client hints a server asks for in ALPS, as Chrome 155 was measured taking
// them (testdata/chrome155-alps.json). Among the HTTP/2 frames a server gives
// in ALPS for h2, an ACCEPT_CH frame names, for an origin, the hints a
// navigation to it over the connection is to carry
// (draft-davidben-http-client-hint-reliability). Chrome finds a page's request
// lacking some once it has its connection, and starts the request again with
// them: they go after the headers its browser gives the request, its hints
// in place; they are the request's alone, kept neither for the origin nor for
// the next hop of a redirect, which the connection asks again; and a script's
// request carries none of them.

// frameAcceptCH is the type of an HTTP/2 ACCEPT_CH frame.
const frameAcceptCH = 0x89

// alpsOf is what the server of conn gave in ALPS: nil for none, or for a
// connection that is not TLS.
func alpsOf(conn net.Conn) []byte {
	tc, ok := conn.(interface{ ConnectionState() utls.ConnectionState })
	if !ok {
		return nil
	}
	return tc.ConnectionState().PeerApplicationSettings
}

// acceptCHOf is what the ACCEPT_CH frames of alps, HTTP/2 frames, ask o for, as
// Chrome reads them (Chromium's AlpsDecoder::AcceptChParser and
// SpdySession::ParseAlps): each frame on no stream and with no flags a run of
// entries, an origin and a value each, with their lengths in two bytes before
// them; an entry cut short ends its frame, the entries before it taken; and
// the first entry of the origin as an Origin header says o is the one, an
// origin written otherwise (in capitals, with its scheme's port, with a path)
// none's. A frame cut short ends the reading: fhttp refuses such ALPS, and an
// ACCEPT_CH frame on a stream or with flags, before the connection is made.
func acceptCHOf(alps []byte, o origin) (string, bool) {
	want := o.String()
	for len(alps) >= 9 {
		length := int(alps[0])<<16 | int(alps[1])<<8 | int(alps[2])
		if len(alps) < 9+length {
			break
		}
		typ, flags, stream := alps[3], alps[4], binary.BigEndian.Uint32(alps[5:9])&(1<<31-1)
		entries := cryptobyte.String(alps[9 : 9+length])
		alps = alps[9+length:]
		if typ != frameAcceptCH || flags != 0 || stream != 0 {
			continue
		}
		var origin, value cryptobyte.String
		for entries.ReadUint16LengthPrefixed(&origin) && entries.ReadUint16LengthPrefixed(&value) {
			if string(origin) == want {
				return string(value), true
			}
		}
	}
	return "", false
}

// acceptCHAsked is what the ALPS of conn asks o for: over HTTP/3, the
// ACCEPT_CH entries its transport read of it (quic-go-utls's fakeConn,
// h3.alps_reader), whose frames are HTTP/3's; else those of its HTTP/2
// frames (acceptCHOf).
func acceptCHAsked(conn net.Conn, o origin) (string, bool) {
	if q, ok := conn.(interface{ AcceptCH(string) (string, bool) }); ok {
		return q.AcceptCH(o.String())
	}
	return acceptCHOf(alpsOf(conn), o)
}

// alpsHints are the client hints the ALPS of conn, the connection hop h of a
// page's request goes out on, asks h's origin for that h does not carry, with
// the profile's values, in Chrome's order: none when it asks for none, or for
// none the profile has a value for, or when conn is not TLS.
func (c *Client) alpsHints(conn net.Conn, h hop) Header {
	value, ok := acceptCHAsked(conn, h.to)
	if !ok {
		return nil
	}
	var out Header
	for _, hint := range hintValues(askedHints([]string{value}, c.behavior()), Header(c.profile.ClientHints)) {
		if !h.hints.Has(hint.Name) && !h.alps.Has(hint.Name) {
			out = append(out, hint)
		}
	}
	return out
}
