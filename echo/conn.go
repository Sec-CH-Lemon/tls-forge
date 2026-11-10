package echo

import (
	"net"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// recordingConn keeps a copy of the bytes a client sends until it has a whole
// ClientHello, then gets out of the way.
//
// The ClientHello has to be read from the raw stream because crypto/tls does not
// hand it over: ClientHelloInfo exposes a curated subset — no extension order,
// no GREASE, no unrecognised extensions — and those omissions are precisely the
// fingerprint. So the connection is wrapped before the handshake and the bytes
// are taken as they pass.
//
// Recording stops the moment the hello parses. It is not an optimisation: this
// wrapper stays in place for the life of the connection, and a recorder that
// never stopped would hold every byte of every response in memory.
type recordingConn struct {
	net.Conn

	buffered []byte
	done     bool
	hello    *fingerprint.ClientHello
}

// Only a malformed or hostile peer gets anywhere near this: Chrome's ClientHello
// is about 2 KB with the post-quantum key share in it. Past the limit the
// recorder gives up rather than buffering whatever it is being fed.
const maxRecordedHello = 1 << 16

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.done {
		c.buffered = append(c.buffered, p[:n]...)
		if hello, parseErr := fingerprint.ParseClientHello(c.buffered); parseErr == nil {
			c.hello, c.done = hello, true
			c.buffered = nil
		} else if len(c.buffered) > maxRecordedHello {
			c.done, c.buffered = true, nil
		}
	}
	return n, err
}
