package tlsforge

import (
	"io"
	"sync"
)

// keyLogMu is held around every write of TLS secrets, of every client: utls,
// which makes the connections to sites, and crypto/tls, which makes those to
// an HTTPS proxy, each lock their own writes, and a writer given to more than
// one client gets the lines of all of them.
var keyLogMu sync.Mutex

// keyLog is where a client's TLS secrets go, a line at a time.
type keyLog struct{ w io.Writer }

func (k keyLog) Write(p []byte) (int, error) {
	keyLogMu.Lock()
	defer keyLogMu.Unlock()
	return k.w.Write(p)
}

// keyLogOf is where the secrets given to w go, or nil for no writer, which
// a TLS config takes as none.
func keyLogOf(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	return keyLog{w}
}
