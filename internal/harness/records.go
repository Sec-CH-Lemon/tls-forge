package harness

import (
	"net"
	"strconv"
	"strings"
	"sync"
)

// tls13Overhead is what TLS 1.3 adds to the plaintext of a record of
// application data: the AEAD's tag, 16 bytes for AES-GCM and
// ChaCha20-Poly1305 alike, and the content type, one byte. Neither Chrome nor
// Go pads a record.
const tls13Overhead = 17

// clientRecords are the TLS records a client sent on a connection, as the
// bytes came: of each record of application data after the client's Finished,
// where its plaintext ends in the stream the client sent, so that the bytes
// of a frame can be told by the records that carried them.
type clientRecords struct {
	mu        sync.Mutex
	buf       []byte
	encrypted int
	ends      []int
}

// read takes the next bytes the client sent.
func (r *clientRecords) read(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, b...)
	for len(r.buf) >= 5 {
		length := int(r.buf[3])<<8 | int(r.buf[4])
		if len(r.buf) < 5+length {
			return
		}
		// The client's first encrypted record is its Finished; those after
		// it carry what it writes.
		if r.buf[0] == 23 {
			if r.encrypted++; r.encrypted > 1 {
				end := length - tls13Overhead
				if n := len(r.ends); n > 0 {
					end += r.ends[n-1]
				}
				r.ends = append(r.ends, end)
			}
		}
		r.buf = r.buf[5+length:]
	}
}

// frameSpan is a frame of a request in the stream a client sent: its kind,
// H for HEADERS, C for CONTINUATION, D for DATA, its payload's length, and
// where its bytes begin and end.
type frameSpan struct {
	kind       byte
	length     int
	start, end int
}

// layout is how the records carried spans: for each record that carried any
// byte of them, in the order they came, the frames of spans in it, a DATA
// frame with its payload's length, in capitals when the record carried the
// whole frame and in small letters when a part of it, joined by "+". Other
// frames a record carried, such as a SETTINGS acknowledgement, are left out,
// and so is a header block's length, which the ports in it change.
func (r *clientRecords) layout(spans []frameSpan) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	start := 0
	for _, end := range r.ends {
		var parts []string
		for _, f := range spans {
			if f.start >= end || f.end <= start {
				continue
			}
			token := string(f.kind)
			if f.kind == 'D' {
				token += strconv.Itoa(f.length)
			}
			if f.start < start || f.end > end {
				token = strings.ToLower(token)
			}
			parts = append(parts, token)
		}
		if parts != nil {
			out = append(out, strings.Join(parts, "+"))
		}
		start = end
	}
	return out
}

// recordingConn is a client's connection whose TLS records are kept as they
// are read.
type recordingConn struct {
	net.Conn
	records *clientRecords
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.records.read(b[:n])
	return n, err
}
