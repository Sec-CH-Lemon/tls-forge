// Package deadlineconn bounds how long a network connection waits for its
// peer.
package deadlineconn

import (
	"net"
	"sync/atomic"
	"time"
)

// Wrap refreshes the applicable deadline before every read and write. Active
// transfers may run for as long as they make progress; a peer that sends
// nothing cannot retain a goroutine and descriptor forever.
//
// A deadline set on the connection is kept as well, rather than replaced by
// the next refresh: a read or write ends at whichever comes first. That is how
// a caller bounds a whole step, a handshake or a request header, which a peer
// could otherwise stretch forever by sending a byte at a time.
func Wrap(conn net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return conn
	}
	return &Conn{Conn: conn, idle: idle}
}

// Conn is a net.Conn with rolling read and write deadlines, under the ones
// set on it.
type Conn struct {
	net.Conn
	idle time.Duration
	// readBy and writeBy are the deadlines set on the connection, in Unix
	// nanoseconds, or 0 for none.
	readBy, writeBy atomic.Int64
}

// chunk is the most one write hands over at a time. A write is given the idle
// timeout to finish, so a large one to a peer that keeps reading, only slowly,
// would be cut off by a bound meant for a peer that has stopped.
const chunk = 64 << 10

// Read refreshes the read deadline before waiting for input.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(c.until(&c.readBy)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// Write refreshes the write deadline before each chunk it waits for the peer
// to take.
func (c *Conn) Write(p []byte) (int, error) {
	written := 0
	for {
		if err := c.Conn.SetWriteDeadline(c.until(&c.writeBy)); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(p[:min(len(p), chunk)])
		written += n
		p = p[n:]
		if err != nil || len(p) == 0 {
			return written, err
		}
	}
}

// SetDeadline makes reads and writes end by t at the latest, as well as
// within the idle timeout. The zero time takes that end away again.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline is SetDeadline for reads alone. It applies at once, so a
// deadline already past ends a read under way, as it does on any connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readBy.Store(nanos(t))
	return c.Conn.SetReadDeadline(c.until(&c.readBy))
}

// SetWriteDeadline is SetDeadline for writes alone.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeBy.Store(nanos(t))
	return c.Conn.SetWriteDeadline(c.until(&c.writeBy))
}

// until is the deadline for the next wait: the idle timeout from now, or the
// one set, whichever comes first.
func (c *Conn) until(by *atomic.Int64) time.Time {
	deadline := time.Now().Add(c.idle)
	if set := by.Load(); set != 0 && set < deadline.UnixNano() {
		return time.Unix(0, set)
	}
	return deadline
}

// nanos is t in Unix nanoseconds, 0 for none: the zero time. The one instant
// that is 0 in its own right, the Unix epoch, is a deadline long past, and is
// kept as one.
func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	if n := t.UnixNano(); n != 0 {
		return n
	}
	return 1
}
