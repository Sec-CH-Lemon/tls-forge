// Package deadlineconn applies a rolling idle timeout to a network connection.
package deadlineconn

import (
	"net"
	"time"
)

// Wrap refreshes the applicable deadline before every read and write. Active
// transfers may run for as long as they make progress; a peer that sends
// nothing cannot retain a goroutine and descriptor forever.
func Wrap(conn net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return conn
	}
	return &Conn{Conn: conn, idle: idle}
}

// Conn is a net.Conn with rolling read and write deadlines.
type Conn struct {
	net.Conn
	idle time.Duration
}

// Read refreshes the read deadline before waiting for input.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// Write refreshes the write deadline before waiting for the peer.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
