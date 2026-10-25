package tlsforge

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Deadlines belong to this CONNECT stream, not the multiplexed proxy socket.
// A timed-out TLS tunnel cannot be recovered; abort its stream and leave peers
// alive. The TLS writer never resets or rolls back an encryption sequence.
type proxyStream struct {
	net.Conn
	reader                io.ReadCloser
	writer                *io.PipeWriter
	cancel                context.CancelFunc
	once                  sync.Once
	mu                    sync.Mutex
	closed                bool
	expired               bool
	readAt, writeAt       time.Time
	readTimer, writeTimer *time.Timer
}

func (c *proxyStream) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	return n, c.deadlineError(err)
}
func (c *proxyStream) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	return n, c.deadlineError(err)
}
func (c *proxyStream) deadlineError(err error) error {
	c.mu.Lock()
	expired := c.expired
	c.mu.Unlock()
	if err != nil && expired {
		return os.ErrDeadlineExceeded
	}
	return err
}
func (c *proxyStream) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.mu.Unlock()
		c.cancel()
		_ = c.writer.Close()
		_ = c.reader.Close()
	})
	return nil
}
func (c *proxyStream) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setDeadlineLocked(t, true)
	c.setDeadlineLocked(t, false)
	return nil
}
func (c *proxyStream) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setDeadlineLocked(t, true)
	return nil
}
func (c *proxyStream) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setDeadlineLocked(t, false)
	return nil
}
func (c *proxyStream) setDeadlineLocked(at time.Time, read bool) {
	old := c.writeTimer
	target := &c.writeAt
	if read {
		old = c.readTimer
		target = &c.readAt
	}
	if old != nil {
		old.Stop()
	}
	*target = at
	if at.IsZero() || c.closed {
		return
	}
	timer := time.AfterFunc(time.Until(at), func() {
		c.mu.Lock()
		current := c.writeAt
		if read {
			current = c.readAt
		}
		expire := !c.closed && current.Equal(at) && !time.Now().Before(at)
		if expire {
			c.expired = true
		}
		c.mu.Unlock()
		if expire {
			_ = c.Close()
		}
	})
	if read {
		c.readTimer = timer
	} else {
		c.writeTimer = timer
	}
}
