package echo

import (
	"net"
	"testing"
	"time"
)

type closeSpyConn struct {
	net.Conn
	closed bool
}

func (c *closeSpyConn) Close() error {
	c.closed = true
	return nil
}

// The end-to-end race below proves Close returns, but scheduling decides which
// side of track it exercises. Pin the late-handler side directly as well, so
// the safety branch and its coverage do not depend on winning a race 40 times.
func TestAHandlerArrivingAfterCloseRefusesAndClosesTheConnection(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	server := &Server{closed: closed, conns: make(map[net.Conn]struct{})}
	conn := &closeSpyConn{}

	server.handleTLS(conn, nil, false)

	if !conn.closed {
		t.Error("a connection refused after Close was not closed")
	}
	if len(server.conns) != 0 {
		t.Error("a connection refused after Close was registered")
	}
}

// TestCloseDoesNotWaitForAConnectionAcceptedWhileClosing pins the window
// between Accept and the handler registering itself.
//
// accept() counts the connection in the WaitGroup before handle() puts it in
// s.conns, so a connection landing in between was already waited on but was not
// in the snapshot Close closes. Close then blocked until the client hung up,
// which for an idle peer is never — the exact thing the comment on s.conns says
// the field exists to prevent.
func TestCloseDoesNotWaitForAConnectionAcceptedWhileClosing(t *testing.T) {
	for i := range 40 {
		server, err := Start()
		if err != nil {
			t.Fatalf("Start: %v", err)
		}

		// A bare TCP dial: no TLS handshake, so the handler is parked exactly
		// where a silent peer would leave it.
		conn, err := net.Dial("tcp", server.Addr())
		if err != nil {
			_ = server.Close()
			t.Fatalf("dial: %v", err)
		}

		done := make(chan struct{})
		go func() {
			_ = server.Close()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = conn.Close()
			t.Fatalf("iteration %d: Close() blocked with an idle connection open", i)
		}
		_ = conn.Close()
	}
}
