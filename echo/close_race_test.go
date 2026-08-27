package echo

import (
	"net"
	"testing"
	"time"
)

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
