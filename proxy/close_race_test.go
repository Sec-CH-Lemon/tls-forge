package proxy

import (
	"net"
	"testing"
	"time"
)

// TestCloseDoesNotWaitForAConnectionAcceptedWhileClosing pins the window
// between Accept and track.
//
// accept() counts a connection in the WaitGroup and hands it to a goroutine
// that only registers it in s.conns once handle() starts. A connection that
// lands in between is invisible to Close's snapshot but already counted, so
// before track() learned to refuse, Close blocked in wg.Wait() until the client
// happened to hang up — which for an idle keep-alive peer is never.
//
// The client conn is deliberately left open for the duration: that is the whole
// point. If Close only returns once the test closes it, Close is waiting on the
// peer rather than on itself.
func TestCloseDoesNotWaitForAConnectionAcceptedWhileClosing(t *testing.T) {
	ca := newCAForTest(t)

	// Repeated, because the window is a race: one iteration may register in
	// time and prove nothing. Any single hang fails the test.
	for i := range 40 {
		server, err := Start(Options{CA: ca, Client: stubClient{status: 200}})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}

		conn, err := net.Dial("tcp", server.Addr())
		if err != nil {
			server.Close()
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
			t.Fatalf("iteration %d: Close() blocked with an idle client connection open", i)
		}
		_ = conn.Close()
	}
}

// TestCloseEndsAnAlreadyTrackedConnection covers the other side of the same
// window: a connection that did reach track before Close is closed by Close's
// snapshot, so its handler returns and Close still does not hang.
func TestCloseEndsAnAlreadyTrackedConnection(t *testing.T) {
	ca := newCAForTest(t)
	server, err := Start(Options{CA: ca, Client: stubClient{status: 200}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		server.Close()
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Wait until the handler has registered, so this exercises the tracked path
	// rather than racing it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		server.mu.Lock()
		tracked := len(server.conns)
		server.mu.Unlock()
		if tracked > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connection was never tracked")
		}
		time.Sleep(time.Millisecond)
	}

	done := make(chan struct{})
	go func() {
		_ = server.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() blocked on a connection it had tracked")
	}
}
