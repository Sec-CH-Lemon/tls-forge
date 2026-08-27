package proxy

import (
	"sync"
	"testing"
)

// TestLeafForIsSafeUnderConcurrentUse drives the leaf-certificate cache the way
// a browser does.
//
// The cache is guarded by c.mu, and until this test existed nothing checked it:
// every caller in the suite ran on the test goroutine, so the lock had full line
// coverage and no race coverage at all. Deleting both c.mu lines left the whole
// `go test -race ./...` run green, which is the wrong answer for a map written
// from one goroutine per connection.
//
// A mix of repeated and distinct hosts, because they exercise different halves:
// the same host races two readers against one writer, distinct hosts race two
// writers against each other.
func TestLeafForIsSafeUnderConcurrentUse(t *testing.T) {
	ca := newCAForTest(t)

	hosts := []string{
		"example.com", "example.com", "example.com",
		"a.example.com", "b.example.com", "c.example.com",
		"d.example.com", "e.example.com",
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(hosts)*4)
	for range 4 {
		for _, host := range hosts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := ca.leafFor(host); err != nil {
					errs <- err
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("leafFor: %v", err)
	}

	// The same host must resolve to one cached certificate, not one per caller.
	first, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	second, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if first != second {
		t.Error("leafFor returned a different certificate for a cached host")
	}
}

// TestConnectionTrackingIsSafeUnderConcurrentUse races the conns map the same
// way, since it is written by every handler goroutine and read by Close.
func TestConnectionTrackingIsSafeUnderConcurrentUse(t *testing.T) {
	server, _ := newTestServer(t, stubClient{status: 200})

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn := &scriptedConn{writeBudget: 1 << 20}
			if server.track(conn) {
				server.forget(conn)
			}
		}()
	}
	wg.Wait()

	server.mu.Lock()
	left := len(server.conns)
	server.mu.Unlock()
	if left != 0 {
		t.Errorf("conns has %d entries left, want 0", left)
	}
}
