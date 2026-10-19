package tlsforge

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestARequestWaitsForAStreamOnItsConnectionAsChromeWaits(t *testing.T) {
	// A server that allows one stream at a time, its one stream taken: a
	// Chromium profile's next request waits for it on the connection, as
	// Chrome waited on its connection for a stream a server's ALPS allowed
	// none of (alps-settings-streams-0); another browser's profile is the
	// transport's, which opens another connection.
	for _, tc := range []struct {
		profile string
		wait    bool
	}{
		{"chrome_155_macos", true},
		{"firefox_148", false},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			release, slow := make(chan struct{}), make(chan struct{}, 1)
			var conns atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/slow" {
					slow <- struct{}{}
					<-release
				}
			}))
			server.EnableHTTP2 = true
			server.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 1}
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					conns.Add(1)
				}
			}
			server.StartTLS()
			t.Cleanup(server.Close)
			client := newTestClient(t, WithProfile(tc.profile), WithTimeout(10*time.Second))
			// One answered first: the client has the server's SETTINGS.
			if _, err := client.Get(server.URL + "/first"); err != nil {
				t.Fatalf("Get: %v", err)
			}
			done := make(chan error, 2)
			go func() { _, err := client.Get(server.URL + "/slow"); done <- err }()
			<-slow
			before := conns.Load()
			go func() { _, err := client.Get(server.URL + "/next"); done <- err }()
			// The next request opens another connection, or waits: it is
			// given time enough to open one.
			for deadline := time.Now().Add(300 * time.Millisecond); conns.Load() == before && time.Now().Before(deadline); {
				time.Sleep(5 * time.Millisecond)
			}
			opened := conns.Load() > before
			close(release)
			for range 2 {
				if err := <-done; err != nil {
					t.Errorf("Get: %v", err)
				}
			}
			if opened == tc.wait {
				t.Errorf("another connection opened while the stream was taken: %v (%d in all)", opened, conns.Load())
			}
		})
	}
}
