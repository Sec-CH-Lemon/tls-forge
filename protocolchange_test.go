package tlsforge

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestEveryRequestGoesThroughAServerThatChangesItsProtocol(t *testing.T) {
	// A server whose connections, one request each, say h2 and then
	// http/1.1, as a load balancer can over servers that differ: every
	// request is answered on the connection already negotiated, including a
	// replacement whose protocol differs from the previously cached transport.
	for _, tc := range []struct {
		name string
		// http1 says which handshakes, from 1, offer http/1.1 alone.
		http1      func(n int32) bool
		seen       map[string]int
		handshakes int32
	}{
		{"changed once", func(n int32) bool { return n > 1 }, map[string]int{"HTTP/2.0": 1, "HTTP/1.1": 7}, 8},
		{"changing on every connection", func(n int32) bool { return n%2 == 0 }, map[string]int{"HTTP/2.0": 4, "HTTP/1.1": 4}, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var handshakes atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.Proto))
			}))
			server.EnableHTTP2 = true
			server.Config.SetKeepAlivesEnabled(false)
			server.StartTLS()
			t.Cleanup(server.Close)
			certificates := server.TLS.Certificates
			server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				protocols := []string{"h2"}
				if tc.http1(handshakes.Add(1)) {
					protocols = []string{"http/1.1"}
				}
				return &tls.Config{Certificates: certificates, NextProtos: protocols}, nil
			}
			client := newTestClient(t, WithProfile("chrome_155_macos"))
			seen := map[string]int{}
			for i := range 8 {
				res, err := client.Do(&Request{URL: server.URL + "/"})
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				seen[string(res.Body)]++
			}
			if len(seen) != len(tc.seen) || seen["HTTP/2.0"] != tc.seen["HTTP/2.0"] || seen["HTTP/1.1"] != tc.seen["HTTP/1.1"] {
				t.Errorf("answered over %v, want %v", seen, tc.seen)
			}
			if n := handshakes.Load(); n != tc.handshakes {
				t.Errorf("%d handshakes, want %d", n, tc.handshakes)
			}
		})
	}
}
