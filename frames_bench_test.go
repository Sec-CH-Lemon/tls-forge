//go:build !race

package tlsforge

import (
	"io"
	"log"
	"os"
	"testing"

	"github.com/igor-lemon/fhttp/http2"

	"github.com/Sec-CH-Lemon/tls-forge/echo"
)

// BenchmarkHTTP2FrameLines is what the transport saying every HTTP/2 frame it
// reads costs a request, which it does whenever http2.VerboseLogs is on: the
// line is made whether or not anybody keeps it. tls-forge turns it on only for
// a run whose log keeps lines at the trace level.
//
// Not under the race detector: the switch is read, unguarded, by every
// connection's goroutine, and is flipped here between the two halves.
func BenchmarkHTTP2FrameLines(b *testing.B) {
	server, err := echo.Start()
	if err != nil {
		b.Fatalf("echo.Start: %v", err)
	}
	b.Cleanup(func() { _ = server.Close() })
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(os.Stderr) })

	for _, tc := range []struct {
		name    string
		verbose bool
	}{{"quiet", false}, {"verbose", true}} {
		b.Run(tc.name, func(b *testing.B) {
			http2.VerboseLogs = tc.verbose
			b.Cleanup(func() { http2.VerboseLogs = false })
			client, err := New(WithInsecureSkipVerify())
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			b.Cleanup(func() { _ = client.Close() })
			b.ReportAllocs()
			for b.Loop() {
				if _, err := client.Get(server.URL() + "/api/all"); err != nil {
					b.Fatalf("Get: %v", err)
				}
			}
		})
	}
}
