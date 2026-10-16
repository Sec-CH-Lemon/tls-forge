package tlsforge

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// startEchoWithTickets is the echo server issuing session tickets, as a site
// does, so that a client that resumes one can be seen to.
func startEchoWithTickets(t *testing.T) *echo.Server {
	t.Helper()
	server, err := echo.Start(echo.WithSessionTickets(true))
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// sortedExtensions are the extension types without GREASE, sorted.
func sortedExtensions(types []uint16) []uint16 {
	out := slices.DeleteFunc(slices.Clone(types), fingerprint.IsGREASE)
	slices.Sort(out)
	return out
}

// capturedTypes are a capture's extension types, in the order sent.
func capturedTypes(c *capture.Capture) []uint16 {
	var out []uint16
	for _, extension := range c.TLS.Extensions {
		out = append(out, extension.Code)
	}
	return out
}

// chromeTypes are the extension types of a hello Chrome 155 sent, in the order
// sent.
func chromeTypes(t *testing.T, name string) []uint16 {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	hello, err := fingerprint.ParseClientHello(raw)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return hello.ExtensionTypes()
}

// measuredOn is what the echo server saw of one request, and the connection the
// request went out on.
func measuredOn(t *testing.T, client *Client, server *echo.Server) (*capture.Capture, ConnInfo) {
	t.Helper()
	var seen recorded
	res, err := client.Do(&Request{URL: server.URL() + "/api/all", Trace: seen.trace()})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	var measured capture.Capture
	if err := json.Unmarshal(res.Body, &measured); err != nil || measured.TLS.JA4 == "" || len(seen.conns) != 1 {
		t.Fatalf("the echo server answered %q (%v), over %d connections", res.Body, err, len(seen.conns))
	}
	return &measured, seen.conns[0]
}

func TestAClientResumesAsChromeDoes(t *testing.T) {
	server := startEchoWithTickets(t)
	client := newTestClient(t, WithProfile("chrome_155_macos"))

	// The first connection is the capture: Chrome's first contact, cold.
	first, conn := measuredOn(t, client, server)
	if first.TLS.Resumed || conn.Resumed || first.TLS.JA4 != "t13d1517h2_8daaf6152771_cb7bf5808d99" ||
		!slices.Equal(sortedExtensions(capturedTypes(first)), sortedExtensions(chromeTypes(t, "chrome155-clienthello.bin"))) {
		t.Errorf("the first connection was %s, resumed %v, with %v", first.TLS.JA4, first.TLS.Resumed, capturedTypes(first))
	}

	// A new connection to the site that issued a ticket resumes it, as Chrome's
	// does: the same JA4 and the same extensions Chrome came back with, the one
	// it adds last, after the second GREASE.
	client.CloseIdleConnections()
	second, conn := measuredOn(t, client, server)
	sent := capturedTypes(second)
	if !second.TLS.Resumed || !conn.Resumed || conn.Reused || second.TLS.JA4 != "t13d1518h2_8daaf6152771_e2d80978ab2e" ||
		!slices.Equal(sortedExtensions(sent), sortedExtensions(chromeTypes(t, "chrome155-clienthello-resumed.bin"))) {
		t.Errorf("the next connection was %s, resumed %v, reused %v, with %v", second.TLS.JA4, second.TLS.Resumed, conn.Reused, sent)
	}
	if sent[len(sent)-1] != fingerprint.ExtPreSharedKey || !fingerprint.IsGREASE(sent[len(sent)-2]) {
		t.Errorf("the resumed hello ends with %v", sent[len(sent)-2:])
	}

	// While a connection is open there is no hello at all: the request goes out
	// on it.
	if _, conn := measuredOn(t, client, server); !conn.Reused {
		t.Errorf("a request with a connection open went out on %+v", conn)
	}
}

func TestAClientWithoutSessionResumption(t *testing.T) {
	server := startEchoWithTickets(t)
	client := newTestClient(t, WithProfile("chrome_155_macos"), WithoutSessionResumption())
	for range 2 {
		measured, conn := measuredOn(t, client, server)
		if measured.TLS.Resumed || conn.Resumed || measured.TLS.JA4 != "t13d1517h2_8daaf6152771_cb7bf5808d99" {
			t.Errorf("a connection without resumption was %s, resumed %v", measured.TLS.JA4, measured.TLS.Resumed)
		}
		client.CloseIdleConnections()
	}
}

// echLengths are the GREASE ECH payload lengths of the hellos a log says went
// out, resumed or cold as asked, with how often each went.
func echLengths(t *testing.T, book *logBook, resumed bool) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, hello := range book.with(t, "client hello", "pre_shared_key", fmt.Sprint(resumed)) {
		out[hello.get("ech_payload_bytes")]++
	}
	return out
}

func TestEveryConnectionDrawsItsECHLengthColdOrResumed(t *testing.T) {
	// Chrome draws the length afresh for every connection, from four, each as
	// likely, whether it resumes or not. Sixteen connections each way: all
	// sixteen alike would come by chance once in a billion runs.
	const connections = 16
	server := startEchoWithTickets(t)
	for _, resumed := range []bool{false, true} {
		book, log := newLogBook(LevelTrace)
		opts := []Option{WithProfile("chrome_155_macos"), WithLogger(log)}
		if !resumed {
			opts = append(opts, WithoutSessionResumption())
		}
		client := newTestClient(t, opts...)
		// With resumption the first connection is cold, and the rest resume.
		for range connections + 1 {
			if _, err := client.Get(server.URL() + "/api/all"); err != nil {
				t.Fatalf("Get: %v", err)
			}
			client.CloseIdleConnections()
		}
		lengths := echLengths(t, book, resumed)
		sent := 0
		for length, count := range lengths {
			if !slices.Contains([]string{"144", "176", "208", "240"}, length) {
				t.Errorf("resumed %v: %d hellos went with an ECH payload of %q bytes", resumed, count, length)
			}
			sent += count
		}
		want := connections
		if !resumed {
			want++ // the first one too
		}
		if sent != want || len(lengths) < 2 {
			t.Errorf("resumed %v: %d hellos, want %d, drew %v", resumed, sent, want, lengths)
		}
	}
}
