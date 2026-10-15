package tlsforge

import (
	"encoding/json"
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
