package tlsforge

import (
	"context"
	"maps"
	"net"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	tls_client "github.com/igor-lemon/tls-client"
)

// falseStartClient is a client wearing profile that takes the bench's
// certificate on trust and dials the port of url on the loopback address.
func falseStartClient(t *testing.T, profile, page string) *Client {
	t.Helper()
	u, err := url.Parse(page)
	if err != nil {
		t.Fatal(err)
	}
	return newTestClient(t, WithProfile(profile), WithInsecureSkipVerify(),
		WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", u.Port()))
		})))
}

func TestTLS12ConnectionsFalseStartAsChromesDid(t *testing.T) {
	// Each TLS 1.2 server of the fixture, its Finished held back: the request
	// goes before it where Chrome's went (ECDHE, an AEAD, ALPN), after it
	// where Chrome's did (no ALPN, CBC, an RSA key exchange), and over the
	// protocol Chrome's did.
	fixture, err := harness.LoadFalseStart("testdata/chrome155-falsestart.json")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(fixture.Scenarios)), slices.Sorted(maps.Keys(harness.FalseStartShapes()))) {
		t.Fatalf("the fixture has %v", slices.Sorted(maps.Keys(fixture.Scenarios)))
	}
	server, err := harness.StartFalseStartServer(300 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	for _, id := range slices.Sorted(maps.Keys(fixture.Scenarios)) {
		server.Reset()
		res, err := falseStartClient(t, "chrome_155_macos", server.URL(id)).Do(&Request{URL: server.URL(id)})
		if err != nil || res.Status != 200 {
			t.Fatalf("%s: %v", id, err)
		}
		got, err := server.Scenario(id)
		if err != nil {
			t.Fatal(err)
		}
		if diff := harness.DiffFalseStart(fixture.Scenarios[id], got); diff != nil {
			t.Errorf("%s: %v", id, diff)
		}
	}
}

func TestAProfileOfAnotherBrowserWaitsForTheServersFinished(t *testing.T) {
	// Firefox was not measured: its profile waits, as Go's TLS does.
	server, err := harness.StartFalseStartServer(300 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	const id = "fs-h1-ecdhe-ecdsa-aes128gcm"
	if _, err := falseStartClient(t, "firefox_148", server.URL(id)).Do(&Request{URL: server.URL(id)}); err != nil {
		t.Fatal(err)
	}
	if got, err := server.Scenario(id); err != nil || got.Early {
		t.Errorf("firefox_148: %+v, %v", got, err)
	}
}
