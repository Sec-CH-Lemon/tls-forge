package tlsforge

import "testing"

// The noise of the network hints of an IPv6 address is drawn from it in its
// brackets, as Chromium's GURL::GetHost says it; a name and an IPv4 address
// as they are.
func TestTheNetworkHintsOfAHostAreDrawnFromItAsGURLSaysIt(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"::1", "[::1]"}, {"2001:db8::1", "[2001:db8::1]"}, {"www.example.com", "www.example.com"}, {"192.0.2.1", "192.0.2.1"},
	} {
		if got := gurlHost(tc.host); got != tc.want {
			t.Errorf("gurlHost(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
	// Salts are drawn for each client, and a host's noise with them: the
	// hints of ::1 are those of [::1], and over the clients other than those
	// of ::1 without its brackets at least once.
	apart := false
	for range 16 {
		c := newTestClient(t, WithProfile("chrome_156_macos"))
		if c.network == nil {
			t.Fatal("a Chrome profile's client estimates no network")
		}
		got, bracketed, bare := c.networkHintValues("::1"), c.network.state.Hints("[::1]"), c.network.state.Hints("::1")
		if got.Get("downlink") != bracketed["downlink"] || got.Get("rtt") != bracketed["rtt"] {
			t.Errorf("hints %v, of [::1] %v", got, bracketed)
		}
		apart = apart || bracketed["downlink"] != bare["downlink"]
	}
	if !apart {
		t.Error("the hints of [::1] and ::1 were alike for every salt")
	}
}
