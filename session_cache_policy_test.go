package tlsforge

import (
	"regexp"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// shippedChrome names the 18 Chrome profiles tls-forge ships.
var shippedChrome = regexp.MustCompile(`^chrome_15[1-6]_(macos|linux|windows)$`)

// Chrome's TLS and QUIC session caches keep two sessions a key
// (SSLClientSessionCache::Entry of net/ssl, quiche's QuicClientSessionCache
// ::Entry), so that a server's second ticket serves a second connection at
// once, where one kept would make it a full handshake. Every Chrome profile
// says so, and the client profile tls-forge builds of it carries both values
// to tls-client, whose caches are built of them
// (TestAClientsCachesKeepTheSessionsAnEntryTheirProfileSays there). The
// servers of tls-forge's tests give one ticket a connection, as Go's do, and
// connections to one address are dialed one after another, so no test here
// sees a second session taken at once.
func TestEveryChromeProfileKeepsTwoSessionsAKeyAsChrome(t *testing.T) {
	keys := []string{"tls.session_cache_sessions_per_entry", "quic.session_cache_sessions_per_entry"}
	seen := 0
	for _, name := range profile.Names() {
		if !shippedChrome.MatchString(name) {
			continue
		}
		p, err := profile.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		built, err := p.ClientProfile()
		if err != nil {
			t.Fatal(name, err)
		}
		for _, key := range keys {
			if p.Behavior.Int(key) != 2 || built.GetBehavior().Int(key) != 2 {
				t.Errorf("%s: %s is %d, its client profile's %d, want Chrome's 2", name, key,
					p.Behavior.Int(key), built.GetBehavior().Int(key))
			}
		}
		seen++
	}
	if seen != 18 {
		t.Fatalf("%d Chrome profiles, want 18", seen)
	}
}
