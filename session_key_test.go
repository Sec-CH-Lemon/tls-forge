package tlsforge

import (
	stdtls "crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// A ticket a server gave on one port is not offered on another port of its
// name, as Chrome keys its sessions by host and port (SSLClientSessionCache
// ::Key): a redirect from one port to the other within one request goes as a
// full handshake where every Chrome profile says tls.session_cache_key
// host-port; without it, by name alone as crypto/tls keys them, it resumes.
func TestASessionIsOfferedOnlyToThePortItsServerGaveItOn(t *testing.T) {
	shipped, err := profile.Get("chrome_156_macos")
	if err != nil {
		t.Fatal(err)
	}
	if shipped.Behavior.Text("tls.session_cache_key") != "host-port" || shipped.Behavior.Text("quic.session_cache_key") != "host-port" {
		t.Fatal("the shipped profile keys its sessions by name alone")
	}
	byName := shipped.Clone()
	delete(byName.Behavior, "tls.session_cache_key")
	delete(byName.Behavior, "quic.session_cache_key")
	key := [32]byte{4, 5, 6}
	for _, p := range []*profile.Profile{shipped, byName} {
		var mu sync.Mutex
		resumed := map[string]bool{}
		var b *httptest.Server
		a := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			resumed["a"] = r.TLS.DidResume
			mu.Unlock()
			http.Redirect(w, r, b.URL+"/", http.StatusFound)
		}))
		b = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			resumed["b"] = r.TLS.DidResume
			mu.Unlock()
		}))
		for _, s := range []*httptest.Server{a, b} {
			s.TLS = &stdtls.Config{}
			s.TLS.SetSessionTicketKeys([][32]byte{key})
			s.StartTLS()
			t.Cleanup(s.Close)
		}
		c := newTestClient(t, WithProfileValue(p), WithInsecureSkipVerify())
		if _, err := c.Do(&Request{URL: a.URL + "/"}); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		hostPort := p.Behavior.Text("tls.session_cache_key") == "host-port"
		if resumed["a"] || resumed["b"] == hostPort {
			t.Errorf("host-port %v: resumed at a %v, at b %v", hostPort, resumed["a"], resumed["b"])
		}
		mu.Unlock()
	}
}
