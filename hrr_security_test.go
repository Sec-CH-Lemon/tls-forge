package tlsforge

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The independent standard-library server verifies the actual wire binder and
// reports PSK acceptance. A successful full handshake cannot satisfy this test.
func TestPSKResumptionAfterHelloRetryRequest(t *testing.T) {
	for _, curve := range []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519} {
		t.Run(fmt.Sprint(curve), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "close")
				_, _ = fmt.Fprintf(w, "resumed=%v", r.TLS.DidResume)
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{curve}}
			server.StartTLS()
			defer server.Close()
			p := shippedProfile(t, "chrome_155_macos")
			p.Name, p.UserAgent = "neutral_retry_profile", "Metadata does not select TLS retry behavior"
			client := newTestClient(t, WithProfileValue(p))
			for n := 1; n <= 6; n++ {
				response, err := client.Get(server.URL)
				if err != nil {
					t.Errorf("request %d: %v", n, err)
					continue
				}
				want := fmt.Sprintf("resumed=%v", n > 1)
				if strings.TrimSpace(response.Text()) != want {
					t.Errorf("request %d: %s, want %s", n, response.Text(), want)
				}
				client.CloseIdleConnections()
			}
		})
	}
}
