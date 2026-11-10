package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	tls "github.com/igor-lemon/utls"
)

func TestProfileMetadataCannotSelectUTLSImplementation(t *testing.T) {
	p := mustGet(t, "chrome_156_macos")
	reference, err := fingerprint.ParseClientHello(p.ClientHello)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Golang", "CustomInternal", "Randomized", "Randomized-ALPN", "Randomized-NoALPN", "Chrome", "neutral"} {
		t.Run(name, func(t *testing.T) {
			q := p.Clone()
			q.Name = name
			q.UserAgent = "metadata without a browser family"
			cp, err := q.ClientProfileShuffled(false)
			if err != nil {
				t.Fatal(err)
			}
			conn := tls.UClient(nil, &tls.Config{ServerName: "identity.test", OmitEmptyPsk: true, Behavior: q.RuntimeBehavior()}, cp.GetClientHelloId(), false, false, false)
			if err := conn.BuildHandshakeState(); err != nil {
				t.Fatal("metadata selected a different implementation", err)
			}
			message := conn.HandshakeState.Hello.Raw
			raw := append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...)
			if dir := os.Getenv("TLSFORGE_A13_IDENTITY_EVIDENCE_DIR"); dir != "" {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name+".bin"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			hello, err := fingerprint.ParseClientHello(raw)
			if err != nil {
				t.Fatal(err)
			}
			if report := fingerprint.CompareTLS(reference, hello); !report.OK() {
				t.Fatalf("metadata changed the ClientHello: %+v", report)
			}
		})
	}
}
