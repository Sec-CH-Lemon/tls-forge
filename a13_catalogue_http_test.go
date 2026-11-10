package tlsforge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v2/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
)

// This same witness runs in the archived pre-materialization source and the
// candidate. The input is the complete old policy+base descriptor or full JSON,
// not Registry.Get, whose captured profiles can shadow catalogue aliases.
func TestA13CatalogueHTTPProduction(t *testing.T) {
	path := os.Getenv("TLSFORGE_A13_CATALOGUE_INPUT")
	if path == "" {
		path = "profile/catalogue.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if err = json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Entries) != 83 {
		t.Fatal("catalogue denominator", len(inv.Entries))
	}
	names := make([]string, 0, 83)
	for name := range inv.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			for _, h1 := range []bool{false, true} {
				t.Run(fmt.Sprint("h1=", h1), func(t *testing.T) {
					p, err := profile.Load(inv.Entries[name])
					if err != nil {
						t.Fatal(err)
					}
					spec, err := p.Spec()
					if err != nil {
						t.Fatal(err)
					}
					wantH2 := false
					hasALPN := false
					for _, e := range spec.Extensions {
						if a, ok := e.(*tls.ALPNExtension); ok {
							hasALPN = true
							for _, v := range a.AlpnProtocols {
								if v == "h2" {
									wantH2 = true
								}
							}
						}
					}
					server := startEchoWithTickets(t)
					options := []Option{WithProfileValue(p)}
					if h1 {
						options = append(options, WithTransportOption(tc.WithForceHttp1()))
					}
					client := newTestClient(t, options...)
					for i := range 3 {
						if i == 2 {
							client.CloseIdleConnections()
						}
						cap, conn := measuredOn(t, client, server)
						if conn.Reused != (i == 1) || cap.TLS.Resumed != conn.Resumed {
							t.Fatalf("lifecycle %d %+v resumed %v", i, conn, cap.TLS.Resumed)
						}
						if h1 && (cap.HTTP1 == nil || hasALPN && cap.Negotiated != "http/1.1") {
							t.Fatal("forced H1 missing")
						}
						if !h1 && wantH2 && cap.HTTP2 == nil {
							t.Fatal("H2 missing", cap.Negotiated)
						}
						if !h1 && !wantH2 && cap.HTTP1 == nil {
							t.Fatal("declared H1 missing")
						}
						evidence := struct {
							Capture *capture.Capture `json:"capture"`
							Reused  bool             `json:"reused"`
							Resumed bool             `json:"resumed"`
						}{cap, conn.Reused, conn.Resumed}
						relative := filepath.Join(name, fmt.Sprintf("h1-%v", h1), fmt.Sprintf("%d.json", i))
						if base := os.Getenv("TLSFORGE_A13_CATALOGUE_BEFORE"); base != "" {
							b, err := os.ReadFile(filepath.Join(base, relative))
							if err != nil {
								t.Fatal(err)
							}
							var before struct {
								Capture *capture.Capture `json:"capture"`
								Reused  bool             `json:"reused"`
								Resumed bool             `json:"resumed"`
							}
							if err = json.Unmarshal(b, &before); err != nil {
								t.Fatal(err)
							}
							if conn.Reused != before.Reused || conn.Resumed != before.Resumed || cap.Negotiated != before.Capture.Negotiated {
								t.Fatal("lifecycle changed")
							}
							if cap.HTTP2 != nil {
								if report := fingerprint.CompareHTTP2(before.Capture.HTTP2.Fingerprint(), cap.HTTP2.Fingerprint()); !report.OK() {
									t.Fatalf("H2 changed: %+v", report)
								}
							} else {
								if report := fingerprint.CompareHTTP1(before.Capture.HTTP1.Fingerprint(), cap.HTTP1.Fingerprint()); !report.OK() {
									t.Fatalf("H1 changed: %+v", report)
								}
							}
						}
						if dir := os.Getenv("TLSFORGE_A13_CATALOGUE_EVIDENCE"); dir != "" {
							target := filepath.Join(dir, relative)
							if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
								t.Fatal(err)
							}
							b, err := json.MarshalIndent(evidence, "", "  ")
							if err != nil {
								t.Fatal(err)
							}
							if err = os.WriteFile(target, b, 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
				})
			}
		})
	}
}
