package tlsforge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestA12HTTPUpgradeLookupIsHandedToTheConnection(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgrade-%v", upgrade), func(t *testing.T) {
			requests := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write([]byte("fresh"))
			})
			var server *httptest.Server
			if upgrade {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			t.Cleanup(server.Close)
			_, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://"))
			if err != nil {
				t.Fatal(err)
			}
			const host = "a12-handoff.example.test"
			dns := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
				switch q.Type {
				case dnsmessage.TypeA:
					return []dnsRecord{{name: host, ttl: 30, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
				case dnsmessage.TypeAAAA:
					return nil, 0, 0
				case dnsmessage.TypeHTTPS:
					if upgrade {
						return []dnsRecord{{name: strings.TrimSuffix(q.Name.String(), "."), ttl: 30, https: service(1, host, alpnParam("h2", "http/1.1"))}}, 0, 0
					}
				}
				return nil, 0, 0
			})
			client, err := New(WithProfile("chrome_156_macos"), WithDNSServer(dns.addr), WithInsecureSkipVerify())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			for call := 0; call < 2; call++ {
				result, err := client.Do(&Request{URL: "http://" + host + ":" + port + "/fresh", Context: context.Background()})
				if err != nil || string(result.Body) != "fresh" {
					t.Fatalf("call%d: %+v,%v", call, result, err)
				}
			}
			if requests != 2 {
				t.Fatalf("origin requests%d, want2", requests)
			}
			counts := map[string]int{}
			for _, q := range dns.queries() {
				counts[strings.Fields(q)[0]]++
			}
			if counts["A"] != 2 || counts["AAAA"] != 2 || counts["HTTPS"] != 2 {
				t.Fatalf("DNSwire=%v;want one A/AAAA/HTTPS per isolated top-level request", counts)
			}
		})
	}
}
