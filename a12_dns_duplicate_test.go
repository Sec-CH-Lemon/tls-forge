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
			httpsObserved := make(chan struct{}, 2)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Observe the asynchronous DNS peer before treating origin completion
				// as the measurement boundary. A query never sent still fails:
				// this barrier cannot create a DNS question or retry a request.
				timer := time.NewTimer(time.Second)
				defer timer.Stop()
				select {
				case <-httpsObserved:
				case <-timer.C:
					t.Error("DNS peer did not observe an HTTPS question before origin completion")
					http.Error(w, "missing HTTPS query", http.StatusInternalServerError)
					return
				case <-r.Context().Done():
					return
				}
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
					select {
					case httpsObserved <- struct{}{}:
					default:
					}
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
				perCall := map[string]int{}
				for _, q := range dns.queries() {
					perCall[strings.Fields(q)[0]]++
				}
				if perCall["A"] != call+1 || perCall["AAAA"] != call+1 || perCall["HTTPS"] != call+1 {
					t.Fatalf("call%d DNSwire=%v; want one A/AAAA/HTTPS per isolated request", call, perCall)
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
