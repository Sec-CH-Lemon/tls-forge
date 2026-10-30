package tlsforge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestA12MalformedDNSPolicyStopsBeforeNetwork(t *testing.T) {
	p := startA12DNSWire(t, a12DNSMode{})
	origin, count := a12TLSOrigin(t)
	for _, tc := range []struct{ key, value string }{
		{"dns.https_query_recursion_desired", ""}, {"dns.https_query_udp_payload_bytes", ""}, {"dns.https_query_timeout_ms", ""},
		{"dns.https_query_recursion_desired", `"false"`}, {"dns.https_query_recursion_desired", "null"},
		{"dns.https_query_udp_payload_bytes", "511"}, {"dns.https_query_udp_payload_bytes", "65536"},
		{"dns.https_query_timeout_ms", "0"}, {"dns.https_query_timeout_ms", "60001"}, {"dns.https_query_timeout_ms", "18446744073709551615"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			candidate, err := profile.Get("chrome_156_macos")
			if err != nil {
				t.Fatal(err)
			}
			candidate.Name = "rejected-dns-policy"
			if tc.value == "" {
				delete(candidate.Behavior, tc.key)
			} else {
				candidate.Behavior[tc.key] = json.RawMessage(tc.value)
			}
			c, err := New(WithProfileValue(candidate), WithDNSServer(p.addr), WithInsecureSkipVerify())
			if err == nil {
				defer c.Close()
				_, _ = c.Do(&Request{URL: a12URL(origin, "never.a12.example.test")})
				t.Error("invalid policy reached a constructed client")
			} else if !strings.Contains(err.Error(), candidate.Name) || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("non-specific profile rejection:%v", err)
			}
			if len(p.snapshot()) != 0 || count.Load() != 0 {
				t.Fatal("invalid DNS policy caused traffic")
			}
		})
	}
}
