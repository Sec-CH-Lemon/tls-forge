package tlsforge

import (
	"crypto/ecdh"
	"crypto/tls"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A profile that bounds the wait by nothing (dns.https_wait_* all 0) waits
// for the records as long as they take, as Chromium starts no timer then:
// records 300 ms late give their ECH. Chrome's own wait, 50 ms at most, does
// not wait for them.
func TestRecordsAWaitBoundsByNothingAreWaitedFor(t *testing.T) {
	good := newECHKey(t, 0x11, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
	for _, tc := range []struct {
		name   string
		values map[string]any
		want   string
	}{
		{"Chrome's", nil, "grease"},
		{"none", map[string]any{"dns.https_wait_percent": 0, "dns.https_wait_min_ms": 0, "dns.https_wait_max_ms": 0},
			"ech:good"},
	} {
		site := startECHSite(t, []tls.EncryptedClientHelloKey{{Config: good.config, PrivateKey: good.key.Bytes()}},
			[]echKey{good})
		dns := echNames(t, map[string]*dnsmessage.SVCBResource{"ech.ech.test": service(1, "ech.ech.test",
			echParam(echList(good)))}, 0, 300*time.Millisecond)
		var opts []Option
		if tc.values != nil {
			opts = append(opts, WithProfileValue(policyFile(t, tc.values)))
		}
		if _, err := echClient(t, dns, opts...).Do(&Request{URL: "https://ech.ech.test:" + site.port + "/"}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := site.seen()[0].kindOf(map[uint8]string{0x11: "good"}); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}
