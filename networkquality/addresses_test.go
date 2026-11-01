package networkquality

import (
	"net/netip"
	"testing"
)

func TestJSONAddressEligibilityMatchesPinnedSourceBoundaries(t *testing.T) {
	p := candidatePolicy(t).Addresses
	for _, ip := range []string{"8.8.8.8", "100.63.255.255", "100.128.0.0", "2001:db8::1", "ff02::1", "::ffff:8.8.8.8"} {
		if !p.Public(netip.MustParseAddr(ip)) {
			t.Fatal("source-public address rejected", ip)
		}
	}
	for _, ip := range []string{"0.1.2.3", "10.2.3.4", "100.64.0.0", "100.127.255.255", "127.0.0.1", "169.254.1.2", "172.16.0.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1"} {
		if p.Public(netip.MustParseAddr(ip)) {
			t.Fatal("source-private address accepted", ip)
		}
	}
	if p.Public(netip.Addr{}) {
		t.Fatal("missing peer invented a sample")
	}
	p.UnmapIPv4 = false
	if p.Public(netip.MustParseAddr("::ffff:8.8.8.8")) {
		t.Fatal("unmap policy ignored")
	}
	p.Rules = []AddressRule{{"10.0.0.0/8", true}}
	p.DefaultPublic = true
	if !p.Public(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("explicit default ignored")
	}
	p.Rules[0].Prefix = "invalid"
	if p.Public(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("unchecked invalid rule accepted")
	}
}
func TestAddressRulesRejectAmbiguousOrUnboundedJSONData(t *testing.T) {
	for _, rules := range [][]AddressRule{nil, make([]AddressRule, 4097), {{"no-prefix", false}}, {{"10.1.2.3/8", false}}, {{"10.0.0.0/8", false}, {"10.0.0.0/8", true}}} {
		p := candidatePolicy(t)
		p.Addresses.Rules = rules
		if p.Validate() == nil {
			t.Fatal("invalid address rules accepted", len(rules))
		}
	}
}
