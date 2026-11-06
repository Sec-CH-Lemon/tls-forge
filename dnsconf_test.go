package tlsforge

import (
	"net/netip"
	"slices"
	"testing"
)

func TestTheAdaptersDNSServersAreThoseGosResolverAsks(t *testing.T) {
	addrs := func(ss ...string) []netip.Addr {
		var out []netip.Addr
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		adapters []adapterDNS
		want     []string
	}{
		{"none", nil, nil},
		{"an adapter up with a gateway, each server on port 53, in order", []adapterDNS{
			{up: true, routed: true, servers: addrs("192.0.2.53", "2001:db8::53")},
		}, []string{"192.0.2.53:53", "[2001:db8::53]:53"}},
		// Go's resolver asks neither of these, so the records are not asked
		// of them: the addresses come from elsewhere.
		{"an adapter down", []adapterDNS{{up: false, routed: true, servers: addrs("192.0.2.1")}}, nil},
		{"an adapter with no gateway", []adapterDNS{{up: true, servers: addrs("192.0.2.1")}}, nil},
		{"the site-local servers Windows names where none is set", []adapterDNS{
			{up: true, routed: true, servers: addrs("fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0::53", "2001:db8::1")},
		}, []string{"[2001:db8::1]:53"}},
		// Go passes over fec0 alone, not the rest of fec0::/10, nor fe80.
		{"fec1, fe80 and 20c0 are asked", []adapterDNS{
			{up: true, routed: true, servers: addrs("fec1::53", "fe80::53", "fe00::53", "20c0::53")},
		}, []string{"[fec1::53]:53", "[fe80::53]:53", "[fe00::53]:53", "[20c0::53]:53"}},
		{"an IPv4 server written as IPv6 is said as IPv4, as Go says it", []adapterDNS{
			{up: true, routed: true, servers: addrs("::ffff:192.0.2.9")},
		}, []string{"192.0.2.9:53"}},
		{"several adapters, in order, those left out passed over", []adapterDNS{
			{up: true, routed: true, servers: addrs("192.0.2.1")},
			{up: true, servers: addrs("192.0.2.2")},
			{up: false, routed: true, servers: addrs("192.0.2.3")},
			{up: true, routed: true, servers: addrs("192.0.2.4")},
		}, []string{"192.0.2.1:53", "192.0.2.4:53"}},
	} {
		if got := adaptersDNSServers(tc.adapters); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
