//go:build windows

package tlsforge

import (
	"net/netip"
	"testing"
)

func TestTheMachinesDNSServersAreItsAdapters(t *testing.T) {
	// Whatever the machine's adapters name, each is an address on port 53.
	for _, s := range machineDNSServers() {
		if a, err := netip.ParseAddrPort(s); err != nil || a.Port() != 53 {
			t.Errorf("%q: %v", s, err)
		}
	}
}
