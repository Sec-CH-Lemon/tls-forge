package tlsforge

import (
	"net"
	"testing"
)

func TestDarwinAirPortEthernetEntityIsWiFi(t *testing.T) {
	s := newNetworkCFStore()
	s.dictionary("State:/Network/Global/IPv4", map[string]string{"PrimaryInterface": "owned0", "PrimaryService": "service"})
	s.dictionary("Setup:/Network/Service/service/Interface", map[string]string{"Type": "Ethernet", "Hardware": "AirPort", "DeviceName": "owned0"})
	route, e := darwinNetworkRoute([]string{"ipv4"}, func() (*darwinConfiguration, error) { return s.api, nil }, func(string) (*net.Interface, error) { return &net.Interface{Index: 7}, nil })
	if e != nil || route.kind != "wifi" {
		t.Fatalf("actual AirPort metadata classified as %q: %v", route.kind, e)
	}
}
