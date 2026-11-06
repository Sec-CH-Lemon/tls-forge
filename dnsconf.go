package tlsforge

import (
	"net"
	"net/netip"
)

// adapterDNS is what an adapter of the machine says of itself and its DNS
// servers, as Windows names them.
type adapterDNS struct {
	up      bool // its operational status is up
	routed  bool // it has a gateway
	servers []netip.Addr
}

// adaptersDNSServers are the DNS servers of the machine's adapters as Go's
// resolver reads them on Windows (dnsReadConfig, net/dnsconfig_windows.go),
// so that the HTTPS records are asked of the servers the addresses come
// from: an adapter's that is up and has a gateway, each on port 53, but an
// IPv6 one under fec0, the site-local address Windows names where no other is
// set. None when there are none: Go would ask the machine itself then.
func adaptersDNSServers(adapters []adapterDNS) []string {
	var servers []string
	for _, a := range adapters {
		if !a.up || !a.routed {
			continue
		}
		for _, s := range a.servers {
			if b := s.As16(); b[0] == 0xfe && b[1] == 0xc0 {
				continue
			}
			servers = append(servers, net.JoinHostPort(s.Unmap().String(), "53"))
		}
	}
	return servers
}
