//go:build windows

package tlsforge

import (
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// machineDNSServers are the DNS servers of the machine's adapters, as Go's
// resolver reads them (adaptersDNSServers); none when there are none.
func machineDNSServers() []string {
	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		flags := uint32(windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_INCLUDE_GATEWAYS)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil || size == 0 {
			return nil
		}
		var adapters []adapterDNS
		for a := first; a != nil; a = a.Next {
			adapter := adapterDNS{up: a.OperStatus == windows.IfOperStatusUp, routed: a.FirstGatewayAddress != nil}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				sa, err := d.Address.Sockaddr.Sockaddr()
				if err != nil {
					continue
				}
				switch sa := sa.(type) {
				case *syscall.SockaddrInet4:
					adapter.servers = append(adapter.servers, netip.AddrFrom4(sa.Addr))
				case *syscall.SockaddrInet6:
					adapter.servers = append(adapter.servers, netip.AddrFrom16(sa.Addr))
				}
			}
			adapters = append(adapters, adapter)
		}
		return adaptersDNSServers(adapters)
	}
	return nil
}
