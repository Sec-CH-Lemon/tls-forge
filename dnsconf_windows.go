//go:build windows

package tlsforge

import (
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// machineDNSServers are the DNS servers of the machine's adapters that are
// up, each on port 53, as Go's resolver reads them; none when there are none.
func machineDNSServers() []string {
	var servers []string
	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			break
		}
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				sa, err := d.Address.Sockaddr.Sockaddr()
				if err != nil {
					continue
				}
				var addr netip.Addr
				switch sa := sa.(type) {
				case *syscall.SockaddrInet4:
					addr = netip.AddrFrom4(sa.Addr)
				case *syscall.SockaddrInet6:
					addr = netip.AddrFrom16(sa.Addr)
				default:
					continue
				}
				servers = append(servers, net.JoinHostPort(addr.String(), "53"))
			}
		}
		break
	}
	return servers
}
