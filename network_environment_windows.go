package tlsforge

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"unsafe"
)

func systemNetworkRoute(families []string) (networkRoute, error) {
	for _, family := range families {
		af := uint16(windows.AF_INET)
		if family == "ipv6" {
			af = windows.AF_INET6
		}
		var table *windows.MibIpForwardTable2
		if err := windows.GetIpForwardTable2(af, &table); err != nil {
			return networkRoute{}, err
		}
		if table.NumEntries > 65536 {
			windows.FreeMibTable(unsafe.Pointer(table))
			return networkRoute{}, fmt.Errorf("route table exceeds engine bound")
		}
		var selected networkRoute
		cost := uint64(^uint64(0))
		for _, row := range table.Rows() {
			if row.DestinationPrefix.PrefixLength != 0 || row.Loopback != 0 {
				continue
			}
			iface := windows.MibIfRow2{InterfaceLuid: row.InterfaceLuid, InterfaceIndex: row.InterfaceIndex}
			if err := windows.GetIfEntry2Ex(0, &iface); err != nil || iface.OperStatus != windows.IfOperStatusUp {
				continue
			}
			ip := windows.MibIpInterfaceRow{Family: af, InterfaceLuid: row.InterfaceLuid, InterfaceIndex: row.InterfaceIndex}
			if err := windows.GetIpInterfaceEntry(&ip); err != nil || ip.Connected == 0 {
				continue
			}
			score := uint64(row.Metric) + uint64(ip.Metric)
			if score >= cost {
				continue
			}
			kind := "unknown"
			switch iface.Type {
			case windows.IF_TYPE_ETHERNET_CSMACD:
				kind = "ethernet"
			case windows.IF_TYPE_IEEE80211:
				kind = "wifi"
			}
			gateway := ""
			switch row.NextHop.Family {
			case windows.AF_INET:
				address := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop))
				gateway = net.IP(address.Addr[:]).String()
			case windows.AF_INET6:
				address := (*windows.RawSockaddrInet6)(unsafe.Pointer(&row.NextHop))
				gateway = net.IP(address.Addr[:]).String()
			default:
				continue
			}
			selected = networkRoute{index: int(row.InterfaceIndex), gateway: gateway, kind: kind}
			cost = score
		}
		windows.FreeMibTable(unsafe.Pointer(table))
		if selected.index != 0 {
			return selected, nil
		}
	}
	return networkRoute{}, fmt.Errorf("no default network route")
}
