package tlsforge

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func systemNetworkRoute(families []string) (networkRoute, error) {
	return linuxNetworkRoute(families, os.ReadFile, os.Stat, net.InterfaceByName)
}

func linuxNetworkRoute(families []string, readFile func(string) ([]byte, error), stat func(string) (os.FileInfo, error), interfaceOf func(string) (*net.Interface, error)) (networkRoute, error) {
	for _, family := range families {
		path := "/proc/net/route"
		if family == "ipv6" {
			path = "/proc/net/ipv6_route"
		}
		raw, err := readFile(path)
		if err != nil {
			continue
		}
		name, gateway, ok := linuxDefaultRoute(string(raw), family)
		if !ok {
			continue
		}
		iface, err := interfaceOf(name)
		if err != nil {
			return networkRoute{}, err
		}
		kind := "unknown"
		if _, err := stat(filepath.Join("/sys/class/net", name, "wireless")); err == nil {
			kind = "wifi"
		} else if raw, err := readFile(filepath.Join("/sys/class/net", name, "type")); err == nil && strings.TrimSpace(string(raw)) == "1" {
			kind = "ethernet"
		}
		return networkRoute{index: iface.Index, gateway: gateway, kind: kind}, nil
	}
	return networkRoute{}, fmt.Errorf("no default network route")
}
func linuxDefaultRoute(raw, family string) (string, string, bool) {
	var name, gateway string
	var metric uint64 = ^uint64(0)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		var candidate, nextHop string
		var cost, flags uint64
		var err, errorFlags error
		if family == "ipv4" {
			if len(fields) < 11 || fields[1] != "00000000" || fields[7] != "00000000" {
				continue
			}
			candidate = fields[0]
			nextHop = fields[2]
			cost, err = strconv.ParseUint(fields[6], 10, 64)
			flags, errorFlags = strconv.ParseUint(fields[3], 16, 64)
		} else {
			if len(fields) != 10 || fields[0] != strings.Repeat("0", 32) || fields[1] != "00" {
				continue
			}
			candidate = fields[9]
			nextHop = fields[4]
			cost, err = strconv.ParseUint(fields[5], 16, 64)
			flags, errorFlags = strconv.ParseUint(fields[8], 16, 64)
		}
		if err != nil || errorFlags != nil || flags&1 == 0 || flags&0x200 != 0 || cost >= metric {
			continue
		}
		name, gateway, metric = candidate, nextHop, cost
	}
	return name, gateway, name != ""
}
