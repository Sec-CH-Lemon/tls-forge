package tlsforge

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestLinuxDefaultRouteParsesBothKernelFormats(t *testing.T) {
	ipv4 := func(name, gateway, cost, flags string) string {
		return fmt.Sprintf("%s 00000000 %s %s 0 0 %s 00000000 0 0 0\n", name, gateway, flags, cost)
	}
	zero := strings.Repeat("0", 32)
	ipv6 := func(name, gateway, cost, flags string) string {
		return fmt.Sprintf("%s 00 %s 00 %s %s 0 0 %s %s\n", zero, zero, gateway, cost, flags, name)
	}
	for _, c := range []struct{ name, family, raw, want, gw string }{
		{"ipv4 metric/up/reject", "ipv4", "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" + ipv4("down", "01", "1", "0") + ipv4("reject", "02", "1", "201") + ipv4("badcost", "03", "bad", "1") + ipv4("badflags", "04", "1", "badflags") + ipv4("high", "05", "99", "1") + ipv4("low", "06", "2", "3") + ipv4("equal", "07", "2", "1"), "low", "06"},
		{"ipv4 nondefault", "ipv4", "eth0 00000001 01 1 0 0 1 00000000 0 0 0\neth0 00000000 01 1 0 0 1 FFFFFFFF 0 0 0\nshort\n", "", ""},
		{"ipv6 metric/up/reject", "ipv6", ipv6("down", zero, "1", "0") + ipv6("reject", zero, "1", "201") + ipv6("badcost", zero, "z", "1") + ipv6("badflags", zero, "1", "z") + ipv6("high", zero, "ff", "1") + ipv6("low", "00000000000000000000000000000001", "a", "1") + ipv6("equal", zero, "a", "1"), "low", "00000000000000000000000000000001"},
		{"ipv6 nondefault", "ipv6", strings.Replace(ipv6("nondefault", zero, "1", "1"), " 00 ", " 80 ", 1) + strings.Replace(ipv6("destination", zero, "1", "1"), zero, strings.Repeat("f", 32), 1) + "short\n", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			name, gw, ok := linuxDefaultRoute(c.raw, c.family)
			if name != c.want || gw != c.gw || ok != (c.want != "") {
				t.Fatal(name, gw, ok)
			}
		})
	}
}

func TestLinuxRouteReadsActualFamilyAndInterfaceMetadata(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	zero := strings.Repeat("0", 32)
	v4 := "owned0 00000000 0100007F 0003 0 0 4 00000000 0 0 0\n"
	v6 := fmt.Sprintf("%s 00 %s 00 %s 00000004 0 0 00000001 owned0\n", zero, zero, zero)
	failure := errors.New("interface unavailable")
	for _, c := range []struct {
		name, kind                                               string
		wifi, missing4, invalid4, noRoutes, badInterface, noType bool
		hw                                                       string
	}{
		{name: "ethernet", kind: "ethernet", hw: "1\n"},
		{name: "wifi", kind: "wifi", wifi: true},
		{name: "other hardware", kind: "unknown", hw: "772"},
		{name: "missing type", kind: "unknown", noType: true},
		{name: "next family on read error", kind: "ethernet", missing4: true, hw: "1"},
		{name: "next family on no default", kind: "ethernet", invalid4: true, hw: "1"},
		{name: "no routes", noRoutes: true},
		{name: "missing interface", badInterface: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var routes []string
			read := func(path string) ([]byte, error) {
				switch path {
				case "/proc/net/route":
					routes = append(routes, path)
					if c.noRoutes || c.missing4 {
						return nil, os.ErrNotExist
					}
					if c.invalid4 {
						return []byte("not a default route"), nil
					}
					return []byte(v4), nil
				case "/proc/net/ipv6_route":
					routes = append(routes, path)
					if c.noRoutes {
						return nil, os.ErrNotExist
					}
					return []byte(v6), nil
				case "/sys/class/net/owned0/type":
					if c.noType {
						return nil, os.ErrNotExist
					}
					return []byte(c.hw), nil
				default:
					t.Fatalf("unexpected metadata path %q", path)
					return nil, os.ErrNotExist
				}
			}
			stat := func(path string) (os.FileInfo, error) {
				if path != "/sys/class/net/owned0/wireless" {
					t.Fatalf("unexpected path %q", path)
				}
				if c.wifi {
					return info, nil
				}
				return nil, os.ErrNotExist
			}
			iface := func(name string) (*net.Interface, error) {
				if name != "owned0" {
					t.Fatal(name)
				}
				if c.badInterface {
					return nil, failure
				}
				return &net.Interface{Index: 7}, nil
			}
			route, err := linuxNetworkRoute([]string{"ipv4", "ipv6"}, read, stat, iface)
			if c.noRoutes {
				if err == nil {
					t.Fatal("absent routes accepted")
				}
				return
			}
			if c.badInterface {
				if !errors.Is(err, failure) {
					t.Fatal(err)
				}
				return
			}
			if err != nil || route.index != 7 || route.kind != c.kind {
				t.Fatal(route, err)
			}
			if len(routes) == 0 || routes[0] != "/proc/net/route" {
				t.Fatal("family preference lost", routes)
			}
			if c.missing4 || c.invalid4 {
				if len(routes) != 2 || route.gateway != zero {
					t.Fatal("IPv6 fallback lost", route, routes)
				}
			} else if len(routes) != 1 || route.gateway != "0100007F" {
				t.Fatal(route, routes)
			}
		})
	}
}
