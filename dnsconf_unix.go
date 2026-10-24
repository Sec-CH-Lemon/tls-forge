//go:build !windows

package tlsforge

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

// resolvConf is where the machine's DNS servers are said.
var resolvConf = "/etc/resolv.conf"

// machineDNSServers are the DNS servers the machine asks, as resolv.conf
// names them, each on port 53; none when it names none.
func machineDNSServers() []string {
	var servers []string
	if f, err := os.Open(resolvConf); err == nil {
		defer func() { _ = f.Close() }()
		lines := bufio.NewScanner(f)
		for lines.Scan() {
			fields := strings.Fields(lines.Text())
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			if addr, err := netip.ParseAddr(fields[1]); err == nil {
				servers = append(servers, net.JoinHostPort(addr.String(), "53"))
			}
		}
	}
	return servers
}
