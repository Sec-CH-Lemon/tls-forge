package tlsforge

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// The socket options a connection is probed by while idle, and what the
// system gives one that sets none, on Linux.
const tcpKeepIdle = syscall.TCP_KEEPIDLE

func systemKeepAlive() (interval, count int, err error) {
	read := func(name string) (int, error) {
		b, err := os.ReadFile("/proc/sys/net/ipv4/" + name)
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if interval, err = read("tcp_keepalive_intvl"); err != nil {
		return 0, 0, err
	}
	count, err = read("tcp_keepalive_probes")
	return interval, count, err
}
