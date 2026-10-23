package tlsforge

import "syscall"

// The socket options a connection is probed by while idle, and what the
// system gives one that sets none, on macOS.
const tcpKeepIdle = syscall.TCP_KEEPALIVE

func systemKeepAlive() (interval, count int, err error) {
	ms, err := syscall.SysctlUint32("net.inet.tcp.keepintvl")
	if err != nil {
		return 0, 0, err
	}
	n, err := syscall.SysctlUint32("net.inet.tcp.keepcnt")
	return int(ms / 1000), int(n), err
}
