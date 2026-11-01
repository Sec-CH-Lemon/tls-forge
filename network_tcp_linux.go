package tlsforge

import (
	"golang.org/x/sys/unix"
	"net"
	"syscall"
	"time"
)

func networkTCPRTT(conn net.Conn) (time.Duration, bool) {
	c, ok := conn.(syscall.Conn)
	if !ok {
		return 0, false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, false
	}
	var info *unix.TCPInfo
	var inner error
	err = raw.Control(func(fd uintptr) { info, inner = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) })
	if err != nil || inner != nil || info == nil || info.Rtt == 0 {
		return 0, false
	}
	return time.Duration(info.Rtt) * time.Microsecond, true
}
