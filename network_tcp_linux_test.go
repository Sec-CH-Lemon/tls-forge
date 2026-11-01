package tlsforge

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type networkTestLinuxSocket struct {
	net.Conn
	raw syscall.RawConn
	err error
}

func (c networkTestLinuxSocket) SyscallConn() (syscall.RawConn, error) { return c.raw, c.err }

type networkTestLinuxRaw struct{ err error }

func (c networkTestLinuxRaw) Control(f func(uintptr)) error {
	if c.err != nil {
		return c.err
	}
	f(42)
	return nil
}
func (networkTestLinuxRaw) Read(func(uintptr) bool) error  { return os.ErrInvalid }
func (networkTestLinuxRaw) Write(func(uintptr) bool) error { return os.ErrInvalid }

func TestLinuxTCPInfoRejectsUnavailableAndPreservesUnits(t *testing.T) {
	a, z := net.Pipe()
	defer a.Close()
	defer z.Close()
	failure := errors.New("socket metadata unavailable")
	for _, c := range []struct {
		name string
		conn net.Conn
		info *unix.TCPInfo
		err  error
		want time.Duration
	}{
		{name: "not a physical socket", conn: a},
		{name: "descriptor unavailable", conn: networkTestLinuxSocket{err: failure}},
		{name: "control fails", conn: networkTestLinuxSocket{raw: networkTestLinuxRaw{err: failure}}},
		{name: "syscall fails", conn: networkTestLinuxSocket{raw: networkTestLinuxRaw{}}, err: failure},
		{name: "no info", conn: networkTestLinuxSocket{raw: networkTestLinuxRaw{}}},
		{name: "no measured RTT", conn: networkTestLinuxSocket{raw: networkTestLinuxRaw{}}, info: &unix.TCPInfo{}},
		{name: "microseconds", conn: networkTestLinuxSocket{raw: networkTestLinuxRaw{}}, info: &unix.TCPInfo{Rtt: 1234}, want: 1234 * time.Microsecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			read := func(fd, level, opt int) (*unix.TCPInfo, error) {
				if fd != 42 || level != unix.IPPROTO_TCP || opt != unix.TCP_INFO {
					t.Fatal(fd, level, opt)
				}
				return c.info, c.err
			}
			got, ok := networkTCPRTTFrom(c.conn, read)
			if got != c.want || ok != (c.want > 0) {
				t.Fatal(got, ok, c.want)
			}
		})
	}
}

func TestLinuxTCPInfoReadsTheOwnedEstablishedSocket(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			failed <- e
			return
		}
		accepted <- c
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var peer net.Conn
	select {
	case peer = <-accepted:
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("owned TCP handshake did not complete")
	}
	defer peer.Close()
	rtt, ok := networkTCPRTT(c)
	if !ok || rtt <= 0 {
		t.Fatal("actual established TCP_INFO RTT unavailable", rtt, ok)
	}
}
