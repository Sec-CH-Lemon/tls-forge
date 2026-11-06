//go:build unix

package tlsforge

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// peerClosed says, as tls-client's connected asks, whether the server of the
// socket under conn, looked at through each NetConn, has closed it; false too
// where no socket can be looked at, which tls-client takes as connected.
func peerClosed(conn net.Conn) bool {
	for {
		if socket, ok := conn.(syscall.Conn); ok {
			raw, err := socket.SyscallConn()
			if err != nil {
				return false
			}
			closed := false
			_ = raw.Read(func(fd uintptr) bool {
				var b [1]byte
				n, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
				closed = n == 0 && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK)
				return true
			})
			return closed
		}
		inner, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			return false
		}
		conn = inner.NetConn()
	}
}

func TestAnECHConnectionLetsItsSocketBeLookedAt(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := echConn{Conn: conn, configs: []byte{1}}
	if peerClosed(wrapped) {
		t.Fatal("a connection its server keeps is closed")
	}
	// The server lets go of it: what lost a race and waits to be taken up is
	// seen to be gone, not taken for alive for its minute.
	server.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !peerClosed(wrapped) {
		if time.Now().After(deadline) {
			t.Fatal("a connection its server closed is not seen to be")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
