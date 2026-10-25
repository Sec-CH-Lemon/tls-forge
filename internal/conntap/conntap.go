// Package conntap lets whoever makes a request see the connections it goes
// out on: each TCP connection dialed for it, as it is dialed, each QUIC
// connection made for it, datagram by datagram, and each one it goes out on,
// made for it or for another before it. The request's context carries the
// tap to the dialers and to the hook that hears of a connection.
package conntap

import (
	"context"
	"net"
	"time"
)

// A Tap is told of a request's connections.
type Tap interface {
	// Dialed is a connection dialed for the request, the dial having begun
	// at began. What it returns goes out in its place, so that the tap sees
	// what goes over it.
	Dialed(conn net.Conn, began time.Time) net.Conn
	// QUIC is a QUIC connection made for the request, its socket's from
	// local to remote, the dial having begun at began: what it returns is
	// told of every datagram the socket writes and reads.
	QUIC(local, remote net.Addr, began time.Time) Datagrams
	// Used is a connection the request goes out on.
	Used(conn net.Conn)
}

// Datagrams is told of what a QUIC connection's socket wrote and read, a
// datagram at a time, and of its end. What it is given it may not keep.
type Datagrams interface {
	Wrote(b []byte)
	Read(b []byte)
	Closed()
}

type key struct{}

// With is ctx carrying t.
func With(ctx context.Context, t Tap) context.Context {
	return context.WithValue(ctx, key{}, t)
}

// From is the tap ctx carries, or nil.
func From(ctx context.Context) Tap {
	t, _ := ctx.Value(key{}).(Tap)
	return t
}
