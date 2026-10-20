// Package conntap lets whoever makes a request see the TCP connections it
// goes out on: each one dialed for it, as it is dialed, and each one it goes
// out on, dialed for it or for another before it. The request's context
// carries the tap to the dialers and to the hook that hears of a connection.
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
	// Used is a connection the request goes out on.
	Used(conn net.Conn)
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
