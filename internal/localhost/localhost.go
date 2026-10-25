// Package localhost listens where localhost leads: at both loopback addresses,
// on one port.
package localhost

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// Tries is how many ports Listen tries at most.
const Tries = 16

// ErrNoIPv6 is Listen's when [::1] takes no port at all, as on a machine
// without an IPv6 loopback address.
var ErrNoIPv6 = errors.New("no IPv6 loopback address")

// Listen listens, through listen, at 127.0.0.1 and at [::1] on one port the
// system picks. localhost names both, and a client of it may try [::1] first,
// as Chrome does and Go's resolver on macOS: whatever holds the port there is
// what it reaches.
//
// The system gives a port no socket holds at the address it is asked for,
// which a socket may hold at the other. Measured on macOS (2026-10-25): with
// [::1] crowded by sockets of IPv6 alone, as another program's node ones are,
// half the ports it gave at 127.0.0.1 were taken at [::1], and one in a
// thousand the other way round; with 127.0.0.1 crowded, a quarter of those it
// gave at [::1] were taken at 127.0.0.1, and none the other way. So the first
// try asks 127.0.0.1 first, where a test's servers and connections are, a
// port taken at the other address is let go of, and the next try asks the
// other address first, Tries times at most.
func Listen(listen func(network, address string) (net.Listener, error)) (v4, v6 net.Listener, err error) {
	for try := range Tries {
		first, second := "127.0.0.1", "::1"
		if try%2 == 1 {
			first, second = second, first
		}
		var a, b net.Listener
		if a, err = listen("tcp", net.JoinHostPort(first, "0")); err != nil {
			if first == "::1" {
				return nil, nil, fmt.Errorf("%w: %w", ErrNoIPv6, err)
			}
			return nil, nil, err
		}
		port := strconv.Itoa(a.Addr().(*net.TCPAddr).Port)
		if b, err = listen("tcp", net.JoinHostPort(second, port)); err == nil {
			if first == "::1" {
				return b, a, nil
			}
			return a, b, nil
		}
		_ = a.Close()
	}
	return nil, nil, err
}

// Joined listens through listen as Listen does, and is its two listeners as
// one, as a server that takes one listener serves them (httptest, http.Serve):
// Accept gives what either accepts, Addr is 127.0.0.1's, which such a server's
// URL then names, and Close closes both. A test's server that listened at
// 127.0.0.1 alone, its client asking for it by localhost, lost the client now
// and then to another program's socket at [::1] on its port (2026-10-25: "http:
// server gave HTTP response to HTTPS client"). Where [::1] takes no port
// (ErrNoIPv6), nothing can hold one there: 127.0.0.1's listener alone.
func Joined(listen func(network, address string) (net.Listener, error)) (net.Listener, error) {
	v4, v6, err := Listen(listen)
	switch {
	case errors.Is(err, ErrNoIPv6):
		return listen("tcp", "127.0.0.1:0")
	case err != nil:
		return nil, err
	}
	j := &joined{v4: v4, v6: v6, accepted: make(chan acceptance), closed: make(chan struct{})}
	go j.take(v4)
	go j.take(v6)
	return j, nil
}

// joined is two listeners as one.
type joined struct {
	v4, v6 net.Listener
	// accepted carries what either listener's Accept came back with to
	// Accept, one at a time.
	accepted chan acceptance
	// closed is closed by Close; from then on what nothing takes is let go of.
	closed  chan struct{}
	closing sync.Once
}

// acceptance is what one Accept came back with.
type acceptance struct {
	conn net.Conn
	err  error
}

// take hands Accept what l's Accept comes back with, each in turn: a failure
// as well, as l would hand it, for Accept's caller to wait out or stop at, as
// http.Server does either, and to be told again when it asks again. Once j is
// closed, what nothing takes is let go of, and take ends.
func (j *joined) take(l net.Listener) {
	for {
		conn, err := l.Accept()
		select {
		case j.accepted <- acceptance{conn, err}:
		case <-j.closed:
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
	}
}

// Accept is the next connection either listener accepted, or the next failure
// one came back with; net.ErrClosed once j is closed.
func (j *joined) Accept() (net.Conn, error) {
	select {
	case a := <-j.accepted:
		return a.conn, a.err
	case <-j.closed:
		return nil, net.ErrClosed
	}
}

// Close closes both listeners, and lets go of what they accept after.
func (j *joined) Close() error {
	j.closing.Do(func() { close(j.closed) })
	return errors.Join(j.v4.Close(), j.v6.Close())
}

// Addr is 127.0.0.1's, on the port both listen on.
func (j *joined) Addr() net.Addr { return j.v4.Addr() }
