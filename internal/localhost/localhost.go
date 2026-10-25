// Package localhost listens where localhost leads: at both loopback addresses,
// on one port.
package localhost

import (
	"errors"
	"fmt"
	"net"
	"strconv"
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
