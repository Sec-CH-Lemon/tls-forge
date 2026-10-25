package localhost

import (
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// told is a listener that says it is at addr when addr is set, and keeps
// whether it was closed.
type told struct {
	net.Listener
	addr   net.Addr
	closed bool
}

func (l *told) Addr() net.Addr {
	if l.addr == nil {
		return l.Listener.Addr()
	}
	return l.addr
}

func (l *told) Close() error {
	l.closed = true
	return l.Listener.Close()
}

var errRefused = errors.New("no")

// asking is a listen that keeps what it was asked and gives a told listener
// for each address it does not refuse: refuse says, by the order of the calls,
// which it refuses, and lie, by the order the listeners were given, the port
// one says it is at.
type asking struct {
	asked  []string
	given  []*told
	refuse func(call int, address string) bool
	lie    map[int]int
}

func (a *asking) listen(network, address string) (net.Listener, error) {
	call := len(a.asked)
	a.asked = append(a.asked, address)
	if a.refuse != nil && a.refuse(call, address) {
		return nil, errRefused
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	l := &told{Listener: ln}
	if port, ok := a.lie[len(a.given)]; ok {
		l.addr = &net.TCPAddr{IP: ln.Addr().(*net.TCPAddr).IP, Port: port}
	}
	a.given = append(a.given, l)
	return l, nil
}

// accepted is the connection l accepts within a few seconds: a dial that
// reached another listener is not waited for.
func accepted(l net.Listener) (net.Conn, error) {
	if t, ok := l.(*told); ok {
		l = t.Listener
	}
	_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	return l.Accept()
}

// onOnePort fails the test unless v4 and v6 listen at 127.0.0.1 and at [::1]
// on one port and answer there, and closes them.
func onOnePort(t *testing.T, v4, v6 net.Listener) {
	t.Helper()
	defer func() { _ = v4.Close() }()
	defer func() { _ = v6.Close() }()
	port := strconv.Itoa(v4.Addr().(*net.TCPAddr).Port)
	for _, l := range []struct {
		ln   net.Listener
		addr string
	}{{v4, "127.0.0.1:" + port}, {v6, "[::1]:" + port}} {
		if got := l.ln.Addr().String(); got != l.addr {
			t.Errorf("listening at %s, not %s", got, l.addr)
			continue
		}
		conn, err := net.Dial("tcp", l.addr)
		if err != nil {
			t.Errorf("dial %s: %v", l.addr, err)
			continue
		}
		theirs, err := accepted(l.ln)
		if err != nil || theirs.RemoteAddr().String() != conn.LocalAddr().String() {
			t.Errorf("%s accepted %v, %v", l.addr, theirs, err)
		}
		_ = conn.Close()
		if theirs != nil {
			_ = theirs.Close()
		}
	}
}

func TestBothAddressesAreListenedAtOnOnePort(t *testing.T) {
	a := &asking{}
	v4, v6, err := Listen(a.listen)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	onOnePort(t, v4, v6)
	// 127.0.0.1 first, as it is the crowded one.
	if a.asked[0] != "127.0.0.1:0" {
		t.Errorf("asked %v", a.asked)
	}
}

func TestAPortASocketHoldsAtTheOtherAddressIsLetGoOf(t *testing.T) {
	// The port the system gives at 127.0.0.1 is one a socket holds at [::1]:
	// let go of, and the next try asks [::1] first.
	held, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = held.Close() }()
	port := held.Addr().(*net.TCPAddr).Port
	a := &asking{lie: map[int]int{0: port}}
	v4, v6, err := Listen(a.listen)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	onOnePort(t, v4, v6)
	if len(a.asked) < 4 || !slices.Equal(a.asked[:3], []string{"127.0.0.1:0", "[::1]:" + strconv.Itoa(port), "[::1]:0"}) ||
		!a.given[0].closed {
		t.Errorf("asked %v, the port held at [::1] let go of: %v", a.asked, a.given[0].closed)
	}

	// The port it gives at [::1] is one a socket holds at 127.0.0.1: let go of,
	// and the next try asks 127.0.0.1 first.
	held, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = held.Close() }()
	port = held.Addr().(*net.TCPAddr).Port
	// The first try's port is refused at [::1], so that the second asks
	// [::1] first, and is given the port held.
	a = &asking{refuse: func(call int, _ string) bool { return call == 1 }, lie: map[int]int{1: port}}
	v4, v6, err = Listen(a.listen)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	onOnePort(t, v4, v6)
	if len(a.asked) < 6 || !slices.Equal(a.asked[2:5], []string{"[::1]:0", "127.0.0.1:" + strconv.Itoa(port), "127.0.0.1:0"}) ||
		!a.given[0].closed || !a.given[1].closed {
		t.Errorf("asked %v, let go of: %v and %v", a.asked, a.given[0].closed, a.given[1].closed)
	}
}

func TestAPortTakenAtTheOtherAddressOnEveryTryIsSaid(t *testing.T) {
	// Every second listen is refused: as many ports as Listen tries, each let
	// go of, each try asking the other address first, and the last refusal
	// said.
	a := &asking{refuse: func(call int, _ string) bool { return call%2 == 1 }}
	if _, _, err := Listen(a.listen); !errors.Is(err, errRefused) || errors.Is(err, ErrNoIPv6) {
		t.Errorf("Listen: %v", err)
	}
	if len(a.asked) != 2*Tries || len(a.given) != Tries {
		t.Fatalf("asked %d times, given %d", len(a.asked), len(a.given))
	}
	for i, l := range a.given {
		if first := []string{"127.0.0.1:0", "[::1]:0"}[i%2]; a.asked[2*i] != first || !l.closed {
			t.Errorf("try %d asked %s first, let go of: %v", i, a.asked[2*i], l.closed)
		}
	}
}

func TestAnAddressThatTakesNoPortIsSaidAtOnce(t *testing.T) {
	// No port at 127.0.0.1 is no port, whatever [::1] would say.
	a := &asking{refuse: func(_ int, address string) bool { return strings.HasPrefix(address, "127.0.0.1:") }}
	if _, _, err := Listen(a.listen); !errors.Is(err, errRefused) || errors.Is(err, ErrNoIPv6) || len(a.asked) != 1 {
		t.Errorf("Listen: %v, after asking %v", err, a.asked)
	}
	// None at [::1], even on a port it picks, is no IPv6 loopback address:
	// said as such, the port had at 127.0.0.1 let go of.
	a = &asking{refuse: func(_ int, address string) bool { return strings.HasPrefix(address, "[::1]:") }}
	if _, _, err := Listen(a.listen); !errors.Is(err, ErrNoIPv6) || !errors.Is(err, errRefused) ||
		len(a.asked) != 3 || a.asked[2] != "[::1]:0" || !a.given[0].closed {
		t.Errorf("Listen: %v, after asking %v", err, a.asked)
	}
}
