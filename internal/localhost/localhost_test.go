package localhost

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// taken is what l's Accept comes back with within a few seconds.
func taken(l net.Listener) (net.Conn, error) {
	got := make(chan acceptance, 1)
	go func() {
		conn, err := l.Accept()
		got <- acceptance{conn, err}
	}()
	select {
	case a := <-got:
		return a.conn, a.err
	case <-time.After(5 * time.Second):
		return nil, errors.New("nothing accepted")
	}
}

// goroutinesBackTo fails the test unless the goroutines are as many as before
// within a few seconds.
func goroutinesBackTo(t *testing.T, before int) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); runtime.NumGoroutine() > before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			stacks := make([]byte, 1<<16)
			t.Fatalf("%d goroutines, %d before:\n%s", runtime.NumGoroutine(), before, stacks[:runtime.Stack(stacks, true)])
		}
	}
}

func TestJoinedAcceptsAtBothAddressesOnOnePort(t *testing.T) {
	before := runtime.NumGoroutine()
	ln, err := Joined(net.Listen)
	if err != nil {
		t.Fatalf("Joined: %v", err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if got := ln.Addr().String(); got != "127.0.0.1:"+port {
		t.Errorf("says it is at %s", got)
	}
	// A connection to either address is accepted, each as it comes.
	addrs := []string{"127.0.0.1:" + port, "[::1]:" + port}
	for _, addr := range addrs {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		theirs, err := taken(ln)
		if err != nil || theirs.RemoteAddr().String() != conn.LocalAddr().String() {
			t.Errorf("%s accepted %v, %v", addr, theirs, err)
		}
		_ = conn.Close()
		if theirs != nil {
			_ = theirs.Close()
		}
	}
	// Closed, neither address takes a connection, what took them for Accept
	// ends, and Accept says it is closed; closed again, it says so, and does
	// not panic.
	if err := ln.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	for _, addr := range addrs {
		if conn, err := net.Dial("tcp", addr); err == nil {
			_ = conn.Close()
			t.Errorf("%s is listened at after Close", addr)
		}
	}
	goroutinesBackTo(t, before)
	if conn, err := taken(ln); conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close: %v, %v", conn, err)
	}
	if err := ln.Close(); err == nil {
		t.Error("closed twice, and said nothing")
	}
}

func TestWithoutIPv6JoinedIs127001sListenerAlone(t *testing.T) {
	// No port at [::1]: the port had at 127.0.0.1 let go of, as Listen does,
	// and another asked for there alone.
	a := &asking{refuse: func(_ int, address string) bool { return strings.HasPrefix(address, "[::1]:") }}
	ln, err := Joined(a.listen)
	if err != nil {
		t.Fatalf("Joined: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if len(a.asked) != 4 || !slices.Equal(a.asked[2:], []string{"[::1]:0", "127.0.0.1:0"}) || len(a.given) != 2 ||
		!a.given[0].closed || ln != net.Listener(a.given[1]) {
		t.Errorf("asked %v, listening with %v", a.asked, ln)
	}
}

func TestJoinedSaysWhyItListensNowhere(t *testing.T) {
	a := &asking{refuse: func(_ int, address string) bool { return strings.HasPrefix(address, "127.0.0.1:") }}
	if ln, err := Joined(a.listen); ln != nil || !errors.Is(err, errRefused) || errors.Is(err, ErrNoIPv6) ||
		len(a.asked) != 1 {
		t.Errorf("Joined: %v, %v, after asking %v", ln, err, a.asked)
	}
}

// handed is a listener whose Accept comes back with what the test hands it,
// and with net.ErrClosed once it is closed.
type handed struct {
	addr   *net.TCPAddr
	gives  chan acceptance
	closed chan struct{}
	once   sync.Once
}

func (h *handed) Accept() (net.Conn, error) {
	select {
	case a := <-h.gives:
		return a.conn, a.err
	case <-h.closed:
		return nil, net.ErrClosed
	}
}

func (h *handed) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}

func (h *handed) Addr() net.Addr { return h.addr }

// handing is a listen that gives a handed listener at each address it is
// asked for, on port 4242 where the system would pick one.
type handing struct{ given []*handed }

func (h *handing) listen(_, address string) (net.Listener, error) {
	host, port, _ := net.SplitHostPort(address)
	n, _ := strconv.Atoi(port)
	if n == 0 {
		n = 4242
	}
	l := &handed{addr: &net.TCPAddr{IP: net.ParseIP(host), Port: n}, gives: make(chan acceptance),
		closed: make(chan struct{})}
	h.given = append(h.given, l)
	return l, nil
}

func TestJoinedSaysWhatEitherListenerCameBackWith(t *testing.T) {
	// A failure that passes, as running out of descriptors, then a
	// connection: Accept says each in turn, as the listener would have.
	h := &handing{}
	ln, err := Joined(h.listen)
	if err != nil || len(h.given) != 2 {
		t.Fatalf("Joined: %v, given %v", err, h.given)
	}
	defer func() { _ = ln.Close() }()
	exhausted := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	ours, theirs := net.Pipe()
	defer func() { _ = theirs.Close() }()
	go func() {
		h.given[1].gives <- acceptance{err: exhausted}
		h.given[1].gives <- acceptance{conn: ours}
	}()
	if conn, err := taken(ln); conn != nil || !errors.Is(err, syscall.EMFILE) {
		t.Errorf("first: %v, %v", conn, err)
	}
	if conn, err := taken(ln); conn != ours || err != nil {
		t.Errorf("then: %v, %v", conn, err)
	}
}

func TestWhatNothingTookIsLetGoOfOnceJoinedIsClosed(t *testing.T) {
	// A connection each listener accepted and Accept was not asked for:
	// closing lets go of both.
	h := &handing{}
	ln, err := Joined(h.listen)
	if err != nil || len(h.given) != 2 {
		t.Fatalf("Joined: %v, given %v", err, h.given)
	}
	var theirs []net.Conn
	for i, l := range h.given {
		ours, other := net.Pipe()
		theirs = append(theirs, other)
		select {
		case l.gives <- acceptance{conn: ours}:
		case <-time.After(5 * time.Second):
			t.Fatalf("nothing accepted on listener %d", i)
		}
	}
	if err := ln.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	for i, conn := range theirs {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("the connection listener %d accepted: %v", i, err)
		}
		_ = conn.Close()
	}
}
