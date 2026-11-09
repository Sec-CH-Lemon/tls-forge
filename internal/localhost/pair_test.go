package localhost

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestAUDPSocketAndATCPListenerShareAPort(t *testing.T) {
	udp, tcp, err := UDPAndTCP(net.ListenPacket, net.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	defer tcp.Close()
	if u, l := udp.LocalAddr().(*net.UDPAddr), tcp.Addr().(*net.TCPAddr); u.Port != l.Port || !u.IP.Equal(net.IPv4(127, 0, 0, 1)) || !l.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("UDP at %s, TCP at %s", u, l)
	}
	// both are what they say: a datagram comes, a connection is taken
	sender, err := net.Dial("udp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _, err := udp.ReadFrom(make([]byte, 8)); err != nil || n != 2 {
		t.Fatalf("read %d: %v", n, err)
	}
	conn, err := net.Dial("tcp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if c, err := accepted(tcp); err != nil {
		t.Fatal(err)
	} else {
		_ = c.Close()
	}
}

// heldPacket and heldListener are a socket and a listener ports gives, at a
// port, which keep whether they were closed.
type heldPacket struct {
	net.PacketConn
	port   int
	closed bool
}

func (p *heldPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p.port}
}
func (p *heldPacket) Close() error { p.closed = true; return nil }

type heldListener struct {
	net.Listener
	port   int
	closed bool
}

func (l *heldListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: l.port} }
func (l *heldListener) Close() error   { l.closed = true; return nil }

// errForbidden is what Windows says of a port in a range kept from programs.
var errForbidden = errors.New("bind: An attempt was made to access a socket in a way forbidden by its access permissions")

// ports gives each protocol its ports, from where its next starts, one
// after another, as Windows gives UDP's, refuses the ports a protocol may
// not have, and keeps what it was asked and what it gave.
type ports struct {
	next    map[string]int
	refused map[string]func(port int) bool
	asked   []string
	packets []*heldPacket
	held    []*heldListener
	// broken is a protocol that takes no port at all
	broken string
}

func (p *ports) port(network, address string) (int, error) {
	p.asked = append(p.asked, network+" "+address)
	if network == p.broken {
		return 0, errRefused
	}
	_, s, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(s)
	if port == 0 {
		port = p.next[network]
		p.next[network]++
	}
	if refused := p.refused[network]; refused != nil && refused(port) {
		return 0, fmt.Errorf("listen %s %s: %w", network, address, errForbidden)
	}
	return port, nil
}

func (p *ports) listenPacket(network, address string) (net.PacketConn, error) {
	port, err := p.port(network, address)
	if err != nil {
		return nil, err
	}
	c := &heldPacket{port: port}
	p.packets = append(p.packets, c)
	return c, nil
}

func (p *ports) listen(network, address string) (net.Listener, error) {
	port, err := p.port(network, address)
	if err != nil {
		return nil, err
	}
	l := &heldListener{port: port}
	p.held = append(p.held, l)
	return l, nil
}

// within is whether a port is in a range of a hundred from first.
func within(first int) func(int) bool {
	return func(port int) bool { return port >= first && port < first+100 }
}

func TestAPortTheOtherProtocolMayNotHaveIsPassedOver(t *testing.T) {
	// UDP's ports one after another in a range TCP may not have: TCP's
	// own port, which UDP takes, on the second try
	p := &ports{next: map[string]int{"udp4": 49835, "tcp4": 50000}, refused: map[string]func(int) bool{"tcp4": within(49800)}}
	udp, tcp, err := UDPAndTCP(p.listenPacket, p.listen)
	if err != nil {
		t.Fatal(err)
	}
	if udp.LocalAddr().(*net.UDPAddr).Port != 50000 || tcp.Addr().(*net.TCPAddr).Port != 50000 {
		t.Errorf("UDP at %s, TCP at %s, want both at 50000", udp.LocalAddr(), tcp.Addr())
	}
	want := []string{"udp4 127.0.0.1:0", "tcp4 127.0.0.1:49835", "tcp4 127.0.0.1:0", "udp4 127.0.0.1:50000"}
	if !slices.Equal(p.asked, want) {
		t.Errorf("asked %q, want %q", p.asked, want)
	}
	if len(p.packets) != 2 || !p.packets[0].closed || p.packets[1].closed || len(p.held) != 1 || p.held[0].closed {
		t.Errorf("the port not taken let go of, the pair kept: %+v %+v", p.packets, p.held)
	}
}

func TestAPortNeitherProtocolTakesOnEveryTryIsSaid(t *testing.T) {
	// each protocol's ports, one after another, in a range the other may
	// not have
	p := &ports{next: map[string]int{"udp4": 49835, "tcp4": 50000},
		refused: map[string]func(int) bool{"tcp4": within(49800), "udp4": within(50000)}}
	udp, tcp, err := UDPAndTCP(p.listenPacket, p.listen)
	if udp != nil || tcp != nil || !errors.Is(err, errForbidden) || err.Error() != "listen udp4 127.0.0.1:50007: "+errForbidden.Error() {
		t.Fatalf("%v %v %v", udp, tcp, err)
	}
	if len(p.asked) != 2*Tries || len(p.packets) != Tries/2 || len(p.held) != Tries/2 {
		t.Errorf("asked %d times, %d sockets, %d listeners, want %d tries", len(p.asked), len(p.packets), len(p.held), Tries)
	}
	for _, c := range p.packets {
		if !c.closed {
			t.Errorf("UDP's %d kept", c.port)
		}
	}
	for _, l := range p.held {
		if !l.closed {
			t.Errorf("TCP's %d kept", l.port)
		}
	}
}

func TestAProtocolThatTakesNoPortIsSaidAtOnce(t *testing.T) {
	for _, broken := range []string{"udp4", "tcp4"} {
		// TCP is asked first on the second try
		p := &ports{next: map[string]int{"udp4": 49835, "tcp4": 50000}, refused: map[string]func(int) bool{"tcp4": within(49800)}, broken: broken}
		if broken == "udp4" {
			p.refused = nil
		}
		udp, tcp, err := UDPAndTCP(p.listenPacket, p.listen)
		if udp != nil || tcp != nil || !errors.Is(err, errRefused) {
			t.Errorf("%s: %v %v %v", broken, udp, tcp, err)
		}
		want := map[string]int{"udp4": 1, "tcp4": 3}[broken]
		if len(p.asked) != want {
			t.Errorf("%s: asked %q, want %d asks", broken, p.asked, want)
		}
		for _, c := range p.packets {
			if !c.closed {
				t.Errorf("%s: UDP's %d kept", broken, c.port)
			}
		}
	}
}
