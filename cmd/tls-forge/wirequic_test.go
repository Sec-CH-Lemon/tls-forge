package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls/http3"
	utls "github.com/igor-lemon/utls"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/Sec-CH-Lemon/tls-forge/internal/pcapng"
)

// h3NamesAt is a DNS server over UDP that finds every name at 127.0.0.1, with
// an HTTPS record naming h3 and h2 for it.
func h3NamesAt(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		for {
			buf := make([]byte, 1500)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
			switch q.Type {
			case dnsmessage.TypeA:
				_ = b.AResource(rh, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
			case dnsmessage.TypeHTTPS:
				// The record of _PORT._https.NAME names NAME, as Chrome takes one.
				name := q.Name.String()
				if parts := strings.SplitN(name, ".", 3); len(parts) == 3 && parts[1] == "_https" {
					name = parts[2]
				}
				svcb := dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName(name)}
				svcb.SetParam(dnsmessage.SVCParamALPN, []byte("\x02h3\x02h2"))
				_ = b.HTTPSResource(rh, dnsmessage.HTTPSResource{SVCBResource: svcb})
			}
			reply, _ := b.Finish()
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return pc.LocalAddr().String()
}

// lateHandshakes are a listener's connections, their first write late: TCP
// takes a round trip more than QUIC on a network, which loopback has not.
type lateHandshakes struct{ net.Listener }

func (l lateHandshakes) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return &lateFirstWrite{Conn: c}, err
}

type lateFirstWrite struct {
	net.Conn
	once sync.Once
}

func (c *lateFirstWrite) Write(b []byte) (int, error) {
	c.once.Do(func() { time.Sleep(150 * time.Millisecond) })
	return c.Conn.Write(b)
}

// h3Site is a site that answers with the protocol it is asked over, over TLS
// and TCP and over QUIC on one loopback port, writing the secrets of its QUIC
// connections to keys.
func h3Site(t *testing.T, keys io.Writer) string {
	t.Helper()
	var udp net.PacketConn
	var tcp net.Listener
	for tries := 1; ; tries++ {
		var err error
		if udp, err = net.ListenPacket("udp4", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if tcp, err = net.Listen("tcp4", udp.LocalAddr().String()); err == nil {
			break
		}
		_ = udp.Close()
		if tries == 10 {
			t.Fatal(err)
		}
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	server.Listener = lateHandshakes{tcp}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.TLS.Certificates[0]
	h3 := &http3.Server{Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}), TLSConfig: &utls.Config{Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos: []string{"h3"}, KeyLogWriter: keys}}
	go func() { _ = h3.Serve(udp) }()
	t.Cleanup(func() { _ = h3.Close(); _ = udp.Close() })
	_, port, _ := net.SplitHostPort(tcp.Addr().String())
	return port
}

func TestFetchKeepsAQUICConnectionsDatagramsAndItsSecretsInACapture(t *testing.T) {
	clock := fakeClock(t)
	var keys siteKeys
	port := h3Site(t, &keys)
	dir := filepath.Join(t.TempDir(), "out")
	code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--dns-server", h3NamesAt(t), "-o", dir,
		"--pcap", "https://h3.test:"+port+"/")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	name := "h3.test-" + stamp(clock.now())
	if page, err := os.ReadFile(filepath.Join(dir, name+"-1-response.txt")); err != nil || string(page) != "HTTP/3.0" {
		t.Fatalf("the page came over %q (%v), want HTTP/3", page, err)
	}
	capture := readCapture(t, filepath.Join(dir, name+"-1.pcapng"))
	t.Run("received-before-sent-callback", func(t *testing.T) {
		original, err := os.ReadFile(filepath.Join(dir, name+"-1.pcapng"))
		if err != nil {
			t.Fatal(err)
		}
		serverPort, err := strconv.Atoi(port)
		if err != nil {
			t.Fatal(err)
		}
		reordered := receivedFirstCapture(t, original, uint16(serverPort))
		path := filepath.Join(t.TempDir(), "received-first.pcapng")
		if err = os.WriteFile(path, reordered, 0600); err != nil {
			t.Fatal(err)
		}
		got := readCapture(t, path)
		if len(got.quic) != 1 || got.quic[0].server != uint16(serverPort) {
			t.Fatalf("capture direction lost: %+v", got.quic)
		}
		random, ok := pcapng.QUICClientRandom(got.quic[0].sent)
		if !ok {
			t.Fatal("received-first capture lost the actual ClientHello")
		}
		if mine := linesOf(keys.lines(), random); len(mine) != 4 || !containsAll(got.secrets, mine) {
			t.Fatal("received-first capture lost correlated secrets")
		}
		if !slices.EqualFunc(got.quic[0].sent, capture.quic[0].sent, bytes.Equal) ||
			!slices.EqualFunc(got.quic[0].received, capture.quic[0].received, bytes.Equal) ||
			!slices.Equal(got.secrets, capture.secrets) {
			t.Fatal("callback order changed datagram bytes, directional order or secrets")
		}
	})
	if len(capture.quic) != 1 {
		t.Fatalf("%d QUIC connections in the capture", len(capture.quic))
	}
	q := capture.quic[0]
	if strconv.Itoa(int(q.server)) != port || len(q.sent) == 0 || len(q.received) == 0 {
		t.Fatalf("a QUIC connection to %d: %d datagrams sent, %d received", q.server, len(q.sent), len(q.received))
	}
	random, ok := pcapng.QUICClientRandom(q.sent)
	if !ok {
		t.Fatal("no ClientHello in the datagrams it sent")
	}
	if mine := linesOf(keys.lines(), random); len(mine) != 4 || !containsAll(capture.secrets, mine) {
		t.Errorf("the capture holds\n%s\nthe site's lines of its QUIC connection\n%s", strings.Join(capture.secrets, "\n"),
			strings.Join(mine, "\n"))
	}
	if !strings.Contains(capture.comment, "UDP/IP") {
		t.Errorf("the capture says %q", capture.comment)
	}
}

// containsAll says whether every line of some is one of all.
func containsAll(all, some []string) bool {
	for _, line := range some {
		if !slices.Contains(all, line) {
			return false
		}
	}
	return true
}

func TestTheWireKeepsAQUICConnectionsDatagramsAndFindsItsClientHello(t *testing.T) {
	w := newWire()
	tap := w.tap(1)
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	d := tap.QUIC(local, remote, time.Now())
	// A short header datagram: no ClientHello will come, and nothing is
	// looked for after it.
	d.Wrote([]byte{0x40, 1, 2, 3})
	d.Read([]byte{0x40, 9})
	streams, _ := w.capture(1)
	if len(streams) != 1 || !streams[0].Datagrams || len(streams[0].Events) != 2 {
		t.Fatalf("captured %+v", streams)
	}
	w.mu.Lock()
	looked := w.conns[0].looked
	w.mu.Unlock()
	if !looked {
		t.Error("still looking for a ClientHello after a short header datagram")
	}
	d.Closed()
	d.Closed()
	w.mu.Lock()
	left := len(w.conns)
	w.mu.Unlock()
	if left != 0 {
		t.Errorf("%d connections kept once closed and captured", left)
	}
	// A connection of datagrams is found by its ends as a TCP one is.
	d = w.tap(2).QUIC(local, remote, time.Now())
	w.tap(3).Used(fakeQUICConn{local, remote})
	d.Wrote(make([]byte, 1200))
	if streams, _ := w.capture(3); len(streams) != 1 {
		t.Errorf("request 3 went out on %d connections", len(streams))
	}
	// A socket of every address is shown from the one it sends from.
	d = w.tap(5).QUIC(&net.UDPAddr{IP: net.IPv4zero, Port: 50001}, remote, time.Now())
	d.Wrote([]byte{0x40})
	if streams, _ := w.capture(5); len(streams) != 1 || streams[0].Client != netip.MustParseAddrPort("127.0.0.1:50001") {
		t.Errorf("captured %+v", streams)
	}
	// Long header datagrams with no ClientHello in them: it is looked for
	// in as many as its first flight may hold, and in none after them.
	d = w.tap(4).QUIC(local, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 444}, time.Now())
	looking := func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, c := range w.conns {
			if c.server.Port() == 444 {
				return !c.looked
			}
		}
		return false
	}
	for i := 1; i <= maxInitials; i++ {
		d.Wrote(append([]byte{0xc0}, make([]byte, 30)...))
		if looking() != (i < maxInitials) {
			t.Fatalf("after %d datagrams, still looking: %v", i, looking())
		}
	}
}

// fakeQUICConn is what a request on a QUIC connection hears it went out on.
type fakeQUICConn struct{ local, remote net.Addr }

func (c fakeQUICConn) LocalAddr() net.Addr            { return c.local }
func (c fakeQUICConn) RemoteAddr() net.Addr           { return c.remote }
func (fakeQUICConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeQUICConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeQUICConn) Close() error                     { return nil }
func (fakeQUICConn) SetDeadline(time.Time) error      { return nil }
func (fakeQUICConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeQUICConn) SetWriteDeadline(time.Time) error { return nil }

func TestASocketOfEveryAddressIsShownFromTheOneItSendsFrom(t *testing.T) {
	server := netip.MustParseAddrPort("127.0.0.1:443")
	if got := sourceToward(netip.MustParseAddrPort("0.0.0.0:5000"), server); got != netip.MustParseAddrPort("127.0.0.1:5000") {
		t.Errorf("from %s", got)
	}
	if got := sourceToward(netip.MustParseAddrPort("192.0.2.1:5000"), server); got != netip.MustParseAddrPort("192.0.2.1:5000") {
		t.Errorf("an address given became %s", got)
	}
	// Where the system has no way to the server, the socket's own.
	asked := dialUDP
	t.Cleanup(func() { dialUDP = asked })
	dialUDP = func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("network is unreachable")
	}
	if got := sourceToward(netip.MustParseAddrPort("0.0.0.0:5000"), server); got != netip.MustParseAddrPort("0.0.0.0:5000") {
		t.Errorf("no way to the server: %s", got)
	}
}

// A read callback can be recorded before the write callback even though the
// actual UDP write preceded the response. Preserve every block and each
// direction's relative order while constructing that independent counterexample.
func receivedFirstCapture(t *testing.T, data []byte, server uint16) []byte {
	t.Helper()
	var blocks [][]byte
	firstPacket, firstReceived := -1, -1
	for len(data) > 0 {
		n := int(binary.LittleEndian.Uint32(data[4:]))
		block := append([]byte(nil), data[:n]...)
		data = data[n:]
		if binary.LittleEndian.Uint32(block) == 6 {
			if firstPacket < 0 {
				firstPacket = len(blocks)
			}
			packet := block[28:]
			if packet[9] == 17 && binary.BigEndian.Uint16(packet[20:]) == server && firstReceived < 0 {
				firstReceived = len(blocks)
			}
		}
		blocks = append(blocks, block)
	}
	if firstPacket < 0 || firstReceived < 0 {
		t.Fatal("capture lacks packet directions")
	}
	moved := blocks[firstReceived]
	copy(blocks[firstPacket+1:firstReceived+1], blocks[firstPacket:firstReceived])
	blocks[firstPacket] = moved
	return bytes.Join(blocks, nil)
}
