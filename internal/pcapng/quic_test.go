package pcapng

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
)

func TestAQUICStreamIsWrittenAsTheDatagramsItCarried(t *testing.T) {
	for _, ends := range [][2]netip.AddrPort{{client, server},
		{netip.MustParseAddrPort("[2001:db8::10]:51000"), netip.MustParseAddrPort("[2001:db8::20]:443")}} {
		s := Stream{Client: ends[0], Server: ends[1], Datagrams: true, Opened: at(0), Connected: at(1), Events: []Event{
			{At: at(2), What: Sent, Data: []byte("initial")},
			{At: at(3), What: Received, Data: []byte("server initial")},
			{At: at(4), What: Sent, Data: []byte("handshake")},
			{At: at(5), What: Closed},
			{At: at(6), What: Ended},
		}}
		// A TCP connection beside it goes into the file with it, by time.
		tcp := Stream{Client: netip.MustParseAddrPort("192.0.2.10:51001"), Server: server, Opened: at(3),
			Connected: at(3), Events: []Event{{At: at(3), What: Closed}}}
		got := written(t, File{}, s, tcp)
		var udp []readPacket
		for _, p := range got.packets {
			if p.udp {
				udp = append(udp, p)
			}
		}
		want := []struct {
			from, to netip.AddrPort
			data     string
			at       time.Time
		}{{ends[0], ends[1], "initial", at(2)}, {ends[1], ends[0], "server initial", at(3)},
			{ends[0], ends[1], "handshake", at(4)}}
		if len(udp) != len(want) || len(got.packets) != len(want)+4 {
			t.Fatalf("%d UDP packets of %d, want %d of %d", len(udp), len(got.packets), len(want), len(want)+4)
		}
		for i, w := range want {
			p := udp[i]
			if p.src != w.from || p.dst != w.to || string(p.data) != w.data || p.at != uint64(w.at.UnixNano()) ||
				p.v4 != ends[0].Addr().Is4() {
				t.Errorf("datagram %d: %+v, want %+v", i, p, w)
			}
			if comment := p.comment; (i == 0) != (comment == datagramComment) || i > 0 && comment != "" {
				t.Errorf("datagram %d says %q", i, comment)
			}
		}
		// The TCP connection's four packets at 3 ms, after the datagram of
		// then, the stream given first going first.
		var order []bool
		for _, p := range got.packets {
			order = append(order, p.udp)
		}
		if want := []bool{true, true, false, false, false, false, true}; !slices.Equal(order, want) {
			t.Errorf("UDP or not, in order: %v, want %v", order, want)
		}
	}
}

func TestAUDPChecksumThatComesToZeroIsWrittenAsAllOnes(t *testing.T) {
	// A payload of the sum's complement brings the sum to all ones, whose
	// complement, the checksum, is zero: UDP writes it as all ones, zero
	// saying none was made.
	first := udpHeaders(true, client, server, []byte{0, 0})
	sum := binary.BigEndian.Uint16(first[20+6:])
	payload := binary.BigEndian.AppendUint16(nil, sum)
	header := udpHeaders(true, client, server, payload)
	if got := binary.BigEndian.Uint16(header[20+6:]); got != 0xffff {
		t.Errorf("checksum %#04x, want 0xffff", got)
	}
	if onesSum(header[12:20], []byte{0, 17, 0, 10}, header[20:], payload) != 0xffff {
		t.Error("the checksum does not check")
	}
}

// The keys of a client's Initial packets to 0x8394c8f03e515708, as RFC 9001
// works them out (appendix A.1).
func TestTheInitialKeysAreRFC9001s(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	initial, _ := hex.DecodeString("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
	secret := expandLabel(initial, "client in", 32)
	for _, tc := range []struct{ got, want string }{
		{hex.EncodeToString(secret), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"},
		{hex.EncodeToString(expandLabel(secret, "quic key", 16)), "1f369613dd76d5467730efcbe3b1a22d"},
		{hex.EncodeToString(expandLabel(secret, "quic iv", 12)), "fa044b2f42a3fd3b46fb255c"},
		{hex.EncodeToString(expandLabel(secret, "quic hp", 16)), "9f50449e04a0e810283a1e9933adedd2"},
		{hex.EncodeToString(clientInitialKeys(dcid).iv), "fa044b2f42a3fd3b46fb255c"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s, want %s", tc.got, tc.want)
		}
	}
}

func TestAPacketNumberIsReadNearTheOneExpected(t *testing.T) {
	for _, tc := range []struct {
		largest, truncated uint64
		bits               int
		want               uint64
	}{
		{0xa82f30ea, 0x9b32, 16, 0xa82f9b32}, // RFC 9000, appendix A.3
		{0, 0, 8, 0},
		{0, 1, 8, 1},
		{254, 2, 8, 258},
		{129, 2, 8, 258},   // a candidate half a window below the one expected
		{256, 129, 8, 385}, // half a window above
		{300, 250, 8, 250},
		{1<<62 - 2, 0, 8, 1<<62 - 256},
	} {
		if got := packetNumber(tc.largest, tc.truncated, tc.bits); got != tc.want {
			t.Errorf("packetNumber(%#x, %#x, %d) = %#x, want %#x", tc.largest, tc.truncated, tc.bits, got, tc.want)
		}
	}
}

// hello is the start of a ClientHello with random.
func hello(random []byte) []byte {
	return append(append([]byte{1, 0, 1, 0, 3, 3}, random...), 0, 0x20)
}

// frame is a CRYPTO frame of data at offset.
func frame(offset int, data []byte) []byte {
	out := append([]byte{6}, quicVarint(uint64(offset))...)
	out = append(out, quicVarint(uint64(len(data)))...)
	return append(out, data...)
}

func quicVarint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(nil, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(nil, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(nil, v|0xc0<<56)
}

// sealed is an Initial packet of a client to dcid, numbered number in size
// bytes, of frames, padded to about 1200 bytes when pad says so, protected
// as RFC 9001 says; with kind and version another long header packet's.
func sealed(dcid []byte, number uint64, size int, frames []byte, kind byte, version uint32, token []byte, pad bool) []byte {
	keys := clientInitialKeys(dcid)
	payload := append([]byte{}, frames...)
	if n := 1200 - 64 - len(payload); pad && n > 0 {
		payload = append(payload, make([]byte, n)...)
	}
	header := []byte{0xc0 | kind<<4 | byte(size-1)}
	header = binary.BigEndian.AppendUint32(header, version)
	header = append(append(header, byte(len(dcid))), dcid...)
	header = append(header, 8, 1, 2, 3, 4, 5, 6, 7, 8)
	if kind == initialPacket {
		header = append(append(header, quicVarint(uint64(len(token)))...), token...)
	}
	header = append(header, quicVarint(uint64(size+len(payload)+16))...)
	pn := len(header)
	for i := size - 1; i >= 0; i-- {
		header = append(header, byte(number>>(8*i)))
	}
	nonce := append([]byte{}, keys.iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(number >> (8 * i))
	}
	packet := keys.aead.Seal(append([]byte{}, header...), nonce, payload, header)
	mask := make([]byte, 16)
	keys.hp.Encrypt(mask, packet[pn+4:pn+4+16])
	packet[0] ^= mask[0] & 0x0f
	for i := range size {
		packet[pn+i] ^= mask[1+i]
	}
	return packet
}

func TestAQUICClientRandomIsReadFromItsInitialPackets(t *testing.T) {
	dcid, _ := hex.DecodeString("0011223344556677")
	random := bytes.Repeat([]byte{0xab}, 32)
	random[0], random[31] = 1, 2
	want := hex.EncodeToString(random)
	h := append(hello(random), bytes.Repeat([]byte{0xcd}, 100)...)
	initial := func(number uint64, frames ...[]byte) []byte {
		return sealed(dcid, number, 1, bytes.Join(frames, nil), initialPacket, quicVersion1, nil, true)
	}
	bare := func(frames ...[]byte) []byte {
		return sealed(dcid, 1, 1, bytes.Join(frames, nil), initialPacket, quicVersion1, nil, false)
	}
	// An ACK of two ranges with ECN counts, then one without.
	ack := append([]byte{3}, 5, 0, 1, 1, 1, 1, 7, 8, 9)
	ack = append(ack, 2, 4, 0, 0, 0)
	for _, tc := range []struct {
		name string
		sent [][]byte
		ok   bool
	}{
		{"one packet", [][]byte{initial(1, frame(0, h))}, true},
		// quiche's chaos protection: pieces out of order, PINGs between.
		{"its pieces out of order", [][]byte{initial(1, frame(20, h[20:]), []byte{1}, frame(0, h[:20]), []byte{0, 1})}, true},
		{"its start in a later datagram", [][]byte{initial(1, frame(30, h[30:])), initial(2, frame(0, h[:30]))}, true},
		{"after acknowledgements", [][]byte{initial(1, ack, frame(0, h))}, true},
		{"with a token", [][]byte{sealed(dcid, 1, 2, frame(0, h), initialPacket, quicVersion1, []byte("token"), true)}, true},
		{"a Handshake packet before it", [][]byte{append(sealed(dcid, 0, 1, nil, 2, quicVersion1, nil, true), initial(1, frame(0, h))...)}, true},
		{"overlapping pieces", [][]byte{initial(1, frame(0, h[:10]), frame(5, h[5:20]), frame(10, h[10:15]), frame(18, h[18:]))}, true},
		{"a gap", [][]byte{initial(1, frame(0, h[:10]), frame(11, h[11:]))}, false},
		{"none", nil, false},
		{"a short header packet", [][]byte{append([]byte{0x40}, make([]byte, 40)...)}, false},
		{"another version", [][]byte{sealed(dcid, 1, 1, frame(0, h), initialPacket, 0x6b3343cf, nil, true)}, false},
		{"cut short", [][]byte{initial(1, frame(0, h))[:100]}, false},
		{"a header cut short", [][]byte{initial(1, frame(0, h))[:6]}, false},
		// A packet of four bytes after its header: nothing to sample its
		// protection's mask from.
		{"too short to unprotect", [][]byte{append([]byte{0xc0, 0, 0, 0, 1, 1, 9, 0, 0, 4}, 1, 2, 3, 4)}, false},
		{"a bit flipped", [][]byte{func() []byte { p := initial(1, frame(0, h)); p[len(p)-1] ^= 1; return p }()}, false},
		{"no ClientHello", [][]byte{initial(1, frame(0, append([]byte{2}, h[1:]...)))}, false},
		{"a CRYPTO frame cut short", [][]byte{bare(frame(0, h[:10]), []byte{6, 10, 0x44, 0, 1, 2, 3})}, false},
		{"a CRYPTO frame's length cut short", [][]byte{bare(frame(0, h[:10]), []byte{6, 10, 0x80, 0, 0})}, false},
		{"a CRYPTO frame's offset cut short", [][]byte{bare(frame(0, h[:10]), []byte{1, 1, 1, 6, 0x80, 0})}, false},
		{"a CONNECTION_CLOSE", [][]byte{initial(1, []byte{0x1c, 0, 0, 0}, frame(0, h))}, false},
		{"its first 38 bytes alone", [][]byte{initial(1, frame(0, h[:38]))}, true},
		{"37 of them", [][]byte{initial(1, frame(0, h[:37]))}, false},
		// A packet that does not decrypt says nothing of the numbers of those
		// after it: read near its own, the next would not decrypt.
		{"after one that does not decrypt", [][]byte{func() []byte { p := initial(200, frame(0, h[:10])); p[len(p)-1] ^= 1; return p }(),
			initial(1, frame(0, h))}, true},
		// A number of one byte read near the one before: 45 after 300 is 301.
		{"its numbers read near the one before", [][]byte{sealed(dcid, 300, 2, frame(0, h[:20]), initialPacket, quicVersion1, nil, true),
			sealed(dcid, 301, 1, frame(20, h[20:]), initialPacket, quicVersion1, nil, true)}, true},
		// After a Retry the client's Initials go to the connection ID the
		// server gave, their keys its.
		{"to another connection ID", [][]byte{initial(1, frame(0, h[:20])),
			sealed([]byte{9, 9, 9, 9, 9, 9, 9, 9}, 2, 1, frame(20, h[20:]), initialPacket, quicVersion1, []byte("retry token"), true)}, true},
		{"an ACK cut short", [][]byte{bare(frame(0, h[:10]), []byte{1, 1, 1, 1, 2, 1, 0, 0x40})}, false},
		{"an ACK's counts cut short", [][]byte{bare(frame(0, h[:10]), []byte{1, 1, 1, 3, 1, 0, 0, 0, 0x40})}, false},
	} {
		got, ok := QUICClientRandom(tc.sent)
		if ok != tc.ok || ok && got != want {
			t.Errorf("%s: %q, %v", tc.name, got, ok)
		}
	}
}

func TestALongHeaderCutAnywhereIsNoPacket(t *testing.T) {
	dcid := []byte{1, 2, 3, 4}
	full := sealed(dcid, 1, 1, frame(0, hello(make([]byte, 32))), initialPacket, quicVersion1, []byte{9, 9}, true)
	for n := range len(full) {
		if _, _, ok := longHeader(full[:n]); ok {
			t.Fatalf("%d bytes read as a packet", n)
		}
	}
	if p, rest, ok := longHeader(full); !ok || len(rest) != 0 || !bytes.Equal(p.dcid, dcid) || p.kind != initialPacket {
		t.Errorf("the whole packet: %+v, %d left, %v", p, len(rest), ok)
	}
	// Connection IDs longer than version 1's 20 bytes.
	long := append([]byte{0xc0, 0, 0, 0, 1, 21}, make([]byte, 40)...)
	if _, _, ok := longHeader(long); ok {
		t.Error("a 21-byte destination connection ID read")
	}
	long = append([]byte{0xc0, 0, 0, 0, 1, 0, 21}, make([]byte, 40)...)
	if _, _, ok := longHeader(long); ok {
		t.Error("a 21-byte source connection ID read")
	}
	if v, n := varint(nil); v != 0 || n != 0 {
		t.Errorf("varint of nothing: %d, %d", v, n)
	}
}

// selfSigned is a certificate of its own key for 127.0.0.1.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// relay passes datagrams between a client and a server, and keeps what the
// client sent.
type relay struct {
	mu   sync.Mutex
	sent [][]byte
}

func (r *relay) kept() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte{}, r.sent...)
}

func TestTheClientRandomOfARealQUICClientIsItsKeyLogs(t *testing.T) {
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)},
		NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-conn.HandshakeComplete(); _ = conn.CloseWithError(0, "") }()
		}
	}()
	front, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	back, err := net.DialUDP("udp4", nil, ln.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	r := &relay{}
	var from net.Addr
	var fromMu sync.Mutex
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := front.ReadFrom(b)
			if err != nil {
				return
			}
			fromMu.Lock()
			from = addr
			fromMu.Unlock()
			r.mu.Lock()
			r.sent = append(r.sent, append([]byte{}, b[:n]...))
			r.mu.Unlock()
			_, _ = back.Write(b[:n])
		}
	}()
	go func() {
		b := make([]byte, 2048)
		for {
			n, err := back.Read(b)
			if err != nil {
				return
			}
			fromMu.Lock()
			to := from
			fromMu.Unlock()
			_, _ = front.WriteTo(b[:n], to)
		}
	}()
	var keys bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, front.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true,
		NextProtos: []string{"h3"}, KeyLogWriter: &keys}, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-conn.HandshakeComplete()
	_ = conn.CloseWithError(0, "")
	fields := strings.Fields(keys.String())
	if len(fields) < 3 {
		t.Fatalf("key log %q", keys.String())
	}
	got, ok := QUICClientRandom(r.kept())
	if !ok || got != strings.ToLower(fields[1]) {
		t.Errorf("random %q, %v; the key log says %s", got, ok, fields[1])
	}
}
