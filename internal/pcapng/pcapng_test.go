package pcapng

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// A pcapng file read back as Wireshark reads one: block by block, each
// packet's IP and TCP headers checked as a stack checks them.

// read is a file's blocks, held to the rules every block keeps.
type read struct {
	header    readBlock
	iface     readBlock
	secrets   []byte
	hasSecret bool
	packets   []readPacket
}

type readBlock struct {
	body    []byte
	options map[uint16][]byte
}

// readPacket is an Enhanced Packet Block and what its packet says.
type readPacket struct {
	at       uint64
	comment  string
	v4       bool
	udp      bool
	src, dst netip.AddrPort
	seq, ack uint32
	flags    byte
	window   uint16
	data     []byte
}

func readFile(t *testing.T, file []byte) read {
	t.Helper()
	var out read
	for i := 0; len(file) > 0; i++ {
		if len(file) < 12 {
			t.Fatalf("block %d: %d bytes left", i, len(file))
		}
		kind, length := binary.LittleEndian.Uint32(file), binary.LittleEndian.Uint32(file[4:])
		if length%4 != 0 || int(length) > len(file) || length < 12 {
			t.Fatalf("block %d of type %#x: length %d of %d", i, kind, length, len(file))
		}
		if end := binary.LittleEndian.Uint32(file[length-4:]); end != length {
			t.Fatalf("block %d: length %d at the start, %d at the end", i, length, end)
		}
		body := file[8 : length-4]
		file = file[length:]
		switch kind {
		case sectionHeader:
			if i != 0 || binary.LittleEndian.Uint32(body) != byteOrderMagic || binary.LittleEndian.Uint16(body[4:]) != 1 ||
				binary.LittleEndian.Uint16(body[6:]) != 0 || binary.LittleEndian.Uint64(body[8:]) != ^uint64(0) {
				t.Fatalf("section header %d: % x", i, body[:16])
			}
			out.header = readBlock{body: body, options: readOptions(t, body[16:])}
		case interfaceBlock:
			if i != 1 || binary.LittleEndian.Uint16(body) != linkTypeRaw || binary.LittleEndian.Uint32(body[4:]) != 0 {
				t.Fatalf("interface block %d: % x", i, body[:8])
			}
			out.iface = readBlock{body: body, options: readOptions(t, body[8:])}
		case secretsBlock:
			if out.packets != nil || binary.LittleEndian.Uint32(body) != tlsKeyLog {
				t.Fatalf("secrets block %d after packets, or of type %#x", i, binary.LittleEndian.Uint32(body))
			}
			size := binary.LittleEndian.Uint32(body[4:])
			if int(size) > len(body)-8 || len(body)-8-int(size) > 3 {
				t.Fatalf("secrets of %d bytes in a body of %d", size, len(body))
			}
			out.secrets, out.hasSecret = body[8:8+size], true
		case enhancedPacket:
			if binary.LittleEndian.Uint32(body) != 0 {
				t.Fatalf("packet %d on interface %d", i, binary.LittleEndian.Uint32(body))
			}
			at := uint64(binary.LittleEndian.Uint32(body[4:]))<<32 | uint64(binary.LittleEndian.Uint32(body[8:]))
			captured, original := binary.LittleEndian.Uint32(body[12:]), binary.LittleEndian.Uint32(body[16:])
			if captured != original {
				t.Fatalf("packet %d: %d of %d bytes captured", i, captured, original)
			}
			padded := (int(captured) + 3) &^ 3
			p := readIP(t, body[20:20+captured])
			p.at = at
			p.comment = string(readOptions(t, body[20+padded:])[optComment])
			out.packets = append(out.packets, p)
		default:
			t.Fatalf("block %d of type %#x", i, kind)
		}
	}
	return out
}

// readOptions are a block's options by code, held to their padding and end.
func readOptions(t *testing.T, raw []byte) map[uint16][]byte {
	t.Helper()
	out := map[uint16][]byte{}
	if len(raw) == 0 {
		return out
	}
	for {
		if len(raw) < 4 {
			t.Fatalf("options end without their end: % x", raw)
		}
		code, length := binary.LittleEndian.Uint16(raw), int(binary.LittleEndian.Uint16(raw[2:]))
		if code == 0 {
			if length != 0 || len(raw) != 4 {
				t.Fatalf("options end as % x", raw)
			}
			return out
		}
		padded := (length + 3) &^ 3
		if 4+padded > len(raw) || !bytes.Equal(raw[4+length:4+padded], make([]byte, padded-length)) {
			t.Fatalf("option %d of %d bytes in % x", code, length, raw)
		}
		out[code] = raw[4 : 4+length]
		raw = raw[4+padded:]
	}
}

// onesSum is the ones' complement sum of what is given, as one run of bytes.
func onesSum(parts ...[]byte) uint16 {
	all := bytes.Join(parts, nil)
	if len(all)%2 == 1 {
		all = append(all, 0)
	}
	var sum uint32
	for i := 0; i < len(all); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(all[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// readIP is a packet's IP and TCP or UDP headers, their lengths and
// checksums checked.
func readIP(t *testing.T, packet []byte) readPacket {
	t.Helper()
	var p readPacket
	var pseudo, tcp []byte
	var protocol byte
	switch packet[0] >> 4 {
	case 4:
		ip := packet[:20]
		protocol = ip[9]
		if packet[0] != 0x45 || int(binary.BigEndian.Uint16(ip[2:])) != len(packet) || protocol != 6 && protocol != 17 ||
			ip[8] != 64 || binary.BigEndian.Uint16(ip[6:]) != 0x4000 || onesSum(ip) != 0xffff {
			t.Fatalf("an IPv4 header % x for %d bytes", ip, len(packet))
		}
		p.v4 = true
		p.src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip[12:16])), 0)
		p.dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip[16:20])), 0)
		tcp = packet[20:]
		pseudo = append(append(slices.Clone(ip[12:20]), 0, protocol), binary.BigEndian.AppendUint16(nil, uint16(len(tcp)))...)
	case 6:
		ip := packet[:40]
		protocol = ip[6]
		if !bytes.Equal(ip[:4], []byte{0x60, 0, 0, 0}) || int(binary.BigEndian.Uint16(ip[4:])) != len(packet)-40 ||
			protocol != 6 && protocol != 17 || ip[7] != 64 {
			t.Fatalf("an IPv6 header % x for %d bytes", ip, len(packet))
		}
		p.src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(ip[8:24])), 0)
		p.dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(ip[24:40])), 0)
		tcp = packet[40:]
		pseudo = append(slices.Clone(ip[8:40]), binary.BigEndian.AppendUint32(nil, uint32(len(tcp)))...)
		pseudo = append(pseudo, 0, 0, 0, protocol)
	default:
		t.Fatalf("a packet of IP version %d", packet[0]>>4)
	}
	if protocol == 17 {
		udp := tcp
		if int(binary.BigEndian.Uint16(udp[4:])) != len(udp) || onesSum(pseudo, udp) != 0xffff ||
			binary.BigEndian.Uint16(udp[6:]) == 0 {
			t.Fatalf("a UDP header % x for %d bytes", udp[:8], len(udp))
		}
		p.udp = true
		p.src = netip.AddrPortFrom(p.src.Addr(), binary.BigEndian.Uint16(udp))
		p.dst = netip.AddrPortFrom(p.dst.Addr(), binary.BigEndian.Uint16(udp[2:]))
		p.data = udp[8:]
		return p
	}
	if tcp[12] != 5<<4 || onesSum(pseudo, tcp) != 0xffff || tcp[18] != 0 || tcp[19] != 0 {
		t.Fatalf("a TCP header % x", tcp[:20])
	}
	p.src = netip.AddrPortFrom(p.src.Addr(), binary.BigEndian.Uint16(tcp))
	p.dst = netip.AddrPortFrom(p.dst.Addr(), binary.BigEndian.Uint16(tcp[2:]))
	p.seq, p.ack = binary.BigEndian.Uint32(tcp[4:]), binary.BigEndian.Uint32(tcp[8:])
	p.flags, p.window = tcp[13], binary.BigEndian.Uint16(tcp[14:])
	p.data = tcp[20:]
	return p
}

// conversation is what each end of a stream sent, put back together from the
// packets, which are held to TCP as they go: the handshake first, each
// segment where the one before it ended, acknowledging all the other end had
// sent, and nothing after an end's FIN or a RST.
type conversation struct {
	client, server []byte
	clientEnd      byte // flagFIN when the client closed
	serverEnd      byte // flagFIN or flagRST
	packets        int
}

func converse(t *testing.T, packets []readPacket, client, server netip.AddrPort) conversation {
	t.Helper()
	var c conversation
	var mine []readPacket
	for _, p := range packets {
		if (p.src == client && p.dst == server) || (p.src == server && p.dst == client) {
			mine = append(mine, p)
		}
	}
	if len(mine) < 3 {
		t.Fatalf("%d packets between %s and %s", len(mine), client, server)
	}
	if syn := mine[0]; syn.src != client || syn.flags != flagSYN || syn.seq != 0 || syn.ack != 0 ||
		syn.comment != synComment || len(syn.data) != 0 {
		t.Fatalf("the connection begins with %+v", syn)
	}
	if synAck := mine[1]; synAck.src != server || synAck.flags != flagSYN|flagACK || synAck.seq != 0 || synAck.ack != 1 {
		t.Fatalf("the server answered %+v", synAck)
	}
	if ack := mine[2]; ack.src != client || ack.flags != flagACK || ack.seq != 1 || ack.ack != 1 {
		t.Fatalf("the client went on with %+v", ack)
	}
	next := map[netip.AddrPort]uint32{client: 1, server: 1}
	for _, p := range mine[3:] {
		other := server
		if p.src == server {
			other = client
		}
		if p.seq != next[p.src] || p.ack != next[other] || p.window != 65535 || p.comment != "" {
			t.Fatalf("a segment from %s at %d acking %d, want %d and %d: %+v", p.src, p.seq, p.ack,
				next[p.src], next[other], p)
		}
		if (p.src == client && c.clientEnd != 0) || (p.src == server && c.serverEnd != 0) {
			t.Fatalf("%s sent %+v after its end", p.src, p)
		}
		switch p.flags {
		case flagPSH | flagACK:
			if len(p.data) == 0 || len(p.data) > maxData {
				t.Fatalf("a segment of %d bytes", len(p.data))
			}
			if p.src == client {
				c.client = append(c.client, p.data...)
			} else {
				c.server = append(c.server, p.data...)
			}
			next[p.src] += uint32(len(p.data))
		case flagFIN | flagACK:
			if p.src == client {
				c.clientEnd = flagFIN
			} else {
				c.serverEnd = flagFIN
			}
			next[p.src]++
		case flagRST | flagACK:
			if p.src != server {
				t.Fatalf("the client reset: %+v", p)
			}
			c.serverEnd = flagRST
		default:
			t.Fatalf("a segment with flags %#x", p.flags)
		}
	}
	c.packets = len(mine)
	return c
}

var (
	base   = time.Date(2026, 10, 20, 11, 49, 55, 914_000_000, time.UTC)
	client = netip.MustParseAddrPort("192.0.2.10:51000")
	server = netip.MustParseAddrPort("198.51.100.20:443")
)

func at(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }

func written(t *testing.T, f File, streams ...Stream) read {
	t.Helper()
	var out bytes.Buffer
	if err := Write(&out, f, streams); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return readFile(t, out.Bytes())
}

func TestAStreamIsWrittenAsTheTCPItCarried(t *testing.T) {
	hello := []byte("\x16\x03\x01\x00\x05hello")
	big := bytes.Repeat([]byte("0123456789abcdef"), maxData/16*2+5) // past two packets' worth
	s := Stream{Client: client, Server: server, Opened: at(0), Connected: at(3), Events: []Event{
		{At: at(4), What: Sent, Data: hello},
		{At: at(9), What: Received, Data: []byte("odd")}, // an odd length, for the checksum
		{At: at(10), What: Received, Data: big},
		{At: at(11), What: Sent, Data: nil}, // a write of nothing sends nothing
		{At: at(12), What: Sent, Data: []byte("bye")},
		{At: at(13), What: Closed},
		{At: at(14), What: Closed}, // said twice, closed once
	}}
	f := File{Application: "tls-forge v1.2.3", Comment: "the connections of request 1", Interface: "request 1",
		Secrets: []byte("CLIENT_RANDOM 00 11\n")}
	file := written(t, f, s)

	if string(file.header.options[optComment]) != f.Comment ||
		string(file.header.options[optApplication]) != f.Application {
		t.Errorf("the section says %v", file.header.options)
	}
	if string(file.iface.options[optName]) != "tls-forge" || string(file.iface.options[optDescription]) != f.Interface ||
		!bytes.Equal(file.iface.options[optTimeResol], []byte{nanosecondsUnit}) {
		t.Errorf("the interface says %v", file.iface.options)
	}
	if !file.hasSecret || string(file.secrets) != string(f.Secrets) {
		t.Errorf("the secrets are %q", file.secrets)
	}
	c := converse(t, file.packets, client, server)
	if !bytes.Equal(c.client, append(slices.Clone(hello), "bye"...)) || !bytes.Equal(c.server, append([]byte("odd"), big...)) {
		t.Errorf("the client sent %d bytes and got %d", len(c.client), len(c.server))
	}
	// SYN, SYN-ACK, ACK; the hello; odd and three of the big; bye; one FIN.
	if c.clientEnd != flagFIN || c.serverEnd != 0 || c.packets != 3+1+1+3+1+1 {
		t.Errorf("%d packets, the client's end %#x, the server's %#x", c.packets, c.clientEnd, c.serverEnd)
	}
	// Each at the moment it happened, to the nanosecond.
	for i, want := range []time.Time{at(0), at(3), at(3), at(4), at(9), at(10), at(10), at(10), at(12), at(13)} {
		if got := file.packets[i].at; got != uint64(want.UnixNano()) {
			t.Errorf("packet %d at %d, want %d", i, got, want.UnixNano())
		}
	}
	if !file.packets[0].v4 || file.packets[0].src != client || file.packets[1].src != server {
		t.Errorf("the ends are %s and %s", file.packets[0].src, file.packets[1].src)
	}
}

func TestAServerThatEndsOrResetsIsSaidOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		what Kind
		want byte
	}{{"ended", Ended, flagFIN}, {"reset", Reset, flagRST}} {
		t.Run(tc.name, func(t *testing.T) {
			s := Stream{Client: client, Server: server, Opened: at(0), Connected: at(1), Events: []Event{
				{At: at(2), What: Sent, Data: []byte("a")},
				{At: at(3), What: tc.what},
				{At: at(4), What: Ended},
				{At: at(5), What: Reset},
				{At: at(6), What: Closed},
			}}
			c := converse(t, written(t, File{}, s).packets, client, server)
			if c.serverEnd != tc.want || c.clientEnd != flagFIN || c.packets != 3+1+1+1 {
				t.Errorf("the server ended with %#x, the client with %#x, in %d packets", c.serverEnd, c.clientEnd, c.packets)
			}
		})
	}
}

func TestWhatComesAfterTheClientClosedAcknowledgesItsFIN(t *testing.T) {
	// A read that returned as the connection was being closed comes after the
	// client's FIN, which took a sequence number of its own.
	s := Stream{Client: client, Server: server, Opened: at(0), Connected: at(1), Events: []Event{
		{At: at(2), What: Sent, Data: []byte("a")},
		{At: at(3), What: Closed},
		{At: at(4), What: Received, Data: []byte("late")},
		{At: at(5), What: Ended},
	}}
	c := converse(t, written(t, File{}, s).packets, client, server)
	if string(c.server) != "late" || c.clientEnd != flagFIN || c.serverEnd != flagFIN || c.packets != 3+1+1+1+1 {
		t.Errorf("got %q, the ends %#x and %#x, in %d packets", c.server, c.clientEnd, c.serverEnd, c.packets)
	}
}

func TestAnIPv6StreamIsWrittenOverIPv6(t *testing.T) {
	near, far := netip.MustParseAddrPort("[2001:db8::1]:51000"), netip.MustParseAddrPort("[2001:db8::2]:8443")
	s := Stream{Client: near, Server: far, Opened: at(0), Connected: at(1), Events: []Event{
		{At: at(2), What: Sent, Data: []byte("over six")},
		{At: at(3), What: Received, Data: []byte("odd")},
	}}
	file := written(t, File{}, s)
	c := converse(t, file.packets, near, far)
	if file.packets[0].v4 || string(c.client) != "over six" || string(c.server) != "odd" {
		t.Errorf("over IPv4: %v, the client sent %q and got %q", file.packets[0].v4, c.client, c.server)
	}
	// An IPv4 address written as IPv6 is IPv4 all the same.
	mapped := Stream{Client: netip.AddrPortFrom(netip.MustParseAddr("::ffff:192.0.2.10"), 1),
		Server: netip.AddrPortFrom(netip.MustParseAddr("::ffff:198.51.100.20"), 2), Opened: at(0), Connected: at(1)}
	if packets := written(t, File{}, mapped).packets; !packets[0].v4 ||
		packets[0].src != netip.MustParseAddrPort("192.0.2.10:1") {
		t.Errorf("a mapped address went as %+v", packets[0])
	}
}

func TestStreamsGoTogetherByTimeEachInItsOrder(t *testing.T) {
	other := netip.MustParseAddrPort("192.0.2.10:51001")
	first := Stream{Client: client, Server: server, Opened: at(0), Connected: at(10), Events: []Event{
		{At: at(20), What: Sent, Data: []byte("first")},
		// A clock that went back: still after what came before it here.
		{At: at(5), What: Received, Data: []byte("late")},
	}}
	second := Stream{Client: other, Server: server, Opened: at(1), Connected: at(2), Events: []Event{
		{At: at(15), What: Sent, Data: []byte("second")},
	}}
	file := written(t, File{}, first, second)
	var order []string
	for _, p := range file.packets {
		order = append(order, p.src.String()+" "+string(p.data))
	}
	want := []string{
		client.String() + " ", other.String() + " ", server.String() + " ", other.String() + " ",
		server.String() + " ", client.String() + " ", other.String() + " second", client.String() + " first",
		server.String() + " late",
	}
	if !slices.Equal(order, want) {
		t.Errorf("the packets went\n%s\nwant\n%s", strings.Join(order, "\n"), strings.Join(want, "\n"))
	}
	converse(t, file.packets, client, server)
	converse(t, file.packets, other, server)
}

func TestAStreamWithoutItsMomentsIsWrittenAtWhatItHas(t *testing.T) {
	// No moment it was asked for, or none it was there: the one it has.
	for _, s := range []Stream{
		{Client: client, Server: server, Connected: at(7)},
		{Client: client, Server: server, Opened: at(7)},
	} {
		packets := written(t, File{}, s).packets
		for _, p := range packets {
			if p.at != uint64(at(7).UnixNano()) {
				t.Errorf("%+v: a packet at %d", s, p.at)
			}
		}
	}
	// And nothing before 1970, which a timestamp cannot say.
	if packets := written(t, File{}, Stream{Client: client, Server: server}).packets; packets[0].at != 0 {
		t.Errorf("no moment at all is %d", packets[0].at)
	}
}

func TestAFileSaysNothingItWasNotGiven(t *testing.T) {
	file := written(t, File{})
	if len(file.header.options) != 0 || file.hasSecret || len(file.packets) != 0 ||
		len(file.iface.options) != 2 {
		t.Errorf("an empty file says %v, %v, %v and %d packets", file.header.options, file.iface.options,
			file.hasSecret, len(file.packets))
	}
}

// failing takes some bytes, then fails every write, and counts the writes
// tried after it first failed.
type failing struct {
	room  int
	after int
	full  bool
}

func (f *failing) Write(p []byte) (int, error) {
	if f.full {
		f.after++
	}
	if len(p) > f.room {
		f.full = true
		return 0, errors.New("the disk is full")
	}
	f.room -= len(p)
	return len(p), nil
}

func TestAWriteThatFailsEndsTheFile(t *testing.T) {
	// In the section header, in the secrets and among the packets: the error
	// is the one that came back, and nothing more is written after it.
	s := Stream{Client: client, Server: server, Events: []Event{{What: Sent, Data: []byte("a")}}}
	for _, room := range []int{0, 90, 300} {
		w := &failing{room: room}
		if err := Write(w, File{Secrets: []byte("x")}, []Stream{s}); err == nil || err.Error() != "the disk is full" {
			t.Errorf("with room for %d: %v", room, err)
		}
		if !w.full || w.after != 0 {
			t.Errorf("with room for %d: full %v, %d writes after", room, w.full, w.after)
		}
	}
}

func TestTheChecksumIsTheInternetChecksumOfThePartsTogether(t *testing.T) {
	for _, parts := range [][][]byte{
		{},
		{{0x45}},
		{{0x45, 0x00}, {0x01}, {0x02, 0x03, 0x04}},
		{bytes.Repeat([]byte{0xff}, 70001)},
		{{0x01}, {}, {0x02}},
	} {
		if got, want := checksum(parts...), ^onesSum(parts...); got != want {
			t.Errorf("checksum(% x) = %#x, want %#x", parts, got, want)
		}
	}
}

func TestClientRandom(t *testing.T) {
	random := bytes.Repeat([]byte{0xab}, 32)
	hello := func(length int) []byte {
		return append(append([]byte{22, 3, 1, byte(length >> 8), byte(length), 1, 0, 1, 0, 3, 3}, random...), 0)
	}
	want := hex.EncodeToString(random)
	for _, tc := range []struct {
		name string
		sent []byte
		ok   bool
	}{
		{"a ClientHello", hello(512), true},
		{"after a CONNECT", append([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"), hello(512)...), true},
		{"a CONNECT that goes on", []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: x"), false},
		{"after a SOCKS5 handshake", slices.Concat([]byte{5, 1, 0, 5, 1, 0, 3, 11}, []byte("example.com"), []byte{1, 187},
			hello(512)), true},
		{"after a SOCKS4 handshake", slices.Concat([]byte{4, 1, 1, 187, 192, 0, 2, 1}, []byte("nobody\x00"), hello(512)), true},
		{"a SOCKS5 handshake that goes on", []byte{5, 1, 0, 5, 1}, false},
		{"plain HTTP after a SOCKS5 handshake", slices.Concat([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80},
			[]byte("GET / HTTP/1.1\r\n\r\n")), false},
		{"plain HTTP", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), false},
		{"too short", hello(512)[:40], false},
		{"a record too short for its random", hello(37), false},
		{"as short as a random allows", hello(38), true},
		{"not a handshake", append([]byte{23}, hello(512)[1:]...), false},
		{"not TLS", append([]byte{22, 2}, hello(512)[2:]...), false},
		{"not a ClientHello", append(append(hello(512)[:5], 2), hello(512)[6:]...), false},
		{"nothing", nil, false},
	} {
		got, ok := ClientRandom(tc.sent)
		if ok != tc.ok || (ok && got != want) || (!ok && got != "") {
			t.Errorf("%s: %q, %v", tc.name, got, ok)
		}
	}
}

func TestMasked(t *testing.T) {
	hello := []byte("\x16\x03\x01 Proxy-Authorization: Basic x\r\n")
	port := []byte{1, 187}
	for _, tc := range []struct {
		name       string
		sent, want []byte
	}{
		{"a SOCKS5 password", slices.Concat([]byte{5, 2, 0, 2, 1, 5}, []byte("alice"), []byte{6}, []byte("s3cr3t"),
			[]byte{5, 1, 0, 1, 192, 0, 2, 1}, port, hello),
			slices.Concat([]byte{5, 2, 0, 2, 1, 5}, []byte("alice"), []byte{6}, []byte("******"),
				[]byte{5, 1, 0, 1, 192, 0, 2, 1}, port, hello)},
		{"a SOCKS5 password cut short", slices.Concat([]byte{5, 1, 2, 1, 1, 'u', 6}, []byte("s3c")),
			slices.Concat([]byte{5, 1, 2, 1, 1, 'u', 6}, []byte("***"))},
		{"a SOCKS5 password yet to come", []byte{5, 1, 2, 1, 1, 'u', 6}, []byte{5, 1, 2, 1, 1, 'u', 6}},
		{"a SOCKS5 user name and no more", []byte{5, 1, 2, 1, 5, 'a', 'l'}, []byte{5, 1, 2, 1, 5, 'a', 'l'}},
		{"an empty SOCKS5 password", slices.Concat([]byte{5, 1, 2, 1, 1, 'u', 0, 5, 1, 0, 1, 192, 0, 2, 1}, port),
			slices.Concat([]byte{5, 1, 2, 1, 1, 'u', 0, 5, 1, 0, 1, 192, 0, 2, 1}, port)},
		{"a SOCKS5 CONNECT without a password", slices.Concat([]byte{5, 1, 0, 5, 1, 0, 1, 1, 6, 1, 1}, port, hello),
			slices.Concat([]byte{5, 1, 0, 5, 1, 0, 1, 1, 6, 1, 1}, port, hello)},
		{"a SOCKS4 user", slices.Concat([]byte{4, 1}, port, []byte{192, 0, 2, 1}, []byte("nobody@0.0.0.0\x00")),
			slices.Concat([]byte{4, 1}, port, []byte{192, 0, 2, 1}, []byte("nobody@0.0.0.0\x00"))},
		{"a CONNECT's credentials", []byte("CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n" +
			"Proxy-Authorization: Basic YWxpY2U6czNjcjN0\r\nX-Asked: Basic yes\r\n\r\n" + string(hello)),
			[]byte("CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n" +
				"Proxy-Authorization: Basic ****************\r\nX-Asked: Basic yes\r\n\r\n" + string(hello))},
		{"a field in other capitals, spaced out", []byte("CONNECT a:443 HTTP/1.1\r\nproxy-AUTHORIZATION :\t Bearer t0k3n\r\n\r\n"),
			[]byte("CONNECT a:443 HTTP/1.1\r\nproxy-AUTHORIZATION :\t Bearer *****\r\n\r\n")},
		{"a value without a scheme", []byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: t0k3n\r\n\r\n"),
			[]byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: *****\r\n\r\n")},
		{"two of them", []byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic ab\r\nProxy-Authorization: Digest c d\r\n\r\n"),
			[]byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic **\r\nProxy-Authorization: Digest ***\r\n\r\n")},
		{"credentials cut short", []byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxp"),
			[]byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic ****")},
		{"credentials cut at their CR", []byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxp\r"),
			[]byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic ****\r")},
		{"a request line cut short", []byte("CONNECT a:443 HTTP/1.1"), []byte("CONNECT a:443 HTTP/1.1")},
		{"a field without a colon", []byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization\r\n\r\n"),
			[]byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization\r\n\r\n")},
		{"what goes through a tunnel", []byte("CONNECT a:80 HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nProxy-Authorization: Basic x\r\n"),
			[]byte("CONNECT a:80 HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nProxy-Authorization: Basic x\r\n")},
		{"a forward request", []byte("GET / HTTP/1.1\r\nProxy-Authorization: Basic x\r\n"),
			[]byte("GET / HTTP/1.1\r\nProxy-Authorization: Basic *\r\n")},
		{"nothing", nil, nil},
	} {
		sent := bytes.Clone(tc.sent)
		if got := Masked(tc.sent); !bytes.Equal(got, tc.want) || !bytes.Equal(tc.sent, sent) {
			t.Errorf("%s: %q, and what was sent is now %q", tc.name, got, tc.sent)
		}
	}
}

func TestTunnelled(t *testing.T) {
	// A request for a tunnel, and what went through it once it was asked
	// for: before the request is whole, at every byte, nothing yet.
	inside := []byte("\x16\x03\x01 what went through")
	port := []byte{1, 187}
	for _, tc := range []struct {
		name    string
		request []byte
	}{
		{"a CONNECT", []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")},
		{"a SOCKS5 CONNECT to an IPv4 address", slices.Concat([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1}, port)},
		{"a SOCKS5 CONNECT to an IPv6 address", slices.Concat([]byte{5, 1, 0, 5, 1, 0, 4},
			netip.MustParseAddr("2001:db8::1").AsSlice(), port)},
		{"a SOCKS5 CONNECT to a name", slices.Concat([]byte{5, 1, 0, 5, 1, 0, 3, 11}, []byte("example.com"), port)},
		{"a SOCKS5 CONNECT offering two ways in", slices.Concat([]byte{5, 2, 0, 2, 5, 1, 0, 3, 11}, []byte("example.com"),
			port)},
		{"a SOCKS5 CONNECT after a user name and password", slices.Concat([]byte{5, 2, 0, 2, 1, 5}, []byte("alice"),
			[]byte{6}, []byte("s3cr3t"), []byte{5, 1, 0, 3, 11}, []byte("example.com"), port)},
		{"a SOCKS5 CONNECT after an empty user name and password", slices.Concat([]byte{5, 1, 2, 1, 0, 0, 5, 1, 0, 1,
			192, 0, 2, 1}, port)},
		{"a SOCKS4 CONNECT", slices.Concat([]byte{4, 1}, port, []byte{192, 0, 2, 1}, []byte("nobody@0.0.0.0\x00"))},
		{"a SOCKS4 CONNECT without a user", slices.Concat([]byte{4, 1}, port, []byte{192, 0, 2, 1, 0})},
		{"a SOCKS4 CONNECT to 0.0.0.0", slices.Concat([]byte{4, 1}, port, []byte{0, 0, 0, 0}, []byte("u\x00"))},
		{"a SOCKS4 CONNECT to 1.0.0.1", slices.Concat([]byte{4, 1}, port, []byte{1, 0, 0, 1}, []byte("u\x00"))},
		{"a SOCKS4 CONNECT to 0.1.0.1", slices.Concat([]byte{4, 1}, port, []byte{0, 1, 0, 1}, []byte("u\x00"))},
		{"a SOCKS4 CONNECT to 0.0.1.1", slices.Concat([]byte{4, 1}, port, []byte{0, 0, 1, 1}, []byte("u\x00"))},
		{"a SOCKS4a CONNECT", slices.Concat([]byte{4, 1}, port, []byte{0, 0, 0, 1}, []byte("nobody@0.0.0.0\x00example.com\x00"))},
		{"a SOCKS4a CONNECT to 0.0.0.255", slices.Concat([]byte{4, 1}, port, []byte{0, 0, 0, 255}, []byte("\x00a\x00"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for n := range len(tc.request) {
				if got, whole := Tunnelled(tc.request[:n]); whole || got != nil {
					t.Fatalf("the first %d bytes: %q, %v", n, got, whole)
				}
			}
			if got, whole := Tunnelled(tc.request); !whole || len(got) != 0 {
				t.Errorf("the request alone: %q, %v", got, whole)
			}
			if got, whole := Tunnelled(slices.Concat(tc.request, inside)); !whole || !bytes.Equal(got, inside) {
				t.Errorf("with what went through: %q, %v", got, whole)
			}
		})
	}
	// What asks a proxy for no tunnel, or for one but not as a CONNECT: all
	// of it, whole.
	for _, tc := range []struct {
		name string
		sent []byte
	}{
		{"a ClientHello", inside},
		{"plain HTTP", []byte("GET / HTTP/1.1\r\n\r\n")},
		{"a SOCKS5 greeting and then no SOCKS5", []byte{5, 1, 0, 4, 1, 0, 1}},
		{"a SOCKS5 BIND", slices.Concat([]byte{5, 1, 0, 5, 2, 0, 1, 192, 0, 2, 1}, port, inside)},
		{"a SOCKS5 UDP ASSOCIATE", slices.Concat([]byte{5, 1, 0, 5, 3, 0, 1, 192, 0, 2, 1}, port, inside)},
		{"a SOCKS5 CONNECT reserved wrong", slices.Concat([]byte{5, 1, 0, 5, 1, 1, 1, 192, 0, 2, 1}, port, inside)},
		{"a SOCKS5 CONNECT to no kind of address", slices.Concat([]byte{5, 1, 0, 5, 1, 0, 2, 192, 0, 2, 1}, port, inside)},
		{"a SOCKS4 BIND", slices.Concat([]byte{4, 2}, port, []byte{192, 0, 2, 1, 0}, inside)},
	} {
		if got, whole := Tunnelled(tc.sent); !whole || !bytes.Equal(got, tc.sent) {
			t.Errorf("%s: %q, %v", tc.name, got, whole)
		}
	}
}

func TestMaskedForwardRequestsAndBodies(t *testing.T) {
	body := "GET /fake HTTP/1.1\r\nProxy-Authorization: Basic keep-body\r\n\r\n"
	head := fmt.Sprintf("POST http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: Basic never-keep\r\nContent-Length: %d\r\n\r\n", len(body))
	next := "GET http://origin.test/y HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: Bearer never-keep\r\n\r\n"
	for _, sent := range []string{head + body + next, "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\nProxy-Authorization: Basic never-keep\r\n\r\n" + fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body) + next} {
		safe := Masked([]byte(sent))
		if len(safe) != len(sent) || bytes.Contains(safe, []byte("never-keep")) || !bytes.Contains(safe, []byte(body)) {
			t.Errorf("unsafe or changed body: %s", safe)
		}
		for i := range len(sent) + 1 {
			partial := Masked([]byte(sent[:i]))
			if bytes.Contains(partial, []byte("never-keep")) {
				t.Errorf("prefix %d leaked: %s", i, partial)
				break
			}
		}
	}
}

func TestMaskedEventSnapshotKeepsCutsAndInput(t *testing.T) {
	raw := []byte("GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: Basic never-keep\r\n\r\n")
	events := []Event{{What: Received, Data: []byte("server")}}
	for _, b := range raw {
		events = append(events, Event{What: Sent, Data: []byte{b}})
	}
	events = append(events, Event{What: Closed})
	safe := MaskedEvents(events)
	var joined []byte
	for i, event := range safe {
		if event.What != events[i].What || event.At != events[i].At || len(event.Data) != len(events[i].Data) {
			t.Fatalf("event %d changed shape", i)
		}
		if event.What == Sent {
			joined = append(joined, event.Data...)
		}
	}
	if !bytes.Equal(joined, Masked(raw)) {
		t.Fatalf("unmasked: %s", joined)
	}
	var original []byte
	for _, event := range events {
		if event.What == Sent {
			original = append(original, event.Data...)
		}
	}
	if !bytes.Equal(original, raw) || !bytes.Equal(safe[0].Data, []byte("server")) {
		t.Error("input or server data changed")
	}
}
