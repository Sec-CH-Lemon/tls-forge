// Package pcapng writes the TCP connections a client made as a pcapng file
// that Wireshark opens: every byte each connection carried, each way, at the
// moment the client wrote or read it, in packets whose IP and TCP headers are
// made here, and the TLS secrets that let Wireshark read them, in a
// Decryption Secrets Block ahead of the packets.
//
// The headers are made up. The two ends of a connection are its own, but its
// segments are the client's writes and reads, cut only where an IP packet
// must be, with sequence numbers that count from zero, no TCP options and no
// retransmission. What the system did on the wire, its handshake and its
// TCP/IP fingerprint, is not in it: a capture of the wire has that.
package pcapng

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"time"
)

// Kind is what happened on a connection.
type Kind uint8

const (
	// Sent is the client writing Data.
	Sent Kind = iota
	// Received is the client reading Data.
	Received
	// Closed is the client closing the connection.
	Closed
	// Ended is the server ending it: a read came to the end of what it sent.
	Ended
	// Reset is the server resetting it.
	Reset
)

// An Event is something that happened on a connection, when it did.
type Event struct {
	At   time.Time
	What Kind
	Data []byte
}

// A Stream is one TCP connection as its client saw it.
type Stream struct {
	// Client and Server are its two ends.
	Client, Server netip.AddrPort
	// Opened is when it was asked for, and Connected when it was there.
	Opened, Connected time.Time
	// Events are what happened on it, in the order they did.
	Events []Event
}

// File is what the head of a file says.
type File struct {
	// Application is the program that wrote it.
	Application string
	// Comment says what the file is to whoever opens it.
	Comment string
	// Interface says where its packets are from.
	Interface string
	// Secrets are the TLS secrets of its connections, in the NSS key log
	// format. With none the file has no Decryption Secrets Block.
	Secrets []byte
}

// synComment is said of the first packet of every connection, which is the
// one a reader of the TCP/IP layer looks at first.
const synComment = "made up by tls-forge, as is every TCP/IP header in this file: " +
	"the bytes above them are what the connection carried"

// maxData is the most a packet carries past its headers: what fits an IPv4
// packet of 65,535 bytes after 20 of IP and 20 of TCP.
const maxData = 65535 - 20 - 20

// The TCP flags a segment is made with.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
)

// The block types and the codes of the options written.
const (
	sectionHeader   = 0x0A0D0D0A
	interfaceBlock  = 0x00000001
	enhancedPacket  = 0x00000006
	secretsBlock    = 0x0000000A
	byteOrderMagic  = 0x1A2B3C4D
	tlsKeyLog       = 0x544C534B
	linkTypeRaw     = 101
	optComment      = 1
	optName         = 2
	optDescription  = 3
	optTimeResol    = 9
	optApplication  = 4
	nanosecondsUnit = 9
)

// segment is a packet of a stream: its IP and TCP headers, the data they
// carry, and when.
type segment struct {
	at      time.Time
	header  []byte
	data    []byte
	comment string
}

// Write writes the streams to w as a pcapng file: a section header, one
// interface of raw IP packets, the secrets, and the packets of every stream,
// each stream's in its order and the streams' together by time.
func Write(w io.Writer, f File, streams []Stream) error {
	out := &blocks{w: w}
	out.block(sectionHeader, le32(byteOrderMagic), le16(1), le16(0), le64(^uint64(0)),
		options(option(optComment, []byte(f.Comment)), option(optApplication, []byte(f.Application))))
	out.block(interfaceBlock, le16(linkTypeRaw), le16(0), le32(0),
		options(option(optName, []byte("tls-forge")), option(optDescription, []byte(f.Interface)),
			option(optTimeResol, []byte{nanosecondsUnit})))
	if len(f.Secrets) > 0 {
		out.block(secretsBlock, le32(tlsKeyLog), le32(uint32(len(f.Secrets))), padded(f.Secrets))
	}
	lists := make([][]segment, len(streams))
	for i, s := range streams {
		lists[i] = segmentsOf(s)
	}
	next := make([]int, len(lists))
	for {
		first := -1
		for i, list := range lists {
			if next[i] < len(list) && (first < 0 || list[next[i]].at.Before(lists[first][next[first]].at)) {
				first = i
			}
		}
		if first < 0 {
			return out.err
		}
		out.packet(lists[first][next[first]])
		next[first]++
	}
}

// segmentsOf is a stream as packets: the handshake its connection must have
// had, the client's writes and reads, and how it ended.
func segmentsOf(s Stream) []segment {
	opened, connected := s.Opened, s.Connected
	if opened.IsZero() {
		opened = connected
	}
	if connected.IsZero() {
		connected = opened
	}
	v4 := s.Client.Addr().Unmap().Is4() && s.Server.Addr().Unmap().Is4()
	var out []segment
	// The next sequence number of each end, from an initial one of zero.
	var client, server uint32
	add := func(at time.Time, fromClient bool, flags byte, data []byte, comment string) {
		src, dst, seq, ack := s.Client, s.Server, client, server
		if !fromClient {
			src, dst, seq, ack = s.Server, s.Client, server, client
		}
		if flags&flagACK == 0 {
			ack = 0
		}
		out = append(out, segment{at: at, header: headers(v4, src, dst, seq, ack, flags, data), data: data,
			comment: comment})
	}
	add(opened, true, flagSYN, nil, synComment)
	client++
	add(connected, false, flagSYN|flagACK, nil, "")
	server++
	add(connected, true, flagACK, nil, "")
	clientDone, serverDone := false, false
	for _, e := range s.Events {
		switch e.What {
		case Sent, Received:
			fromClient := e.What == Sent
			for data := e.Data; len(data) > 0; {
				part := data[:min(len(data), maxData)]
				add(e.At, fromClient, flagPSH|flagACK, part, "")
				if fromClient {
					client += uint32(len(part))
				} else {
					server += uint32(len(part))
				}
				data = data[len(part):]
			}
		case Closed:
			if !clientDone {
				add(e.At, true, flagFIN|flagACK, nil, "")
				client++
				clientDone = true
			}
		case Ended, Reset:
			if !serverDone {
				flag := byte(flagFIN)
				if e.What == Reset {
					flag = flagRST
				}
				add(e.At, false, flag|flagACK, nil, "")
				if e.What == Ended {
					server++
				}
				serverDone = true
			}
		}
	}
	return out
}

// headers are the IP and TCP headers of a segment from src to dst carrying
// data: IPv4 when both ends are IPv4 addresses, else IPv6, with checksums.
func headers(v4 bool, src, dst netip.AddrPort, seq, ack uint32, flags byte, data []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	length := len(tcp) + len(data)

	var ip, pseudo []byte
	if v4 {
		from, to := src.Addr().Unmap().As4(), dst.Addr().Unmap().As4()
		ip = make([]byte, 20)
		ip[0] = 4<<4 | 5
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+length))
		binary.BigEndian.PutUint16(ip[6:], 0x4000) // don't fragment
		ip[8] = 64
		ip[9] = 6
		copy(ip[12:], from[:])
		copy(ip[16:], to[:])
		binary.BigEndian.PutUint16(ip[10:], checksum(ip))
		pseudo = append(append(append([]byte{}, from[:]...), to[:]...), 0, 6, byte(length>>8), byte(length))
	} else {
		from, to := src.Addr().As16(), dst.Addr().As16()
		ip = make([]byte, 40)
		ip[0] = 6 << 4
		binary.BigEndian.PutUint16(ip[4:], uint16(length))
		ip[6] = 6
		ip[7] = 64
		copy(ip[8:], from[:])
		copy(ip[24:], to[:])
		pseudo = append(append(append([]byte{}, from[:]...), to[:]...),
			0, 0, byte(length>>8), byte(length), 0, 0, 0, 6)
	}
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo, tcp, data))
	return append(ip, tcp...)
}

// checksum is the Internet checksum of the parts, one after another: the
// ones' complement of their ones' complement sum in 16-bit words.
func checksum(parts ...[]byte) uint16 {
	var sum uint64
	var high byte
	odd := false
	for _, part := range parts {
		for _, b := range part {
			if odd {
				sum += uint64(high)<<8 | uint64(b)
			} else {
				high = b
			}
			odd = !odd
		}
	}
	if odd {
		sum += uint64(high) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// ClientRandom is the random of the ClientHello a client began a connection
// with, in hex, which its lines in a key log name it by: at the start of what
// it sent, or after it asked a proxy in the clear for a tunnel (Tunnelled).
// False when what it sent begins with no ClientHello.
func ClientRandom(sent []byte) (string, bool) {
	// Nothing, while the request for a tunnel is cut short.
	sent, _ = Tunnelled(sent)
	// A handshake record, its ClientHello's type, length and version, then
	// the random.
	const random = 5 + 4 + 2
	if len(sent) < random+32 || sent[0] != 22 || sent[1] != 3 || sent[5] != 1 ||
		int(binary.BigEndian.Uint16(sent[3:5])) < random-5+32 {
		return "", false
	}
	return hex.EncodeToString(sent[random : random+32]), true
}

// Tunnelled is what a client sent through the tunnel it asked a proxy for in
// the clear, and whole says it had asked: what it sent after an HTTP proxy's
// CONNECT and the blank line that ends it; after a SOCKS5 proxy's greeting,
// the user name and password if it gave them, and its CONNECT (RFC 1928,
// 1929); or after a SOCKS4 or SOCKS4a proxy's CONNECT. Not whole while what
// it sent is such a request cut short, nothing yet included, since the rest
// is still to come; and all it sent, whole, when it begins as none does.
func Tunnelled(sent []byte) ([]byte, bool) {
	connect := []byte("CONNECT ")
	switch {
	case bytes.HasPrefix(connect, sent):
		return nil, false
	case bytes.HasPrefix(sent, connect):
		end := bytes.Index(sent, []byte("\r\n\r\n"))
		if end < 0 {
			return nil, false
		}
		return sent[end+4:], true
	case sent[0] == 5:
		return socks5(sent)
	case sent[0] == 4:
		return socks4(sent)
	}
	return sent, true
}

// socks5 is Tunnelled for what a SOCKS5 client sent: VER NMETHODS METHODS,
// then VER ULEN UNAME PLEN PASSWD when the proxy asks for them, then VER
// CMD RSV ATYP DST.ADDR DST.PORT. All it sent, whole, when that is no SOCKS5
// CONNECT.
func socks5(sent []byte) ([]byte, bool) {
	// end is where the field at start ends: its length is the byte there, and
	// more bytes follow it. Past what was sent when that byte is not there.
	end := func(start, more int) int {
		if start >= len(sent) {
			return len(sent) + 1
		}
		return start + 1 + int(sent[start]) + more
	}
	asked := end(1, 0)
	if asked < len(sent) && sent[asked] == 1 {
		asked = end(end(asked+1, 0), 0)
	}
	if asked >= len(sent) {
		return nil, false
	}
	if sent[asked] != 5 {
		return sent, true
	}
	if len(sent) < asked+4 {
		return nil, false
	}
	if sent[asked+1] != 1 || sent[asked+2] != 0 {
		return sent, true
	}
	var tunnel int
	switch sent[asked+3] {
	case 1:
		tunnel = asked + 4 + 4 + 2
	case 4:
		tunnel = asked + 4 + 16 + 2
	case 3:
		tunnel = end(asked+4, 2)
	default:
		return sent, true
	}
	if tunnel > len(sent) {
		return nil, false
	}
	return sent[tunnel:], true
}

// socks4 is Tunnelled for what a SOCKS4 client sent: VN CD DSTPORT DSTIP
// USERID and a NUL, then a host's name and a NUL when DSTIP is 0.0.0.x, x not
// 0, as SOCKS4a has it. All it sent, whole, when that is no CONNECT.
func socks4(sent []byte) ([]byte, bool) {
	if len(sent) < 2 {
		return nil, false
	}
	if sent[1] != 1 {
		return sent, true
	}
	if len(sent) < 8 {
		return nil, false
	}
	names := 1
	if sent[4] == 0 && sent[5] == 0 && sent[6] == 0 && sent[7] != 0 {
		names = 2
	}
	tunnel := 8
	for range names {
		nul := bytes.IndexByte(sent[tunnel:], 0)
		if nul < 0 {
			return nil, false
		}
		tunnel += nul + 1
	}
	return sent[tunnel:], true
}

// blocks writes pcapng blocks to w, until a write fails.
type blocks struct {
	w   io.Writer
	err error
}

// block writes a block of a type, its body the parts, each a multiple of
// four bytes long.
func (b *blocks) block(kind uint32, parts ...[]byte) {
	length := 12
	for _, part := range parts {
		length += len(part)
	}
	b.write(le32(kind), le32(uint32(length)))
	b.write(parts...)
	b.write(le32(uint32(length)))
}

// packet writes a segment as an Enhanced Packet Block.
func (b *blocks) packet(s segment) {
	length := len(s.header) + len(s.data)
	at := uint64(max(s.at.UnixNano(), 0))
	var comment []byte
	if s.comment != "" {
		comment = options(option(optComment, []byte(s.comment)))
	}
	pad := make([]byte, (4-length%4)%4)
	b.block(enhancedPacket, le32(0), le32(uint32(at>>32)), le32(uint32(at)), le32(uint32(length)),
		le32(uint32(length)), s.header, s.data, pad, comment)
}

func (b *blocks) write(parts ...[]byte) {
	for _, part := range parts {
		if b.err == nil && len(part) > 0 {
			_, b.err = b.w.Write(part)
		}
	}
}

// option is an option of a block, its value padded to four bytes. None for
// an empty value.
func option(code uint16, value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return append(append(le16(code), le16(uint16(len(value)))...), padded(value)...)
}

// options are the options given, ended as a block's options are.
func options(given ...[]byte) []byte {
	var out []byte
	for _, o := range given {
		out = append(out, o...)
	}
	if out == nil {
		return nil
	}
	return append(out, 0, 0, 0, 0) // the end: a code and a length of zero
}

// padded is value with zeros after it up to a multiple of four bytes.
func padded(value []byte) []byte {
	return append(append([]byte{}, value...), make([]byte, (4-len(value)%4)%4)...)
}

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
