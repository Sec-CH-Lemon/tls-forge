package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/atomicfile"
	"github.com/Sec-CH-Lemon/tls-forge/internal/conntap"
	"github.com/Sec-CH-Lemon/tls-forge/internal/pcapng"
	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
)

// What --pcap keeps beside each request's files: NAME.pcapng, the
// connections the request went out on, every byte each way as tls-forge wrote
// and read it but for the credentials it gave a proxy in the clear, which are
// masked, every datagram of a QUIC connection, and the TLS secrets Wireshark
// opens them with.

// captureSuffix is what a request's capture adds to its name.
const captureSuffix = ".pcapng"

// maxHead is the most of what a connection sent first that is kept to find
// the ClientHello it began with: a CONNECT or a SOCKS handshake and a
// ClientHello are far less. maxInitials is the most datagrams of a QUIC
// connection looked into for it: its ClientHello goes in its first flight.
const (
	maxHead     = 64 << 10
	maxInitials = 16
)

// wire is what the connections of a run carried, kept for --pcap: every byte
// each way and when, which requests went out on each, and the TLS secrets of
// those that began with a ClientHello. A connection is let go of once it is
// closed and every request that went out on it has been kept, and its
// secrets with it.
type wire struct {
	mu    sync.Mutex
	conns []*wiredConn
	// secrets are the lines of the key log by the client random they are of,
	// for the randoms of the connections kept, and part is a line that has not
	// ended yet.
	secrets map[string][]byte
	part    []byte
}

func newWire() *wire {
	return &wire{secrets: map[string][]byte{}}
}

// wiredConn is a connection a request was dialed, as the wire keeps it: a TCP
// connection, or a QUIC one's datagrams.
type wiredConn struct {
	net.Conn
	w *wire

	// Everything below is the wire's, under its lock.
	client, server    netip.AddrPort
	opened, connected time.Time
	// quic says the connection is QUIC's, and source is where its datagrams
	// came from, its client's end given an address where its socket has
	// none.
	quic   bool
	source netip.AddrPort
	// events are private connection bytes. capture masks proxy credentials on
	// a reassembled snapshot before they can reach a pcap file.
	events []pcapng.Event
	// head is what the client sent first, as it sent it, until random, the
	// client random of the ClientHello it began with, is found, or looked says
	// it will not be; for a QUIC connection initials, its datagrams.
	head     []byte
	initials [][]byte
	random   string
	looked   bool
	users    map[int]bool
	closed   bool
}

func (c *wiredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.w.received(c, bytes.Clone(p[:n]), err)
	return n, err
}

func (c *wiredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.w.sent(c, bytes.Clone(p[:n]))
	return n, err
}

func (c *wiredConn) Close() error {
	c.w.closing(c)
	return c.Conn.Close()
}

// tap is how request id shows the wire its connections.
func (w *wire) tap(id int) conntap.Tap {
	return wireTap{w: w, id: id}
}

type wireTap struct {
	w  *wire
	id int
}

func (t wireTap) Dialed(conn net.Conn, began time.Time) net.Conn {
	c := &wiredConn{Conn: conn, w: t.w, client: addrPortOf(conn.LocalAddr()), server: addrPortOf(conn.RemoteAddr()),
		opened: began, connected: time.Now(), users: map[int]bool{t.id: true}}
	t.w.mu.Lock()
	t.w.conns = append(t.w.conns, c)
	t.w.mu.Unlock()
	return c
}

func (t wireTap) QUIC(local, remote net.Addr, began time.Time) conntap.Datagrams {
	client, server := addrPortOf(local), addrPortOf(remote)
	c := &wiredConn{w: t.w, client: client, server: server, source: sourceToward(client, server), quic: true,
		opened: began, connected: began, users: map[int]bool{t.id: true}}
	t.w.mu.Lock()
	t.w.conns = append(t.w.conns, c)
	t.w.mu.Unlock()
	return wiredDatagrams{c}
}

// sourceToward is client, the end of a socket, with the address the system
// sends from to server where the socket has none (it is bound to every
// address).
func sourceToward(client, server netip.AddrPort) netip.AddrPort {
	if !client.Addr().IsUnspecified() {
		return client
	}
	probe, err := dialUDP("udp", nil, net.UDPAddrFromAddrPort(server))
	if err != nil {
		return client
	}
	defer func() { _ = probe.Close() }()
	return netip.AddrPortFrom(addrPortOf(probe.LocalAddr()).Addr(), client.Port())
}

// dialUDP is how sourceToward asks the system the way to a server: the seam
// a test makes find none, since which address finds none is the system's to
// say (macOS none to 0.0.0.0, Linux and Windows the loopback).
var dialUDP = net.DialUDP

// wiredDatagrams is how a QUIC connection's socket tells the wire of its
// datagrams.
type wiredDatagrams struct{ c *wiredConn }

func (d wiredDatagrams) Wrote(b []byte) { d.c.w.wrote(d.c, bytes.Clone(b)) }
func (d wiredDatagrams) Read(b []byte)  { d.c.w.received(d.c, bytes.Clone(b), nil) }
func (d wiredDatagrams) Closed()        { d.c.w.closing(d.c) }

func (t wireTap) Used(conn net.Conn) {
	local, remote := addrPortOf(conn.LocalAddr()), addrPortOf(conn.RemoteAddr())
	t.w.mu.Lock()
	defer t.w.mu.Unlock()
	for _, c := range t.w.conns {
		if !c.closed && c.client == local && c.server == remote {
			c.users[t.id] = true
			return
		}
	}
}

// addrPortOf is the address and port of one end of a TCP connection, an IPv4
// address as IPv4 however it is written.
func addrPortOf(addr net.Addr) netip.AddrPort {
	var end netip.AddrPort
	if tcp, ok := addr.(*net.TCPAddr); ok {
		end = tcp.AddrPort()
	} else {
		end, _ = netip.ParseAddrPort(addr.String())
	}
	return netip.AddrPortFrom(end.Addr().Unmap(), end.Port())
}

func (w *wire) sent(c *wiredConn, data []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(data) == 0 {
		return
	}
	at := time.Now()
	if !c.looked {
		c.head = append(c.head, data...)
	}
	c.events = append(c.events, pcapng.Event{At: at, What: pcapng.Sent, Data: data})
	if c.looked {
		return
	}
	if random, ok := pcapng.ClientRandom(c.head); ok {
		c.random = random
		w.secrets[random] = nil
	} else if len(c.head) < maxHead && beginsTLS(c.head) {
		return
	}
	c.looked, c.head = true, nil
}

// wrote is a datagram a QUIC connection's socket sent; until the client
// random of the connection's ClientHello is found in its Initial packets, the
// wire looks for it there, while it sends long header packets.
func (w *wire) wrote(c *wiredConn, data []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	c.events = append(c.events, pcapng.Event{At: time.Now(), What: pcapng.Sent, Data: data})
	if c.looked {
		return
	}
	c.initials = append(c.initials, data)
	if random, ok := pcapng.QUICClientRandom(c.initials); ok {
		c.random = random
		w.secrets[random] = nil
	} else if len(c.initials) < maxInitials && len(data) > 0 && data[0]&0x80 != 0 {
		return
	}
	c.looked, c.initials = true, nil
}

// beginsTLS says whether what a client sent so far may yet begin with a
// ClientHello: a handshake record, or a request for a tunnel through a proxy
// in the clear, a CONNECT or a SOCKS handshake, which one follows, or no more
// of either than is there.
func beginsTLS(head []byte) bool {
	tunnelled, whole := pcapng.Tunnelled(head)
	return !whole || len(tunnelled) == 0 || tunnelled[0] == 22
}

func (w *wire) received(c *wiredConn, data []byte, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	at := time.Now()
	if len(data) > 0 {
		c.events = append(c.events, pcapng.Event{At: at, What: pcapng.Received, Data: data})
	}
	switch {
	case errors.Is(err, io.EOF):
		c.events = append(c.events, pcapng.Event{At: at, What: pcapng.Ended})
	case errors.Is(err, syscall.ECONNRESET):
		c.events = append(c.events, pcapng.Event{At: at, What: pcapng.Reset})
	}
}

func (w *wire) closing(c *wiredConn) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c.closed {
		return
	}
	c.events = append(c.events, pcapng.Event{At: time.Now(), What: pcapng.Closed})
	c.closed = true
	w.letGo()
}

// letGo lets go of the connections closed that no request is still to be
// kept with, and of their secrets.
func (w *wire) letGo() {
	w.conns = slices.DeleteFunc(w.conns, func(c *wiredConn) bool {
		gone := c.closed && len(c.users) == 0
		if gone && c.random != "" {
			delete(w.secrets, c.random)
		}
		return gone
	})
}

// Write takes the TLS secrets of the run, a line of the NSS key log at a
// time, and keeps those of a connection the wire has. It never fails: a
// handshake whose secrets are not kept goes on all the same.
func (w *wire) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.part = append(w.part, p...)
	for {
		end := bytes.IndexByte(w.part, '\n')
		if end < 0 {
			return len(p), nil
		}
		line := w.part[:end+1]
		w.part = w.part[end+1:]
		// LABEL CLIENT_RANDOM SECRET, the random in hex.
		fields := strings.Fields(string(line))
		if len(fields) != 3 {
			continue
		}
		random := strings.ToLower(fields[1])
		if kept, wanted := w.secrets[random]; wanted {
			w.secrets[random] = append(kept, line...)
		}
	}
}

// capture is what request id went out on: the connections, each as far as
// it has got, and their secrets. The request is kept with them, so the wire
// lets go of what nothing needs any more.
func (w *wire) capture(id int) ([]pcapng.Stream, []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var streams []pcapng.Stream
	var secrets []byte
	for _, c := range w.conns {
		if !c.users[id] {
			continue
		}
		client := c.client
		if c.quic {
			client = c.source
		}
		events := c.events[:len(c.events):len(c.events)]
		if !c.quic {
			events = pcapng.MaskedEvents(events)
		}
		streams = append(streams, pcapng.Stream{Client: client, Server: c.server, Opened: c.opened,
			Connected: c.connected, Events: events, Datagrams: c.quic})
		secrets = append(secrets, w.secrets[c.random]...)
		delete(c.users, id)
	}
	w.letGo()
	return streams, secrets
}

// keep writes what request j went out on to path, as a pcapng file.
func (w *wire) keep(path string, r *result, j job, about requestAbout) error {
	streams, secrets := w.capture(j.id)
	file := pcapng.File{
		Application: "tls-forge " + version,
		Comment: fmt.Sprintf("%s %s, request %d of run %s: the connections it went out on, as tls-forge wrote and "+
			"read them. Every TCP/IP and UDP/IP header is made up; the bytes above them are what the connections "+
			"carried, but for the credentials a proxy was given in the clear, a * for each of their bytes, and a QUIC "+
			"connection's datagrams as its socket wrote and read them. "+
			"The TLS secrets are in this file: whoever has it reads every connection.",
			about.method, redact.URL(r.URL), j.id, about.run),
		Interface: "the connections of request " + fmt.Sprint(j.id),
		Secrets:   secrets,
	}
	return atomicfile.Stream(path, 0o600, func(out io.Writer) error { return pcapng.Write(out, file, streams) })
}
