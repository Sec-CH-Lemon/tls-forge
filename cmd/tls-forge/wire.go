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

	"github.com/Sec-CH-Lemon/tls-forge/v4/internal/atomicfile"
	"github.com/Sec-CH-Lemon/tls-forge/v4/internal/conntap"
	"github.com/Sec-CH-Lemon/tls-forge/v4/internal/pcapng"
)

// What --pcap keeps beside each request's files: NAME.pcapng, the
// connections the request went out on, every byte each way as tls-forge wrote
// and read it but for the credentials it gave a proxy in the clear, which are
// masked, and the TLS secrets Wireshark opens them with.

// captureSuffix is what a request's capture adds to its name.
const captureSuffix = ".pcapng"

// maxHead is the most of what a connection sent first that is kept to find
// the ClientHello it began with: a CONNECT or a SOCKS handshake and a
// ClientHello are far less.
const maxHead = 64 << 10

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

// wiredConn is a connection a request was dialed, as the wire keeps it.
type wiredConn struct {
	net.Conn
	w *wire

	// Everything below is the wire's, under its lock.
	client, server    netip.AddrPort
	opened, connected time.Time
	// events are what happened on the connection, what the client sent with
	// the credentials it gave a proxy masked (pcapng.Masked).
	events []pcapng.Event
	// head is what the client sent first, as it sent it, until random, the
	// client random of the ClientHello it began with, is found, or looked says
	// it will not be.
	head   []byte
	random string
	looked bool
	users  map[int]bool
	closed bool
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
		// What a proxy was given to let the tunnel through goes into no
		// capture: data is the wire's own copy.
		c.head = append(c.head, data...)
		copy(data, pcapng.Masked(c.head)[len(c.head)-len(data):])
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
		streams = append(streams, pcapng.Stream{Client: c.client, Server: c.server, Opened: c.opened,
			Connected: c.connected, Events: c.events[:len(c.events):len(c.events)]})
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
			"read them. Every TCP/IP header is made up; the bytes above them are what the connections carried, but for "+
			"the credentials a proxy was given in the clear, a * for each of their bytes. "+
			"The TLS secrets are in this file: whoever has it reads every connection.",
			about.method, r.URL, j.id, about.run),
		Interface: "the connections of request " + fmt.Sprint(j.id),
		Secrets:   secrets,
	}
	return atomicfile.Stream(path, 0o600, func(out io.Writer) error { return pcapng.Write(out, file, streams) })
}
