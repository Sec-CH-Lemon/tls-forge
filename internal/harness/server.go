package harness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Entry is a request as the bytes said it.
type Entry struct {
	// Proto is h2 or http/1.1.
	Proto string
	// Conn numbers the connection it came on, in the order they were made,
	// Resumed says that connection resumed a TLS session, and Stream is its
	// HTTP/2 stream.
	Conn    int
	Resumed bool
	Stream  uint32
	Method  string
	// Target is the URL asked for: the scheme, the authority as sent, the
	// path and query.
	Target string
	// Headers are the fields in the order sent, each name spelt as sent:
	// HTTP/2's pseudo-headers first.
	Headers [][2]string
	Body    string
	// Priority is an HTTP/2 HEADERS frame's priority: exclusive, the stream it
	// depends on, the weight as on the wire. Nil without one.
	Priority *[3]uint32
	// Block is an HTTP/2 request's header block as the client wrote it into
	// HPACK: its fragments joined, without padding or priority.
	Block []byte
}

// Server keeps every request made of it, over HTTP/2 and HTTP/1.1 on TLS and
// over plain HTTP, and answers as the scenarios need: their pages, redirects,
// CORS and cookies. It listens on the loopback address, and serves plain HTTP
// on the IPv6 one as well.
type Server struct {
	// H2, H1 and Plain are its ports: TLS that offers HTTP/2 and HTTP/1.1,
	// TLS that offers HTTP/1.1 alone, and plain HTTP, at 127.0.0.1 and at
	// [::1].
	H2, H1, Plain int
	// Tables are the ports of TLS that offers HTTP/2 alone, by the size of
	// the HPACK table its SETTINGS let a client have, for each size a scenario
	// asks for. What each sends a connection waits until the client's first
	// header block has come, as across a network: the client writes it before
	// it hears the size.
	Tables map[uint32]int

	catalogue map[string]scenario
	listeners []net.Listener
	// The connections whose bytes are read along the way reach two servers:
	// one that speaks HTTP/1.1, one that speaks HTTP/2 by prior knowledge.
	http1, http2 *chanListener
	h1, h2       *http.Server
	tables       map[uint32]*tableServer
	tls          *tls.Config
	// spki is its key as Chrome's --ignore-certificate-errors-spki-list
	// names one: the SHA-256 of its SubjectPublicKeyInfo, in base64.
	spki string
	done sync.WaitGroup

	// misdirection answers under /misdirected/.
	misdirection Misdirection

	mu      sync.Mutex
	entries []*Entry
	trouble []error
	conns   int
	open    map[net.Conn]struct{}
	closed  bool
}

// The seams the tests reach through.
var (
	newKey            = func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	createCertificate = x509.CreateCertificate
	listen            = net.Listen
)

// StartServer starts a Server answering the scenarios of the catalogue.
func StartServer() (*Server, error) { return startServer(catalogue) }

// tableServer is an HTTP/2 server whose SETTINGS let a client's HPACK table be
// size bytes, fed the connections whose bytes are read along the way.
type tableServer struct {
	size   uint32
	ln     *chanListener
	server *http.Server
}

func startServer(scenarios map[string]scenario) (*Server, error) {
	cert, err := certificate()
	if err != nil {
		return nil, err
	}
	spki := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	s := &Server{catalogue: scenarios, open: map[net.Conn]struct{}{}, Tables: map[uint32]int{},
		http1:  newChanListener(),
		http2:  newChanListener(),
		tables: map[uint32]*tableServer{},
		tls:    &tls.Config{Certificates: []tls.Certificate{cert}},
		spki:   base64.StdEncoding.EncodeToString(spki[:])}
	// Each connection's TLS is a clone of this, which would draw keys of its
	// own for the session tickets it gives, and resume no other's sessions.
	var ticketKey [32]byte
	_, _ = rand.Read(ticketKey[:])
	s.tls.SetSessionTicketKeys([][32]byte{ticketKey})
	var prior http.Protocols
	prior.SetUnencryptedHTTP2(true)
	s.h1 = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: time.Minute, ConnContext: servedName}
	s.h2 = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: time.Minute, Protocols: &prior,
		ConnContext: servedName}
	for _, sc := range scenarios {
		if sc.table != 0 && s.tables[sc.table] == nil {
			s.tables[sc.table] = &tableServer{size: sc.table, ln: newChanListener(),
				server: &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: time.Minute, Protocols: &prior,
					HTTP2: &http.HTTP2Config{MaxDecoderHeaderTableSize: int(sc.table)}, ConnContext: servedName}}
		}
	}
	tables := slices.Sorted(maps.Keys(s.tables))
	for range 3 + len(tables) {
		ln, err := listen("tcp", "127.0.0.1:0")
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("harness: %w", err)
		}
		s.listeners = append(s.listeners, ln)
	}
	ports := make([]int, len(s.listeners))
	for i, ln := range s.listeners {
		ports[i] = ln.Addr().(*net.TCPAddr).Port
	}
	s.H2, s.H1, s.Plain = ports[0], ports[1], ports[2]
	// Plain HTTP at the IPv6 loopback address too, on the same port, so that
	// a URL naming [::1] is kept as one naming 127.0.0.1 is.
	ln, err := listen("tcp", net.JoinHostPort("::1", strconv.Itoa(s.Plain)))
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("harness: %w", err)
	}
	s.listeners = append(s.listeners, ln)
	servers := map[*http.Server]*chanListener{s.h1: s.http1, s.h2: s.http2}
	for i, size := range tables {
		s.Tables[size] = ports[3+i]
		servers[s.tables[size].server] = s.tables[size].ln
	}
	s.done.Add(2*len(servers) + 2)
	for server, ln := range servers {
		go func() {
			defer s.done.Done()
			_ = server.Serve(ln)
		}()
	}
	go s.accept(s.listeners[0], []string{"h2", "http/1.1"}, nil)
	go s.accept(s.listeners[1], []string{"http/1.1"}, nil)
	go s.accept(s.listeners[2], nil, nil)
	go s.accept(ln, nil, nil)
	for i, size := range tables {
		go s.accept(s.listeners[3+i], []string{"h2"}, s.tables[size])
	}
	return s, nil
}

// certificate is the server's, for every name the scenarios use: their
// browser takes it on trust.
func certificate() (tls.Certificate, error) {
	key, err := newKey()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames:    []string{"example.com", "*.example.com", "example.net", "*.example.net", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := createCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// accept serves what comes to ln: over TLS offering protos, or plain HTTP
// when there are none; HTTP/2 by table, when there is one.
func (s *Server) accept(ln net.Listener, protos []string, table *tableServer) {
	defer s.done.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		if !s.track(raw) {
			_ = raw.Close()
			return
		}
		s.done.Add(1)
		go func() {
			defer s.done.Done()
			s.serveConn(raw, protos, table)
		}()
	}
}

// track keeps conn to be closed with the server, unless it is closed already.
func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.open[conn] = struct{}{}
	return true
}

func (s *Server) serveConn(raw net.Conn, protos []string, table *tableServer) {
	defer func() {
		s.mu.Lock()
		delete(s.open, raw)
		s.mu.Unlock()
	}()
	if protos == nil {
		parser := &h1parser{s: s, conn: s.nextConn(), scheme: "http"}
		s.http1.hand(newTeeConn(raw, "", parser.write, nil))
		return
	}
	config := s.tls.Clone()
	config.NextProtos = protos
	conn := tls.Server(raw, config)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol == "h2" {
		parser := &h2parser{s: s, conn: s.nextConn(), resumed: state.DidResume, dec: hpack.NewDecoder(4096, nil),
			open: map[uint32]*Entry{}}
		if table == nil {
			s.http2.hand(newTeeConn(conn, state.ServerName, parser.write, nil))
			return
		}
		parser.dec.SetAllowedMaxDynamicTableSize(table.size)
		parser.first = make(chan struct{})
		table.ln.hand(newTeeConn(conn, state.ServerName, parser.write, parser.first))
		return
	}
	parser := &h1parser{s: s, conn: s.nextConn(), resumed: state.DidResume, scheme: "https"}
	s.http1.hand(newTeeConn(conn, state.ServerName, parser.write, nil))
}

// nameKey is where a request's context keeps the server name the TLS of its
// connection asked for, empty in the clear.
type nameKey struct{}

// servedName is ctx for a connection the bench hands its servers, with the
// server name its TLS asked for: what a request on it is answered by.
func servedName(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, nameKey{}, conn.(*teeConn).name)
}

// servedNameOf is the server name the TLS of the connection r came on asked
// for, empty in the clear and for a request that came on none of the bench's.
func servedNameOf(r *http.Request) string {
	name, _ := r.Context().Value(nameKey{}).(string)
	return name
}

func (s *Server) nextConn() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns++
	return s.conns
}

// record keeps e, which is the server's to change from then on.
func (s *Server) record(e *Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

func (s *Server) addBody(e *Entry, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Body += string(b)
}

func (s *Server) troubled(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trouble = append(s.trouble, err)
}

// Requests are what was asked of the server since it started or was reset, in
// the order asked, and what it could not read of them.
func (s *Server) Requests() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		out[i] = *e
		out[i].Headers = slices.Clone(e.Headers)
		out[i].Block = slices.Clone(e.Block)
	}
	return out, errors.Join(s.trouble...)
}

// Reset forgets every request made so far, the trouble reading them, and
// which URLs were asked for under /misdirected/.
func (s *Server) Reset() {
	s.misdirection.Forget()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries, s.trouble = nil, nil
}

// Close stops the server and ends every connection it has.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	for conn := range s.open {
		_ = conn.Close()
	}
	s.mu.Unlock()
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.http1.close()
	s.http2.close()
	_ = s.h1.Close()
	_ = s.h2.Close()
	for _, table := range s.tables {
		table.ln.close()
		_ = table.server.Close()
	}
	s.done.Wait()
	return nil
}

// teeConn hands what is read of a connection to parse as well. Given held, it
// writes nothing until held is closed, or it is. name is the server name its
// TLS asked for, empty in the clear.
type teeConn struct {
	net.Conn
	name   string
	parse  func([]byte)
	held   <-chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newTeeConn(conn net.Conn, name string, parse func([]byte), held <-chan struct{}) *teeConn {
	return &teeConn{Conn: conn, name: name, parse: parse, held: held, closed: make(chan struct{})}
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.parse(p[:n])
	}
	return n, err
}

func (c *teeConn) Write(p []byte) (int, error) {
	if c.held != nil {
		select {
		case <-c.held:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	return c.Conn.Write(p)
}

func (c *teeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// chanListener is how connections whose bytes are read along the way reach the
// HTTP/1.1 server.
type chanListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) hand(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

func (l *chanListener) close()         { l.once.Do(func() { close(l.done) }) }
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// h2parser reads requests out of an HTTP/2 connection's bytes as the client
// wrote them: their frames, header blocks and bodies. It closes first, when
// there is one, once the first header block has come.
type h2parser struct {
	s         *Server
	conn      int
	resumed   bool
	buf       []byte
	preface   bool
	dec       *hpack.Decoder
	block     []byte
	stream    uint32
	endStream bool
	priority  *[3]uint32
	open      map[uint32]*Entry
	first     chan struct{}
}

func (p *h2parser) write(b []byte) {
	p.buf = append(p.buf, b...)
	if !p.preface {
		if len(p.buf) < len(http2.ClientPreface) {
			return
		}
		p.buf, p.preface = p.buf[len(http2.ClientPreface):], true
	}
	for len(p.buf) >= 9 {
		length := int(p.buf[0])<<16 | int(p.buf[1])<<8 | int(p.buf[2])
		if len(p.buf) < 9+length {
			return
		}
		typ, flags := http2.FrameType(p.buf[3]), http2.Flags(p.buf[4])
		stream := binary.BigEndian.Uint32(p.buf[5:9]) & 0x7fffffff
		payload := slices.Clone(p.buf[9 : 9+length])
		p.buf = p.buf[9+length:]
		p.frame(typ, flags, stream, payload)
	}
}

// unpadded is a frame's payload without its padding, or false when the
// padding says more than there is.
func unpadded(flags http2.Flags, payload []byte) ([]byte, bool) {
	if !flags.Has(http2.FlagDataPadded) {
		return payload, true
	}
	if len(payload) == 0 || int(payload[0]) > len(payload)-1 {
		return nil, false
	}
	return payload[1 : len(payload)-int(payload[0])], true
}

func (p *h2parser) frame(typ http2.FrameType, flags http2.Flags, stream uint32, payload []byte) {
	switch typ {
	case http2.FrameData:
		payload, ok := unpadded(flags, payload)
		if e := p.open[stream]; e != nil && ok {
			p.s.addBody(e, payload)
		}
	case http2.FrameHeaders:
		payload, ok := unpadded(flags, payload)
		if !ok {
			p.s.troubled(fmt.Errorf("harness: a HEADERS frame padded past its end on stream %d", stream))
			return
		}
		p.priority = nil
		if flags.Has(http2.FlagHeadersPriority) {
			if len(payload) < 5 {
				p.s.troubled(fmt.Errorf("harness: a HEADERS frame too short for its priority on stream %d", stream))
				return
			}
			dependency := binary.BigEndian.Uint32(payload[0:4])
			p.priority = &[3]uint32{dependency >> 31, dependency & 0x7fffffff, uint32(payload[4])}
			payload = payload[5:]
		}
		p.block, p.stream, p.endStream = append(p.block[:0], payload...), stream, flags.Has(http2.FlagHeadersEndStream)
		if flags.Has(http2.FlagHeadersEndHeaders) {
			p.decode()
		}
	case http2.FrameContinuation:
		p.block = append(p.block, payload...)
		if flags.Has(http2.FlagContinuationEndHeaders) {
			p.decode()
		}
	}
}

func (p *h2parser) decode() {
	if p.first != nil {
		close(p.first)
		p.first = nil
	}
	fields, err := p.dec.DecodeFull(p.block)
	if err != nil {
		p.s.troubled(fmt.Errorf("harness: the header block of stream %d: %w", p.stream, err))
		return
	}
	e := &Entry{Proto: "h2", Conn: p.conn, Resumed: p.resumed, Stream: p.stream, Priority: p.priority,
		Block: slices.Clone(p.block)}
	var scheme, authority, path string
	for _, f := range fields {
		e.Headers = append(e.Headers, [2]string{f.Name, f.Value})
		switch f.Name {
		case ":method":
			e.Method = f.Value
		case ":scheme":
			scheme = f.Value
		case ":authority":
			authority = f.Value
		case ":path":
			path = f.Value
		}
	}
	e.Target = scheme + "://" + authority + path
	p.s.record(e)
	if !p.endStream {
		p.open[p.stream] = e
	}
}

// h1parser reads requests out of an HTTP/1.1 connection's bytes: the request
// line, the header lines and a body of the length they say.
type h1parser struct {
	s       *Server
	conn    int
	resumed bool
	scheme  string
	buf     []byte
	left    int
	cur     *Entry
}

func (p *h1parser) write(b []byte) {
	p.buf = append(p.buf, b...)
	for {
		if p.left > 0 {
			take := min(p.left, len(p.buf))
			p.s.addBody(p.cur, p.buf[:take])
			p.buf, p.left = p.buf[take:], p.left-take
			if p.left > 0 {
				return
			}
			continue
		}
		end := bytes.Index(p.buf, []byte("\r\n\r\n"))
		if end < 0 {
			return
		}
		lines := strings.Split(string(p.buf[:end]), "\r\n")
		p.buf = p.buf[end+4:]
		parts := strings.SplitN(lines[0], " ", 3)
		if len(parts) < 3 {
			p.s.troubled(fmt.Errorf("harness: a request line that is not one: %q", lines[0]))
			continue
		}
		e := &Entry{Proto: "http/1.1", Conn: p.conn, Resumed: p.resumed, Method: parts[0]}
		host := ""
		for _, line := range lines[1:] {
			name, value, _ := strings.Cut(line, ":")
			value = strings.TrimLeft(value, " \t")
			e.Headers = append(e.Headers, [2]string{name, value})
			if strings.EqualFold(name, "host") {
				host = value
			}
			if strings.EqualFold(name, "content-length") {
				p.left, _ = strconv.Atoi(value)
			}
		}
		e.Target = p.scheme + "://" + host + parts[1]
		p.s.record(e)
		p.cur = e
	}
}
