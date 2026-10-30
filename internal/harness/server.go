package harness

import (
	"bytes"
	"cmp"
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

	"github.com/Sec-CH-Lemon/tls-forge/internal/localhost"
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
	// SNI is the server name the TLS of its connection asked for: none in
	// the clear, nor for an address.
	SNI string
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
	// Frames are the payload lengths of an HTTP/2 request's HEADERS frame
	// and of the CONTINUATION frames after it, as on the wire: priority and
	// padding included.
	Frames []int
	// Data are the payload lengths of an HTTP/2 request's DATA frames, as on
	// the wire, and Records how the TLS records of its connection carried its
	// frames, HEADERS to the last DATA (clientRecords.layout).
	Data    []int
	Records []string
	// spans are its frames in what the client sent, which records carried.
	spans   []frameSpan
	records *clientRecords
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
	// Settled are the ports of TLS that offers HTTP/2 alone, by the SETTINGS
	// it says where they are not Go's, for each a scenario asks for. What each
	// sends a connection waits until the client's first header block has
	// come, as across a network: the client writes it before it hears them.
	Settled map[H2Settings]int
	// ALPS are the ports of the bench's ALPS server, by the variant of what
	// it gives (alpsVariants), for each a scenario names.
	ALPS map[string]int

	catalogue map[string]scenario
	listeners []net.Listener
	// The connections whose bytes are read along the way reach two servers:
	// one that speaks HTTP/1.1, one that speaks HTTP/2 by prior knowledge.
	http1, http2 *chanListener
	h1, h2       *http.Server
	settled      map[H2Settings]*settledServer
	alps         map[string]*alpsServer
	tls          *tls.Config
	// spki is its key as Chrome's --ignore-certificate-errors-spki-list
	// names one: the SHA-256 of its SubjectPublicKeyInfo, in base64.
	spki string
	done sync.WaitGroup

	// misdirection answers under /misdirected/.
	misdirection Misdirection
	// urls are the URLs the run pages of the URL catalogue go to, by case
	// (urls.go).
	urls map[string]urlCase

	mu      sync.Mutex
	entries []*Entry
	// hellos are the ClientHellos read since the server started or was reset
	// (hellos.go).
	hellos []sentHello
	// alpsSeen are the handshakes of the ALPS server since the server
	// started or was reset (alps.go).
	alpsSeen []*ALPSHandshake
	// alpsReadFirst holds a variant's HTTP/2 replies until the client has
	// sent HEADERS or GOAWAY. See ReadALPSBeforeReply.
	alpsReadFirst map[string]bool
	trouble       []error
	conns         int
	open          map[net.Conn]struct{}
	closed        bool
}

// The seams the tests reach through.
var (
	newKey            = func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	createCertificate = x509.CreateCertificate
	listen            = net.Listen
)

// StartServer starts a Server answering the scenarios of the catalogue.
func StartServer() (*Server, error) { return startServer(catalogue) }

// H2Settings are what an HTTP/2 server of the bench says in its SETTINGS
// where it does not say Go's: the size of the HPACK table it lets a client
// have (Go's 4096 for 0), and the largest frame it lets a client send (Go's
// 1 MiB for 0).
type H2Settings struct{ Table, Frame uint32 }

// settledServer is an HTTP/2 server whose SETTINGS say settings, fed the
// connections whose bytes are read along the way.
type settledServer struct {
	settings H2Settings
	ln       *chanListener
	server   *http.Server
}

func startServer(scenarios map[string]scenario, opts ...func(*Server)) (*Server, error) {
	cert, err := certificate()
	if err != nil {
		return nil, err
	}
	spki := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	s := &Server{catalogue: scenarios, open: map[net.Conn]struct{}{}, Settled: map[H2Settings]int{}, ALPS: map[string]int{},
		http1:   newChanListener(),
		http2:   newChanListener(),
		settled: map[H2Settings]*settledServer{},
		alps:    map[string]*alpsServer{},
		tls:     &tls.Config{Certificates: []tls.Certificate{cert}},
		spki:    base64.StdEncoding.EncodeToString(spki[:])}
	s.tls.GetConfigForClient = s.hello
	// Each connection's TLS is a clone of this, which would draw keys of its
	// own for the session tickets it gives, and resume no other's sessions.
	for _, opt := range opts {
		opt(s)
	}
	var ticketKey [32]byte
	_, _ = rand.Read(ticketKey[:])
	s.tls.SetSessionTicketKeys([][32]byte{ticketKey})
	var prior http.Protocols
	prior.SetUnencryptedHTTP2(true)
	s.h1 = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: time.Minute, ConnContext: servedName}
	s.h2 = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: time.Minute, Protocols: &prior,
		ConnContext: servedName}
	keys := []H2Settings{}
	for _, sc := range scenarios {
		keys = append(keys, sc.settings(), H2Settings{Table: alpsVariants[sc.alps].table})
	}
	for _, key := range keys {
		if key != (H2Settings{}) && s.settled[key] == nil {
			s.settled[key] = &settledServer{settings: key, ln: newChanListener(),
				server: &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: time.Minute, Protocols: &prior,
					HTTP2:       &http.HTTP2Config{MaxDecoderHeaderTableSize: int(key.Table), MaxReadFrameSize: int(key.Frame)},
					ConnContext: servedName}}
		}
	}
	settled := slices.SortedFunc(maps.Keys(s.settled), func(a, b H2Settings) int {
		return cmp.Or(cmp.Compare(a.Table, b.Table), cmp.Compare(a.Frame, b.Frame))
	})
	// Plain HTTP at the IPv6 loopback address too, on the same port, so that
	// a URL naming [::1] is kept as one naming 127.0.0.1 is.
	plain, plain6, err := localhost.Listen(listen)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("harness: %w", err)
	}
	s.listeners = append(s.listeners, plain, plain6)
	for range 2 + len(settled) {
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
	s.Plain, s.H2, s.H1 = ports[0], ports[2], ports[3]
	names := alpsNames(scenarios)
	for _, name := range names {
		ln, err := listen("tcp", "127.0.0.1:0")
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("harness: %w", err)
		}
		s.listeners = append(s.listeners, ln)
		port := ln.Addr().(*net.TCPAddr).Port
		srv := &alpsServer{cert: cert, protos: []string{"h2", "http/1.1"}, settings: map[string][]byte{}}
		if give := alpsVariants[name].settings; give != nil {
			srv.settings["h2"] = give(originOf(port))
		}
		s.ALPS[name], s.alps[name] = port, srv
	}
	servers := map[*http.Server]*chanListener{s.h1: s.http1, s.h2: s.http2}
	for i, key := range settled {
		s.Settled[key] = ports[4+i]
		servers[s.settled[key].server] = s.settled[key].ln
	}
	s.done.Add(2*len(servers) + 2 + len(names))
	for server, ln := range servers {
		go func() {
			defer s.done.Done()
			_ = server.Serve(ln)
		}()
	}
	go s.accept(plain, nil, nil)
	go s.accept(plain6, nil, nil)
	go s.accept(s.listeners[2], []string{"h2", "http/1.1"}, nil)
	go s.accept(s.listeners[3], []string{"http/1.1"}, nil)
	for i, key := range settled {
		go s.accept(s.listeners[4+i], []string{"h2"}, s.settled[key])
	}
	for i, name := range names {
		go s.acceptALPS(s.listeners[4+len(settled)+i], name)
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
// when there are none; HTTP/2 by settled, when there is one.
func (s *Server) accept(ln net.Listener, protos []string, settled *settledServer) {
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
			s.serveConn(raw, protos, settled)
		}()
	}
}

// acceptALPS serves what comes to ln with the bench's ALPS server of the
// variant named name.
func (s *Server) acceptALPS(ln net.Listener, name string) {
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
			s.serveALPS(raw, name)
		}()
	}
}

// serveALPS shakes hands on raw as the bench's ALPS server of the variant
// named name, keeps the handshake, and reads and answers what follows over
// HTTP/2, from a server whose table is as large as the variant says, or over
// HTTP/1.1.
func (s *Server) serveALPS(raw net.Conn, name string) {
	defer func() {
		s.mu.Lock()
		delete(s.open, raw)
		s.mu.Unlock()
	}()
	conn, seen, err := s.alps[name].handshake(raw)
	if err != nil {
		_ = raw.Close()
		return
	}
	seen.Conn = s.nextConn()
	s.mu.Lock()
	s.alpsSeen = append(s.alpsSeen, seen)
	readFirst := s.alpsReadFirst[name]
	s.mu.Unlock()
	if seen.ALPN != "h2" {
		parser := &h1parser{s: s, conn: seen.Conn, scheme: "https"}
		s.http1.hand(newTeeConn(conn, "", parser.write, nil))
		return
	}
	parser := &h2parser{s: s, conn: seen.Conn, dec: hpack.NewDecoder(4096, nil), open: map[uint32]*Entry{}, alps: seen}
	table := alpsVariants[name].table
	if readFirst || table != 0 {
		parser.first = make(chan struct{})
	}
	if table == 0 {
		s.http2.hand(newTeeConn(conn, "", parser.write, parser.first))
		return
	}
	parser.dec.SetAllowedMaxDynamicTableSize(table)
	s.settled[H2Settings{Table: table}].ln.hand(newTeeConn(conn, "", parser.write, parser.first))
}

// keepConnection keeps of an ALPS handshake the first SETTINGS its client
// sent, and the error of a GOAWAY.
func (s *Server) keepConnection(h *ALPSHandshake, settings []string, goAway string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if settings != nil && h.Settings == nil {
		h.Settings = settings
	}
	if goAway != "" {
		h.GoAway = goAway
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

func (s *Server) serveConn(raw net.Conn, protos []string, settled *settledServer) {
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
	records := &clientRecords{}
	conn := tls.Server(&recordingConn{Conn: raw, records: records}, config)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol == "h2" {
		parser := &h2parser{s: s, conn: s.nextConn(), resumed: state.DidResume, sni: state.ServerName,
			dec: hpack.NewDecoder(4096, nil), open: map[uint32]*Entry{}, records: records}
		if settled == nil {
			s.http2.hand(newTeeConn(conn, state.ServerName, parser.write, nil))
			return
		}
		if table := settled.settings.Table; table != 0 {
			parser.dec.SetAllowedMaxDynamicTableSize(table)
		}
		parser.first = make(chan struct{})
		settled.ln.hand(newTeeConn(conn, state.ServerName, parser.write, parser.first))
		return
	}
	parser := &h1parser{s: s, conn: s.nextConn(), resumed: state.DidResume, scheme: "https", sni: state.ServerName,
		records: records}
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

// addData keeps of e a DATA frame of it, span.
func (s *Server) addData(e *Entry, span frameSpan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Data = append(e.Data, span.length)
	e.spans = append(e.spans, span)
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
		out[i].Data = slices.Clone(e.Data)
		out[i].spans = slices.Clone(e.spans)
		if e.records != nil {
			out[i].Records = e.records.layout(e.spans)
		}
	}
	return out, errors.Join(s.trouble...)
}

// Reset forgets every request made so far, the trouble reading them, the
// ClientHellos read, and which URLs were asked for under /misdirected/.
func (s *Server) Reset() {
	s.misdirection.Forget()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries, s.trouble, s.hellos, s.alpsSeen = nil, nil, nil, nil
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
	for _, settled := range s.settled {
		settled.ln.close()
		_ = settled.server.Close()
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
	sni       string
	buf       []byte
	preface   bool
	dec       *hpack.Decoder
	block     []byte
	stream    uint32
	endStream bool
	priority  *[3]uint32
	// frames are the payload lengths of the frames of the header block read,
	// and spans where they are in the stream.
	frames []int
	spans  []frameSpan
	open   map[uint32]*Entry
	// records are the TLS records of the connection, and read how much of
	// what they carried has been read.
	records *clientRecords
	read    int
	first   chan struct{}
	// alps is the handshake of the bench's ALPS server the connection made,
	// which keeps its first SETTINGS and its GOAWAY.
	alps *ALPSHandshake
}

func (p *h2parser) write(b []byte) {
	p.buf = append(p.buf, b...)
	p.read += len(b)
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
		start := p.read - len(p.buf)
		p.buf = p.buf[9+length:]
		p.frame(typ, flags, stream, payload, start)
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

// frame is one frame of the connection, whose bytes begin at start of the
// stream.
func (p *h2parser) frame(typ http2.FrameType, flags http2.Flags, stream uint32, payload []byte, start int) {
	span := frameSpan{length: len(payload), start: start, end: start + 9 + len(payload)}
	switch typ {
	case http2.FrameData:
		span.kind = 'D'
		payload, ok := unpadded(flags, payload)
		if e := p.open[stream]; e != nil && ok {
			p.s.addBody(e, payload)
			p.s.addData(e, span)
		}
	case http2.FrameHeaders:
		span.kind = 'H'
		p.frames, p.spans = []int{len(payload)}, []frameSpan{span}
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
	case http2.FrameSettings:
		if p.alps != nil && !flags.Has(http2.FlagSettingsAck) {
			p.s.keepConnection(p.alps, settingsOf(payload), "")
		}
	case http2.FrameGoAway:
		if p.alps != nil && len(payload) >= 8 {
			p.s.keepConnection(p.alps, nil, http2.ErrCode(binary.BigEndian.Uint32(payload[4:8])).String()+": "+
				string(payload[8:]))
			p.releaseFirst()
		}
	case http2.FrameContinuation:
		span.kind = 'C'
		p.frames, p.spans = append(p.frames, len(payload)), append(p.spans, span)
		p.block = append(p.block, payload...)
		if flags.Has(http2.FlagContinuationEndHeaders) {
			p.decode()
		}
	}
}

func (p *h2parser) releaseFirst() {
	if p.first != nil {
		close(p.first)
		p.first = nil
	}
}

func (p *h2parser) decode() {
	p.releaseFirst()
	fields, err := p.dec.DecodeFull(p.block)
	if err != nil {
		p.s.troubled(fmt.Errorf("harness: the header block of stream %d: %w", p.stream, err))
		return
	}
	e := &Entry{Proto: "h2", Conn: p.conn, Resumed: p.resumed, SNI: p.sni, Stream: p.stream, Priority: p.priority,
		Block: slices.Clone(p.block), Frames: slices.Clone(p.frames), spans: slices.Clone(p.spans), records: p.records}
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
// line, the header lines and a body of the length they say. Over TLS records
// are the records that carried them, and at is where buf begins in what the
// client sent.
type h1parser struct {
	s       *Server
	conn    int
	resumed bool
	scheme  string
	sni     string
	buf     []byte
	left    int
	cur     *Entry
	records *clientRecords
	at      int
}

func (p *h1parser) write(b []byte) {
	p.buf = append(p.buf, b...)
	for {
		if p.left > 0 {
			take := min(p.left, len(p.buf))
			p.s.addBody(p.cur, p.buf[:take])
			p.buf, p.left, p.at = p.buf[take:], p.left-take, p.at+take
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
		head := frameSpan{kind: 'R', length: end + 4, start: p.at, end: p.at + end + 4}
		p.at = head.end
		parts := strings.SplitN(lines[0], " ", 3)
		if len(parts) < 3 {
			p.s.troubled(fmt.Errorf("harness: a request line that is not one: %q", lines[0]))
			continue
		}
		e := &Entry{Proto: "http/1.1", Conn: p.conn, Resumed: p.resumed, SNI: p.sni, Method: parts[0]}
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
		if p.records != nil {
			e.records, e.spans = p.records, []frameSpan{head}
			if p.left > 0 {
				e.spans = append(e.spans, frameSpan{kind: 'B', length: p.left, start: head.end, end: head.end + p.left})
			}
		}
		p.s.record(e)
		p.cur = e
	}
}
