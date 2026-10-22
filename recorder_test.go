package tlsforge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tls_client "github.com/igor-lemon/tls-client"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/v5/internal/harness"
)

// keptRequest is a request as a recorder kept it: the method, the URL with no
// port, the headers in order as the bytes said them, the priority of the
// HTTP/2 HEADERS frame (exclusive, the stream it depends on, the weight on
// the wire), and the body; the connection it came on, numbered as every
// recorder took them, and whether that one resumed a TLS session.
type keptRequest struct {
	bodyMu      sync.Mutex
	method, url string
	headers     [][2]string
	priority    *[3]uint32
	body        string
	conn        int64
	resumed     bool
}

// taken numbers the connections every recorder takes, in the order taken.
var taken atomic.Int64

// recorder is a server that keeps every request as the bytes said it, over
// HTTP/2 or HTTP/1.1 behind TLS, or HTTP/1.1 in the clear, and answers each
// with handler. A client made with dialing reaches it whatever host a URL
// names.
type recorder struct {
	mu      sync.Mutex
	got     []*keptRequest
	addr    string
	handler http.Handler
	// into is a recorder this one keeps what it is sent in instead.
	into *recorder
	// closed are the connections its server has closed.
	closed map[int64]bool
	// misdirection answers under /misdirected/ as the bench does.
	misdirection harness.Misdirection
}

// recorderKey and servedNameKey are where the context of a request a
// recorder answers keeps the recorder, and the server name the TLS of the
// connection it came on asked for, empty in the clear.
type (
	recorderKey   struct{}
	servedNameKey struct{}
)

// served is ctx for a connection the recorder hands its servers.
func (r *recorder) served(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(context.WithValue(ctx, recorderKey{}, r), servedNameKey{}, conn.(*teeConn).name)
}

// misdirected answers req as the bench does under /misdirected/, and reports
// whether it did: a 421, or a 401 (harness.Misdirection).
func misdirected(w http.ResponseWriter, req *http.Request) bool {
	r := req.Context().Value(recorderKey{}).(*recorder)
	return r.misdirection.Answers(w, req, req.Context().Value(servedNameKey{}).(string))
}

func (r *recorder) keep(req *keptRequest) {
	r.mu.Lock()
	into := r.into
	if into == nil {
		r.got = append(r.got, req)
	}
	r.mu.Unlock()
	if into != nil {
		into.keep(req)
	}
}

func (r *recorder) requests() []*keptRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*keptRequest, len(r.got))
	for i, req := range r.got {
		req.bodyMu.Lock()
		q := &keptRequest{method: req.method, url: req.url, headers: append([][2]string(nil), req.headers...), body: req.body, conn: req.conn, resumed: req.resumed}
		if req.priority != nil {
			v := *req.priority
			q.priority = &v
		}
		req.bodyMu.Unlock()
		out[i] = q
	}
	return out
}

// close notes that the server closed connection conn.
func (r *recorder) close(conn int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed[conn] = true
}

// waitClosed waits until the server has closed connection conn.
func (r *recorder) waitClosed(t *testing.T, conn int64) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		r.mu.Lock()
		closed := r.closed[conn]
		r.mu.Unlock()
		if closed {
			return
		}
	}
	t.Fatalf("connection %d was never closed", conn)
}

// dialing routes every connection the client opens to the recorder.
func (r *recorder) dialing() Option {
	return WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, r.addr)
	}))
}

// trusting is dialing, and has the client take the recorder's certificate as
// a site's, as Chrome took the bench's (--ignore-certificate-errors-spki-list),
// and find every name it looks up at the recorder's address, where the
// recorder answers on whatever port a URL names: what an HTTP/2 connection
// takes to carry a request to another name. The transport options are the
// client's own, and the roots.
func (r *recorder) trusting(t *testing.T) Option {
	t.Helper()
	leaf, err := x509.ParseCertificate(recorderCertificate(t).Certificate[0])
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	at := netip.MustParseAddrPort(r.addr).Addr()
	return WithTransportOption(
		tls_client.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, r.addr)
			if err != nil {
				return nil, err
			}
			_, port, _ := net.SplitHostPort(addr)
			named, _ := strconv.Atoi(port)
			return &answeredAt{Conn: conn, at: &net.TCPAddr{IP: at.AsSlice(), Port: named}}, nil
		}),
		tls_client.WithTransportOptions(&tls_client.TransportOptions{MaxIdleConnsPerHost: 6, DisableCompression: true,
			RootCAs: roots}),
		tls_client.WithConnectionCoalescing(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{at}, nil
		}),
	)
}

// answeredAt is a connection to the recorder, from the address and port the
// client dialed.
type answeredAt struct {
	net.Conn
	at net.Addr
}

func (c *answeredAt) RemoteAddr() net.Addr { return c.at }

// dialingWith routes the connections the client opens to port 80 to plain,
// a recorder in the clear, and the rest to r, and has plain keep what it is
// sent in r's list: one list, in the order a chain of redirects went.
func (r *recorder) dialingWith(plain *recorder) Option {
	plain.mu.Lock()
	plain.into = r
	plain.mu.Unlock()
	return WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		to := r.addr
		if strings.HasSuffix(addr, ":80") {
			to = plain.addr
		}
		var d net.Dialer
		return d.DialContext(ctx, network, to)
	}))
}

// newRecorder starts a recorder speaking proto: "h2" (HTTP/2 offered over
// TLS), "h1" (HTTP/1.1 alone over TLS) or "http" (HTTP/1.1 in the clear).
func newRecorder(t *testing.T, proto string, handler http.HandlerFunc) *recorder {
	t.Helper()
	if handler == nil {
		handler = func(w http.ResponseWriter, req *http.Request) {
			if _, err := io.Copy(io.Discard, req.Body); err != nil {
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<!doctype html><title>page</title>")
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	r := &recorder{addr: ln.Addr().String(), handler: handler, closed: map[int64]bool{}}
	// Two servers fed the connections the recorder has read the TLS of: one
	// that speaks HTTP/1.1, one HTTP/2 by prior knowledge.
	h1 := &chanListener{ch: make(chan net.Conn), done: make(chan struct{}), addr: ln.Addr()}
	server := &http.Server{Handler: handler, ConnContext: r.served}
	go func() { _ = server.Serve(h1) }()
	var prior http.Protocols
	prior.SetUnencryptedHTTP2(true)
	h2 := &chanListener{ch: make(chan net.Conn), done: make(chan struct{}), addr: ln.Addr()}
	h2Server := &http.Server{Handler: handler, Protocols: &prior, ConnContext: r.served}
	go func() { _ = h2Server.Serve(h2) }()
	certificate := recorderCertificate(t)
	protos := []string{"h2", "http/1.1"}
	if proto == "h1" {
		protos = []string{"http/1.1"}
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: protos}
	var wg sync.WaitGroup
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.serve(raw, proto, cfg, h1, h2)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		close(h1.done)
		close(h2.done)
		_ = server.Close()
		_ = h2Server.Close()
		wg.Wait()
	})
	return r
}

func (r *recorder) serve(raw net.Conn, proto string, cfg *tls.Config, h1, h2 *chanListener) {
	if proto == "http" {
		p := &h1Recorder{keep: r.keep, scheme: "http", conn: taken.Add(1)}
		h1.give(&teeConn{Conn: raw, parse: p.write, closed: func() { r.close(p.conn) }})
		return
	}
	tc := tls.Server(raw, cfg)
	if err := tc.Handshake(); err != nil {
		_ = tc.Close()
		return
	}
	state := tc.ConnectionState()
	if state.NegotiatedProtocol == "h2" {
		p := &h2Recorder{keep: r.keep, conn: taken.Add(1), resumed: state.DidResume, dec: hpack.NewDecoder(4096, nil),
			open: map[uint32]*keptRequest{}}
		h2.give(&teeConn{Conn: tc, name: state.ServerName, parse: p.write, closed: func() { r.close(p.conn) }})
		return
	}
	p := &h1Recorder{keep: r.keep, scheme: "https", conn: taken.Add(1), resumed: state.DidResume}
	h1.give(&teeConn{Conn: tc, name: state.ServerName, parse: p.write, closed: func() { r.close(p.conn) }})
}

// chanListener hands the HTTP/1.1 server the connections it is given.
type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
}

func (l *chanListener) give(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// teeConn hands what is read from it to parse, as it is read, and says when
// it is closed; name is the server name its TLS asked for, empty in the
// clear.
type teeConn struct {
	net.Conn
	name   string
	parse  func([]byte)
	closed func()
}

func (c *teeConn) Close() error {
	c.closed()
	return c.Conn.Close()
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.parse(p[:n])
	}
	return n, err
}

// h2Recorder reads the frames a client sends and keeps each request.
type h2Recorder struct {
	keep      func(*keptRequest)
	conn      int64
	resumed   bool
	mu        sync.Mutex
	buf       []byte
	preface   bool
	dec       *hpack.Decoder
	block     []byte
	stream    uint32
	endStream bool
	priority  *[3]uint32
	open      map[uint32]*keptRequest
}

func (p *h2Recorder) write(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
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
		typ, flags := p.buf[3], p.buf[4]
		stream := binary.BigEndian.Uint32(p.buf[5:9]) & 0x7fffffff
		payload := append([]byte(nil), p.buf[9:9+length]...)
		p.buf = p.buf[9+length:]
		p.frame(typ, flags, stream, payload)
	}
}

func (p *h2Recorder) frame(typ, flags byte, stream uint32, payload []byte) {
	switch http2.FrameType(typ) {
	case http2.FrameData:
		if req := p.open[stream]; req != nil {
			req.bodyMu.Lock()
			req.body += string(payload)
			req.bodyMu.Unlock()
		}
	case http2.FrameHeaders:
		p.priority = nil
		if flags&0x20 != 0 {
			dep := binary.BigEndian.Uint32(payload[0:4])
			p.priority = &[3]uint32{dep >> 31, dep & 0x7fffffff, uint32(payload[4])}
			payload = payload[5:]
		}
		p.block, p.stream, p.endStream = append(p.block[:0], payload...), stream, flags&0x1 != 0
		if flags&0x4 != 0 {
			p.decode()
		}
	case http2.FrameContinuation:
		p.block = append(p.block, payload...)
		if flags&0x4 != 0 {
			p.decode()
		}
	}
}

func (p *h2Recorder) decode() {
	fields, err := p.dec.DecodeFull(p.block)
	if err != nil {
		return
	}
	req := &keptRequest{priority: p.priority, conn: p.conn, resumed: p.resumed}
	var scheme, authority, path string
	for _, f := range fields {
		req.headers = append(req.headers, [2]string{f.Name, f.Value})
		switch f.Name {
		case ":method":
			req.method = f.Value
		case ":scheme":
			scheme = f.Value
		case ":authority":
			authority = f.Value
		case ":path":
			path = f.Value
		}
	}
	req.url = scheme + "://" + withoutPort(authority) + path
	p.keep(req)
	if !p.endStream {
		p.open[p.stream] = req
	}
}

// h1Recorder reads the requests a client sends over HTTP/1.1 and keeps each.
type h1Recorder struct {
	keep    func(*keptRequest)
	scheme  string
	conn    int64
	resumed bool
	mu      sync.Mutex
	buf     []byte
	left    int
	cur     *keptRequest
}

func (p *h1Recorder) write(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	for {
		if p.left > 0 {
			take := min(p.left, len(p.buf))
			p.cur.bodyMu.Lock()
			p.cur.body += string(p.buf[:take])
			p.cur.bodyMu.Unlock()
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
		req := &keptRequest{method: parts[0], conn: p.conn, resumed: p.resumed}
		host := ""
		for _, line := range lines[1:] {
			name, value, _ := strings.Cut(line, ":")
			value = strings.TrimLeft(value, " \t")
			req.headers = append(req.headers, [2]string{name, value})
			switch strings.ToLower(name) {
			case "host":
				host = value
			case "content-length":
				p.left, _ = strconv.Atoi(value)
			}
		}
		req.url = p.scheme + "://" + withoutPort(host) + parts[1]
		p.keep(req)
		p.cur = req
	}
}

// withoutPort is a host without its port.
func withoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return host
}

// recorderCertificate is a certificate for every name the tests send requests
// to, made once; the clients that reach a recorder do not verify it.
func recorderCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	recorderCertOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			recorderCertErr = err
			return
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "www.example.com"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			DNSNames:    []string{"example.com", "*.example.com", "example.net", "*.example.net", "localhost"},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
			KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		recorderCert, recorderCertErr = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, err
	})
	if recorderCertErr != nil {
		t.Fatalf("certificate: %v", recorderCertErr)
	}
	return recorderCert
}

var (
	recorderCertOnce sync.Once
	recorderCert     tls.Certificate
	recorderCertErr  error
)
