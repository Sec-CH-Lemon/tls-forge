// Package proxy is an HTTP proxy that re-originates every request with a
// browser's TLS fingerprint.
//
// It intercepts rather than tunnels, and that is the whole point. A proxy that
// answers CONNECT by piping bytes leaves the client's own TLS to reach the
// destination, so the destination sees the client's handshake — Go's, Python's,
// curl's — and the fingerprint has not changed at all. To replace it, the proxy
// has to terminate TLS itself, which means presenting a certificate for the
// requested host, which means signing with an authority the client trusts.
//
// That is the cost, and it is not hidden: `tls-forge proxy` writes its authority
// to a file and prints where. Trusting it is a real decision, because anything
// holding that key can impersonate every site to anyone who trusts it.
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/internal/deadlineconn"
	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
)

const connectionIdleTimeout = 30 * time.Second

// Client is the part of *tlsforge.Client the proxy needs, named so tests can
// answer without opening a socket.
type Client interface {
	Do(*tlsforge.Request) (*tlsforge.Response, error)
	Headers() tlsforge.Header
}

// Options configure a Server.
type Options struct {
	// Addr to listen on. Defaults to 127.0.0.1:0.
	Addr string

	// CA signs the per-host certificates. Required.
	CA *CA

	// Client performs the outbound requests. Required.
	Client Client

	// MaxRequestBody bounds the body buffered before it is re-issued. Zero uses
	// DefaultMaxRequestBody.
	MaxRequestBody int64

	// OnError receives per-connection failures. A proxy that printed them to
	// stdout would corrupt nothing, but a caller that wants them quiet should
	// not have to redirect a stream. What each says has the password of any
	// URL in it taken out, as it is made to be printed; what it wraps is
	// underneath, for errors.Is and errors.As.
	OnError func(error)
}

// DefaultMaxRequestBody is large enough for ordinary browser traffic while
// preventing an exposed proxy from buffering an unbounded upload in memory.
const DefaultMaxRequestBody int64 = 16 << 20

var errRequestTooLarge = errors.New("proxy: request body is too large")

// errUpgradeRefused ends a connection whose request asked to become another
// protocol, once it has been told this proxy does not do that.
var errUpgradeRefused = errors.New("proxy: an upgrade to another protocol was refused")

// Server is a running proxy.
type Server struct {
	listener net.Listener
	opts     Options

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool

	closeOnce sync.Once
	wg        sync.WaitGroup
}

// Start binds the listener and begins accepting. The caller must Close it.
func Start(opts Options) (*Server, error) {
	if opts.CA == nil {
		return nil, errors.New("proxy: no certificate authority")
	}
	if opts.Client == nil {
		return nil, errors.New("proxy: no client")
	}
	if opts.MaxRequestBody < 0 || opts.MaxRequestBody == math.MaxInt64 {
		return nil, errors.New("proxy: maximum request body must be non-negative and bounded")
	}
	if opts.MaxRequestBody == 0 {
		opts.MaxRequestBody = DefaultMaxRequestBody
	}
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:0"
	}
	if given := opts.OnError; given != nil {
		opts.OnError = func(err error) { given(redact.Err(err)) }
	} else {
		opts.OnError = func(error) {}
	}

	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen: %w", err)
	}
	s := &Server{listener: listener, opts: opts, conns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Addr is the address actually bound.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// Close stops accepting, ends open connections and waits for their handlers.
func (s *Server) Close() error {
	err := errors.New("proxy: already closed")
	s.closeOnce.Do(func() {
		err = s.listener.Close()
		s.mu.Lock()
		// Set before the snapshot and under the same lock, so a handler that
		// has not reached track yet cannot slip in behind it.
		s.closed = true
		conns := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			conns = append(conns, conn)
		}
		s.mu.Unlock()
		// A client holding a keep-alive connection is not woken by closing the
		// listener, and waiting for it to lose interest is waiting forever.
		for _, conn := range conns {
			_ = conn.Close()
		}
		s.wg.Wait()
	})
	return err
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	if !s.track(conn) {
		_ = conn.Close()
		return
	}
	raw := conn
	defer s.forget(raw)
	conn = deadlineconn.Wrap(conn, connectionIdleTimeout)

	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !isClosed(err) && err != io.EOF {
				s.opts.OnError(fmt.Errorf("proxy: reading a request: %w", err))
			}
			return
		}
		if req.Method == http.MethodConnect {
			// Everything after this is TLS, so the loop over plaintext requests
			// ends here whatever happens.
			s.serveConnect(conn, req)
			return
		}
		if err := s.forward(conn, req, "http"); err != nil {
			if !isClosed(err) && !errors.Is(err, errRequestTooLarge) && !errors.Is(err, errUpgradeRefused) {
				s.opts.OnError(err)
			}
			return
		}
	}
}

// serveConnect answers CONNECT by becoming the destination.
func (s *Server) serveConnect(conn net.Conn, req *http.Request) {
	host := req.URL.Hostname()
	if host == "" {
		host, _, _ = net.SplitHostPort(req.Host)
	}
	if host == "" {
		host = req.Host
	}

	cert, err := s.opts.CA.leafFor(host)
	if err != nil {
		s.opts.OnError(fmt.Errorf("proxy: certificate for %s: %w", host, err))
		_, _ = io.WriteString(conn, "HTTP/1.1 500 Internal Server Error\r\n\r\n")
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	tlsConn := tlsServer(conn, cert)
	if err := tlsConn.Handshake(); err != nil {
		// Almost always the client refusing our authority, which is a decision
		// on their side rather than a failure on ours.
		s.opts.OnError(fmt.Errorf("proxy: %s did not accept the certificate: %w", host, err))
		return
	}

	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !isClosed(err) && err != io.EOF {
				s.opts.OnError(fmt.Errorf("proxy: reading a request for %s: %w", host, err))
			}
			return
		}
		req.Host = firstNonEmpty(req.Host, host)
		if err := s.forward(tlsConn, req, "https"); err != nil {
			if !isClosed(err) && !errors.Is(err, errRequestTooLarge) && !errors.Is(err, errUpgradeRefused) {
				s.opts.OnError(err)
			}
			return
		}
	}
}

// forward re-issues one request through the fingerprinted client and writes the
// answer back.
func (s *Server) forward(w io.Writer, req *http.Request, scheme string) error {
	defer func() { _ = req.Body.Close() }()
	if req.Header.Get("Upgrade") != "" && connectionNames(req.Header)["upgrade"] {
		// A request that is to become another protocol once it is answered,
		// a WebSocket among them, which this proxy does not speak. Refused,
		// rather than sent on as an ordinary request whose answer the caller
		// would take for the upgrade's.
		if err := writeResponse(w, http.StatusNotImplemented,
			map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
			[]byte("this proxy does not pass on an upgrade to another protocol\n"), req.Method); err != nil {
			return err
		}
		return errUpgradeRefused
	}
	limit := s.opts.MaxRequestBody
	if limit == 0 {
		limit = DefaultMaxRequestBody
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if err != nil {
		return fmt.Errorf("proxy: reading the request body: %w", err)
	}
	if int64(len(body)) > limit {
		if err := writeResponse(w, http.StatusRequestEntityTooLarge,
			map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
			[]byte(fmt.Sprintf("request body exceeds %d bytes\n", limit)), req.Method); err != nil {
			return err
		}
		// Close after the complete 413. The unread remainder belongs to this
		// request and must not be parsed as the next keep-alive request.
		return errRequestTooLarge
	}

	target := *req.URL
	if target.Scheme == "" {
		target.Scheme = scheme
	}
	if target.Host == "" {
		target.Host = req.Host
	}

	res, err := s.opts.Client.Do(&tlsforge.Request{
		Method: req.Method,
		URL:    target.String(),
		Header: mergeHeaders(s.opts.Client.Headers(), req.Header),
		Body:   body,
	})
	if err != nil {
		// The caller is a client waiting on a socket; it deserves a status, not
		// a dropped connection, and the reason, without the password of any
		// URL in it: the caller is somebody else.
		return writeResponse(w, 502, map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
			[]byte(redact.Text(err.Error())+"\n"), req.Method)
	}
	return writeResponse(w, res.Status, res.Header, res.Body, req.Method)
}

// hopByHop are the fields that describe a connection rather than what goes
// over it, and are not passed from one connection to the next (RFC 9110,
// section 7.6.1): the standard ones, and Trailer, since what goes on is a
// whole body with no trailers after it.
var hopByHop = []string{"connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade"}

// connectionOptions are the fields a message says are its connection's alone,
// in lower case: the standard ones, and every one its Connection fields name.
func connectionOptions(header map[string][]string) map[string]bool {
	named := connectionNames(header)
	for _, name := range hopByHop {
		named[name] = true
	}
	return named
}

// connectionNames are what a message's Connection fields name, in lower case:
// every token, on however many lines, in any case and with any spaces.
func connectionNames(header map[string][]string) map[string]bool {
	named := map[string]bool{}
	for key, values := range header {
		if !strings.EqualFold(key, "connection") {
			continue
		}
		for _, value := range values {
			for _, token := range strings.Split(value, ",") {
				if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
					named[token] = true
				}
			}
		}
	}
	return named
}

// mergeHeaders decides what the outgoing request says about itself.
//
// The profile wins every name it defines. That is the point of the proxy: a
// caller whose `user-agent` says curl, sent over Chrome's handshake, has simply
// moved the contradiction one layer up — and it is the layer that is easier to
// look at, not harder.
//
// Headers the profile does not define are kept, because they are the ones
// carrying meaning the proxy cannot invent: cookies, authorisation, content
// type. They follow in sorted order rather than map order, since a header set
// that shuffled itself between two identical requests would be a fingerprint of
// its own.
func mergeHeaders(profile tlsforge.Header, incoming http.Header) tlsforge.Header {
	out := profile.Clone()
	hop := connectionOptions(incoming)

	extras := make([]string, 0, len(incoming))
	for name := range incoming {
		lower := strings.ToLower(name)
		switch {
		case hop[lower], lower == "host", lower == "content-length":
			// Hop-by-hop, those the caller's Connection names as well, or
			// recomputed by the transport. Forwarding them describes the
			// connection to the proxy, not the one to the site.
			continue
		case lower == "proxy-authorization", lower == "proxy-authenticate":
			// Addressed to this proxy, not through it. Forwarding them hands
			// the user's proxy password to whatever site they browsed to.
			continue
		}
		if out.Has(lower) {
			continue
		}
		extras = append(extras, lower)
	}
	sort.Strings(extras)
	for _, name := range extras {
		for _, value := range incoming.Values(name) {
			out.Add(name, value)
		}
	}
	return out
}

// writeResponse writes an answer to a request made with method.
//
// Without the fields that described the connection the answer came on, those
// its Connection names included, and in the order of their names, so that two
// answers alike are written alike. Its length is what is sent: an upstream
// content-length would describe the body the transport has decoded. An answer
// to HEAD keeps the length the origin gave, of the body a GET would have had,
// and sends none; a 1xx, a 204 and a 304 have no body and say no length.
func writeResponse(w io.Writer, status int, header map[string][]string, body []byte, method string) error {
	hop := connectionOptions(header)
	names := make([]string, 0, len(header))
	length := ""
	for name, values := range header {
		lower := strings.ToLower(name)
		switch {
		case lower == "content-length":
			if len(values) > 0 {
				length = values[0]
			}
		case !hop[lower]:
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for _, name := range names {
		for _, value := range header[name] {
			fmt.Fprintf(&b, "%s: %s\r\n", name, value)
		}
	}
	switch {
	case status < 200 || status == http.StatusNoContent || status == http.StatusNotModified:
		body = nil
	case method == http.MethodHead:
		if length != "" {
			fmt.Fprintf(&b, "content-length: %s\r\n", length)
		}
		body = nil
	default:
		fmt.Fprintf(&b, "content-length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// track registers a connection, and reports whether the server is still open.
//
// The boolean is what closes the race between Accept and Close. A connection
// accepted just before Close runs is already counted in the WaitGroup but is
// not yet in s.conns, so Close's snapshot cannot close it — and Close would
// then wait for a handler parked in ReadRequest on a socket nobody will ever
// close. Under the same mutex Close takes its snapshot with, this either
// registers the connection in time to be closed or learns that it was too
// late, and the handler gives up instead of blocking Close forever.
func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) forget(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	_ = conn.Close()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// isClosed reports the ordinary end of a connection, which arrives as a
// different error depending on who hung up first and on the platform.
func isClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed")
}
