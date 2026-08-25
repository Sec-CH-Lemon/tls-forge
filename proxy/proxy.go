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
	"sort"
	"strings"
	"sync"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

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
	// not have to redirect a stream.
	OnError func(error)
}

// DefaultMaxRequestBody is large enough for ordinary browser traffic while
// preventing an exposed proxy from buffering an unbounded upload in memory.
const DefaultMaxRequestBody int64 = 16 << 20

var errRequestTooLarge = errors.New("proxy: request body is too large")

// Server is a running proxy.
type Server struct {
	listener net.Listener
	opts     Options

	mu    sync.Mutex
	conns map[net.Conn]struct{}

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
	if opts.OnError == nil {
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
	s.track(conn)
	defer s.forget(conn)

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
			if !isClosed(err) && !errors.Is(err, errRequestTooLarge) {
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
			if !isClosed(err) && !errors.Is(err, errRequestTooLarge) {
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
			[]byte(fmt.Sprintf("request body exceeds %d bytes\n", limit))); err != nil {
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
		// a dropped connection.
		return writeResponse(w, 502, map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
			[]byte(err.Error()+"\n"))
	}
	return writeResponse(w, res.Status, res.Header, res.Body)
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

	extras := make([]string, 0, len(incoming))
	for name := range incoming {
		lower := strings.ToLower(name)
		switch lower {
		case "proxy-connection", "connection", "keep-alive", "transfer-encoding",
			"upgrade", "host", "content-length":
			// Hop-by-hop, or recomputed by the transport. Forwarding them
			// describes the connection to the proxy, not the one to the site.
			continue
		}
		if out.Has(lower) {
			continue
		}
		extras = append(extras, lower)
	}
	sort.Strings(extras)
	for _, name := range extras {
		out.Set(name, incoming.Get(name))
	}
	return out
}

func writeResponse(w io.Writer, status int, header map[string][]string, body []byte) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for name, values := range header {
		switch strings.ToLower(name) {
		case "content-length", "transfer-encoding", "connection":
			// Written below from what is actually being sent. An upstream
			// content-length copied verbatim would describe the compressed body
			// the transport already decompressed.
			continue
		}
		for _, value := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", name, value)
		}
	}
	fmt.Fprintf(&b, "content-length: %d\r\n\r\n", len(body))

	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func (s *Server) track(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[conn] = struct{}{}
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
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed")
}
