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
	"github.com/Sec-CH-Lemon/tls-forge/internal/accept"
	"github.com/Sec-CH-Lemon/tls-forge/internal/deadlineconn"
	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
)

// budget is what one connection may cost, and how many may cost it at once.
//
// A connection is served for as long as it keeps making progress, and no
// longer. A request's header is sent at once by every client there is, so one
// that trickles in, a byte at a time inside the idle timeout, is holding a
// connection rather than making a request, and the same goes for a handshake.
// A body is bounded by MaxRequestBody and by the idle timeout of each read,
// not by a time for the whole: a large upload on a slow link is a real one.
type budget struct {
	// idle is how long a connection may wait for its next request, and how
	// long any one read or write may wait for the peer.
	idle time.Duration
	// header is how long a request's header may take, from its first byte.
	header time.Duration
	// handshake is how long the TLS handshake in a tunnel may take, in all.
	handshake time.Duration
	// headerBytes bounds a request's header, its request line included, as
	// net/http's DefaultMaxHeaderBytes does.
	headerBytes int64
	// connections is how many are served at once. The next one waits to be
	// accepted until one of them ends: Chrome opens at most 32 to a proxy.
	connections int
	// linger is how long a connection refused with an answer is read on,
	// what still comes dropped, before it is closed (lingered).
	linger time.Duration
}

// defaultBudget is what Start serves with. A variable so that a test can make
// it small; a server keeps the one it started with.
var defaultBudget = budget{
	idle:        30 * time.Second,
	header:      10 * time.Second,
	handshake:   10 * time.Second,
	headerBytes: 1 << 20,
	connections: 1024,
	linger:      time.Second,
}

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

// errHeaderTooLarge is a request header that ran past budget.headerBytes.
var errHeaderTooLarge = errors.New("proxy: request header is too large")

// errUpgradeRefused ends a connection whose request asked to become another
// protocol, once it has been told this proxy does not do that.
var errUpgradeRefused = errors.New("proxy: an upgrade to another protocol was refused")

// Server is a running proxy.
type Server struct {
	listener net.Listener
	opts     Options
	budget   budget
	// slots holds a token for every connection being served, so that accept
	// waits while it is full. Close ends that wait as it ends every
	// connection, which frees their slots.
	slots chan struct{}

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
	s := &Server{listener: listener, opts: opts, budget: defaultBudget, conns: map[net.Conn]struct{}{},
		slots: make(chan struct{}, defaultBudget.connections)}
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
	var pause time.Duration
	for {
		// A slot first: while every one is taken, the next connection waits
		// in the listener's queue rather than being accepted and starved.
		s.slots <- struct{}{}
		conn, err := s.listener.Accept()
		if err != nil {
			<-s.slots
			if accept.Again(err, &pause) {
				continue
			}
			return
		}
		pause = 0
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
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
	conn = deadlineconn.Wrap(conn, s.budget.idle)

	requests := s.requestsOn(conn)
	for {
		req, err := requests.next()
		if err != nil {
			s.unread(conn, err, "")
			return
		}
		if req.Method == http.MethodConnect {
			// Everything after this is TLS, so the loop over plaintext requests
			// ends here whatever happens. What the caller sent behind the
			// CONNECT without waiting for the answer is in the reader already,
			// and is the start of the tunnel.
			s.serveConnect(&bufferedConn{Conn: conn, reader: requests.reader}, req)
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

// requests reads one request after another from a connection: waiting for
// each for as long as a connection may idle and, once it has begun, giving its
// header only so long to arrive and only so many bytes to arrive in.
type requests struct {
	conn   net.Conn
	budget budget
	limit  headerLimit
	reader *bufio.Reader
}

func (s *Server) requestsOn(conn net.Conn) *requests {
	r := &requests{conn: conn, budget: s.budget, limit: headerLimit{r: conn, left: -1}}
	r.reader = bufio.NewReader(&r.limit)
	return r
}

// next is the next request, its body still to be read: the header's bounds
// end with it.
//
// Waiting for the first byte has a deadline of its own, rather than leaving it
// to the connection's idle timeout, which a read that returns anything renews:
// in a tunnel, that first byte comes at the end of a whole TLS record, which a
// peer could otherwise send a byte at a time.
//
// A header cut short by its budget or its time is said to be, whatever the
// parser made of it: the line it was in the middle of reaches the parser as
// though it were whole, and is then malformed.
func (r *requests) next() (*http.Request, error) {
	_ = r.conn.SetReadDeadline(time.Now().Add(r.budget.idle))
	if _, err := r.reader.Peek(1); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(r.budget.header)
	_ = r.conn.SetReadDeadline(deadline)
	r.limit.left = r.budget.headerBytes
	req, err := http.ReadRequest(r.reader)
	spent := r.limit.left == 0
	r.limit.left = -1
	_ = r.conn.SetReadDeadline(time.Time{})
	switch {
	case err == nil:
		return req, nil
	case spent:
		return nil, errHeaderTooLarge
	case !time.Now().Before(deadline):
		return nil, fmt.Errorf("proxy: no request header within %v: %w", r.budget.header, os.ErrDeadlineExceeded)
	}
	return nil, err
}

// headerLimit is what the reader of a request may still read before its
// header has run too long: once it is spent, the header is refused, and a
// read past it says so. Bytes the reader holds already are not counted, so
// that a header is refused only beyond budget.headerBytes and at most one
// buffer more. left is -1 between headers, while a body is read.
type headerLimit struct {
	r    io.Reader
	left int64
}

func (l *headerLimit) Read(p []byte) (int, error) {
	if l.left < 0 {
		return l.r.Read(p)
	}
	if l.left == 0 {
		return 0, errHeaderTooLarge
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

// unread answers a request that could not be read, when the caller can be
// told why, and reports what is worth reporting. A header that ran too long
// is answered 431 and is the caller's doing; a connection that ended or went
// quiet is an ordinary end; anything else is a failure, in the tunnel to
// where when where is not empty.
func (s *Server) unread(conn net.Conn, err error, where string) {
	switch {
	case errors.Is(err, errHeaderTooLarge):
		_ = writeResponse(conn, http.StatusRequestHeaderFieldsTooLarge,
			map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
			[]byte(fmt.Sprintf("request header exceeds %d bytes\n", s.budget.headerBytes)), "")
		s.lingered(conn)
	case isClosed(err):
	case where != "":
		s.opts.OnError(fmt.Errorf("proxy: reading a request for %s: %w", where, err))
	default:
		s.opts.OnError(fmt.Errorf("proxy: reading a request: %w", err))
	}
}

// lingerBytes is the most a connection being lingered on is read of: a caller
// still sending past it is cut off.
const lingerBytes = 1 << 20

// lingered ends a connection whose caller is still sending what will not be
// read, after its answer: the writing side is shut (a TCP FIN, a TLS
// close_notify), and what still comes is read and dropped until the caller
// hangs up, budget.linger passes or lingerBytes came. Closed with bytes it
// had not read, a connection is reset, and a caller whose system throws away
// what it had not read yet when it is reset, as Windows does, loses the
// answer (CI run 40399734448: a 431 without its body).
func (s *Server) lingered(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(s.budget.linger))
	_, _ = io.CopyN(io.Discard, conn, lingerBytes)
}

// bufferedConn is a connection read through the reader that already holds the
// start of what came on it.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// serveConnect answers CONNECT by becoming the destination.
//
// The destination is the host and port the CONNECT names: the certificate is
// made for the host, and every request in the tunnel goes to both. One that
// names another host, or another port, is answered 421 rather than sent
// somewhere the tunnel was not opened to; one that names no port is the
// tunnel's.
func (s *Server) serveConnect(conn net.Conn, req *http.Request) {
	host, port := req.URL.Hostname(), req.URL.Port()
	if host == "" {
		host, port, _ = net.SplitHostPort(req.Host)
	}
	if host == "" {
		host = req.Host
	}
	if port == "" {
		port = "443"
	}
	tunnel := net.JoinHostPort(host, port)
	if port == "443" {
		// As a browser writes it: the default port goes without saying.
		tunnel = strings.TrimSuffix(tunnel, ":443")
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
	_ = tlsConn.SetDeadline(time.Now().Add(s.budget.handshake))
	if err := tlsConn.Handshake(); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			s.opts.OnError(fmt.Errorf("proxy: the TLS handshake for %s took longer than %v", host, s.budget.handshake))
			return
		}
		// Almost always the client refusing our authority, which is a decision
		// on their side rather than a failure on ours.
		s.opts.OnError(fmt.Errorf("proxy: %s did not accept the certificate: %w", host, err))
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	requests := s.requestsOn(tlsConn)
	for {
		req, err := requests.next()
		if err != nil {
			s.unread(tlsConn, err, host)
			return
		}
		if inner := firstNonEmpty(req.URL.Host, req.Host); misdirected(inner, host, port) {
			_ = writeResponse(tlsConn, http.StatusMisdirectedRequest,
				map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
				[]byte("this tunnel was opened to "+tunnel+", not "+inner+"\n"), req.Method)
			return
		}
		req.URL.Scheme, req.URL.Host, req.Host = "", "", tunnel
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
	if len(body) == 0 && len(req.TransferEncoding) == 0 && len(req.Header.Values("Content-Length")) == 0 {
		// No body was sent, which is not an empty one: a GET carries none.
		body = nil
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

	res, err := s.opts.Client.Do(s.request(req, target.String(), body))
	if err != nil {
		// The caller is a client waiting on a socket; it deserves a status, not
		// a dropped connection, and the reason, without the password of any
		// URL in it: the caller is somebody else. A request this proxy will
		// not send as it is, it was given wrong.
		status := http.StatusBadGateway
		if errors.Is(err, tlsforge.ErrNeedsContext) {
			status = http.StatusBadRequest
			err = fmt.Errorf("%w; a request without Sec-Fetch-Mode goes as one: send Sec-Fetch-Site, Sec-Fetch-Mode "+
				"and Sec-Fetch-Dest as a browser would, with the Referer of the page that sends it", err)
		}
		return writeResponse(w, status, map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
			[]byte(redact.Text(err.Error())+"\n"), req.Method)
	}
	return writeResponse(w, res.Status, res.Header, res.Body, req.Method)
}

// request is what the client is asked for req, to target, with body.
//
// A request that says what in a browser sent it, with the Sec-Fetch-Mode a
// browser gives every request, goes as the browser sent it (sentContext): its
// own fields, in Chrome's order for its kind, the profile's in place of the
// browser's for what the profile says itself. One that says nothing goes as a
// request without a browser context, with the fields the profile does not
// define (extraHeaders), and so does one a client cannot take as a browser's.
func (s *Server) request(req *http.Request, target string, body []byte) *tlsforge.Request {
	asked := &tlsforge.Request{Method: req.Method, URL: target, Body: body}
	if browser := sentContext(req); browser != nil {
		sent := *asked
		sent.Header, sent.Browser = sentHeader(req.Header), browser
		if v, ok := s.opts.Client.(interface{ Validate(*tlsforge.Request) error }); ok && v.Validate(&sent) == nil {
			return &sent
		}
	}
	asked.Header = extraHeaders(s.opts.Client.Headers(), req.Header)
	return asked
}

// sentContext is the browser context req says it was sent in, by the
// Sec-Fetch-* a browser gives every request to a potentially trustworthy URL,
// or nil for one that says none: a navigation, typed into the address bar
// when Sec-Fetch-Site says none, or from the page its Referer names; a form's
// POST; or what a page's script or its markup fetches, in the mode it says,
// which goes as fetch() in that mode does, from the page its Referer, else its
// Origin, names, and with credentials when it carries a Cookie or an
// Authorization.
func sentContext(req *http.Request) *tlsforge.BrowserContext {
	page := req.Header.Get("Referer")
	if origin := req.Header.Get("Origin"); page == "" && origin != "" && origin != "null" {
		page = origin + "/"
	}
	switch mode := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Mode"))); {
	case mode == "navigate" && req.Method == http.MethodPost:
		return &tlsforge.BrowserContext{Kind: tlsforge.KindForm, Initiator: page, Sent: true}
	case mode == "navigate":
		browser := &tlsforge.BrowserContext{Kind: tlsforge.KindNavigation, Sent: true}
		if !strings.EqualFold(strings.TrimSpace(req.Header.Get("Sec-Fetch-Site")), "none") {
			browser.Initiator = page
		}
		return browser
	case mode == "cors" || mode == "no-cors" || mode == "same-origin":
		browser := &tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Mode: mode, Initiator: page, Sent: true}
		if req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" {
			browser.Credentials = "include"
		}
		return browser
	}
	return nil
}

// sentHeader is what of a browser's header goes on (forwarded): in the order
// of its names, as a map has none, each name's values in theirs.
func sentHeader(incoming http.Header) tlsforge.Header {
	var out tlsforge.Header
	for _, name := range forwarded(incoming) {
		for _, value := range incoming.Values(name) {
			out.Add(name, value)
		}
	}
	return out
}

// forwarded are the names of the fields of incoming that go on from this
// proxy, sorted: not those of its connection, Host and Content-Length, which
// the transport gives the next, nor those addressed to the proxy.
func forwarded(incoming http.Header) []string {
	hop := connectionOptions(incoming)
	var out []string
	for name := range incoming {
		lower := strings.ToLower(name)
		switch {
		case hop[lower], lower == "host", lower == "content-length":
			// Hop-by-hop, those the caller's Connection names as well, or
			// recomputed by the transport. Forwarding them describes the
			// connection to the proxy, not the one to the site.
		case lower == "proxy-authorization", lower == "proxy-authenticate":
			// Addressed to this proxy, not through it. Forwarding them hands
			// the user's proxy password to whatever site they browsed to.
		default:
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
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

// extraHeaders decides what of a caller's request that says nothing of a
// browser goes on with it: the client lays it over the profile's headers.
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
func extraHeaders(profile tlsforge.Header, incoming http.Header) tlsforge.Header {
	var out tlsforge.Header
	for _, name := range forwarded(incoming) {
		lower := strings.ToLower(name)
		if profile.Has(lower) {
			continue
		}
		for _, value := range incoming.Values(name) {
			out.Add(lower, value)
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

// misdirected says a request in a tunnel opened to host and port names
// somewhere else: another host, in any case, or a port it gives that is not
// the tunnel's. One that names none, or no port, is the tunnel's.
func misdirected(inner, host, port string) bool {
	if inner == "" {
		return false
	}
	name, given, err := net.SplitHostPort(inner)
	if err != nil {
		name, given = strings.TrimSuffix(strings.TrimPrefix(inner, "["), "]"), ""
	}
	return !strings.EqualFold(name, host) || (given != "" && given != port)
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
