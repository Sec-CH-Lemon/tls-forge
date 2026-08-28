// Package echo is a local HTTPS server that tells every client what it just
// sent.
//
// It is the measuring instrument this library is verified with. Point a real
// browser at it and it reports that browser's ClientHello, HTTP/2 preamble and
// header order; point this library at it and it reports the same fields for the
// same connection. Comparing the two answers is the whole verification story,
// and because both sides are measured by one instrument on one machine, a
// difference is a real difference rather than a difference in how two services
// happened to render their output.
//
// Running locally also removes the third-party dependency that makes this kind
// of check rot: no rate limit, no outage, no silent change of output format, no
// sending anybody's traffic to a stranger's host to find out what it looks like.
package echo

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// Session is everything one connection revealed about its client.
type Session struct {
	mu sync.Mutex

	hello         *fingerprint.ClientHello
	negotiated    string
	http2         fingerprint.HTTP2
	http2Recorded bool
	http1         *capture.HTTP1
	navigator     *capture.Navigator
	remote        string

	// navigation and reported are guarded by the Server's mutex, not this
	// session's. They describe how the server files this session among the
	// others, which is not a question a session can answer about itself.
	navigation      bool
	reported        bool
	navigationToken string
}

// Remote is the client's address, which is the only way to tell two otherwise
// identical local sessions apart.
func (s *Session) Remote() string { return s.remote }

// Capture renders the session in the exchange format.
func (s *Session) Capture(source string) *capture.Capture {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &capture.Capture{Source: source, Negotiated: s.negotiated, Navigator: cloneNavigator(s.navigator)}
	if s.hello != nil {
		out.RawClientHello = append([]byte(nil), s.hello.Raw...)
		out.TLS = capture.FromClientHello(s.hello)
	}
	if s.http2Recorded {
		out.HTTP2 = capture.FromHTTP2(&s.http2)
	}
	if s.http1 != nil {
		http1 := *s.http1
		http1.HeaderOrder = append([]string(nil), s.http1.HeaderOrder...)
		http1.Headers = append([]capture.HeaderField(nil), s.http1.Headers...)
		out.HTTP1 = &http1
	}
	return out
}

// Navigator reports the JavaScript-side data, if the capture page delivered it.
func (s *Session) Navigator() *capture.Navigator {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneNavigator(s.navigator)
}

func cloneNavigator(n *capture.Navigator) *capture.Navigator {
	if n == nil {
		return nil
	}
	out := *n
	out.Languages = append([]string(nil), n.Languages...)
	out.Brands = append([]capture.Brand(nil), n.Brands...)
	out.FullVersionList = append([]capture.Brand(nil), n.FullVersionList...)
	out.FormFactors = append([]string(nil), n.FormFactors...)
	out.Extra = append([]byte(nil), n.Extra...)
	return &out
}

// Server is the listener. The zero value is not usable; call Start.
type Server struct {
	listener  net.Listener
	tlsConfig *tls.Config
	host      string

	mu       sync.Mutex
	sessions []*Session
	// Every connection that fetched the capture page, oldest first, together
	// with the token embedded in the page served to it.
	//
	// A list rather than the single pinned session this used to hold: with one,
	// the second browser to open the page was handed the FIRST browser's
	// ClientHello and header order labelled with its own user agent. Which is
	// wrong in a way that looks entirely plausible.
	navigations    []*Session
	navigationByID map[string]*Session
	nextNavigation uint64

	// Completed captures are consumed once, oldest first. Keeping a queue makes
	// a capture that finishes just before Await safe without making every later
	// MeasureBrowserAt call return the previous browser forever.
	completed []*Session
	ready     chan struct{}
	// Open connections, so Close can end them.
	//
	// Without this, Close waits forever on any client holding a keep-alive
	// connection — which is every HTTP client that has not been told to close
	// idle connections, including Go's own. Closing the listener stops new
	// connections; it does nothing to a handler already blocked reading from an
	// old one.
	conns map[net.Conn]struct{}

	// panics holds what has been recovered from connection handlers.
	panics []string

	closeOnce sync.Once
	closed    chan struct{}
	wg        sync.WaitGroup
}

type options struct {
	addr    string
	host    string
	hosts   []string
	tickets bool
}

// Option configures a Server.
type Option func(*options)

// WithAddr sets the listen address. The default binds an ephemeral port on
// loopback, which is what makes it safe to run several at once — in tests, for
// instance.
func WithAddr(addr string) Option { return func(o *options) { o.addr = addr } }

// WithHost sets the hostname used in URL and in the certificate. "localhost"
// rather than an IP keeps the browser's SNI populated, which JA4 records as `d`
// instead of `i`.
func WithHost(host string) Option {
	return func(o *options) {
		o.host = host
		o.hosts = append(o.hosts, host)
	}
}

// WithSessionTickets re-enables TLS session resumption, which is off by
// default.
//
// Off by default because resumption changes the fingerprint being measured: a
// resumed connection carries pre_shared_key, which is one more extension, which
// is a different JA4. Real Chrome 151 sends t13d1516h2_…_806a8c22fdea on a cold
// connection and t13d1517h2_…_a87ad97598a9 on a resumed one. Both are honest,
// but only the cold one is what a server sees on first contact, and a capture
// that silently alternated between them would produce a profile that matched
// the browser about half the time.
//
// Turn it on to study resumption itself.
func WithSessionTickets(enabled bool) Option { return func(o *options) { o.tickets = enabled } }

// Start binds the listener and begins accepting. The caller must Close it.
func Start(opts ...Option) (*Server, error) {
	cfg := options{addr: "127.0.0.1:0", host: "localhost", hosts: []string{"localhost", "127.0.0.1", "::1"}}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("echo: nil option")
		}
		opt(&cfg)
	}
	if strings.TrimSpace(cfg.host) == "" {
		return nil, fmt.Errorf("echo: host must not be empty")
	}
	for _, host := range cfg.hosts {
		if strings.TrimSpace(host) == "" {
			return nil, fmt.Errorf("echo: certificate host must not be empty")
		}
	}

	cert, err := selfSignedCert(cfg.hosts)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("echo: listen: %w", err)
	}

	s := &Server{
		listener:       listener,
		host:           cfg.host,
		closed:         make(chan struct{}),
		ready:          make(chan struct{}),
		conns:          map[net.Conn]struct{}{},
		navigationByID: map[string]*Session{},
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// Both protocols are offered because which one the client picks is
			// itself information. A browser always takes h2; a library that only
			// speaks HTTP/1.1 is announcing that.
			NextProtos:             []string{"h2", "http/1.1"},
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: !cfg.tickets,
		},
	}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Addr is the address actually bound, with the resolved port.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// URL is the base URL clients should use.
func (s *Server) URL() string {
	_, port, _ := net.SplitHostPort(s.Addr())
	return "https://" + net.JoinHostPort(s.host, port)
}

// Certificate exposes the generated certificate so a client can pin it instead
// of disabling verification wholesale.
func (s *Server) Certificate() []byte { return s.tlsConfig.Certificates[0].Certificate[0] }

// Sessions returns every connection observed so far, oldest first.
func (s *Server) Sessions() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Session(nil), s.sessions...)
}

// Await blocks until a browser has completed a capture: it navigated to the
// capture page, and the page reported back what JavaScript can see.
//
// The session returned is the one that carried the DOCUMENT NAVIGATION, which
// is not necessarily the one that delivered the report. Chrome keeps spare
// connections open and will happily send the page's fetch() down a different
// one — and that connection resumes the first one's session, so it carries an
// extra pre_shared_key extension and a different JA4, and its headers are a
// fetch's rather than a navigation's.
//
// Measured, before this was separated out: the capture came back with
// `content-length, sec-ch-ua-platform, user-agent, content-type, origin…` — the
// header order of an XHR — presented as the browser's navigation fingerprint.
// It is wrong in a way that looks entirely plausible, which is why the
// navigation is tracked explicitly rather than inferred from whichever
// connection spoke last.
func (s *Server) Await(ctx context.Context) (*Session, error) {
	for {
		s.mu.Lock()
		if len(s.completed) > 0 {
			sess := s.completed[0]
			s.completed = s.completed[1:]
			s.mu.Unlock()
			return sess, nil
		}
		ready := s.ready
		s.mu.Unlock()

		select {
		case <-ready:
			// A completion was queued. Compete with any other waiter for it.
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.closed:
			return nil, errors.New("echo: server closed while waiting for a capture")
		}
	}
}

// Close stops accepting, ends open connections and waits for their handlers.
func (s *Server) Close() error {
	err := errors.New("echo: already closed")
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.listener.Close()

		// Open connections have to be closed explicitly. A handler blocked
		// reading from a kept-alive connection is not woken by closing the
		// listener, so waiting for it would be waiting for the client to lose
		// interest — which, for an idle HTTP client, is never.
		s.mu.Lock()
		conns := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			conns = append(conns, conn)
		}
		s.mu.Unlock()
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
			// One connection's panic costs that connection, not the process.
			//
			// This is its own goroutine, so an unrecovered panic here takes the
			// whole program down, and everything it runs decodes bytes a peer
			// chose before any handshake has completed. net/http recovers in
			// exactly the same place and for exactly this reason.
			defer func() {
				if r := recover(); r != nil {
					_ = conn.Close()
					s.panicked(r)
				}
			}()
			handleConn(s, conn)
		}()
	}
}

// handleConn is Server.handle, named so a test can make it panic. The recover
// around it is there for a panic nobody has thought of, which is the only kind
// there will ever be, and no test can produce one without this.
var handleConn = (*Server).handle

// panicked records a recovered panic. A test reads it; nothing else does,
// because a server that swallowed one silently would be worse than one that
// crashed.
func (s *Server) panicked(r any) {
	s.mu.Lock()
	s.panics = append(s.panics, fmt.Sprintf("%v", r))
	s.mu.Unlock()
}

// Panics returns what has been recovered from connection handlers, which should
// be nothing.
func (s *Server) Panics() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.panics...)
}

// track registers a connection, and reports whether the server is still open.
//
// The boolean closes the race between Accept and Close. A connection accepted
// just before Close runs is already counted in the WaitGroup but is not yet in
// s.conns, so Close's snapshot cannot close it, and Close would then wait for a
// handler blocked reading a socket nobody will ever close.
//
// Reading s.closed under s.mu is what orders the two: Close closes that channel
// before it takes the snapshot, and both happen under this mutex, so a handler
// arriving late is guaranteed to see the channel closed rather than register
// itself behind the snapshot.
func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return false
	default:
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) handle(raw net.Conn) {
	if !s.track(raw) {
		_ = raw.Close()
		return
	}
	defer func() {
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
		_ = raw.Close()
	}()

	recorder := &recordingConn{Conn: raw}
	conn := tls.Server(recorder, s.tlsConfig)
	sess := &Session{remote: raw.RemoteAddr().String()}

	// The hello is attached whether or not the handshake succeeds. A client that
	// rejects our certificate still told us who it is on the way in, and that is
	// often the only thing worth knowing about it.
	defer func() {
		sess.mu.Lock()
		sess.hello = recorder.hello
		sess.mu.Unlock()
	}()

	s.register(sess)
	if err := conn.Handshake(); err != nil {
		return
	}
	sess.mu.Lock()
	sess.hello = recorder.hello
	sess.negotiated = conn.ConnectionState().NegotiatedProtocol
	negotiated := sess.negotiated
	sess.mu.Unlock()

	if negotiated == "h2" {
		_ = s.serveHTTP2(conn, sess)
		return
	}
	_ = s.serveHTTP1(conn, sess)
}

func (s *Server) register(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = append(s.sessions, sess)
}

// setNavigation records a connection that fetched the capture page.
//
// Once per connection: a reload is a new navigation on a connection that now
// resumes the old one, which is not the cold handshake this is here to measure.
// But every connection that loads the page is recorded, because a second
// browser is a second navigation and deserves its own.
func (s *Server) setNavigation(sess *Session) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.navigation {
		return sess.navigationToken
	}
	s.nextNavigation++
	token := strconv.FormatUint(s.nextNavigation, 36)
	sess.navigation = true
	sess.navigationToken = token
	s.navigations = append(s.navigations, sess)
	s.navigationByID[token] = sess
	return token
}

// captureSession is the session a report belongs to.
//
// The report describes the browser rather than the connection that carried it —
// a POST's header order is an XHR's, not a page load's — so it is filed against
// a navigation. Which navigation is the whole question:
//
//   - The navigation token embedded in the page is authoritative. It survives
//     Chrome moving fetch() to another connection and cannot be confused with
//     a concurrently open browser.
//   - Without a token, the reporting connection's own navigation is used.
//   - Otherwise the reporting session, adopted as a navigation, so that a
//     caller who posts here without loading the page still produces a capture
//     Await can return rather than blocking until its deadline.
func (s *Server) captureSession(token string, fallback *Session) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "" {
		target, ok := s.navigationByID[token]
		if !ok {
			return nil, fmt.Errorf("echo: unknown navigation %q", token)
		}
		target.reported = true
		return target, nil
	}
	if fallback.navigation {
		fallback.reported = true
		return fallback, nil
	}
	s.nextNavigation++
	fallback.navigationToken = strconv.FormatUint(s.nextNavigation, 36)
	fallback.navigation = true
	fallback.reported = true
	s.navigations = append(s.navigations, fallback)
	s.navigationByID[fallback.navigationToken] = fallback
	return fallback, nil
}

// complete hands a finished capture to whoever is waiting for one.
func (s *Server) complete(sess *Session) {
	s.mu.Lock()
	s.completed = append(s.completed, sess)
	close(s.ready)
	s.ready = make(chan struct{})
	s.mu.Unlock()
}

// respond routes a request. The endpoint set is intentionally four items long.
func (s *Server) respond(h *h2conn, sess *Session, req *request) error {
	status, contentType, body := s.route(sess, req)
	return h.writeResponse(req.stream, status, contentType, body)
}

func (s *Server) route(sess *Session, req *request) (status, contentType string, body []byte) {
	path := req.path
	navigationToken := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		if query, err := url.ParseQuery(path[i+1:]); err == nil {
			navigationToken = query.Get("navigation")
		}
		path = path[:i]
	}

	switch path {
	case "/":
		token := s.setNavigation(sess)
		page := strings.Replace(capturePage, navigationPlaceholder, token, 1)
		return "200", "text/html; charset=utf-8", []byte(page)

	case "/api/all":
		return jsonResponse(sess.Capture(capture.SourceBrowser))

	case "/collect":
		var nav capture.Navigator
		if err := json.Unmarshal(req.body, &nav); err != nil {
			_, contentType, body := jsonResponse(map[string]string{"error": err.Error()})
			return "400", contentType, body
		}
		// The report describes the BROWSER, not the connection that carried it,
		// so it is filed against the navigation. Falling back to the reporting
		// session covers a caller that posted here without loading the page.
		target, err := s.captureSession(navigationToken, sess)
		if err != nil {
			_, contentType, body := jsonResponse(map[string]string{"error": err.Error()})
			return "400", contentType, body
		}
		target.mu.Lock()
		target.navigator = &nav
		target.mu.Unlock()
		s.complete(target)
		return jsonResponse(target.Capture(capture.SourceBrowser))

	default:
		// Chrome asks for /favicon.ico unprompted. Answering it politely keeps
		// the console clean; answering it with the capture would be wrong,
		// since it is not the navigation.
		return "404", "text/plain; charset=utf-8", []byte("not found\n")
	}
}

func jsonResponse(v any) (status, contentType string, body []byte) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "500", "text/plain; charset=utf-8", []byte(err.Error())
	}
	return "200", "application/json", append(body, '\n')
}

// isClosed reports the ordinary end of a connection, which arrives as a
// different error depending on who hung up first and on the platform.
func isClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed")
}
