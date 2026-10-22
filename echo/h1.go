package echo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v4/capture"
)

// HTTP/1.1, hand-parsed for the same reason as HTTP/2: net/http keeps headers
// in a map, and the order they arrived in is the thing being measured.
//
// No browser reaches this code — they all negotiate h2 over ALPN — but a client
// that speaks HTTP/1.1 deserves an answer rather than a hang, and `curl
// --http1.1 -k https://localhost:PORT/api/all` is a genuinely useful way to look
// at your own handshake.
//
// It reads a request as RFC 9112 has it written, and takes nothing it would
// have to guess at: a request it cannot read whole is answered with the status
// that says why, and its connection ends, since what follows it could not be
// told from the rest of it. That is all of HTTP/1.1 there is here. Nothing a
// general server needs besides, a chunked body among it, is: one that is sent
// is refused, not half read.

const (
	// A request line or header longer than this is not a client, it is a probe.
	maxHTTP1Line = 8192
	// Browsers send a few dozen headers at most. A count limit complements the
	// per-line limit: without it, a peer could stream short unique headers until
	// the idle deadline while every one remained live in three capture slices.
	maxHTTP1Headers = 100
	// The header lines together, as maxHTTP2HeaderListSize bounds HTTP/2's:
	// a hundred lines of a whole maxHTTP1Line each would otherwise all be kept,
	// in three slices, by a capture.
	maxHTTP1HeaderBytes = 64 << 10
)

// refusal is a request this server will not take, with the status it is
// answered with.
type refusal struct {
	status string
	reason string
}

func (r *refusal) Error() string { return "echo: " + r.reason }

func refuse(status, format string, args ...any) error {
	return &refusal{status: status, reason: fmt.Sprintf(format, args...)}
}

// unread is how a connection whose next request could not be read ends. A
// request refused is answered with why, and is the error; a peer that hung up
// or went quiet ended it in the ordinary way.
func unread(conn io.Writer, err error) error {
	var refused *refusal
	if errors.As(err, &refused) {
		// Whether or not the answer could be written, the refusal is what
		// ended the connection.
		_ = writeHTTP1Response(conn, refused.status, "text/plain; charset=utf-8", "close",
			[]byte(refused.reason+"\n"))
		return err
	}
	if err == io.EOF || isClosed(err) {
		return nil
	}
	return err
}

func (s *Server) serveHTTP1(conn net.Conn, sess *Session) error {
	reader := bufio.NewReaderSize(conn, maxHTTP1Line)
	for {
		req, err := s.nextRequest(conn, reader)
		if err != nil {
			return unread(conn, err)
		}
		sess.recordHTTP1(req)

		asked := &request{path: req.Path, body: req.body, headers: map[string]string{}}
		for _, field := range req.Headers {
			asked.headers[strings.ToLower(field.Name)] = field.Value
		}
		status, contentType, body := s.route(sess, asked)
		last := asked.last || req.closes
		connection := "keep-alive"
		if last {
			connection = "close"
		}
		err = writeHTTP1Response(conn, status, contentType, connection, body)
		s.completeAfter(asked)
		if err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

// serveCaptureHTTP1 measures the second top-level navigation, after the main
// listener has already recorded HTTP/2. /api/all is the library-side
// instrument: it returns the HTTP/1.1 request directly without joining it.
func (s *Server) serveCaptureHTTP1(conn net.Conn, sess *Session) error {
	req, err := s.nextRequest(conn, bufio.NewReaderSize(conn, maxHTTP1Line))
	if err != nil {
		return unread(conn, err)
	}
	sess.recordHTTP1(req)
	path := req.Path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "/api/all" {
		status, contentType, body := jsonResponse(sess.Capture(capture.SourceTLSFetch))
		return writeCaptureHTTP1Response(conn, status, contentType, "", body)
	}

	if s.manual {
		return s.manualHTTP1(conn, sess, req)
	}
	parsed, err := url.ParseRequestURI(req.Path)
	if err != nil {
		return unread(conn, refuse("400", "malformed request target %q", req.Path))
	}
	// A browser launched directly at this endpoint makes a genuinely cold
	// top-level HTTP/1.1 navigation. Complete it independently so the caller can
	// combine it with a second, equally cold HTTP/2 launch. Navigating here from
	// the HTTP/2 page would change Sec-Fetch-Site to same-site and remove
	// Sec-Fetch-User, turning the measuring instrument into part of the profile.
	if parsed.Query().Get("http1") == "cold" {
		body := []byte("HTTP/1.1 capture complete\n")
		if err := writeCaptureHTTP1Response(conn, "200", "text/plain; charset=utf-8", "", body); err != nil {
			return err
		}
		s.complete(sess)
		return nil
	}
	token := parsed.Query().Get("navigation")
	if err := s.attachHTTP1(token, &req.HTTP1); err != nil {
		_, contentType, body := jsonResponse(map[string]string{"error": err.Error()})
		return writeCaptureHTTP1Response(conn, "400", contentType, "", body)
	}
	location := s.URL() + "/?navigation=" + url.QueryEscape(token) + "&http1=done"
	return writeCaptureHTTP1Response(conn, "302", "text/plain; charset=utf-8", location, nil)
}

// nextRequest reads the next request on a connection. Its first byte is
// waited for as long as a connection may idle, and from then the request has
// as long as one may take, its body included.
//
// Both are deadlines of their own rather than the idle timeout, which a read
// renews whenever it returns anything: the first byte comes at the end of a
// whole TLS record, and a peer could send either a byte at a time.
func (s *Server) nextRequest(conn net.Conn, r *bufio.Reader) (*http1Request, error) {
	_ = conn.SetReadDeadline(time.Now().Add(s.limits.idle))
	if _, err := r.Peek(1); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(s.limits.request))
	return readHTTP1Request(r, conn)
}

func writeHTTP1Response(conn io.Writer, status, contentType, connection string, body []byte) error {
	if _, err := fmt.Fprintf(conn,
		"HTTP/1.1 %s %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: %s\r\n\r\n",
		status, statusText(status), contentType, len(body), connection); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

func writeCaptureHTTP1Response(conn net.Conn, status, contentType, location string, body []byte) error {
	if _, err := fmt.Fprintf(conn,
		"HTTP/1.1 %s %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n",
		status, statusText(status), contentType, len(body)); err != nil {
		return err
	}
	if location != "" {
		if _, err := fmt.Fprintf(conn, "Location: %s\r\n", location); err != nil {
			return err
		}
		// The protocol hop is part of the measuring instrument, not a page the
		// browser visited. Letting it become Referer on the h2 navigation would
		// change the HTTP/2 fingerprint we are trying to keep untouched.
		if _, err := io.WriteString(conn, "Referrer-Policy: no-referrer\r\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

type http1Request struct {
	capture.HTTP1
	body []byte
	// closes says the client asked for the connection to end with the answer:
	// Connection: close, or an HTTP/1.0 request that did not ask to keep it.
	closes bool
}

// readHTTP1Request reads one request. w is where a 100 (Continue) goes, to a
// client that waits for one before it sends a body.
func readHTTP1Request(r *bufio.Reader, w io.Writer) (*http1Request, error) {
	// A server SHOULD skip at least one empty line before a request line
	// (RFC 9112, section 2.2): some clients end a body with one.
	var line string
	for line == "" {
		var err error
		if line, err = readLine(r, "414"); err != nil {
			return nil, err
		}
	}
	method, rest, spaced := strings.Cut(line, " ")
	target, version, spacedAgain := strings.Cut(rest, " ")
	if !spaced || !spacedAgain || !isToken(method) || target == "" || hasByte(target, notInTarget) ||
		!isVersion(version) {
		return nil, refuse("400", "malformed request line %q", line)
	}
	if version[len("HTTP/")] != '1' {
		return nil, refuse("505", "%s is not a version of HTTP/1", version)
	}
	req := &http1Request{HTTP1: capture.HTTP1{Method: method, Path: target, Proto: version}}

	size := 0
	for {
		line, err := readLine(r, "431")
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		if len(req.Headers) >= maxHTTP1Headers {
			return nil, refuse("431", "request exceeds %d headers", maxHTTP1Headers)
		}
		if size += len(line) + len("\r\n"); size > maxHTTP1HeaderBytes {
			return nil, refuse("431", "request header exceeds %d bytes", maxHTTP1HeaderBytes)
		}
		if line[0] == ' ' || line[0] == '\t' {
			// obs-fold, a value continued on the next line: refused rather
			// than joined, which RFC 9112 (section 5.2) leaves to the server.
			return nil, refuse("400", "a header continued on another line, %q", line)
		}
		// No space before the colon, which RFC 9112 (section 5.1) says to
		// refuse: one server would take "Content-Length " for the length and
		// another would not, and the request is two different ones.
		wireName, value, found := strings.Cut(line, ":")
		if !found || !isToken(wireName) {
			return nil, refuse("400", "malformed header %q", line)
		}
		value = strings.Trim(value, " \t")
		if hasByte(value, notInValue) {
			return nil, refuse("400", "the value of %s holds a control character", wireName)
		}
		// Keep both views. HPACK's lower-case form makes cross-protocol comparison
		// useful; the wire form is the HTTP/1.1 fingerprint and cannot be rebuilt
		// from it.
		name := strings.ToLower(wireName)
		req.Headers = append(req.Headers, capture.HeaderField{Name: name, Value: value})
		req.HeaderOrder = append(req.HeaderOrder, name)
		req.HeaderNames = append(req.HeaderNames, wireName)
	}

	contentLength := -1
	var expected, connection []string
	for _, h := range req.Headers {
		switch h.Name {
		case "transfer-encoding":
			// This deliberately small parser does not implement chunked bodies.
			// Treating the chunks as the next request would desynchronise the
			// connection, so the request is refused, as RFC 9112 (section 6.1)
			// says to refuse a coding a server does not know.
			return nil, refuse("501", "transfer-encoding is not supported")
		case "content-length":
			if contentLength >= 0 {
				return nil, refuse("400", "duplicate content-length")
			}
			if h.Value == "" || hasByte(h.Value, notDigit) {
				return nil, refuse("400", "unusable content-length %q", h.Value)
			}
			length, err := strconv.Atoi(h.Value)
			if err != nil || length > maxRequestBody {
				return nil, refuse("413", "content-length %s exceeds %d bytes", h.Value, maxRequestBody)
			}
			contentLength = length
		case "expect":
			expected = append(expected, members(h.Value)...)
		case "connection":
			connection = append(connection, members(h.Value)...)
		}
	}
	// HTTP/1.0 knows no expectations, and a server ignores them there.
	http10 := version == "HTTP/1.0"
	if http10 {
		expected = nil
	}
	for _, expectation := range expected {
		if !strings.EqualFold(expectation, "100-continue") {
			return nil, refuse("417", "expectation %q is not supported", expectation)
		}
	}
	req.closes = named(connection, "close") || http10 && !named(connection, "keep-alive")

	if contentLength >= 0 {
		if contentLength > 0 && len(expected) > 0 {
			// The client waits for this before it sends the body, and only
			// for so long: curl, for a second.
			if _, err := io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return nil, err
			}
		}
		req.body = make([]byte, contentLength)
		if _, err := io.ReadFull(r, req.body); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// readLine reads one line, without its ending. A line too long for the reader
// is refused with status; one with a carriage return anywhere but at its end
// is refused as malformed, since RFC 9112 (section 2.2) leaves a bare CR to be
// taken for a line ending by one reader and not by another.
func readLine(r *bufio.Reader, status string) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", refuse(status, "line exceeds %d bytes", maxHTTP1Line)
	}
	if err != nil {
		return "", err
	}
	text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	if strings.IndexByte(text, '\r') >= 0 {
		return "", refuse("400", "a carriage return inside %q", text)
	}
	return text, nil
}

// members are the members of a comma-separated list, without the spaces around
// them, and without the empty ones a list may have.
func members(value string) []string {
	var out []string
	for _, member := range strings.Split(value, ",") {
		if member = strings.Trim(member, " \t"); member != "" {
			out = append(out, member)
		}
	}
	return out
}

// named says option is among the options, in any case.
func named(options []string, option string) bool {
	for _, o := range options {
		if strings.EqualFold(o, option) {
			return true
		}
	}
	return false
}

// isToken says s is a token (RFC 9110, section 5.6.2): what a method and a
// header's name are made of.
func isToken(s string) bool { return s != "" && !hasByte(s, notInToken) }

// notInToken is a byte other than a letter, a digit and !#$%&'*+-.^_`|~.
func notInToken(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return false
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", b) < 0
}

// isVersion says s is HTTP-version: HTTP/, a digit, a dot and a digit.
func isVersion(s string) bool {
	return len(s) == len("HTTP/1.1") && strings.HasPrefix(s, "HTTP/") &&
		!notDigit(s[5]) && s[6] == '.' && !notDigit(s[7])
}

// hasByte says s holds a byte out says is out of place.
func hasByte(s string, out func(byte) bool) bool {
	for i := range len(s) {
		if out(s[i]) {
			return true
		}
	}
	return false
}

func notDigit(b byte) bool { return b < '0' || b > '9' }

// notInTarget is a space or a control character, neither of which a request
// target can hold.
func notInTarget(b byte) bool { return b <= ' ' || b == 0x7f }

// notInValue is a control character other than a tab, which a header's value
// cannot hold. Bytes past ASCII can be in one: obs-text.
func notInValue(b byte) bool { return b < ' ' && b != '\t' || b == 0x7f }

// recordHTTP1 keeps the first request only, for the reason recordRequest gives.
func (s *Session) recordHTTP1(req *http1Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if s.http1 != nil {
		return
	}
	captured := req.HTTP1
	s.http1 = &captured
}

// statusText is the reason phrase RFC 9110 gives each status this server
// answers with.
func statusText(status string) string {
	switch status {
	case "200":
		return "OK"
	case "302":
		return "Found"
	case "400":
		return "Bad Request"
	case "404":
		return "Not Found"
	case "413":
		return "Content Too Large"
	case "414":
		return "URI Too Long"
	case "417":
		return "Expectation Failed"
	case "431":
		return "Request Header Fields Too Large"
	case "500":
		return "Internal Server Error"
	case "501":
		return "Not Implemented"
	case "505":
		return "HTTP Version Not Supported"
	default:
		return "Error"
	}
}
