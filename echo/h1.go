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

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

// HTTP/1.1, hand-parsed for the same reason as HTTP/2: net/http keeps headers
// in a map, and the order they arrived in is the thing being measured.
//
// No browser reaches this code — they all negotiate h2 over ALPN — but a client
// that speaks HTTP/1.1 deserves an answer rather than a hang, and `curl
// --http1.1 -k https://localhost:PORT/api/all` is a genuinely useful way to look
// at your own handshake.

const (
	// A request line or header longer than this is not a client, it is a probe.
	maxHTTP1Line = 8192
	// Browsers send a few dozen headers at most. A count limit complements the
	// per-line limit: without it, a peer could stream short unique headers until
	// the idle deadline while every one remained live in three capture slices.
	maxHTTP1Headers = 100
)

func (s *Server) serveHTTP1(conn net.Conn, sess *Session) error {
	reader := bufio.NewReaderSize(conn, maxHTTP1Line)
	for {
		req, err := readHTTP1Request(reader)
		if err != nil {
			if err == io.EOF || isClosed(err) {
				return nil
			}
			return err
		}
		sess.recordHTTP1(req)

		status, contentType, body := s.route(sess, &request{path: req.Path, body: req.body})
		if _, err := fmt.Fprintf(conn,
			"HTTP/1.1 %s %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n",
			status, statusText(status), contentType, len(body)); err != nil {
			return err
		}
		if _, err := conn.Write(body); err != nil {
			return err
		}
	}
}

// serveCaptureHTTP1 measures the second top-level navigation, after the main
// listener has already recorded HTTP/2. /api/all is the library-side
// instrument: it returns the HTTP/1.1 request directly without joining it.
func (s *Server) serveCaptureHTTP1(conn net.Conn, sess *Session) error {
	req, err := readHTTP1Request(bufio.NewReaderSize(conn, maxHTTP1Line))
	if err != nil {
		return err
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

	parsed, err := url.ParseRequestURI(req.Path)
	if err != nil {
		return err
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
}

func readHTTP1Request(r *bufio.Reader) (*http1Request, error) {
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("echo: malformed request line %q", line)
	}
	req := &http1Request{HTTP1: capture.HTTP1{Method: parts[0], Path: parts[1], Proto: parts[2]}}

	for {
		line, err := readLine(r)
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		if len(req.Headers) >= maxHTTP1Headers {
			return nil, fmt.Errorf("echo: request exceeds %d headers", maxHTTP1Headers)
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("echo: malformed header %q", line)
		}
		wireName := strings.TrimSpace(name)
		// Keep both views. HPACK's lower-case form makes cross-protocol comparison
		// useful; the wire form is the HTTP/1.1 fingerprint and cannot be rebuilt
		// from it.
		name = strings.ToLower(wireName)
		req.Headers = append(req.Headers, capture.HeaderField{Name: name, Value: strings.TrimSpace(value)})
		req.HeaderOrder = append(req.HeaderOrder, name)
		req.HeaderNames = append(req.HeaderNames, wireName)
	}

	contentLength := -1
	for _, h := range req.Headers {
		switch h.Name {
		case "transfer-encoding":
			// This deliberately small parser does not implement chunked bodies.
			// Treating the chunks as the next request would desynchronise the
			// connection, so reject the request explicitly.
			return nil, fmt.Errorf("echo: transfer-encoding is not supported")
		case "content-length":
			if contentLength >= 0 {
				return nil, fmt.Errorf("echo: duplicate content-length")
			}
			length, err := strconv.Atoi(h.Value)
			if err != nil || length < 0 || length > maxResponseBody {
				return nil, fmt.Errorf("echo: unusable content-length %q", h.Value)
			}
			contentLength = length
		}
	}
	if contentLength >= 0 {
		req.body = make([]byte, contentLength)
		if _, err := io.ReadFull(r, req.body); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("echo: line exceeds %d bytes", maxHTTP1Line)
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// recordHTTP1 keeps the first request only, for the reason recordRequest gives.
func (s *Session) recordHTTP1(req *http1Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http1 != nil {
		return
	}
	captured := req.HTTP1
	s.http1 = &captured
}

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
	default:
		return "Error"
	}
}
