package echo

import (
	"bufio"
	"fmt"
	"io"
	"net"
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

// A request line or header longer than this is not a client, it is a probe.
const maxHTTP1Line = 8192

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
		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("echo: malformed header %q", line)
		}
		// Lower-cased so the order and names compare directly against the HTTP/2
		// side, where HPACK requires lower case.
		name = strings.ToLower(strings.TrimSpace(name))
		req.Headers = append(req.Headers, capture.HeaderField{Name: name, Value: strings.TrimSpace(value)})
		req.HeaderOrder = append(req.HeaderOrder, name)
	}

	for _, h := range req.Headers {
		if h.Name != "content-length" {
			continue
		}
		length, err := strconv.Atoi(h.Value)
		if err != nil || length < 0 || length > maxResponseBody {
			return nil, fmt.Errorf("echo: unusable content-length %q", h.Value)
		}
		req.body = make([]byte, length)
		if _, err := io.ReadFull(r, req.body); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxHTTP1Line {
		return "", fmt.Errorf("echo: line exceeds %d bytes", maxHTTP1Line)
	}
	return strings.TrimRight(line, "\r\n"), nil
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
	case "404":
		return "Not Found"
	default:
		return "Error"
	}
}
