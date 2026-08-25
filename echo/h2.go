package echo

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// A minimal HTTP/2 server, written by hand for one reason: net/http does not
// tell a handler what order the client sent its headers in, and that order is
// half of what this tool measures. By the time a request reaches an
// http.Handler its headers are a map — the ordering, the duplicate handling and
// the pseudo-header sequence have all been normalised away.
//
// So the frames are read directly. The scope is deliberately tiny: read the
// preamble, answer one request per stream, no server push, no trailers, no
// prioritisation. It serves a handful of local endpoints to a browser sitting on
// the same machine, and every line it does not have is a line that cannot
// diverge from a real server in a way that changes what the client sends.

// Every HTTP/2 endpoint starts with a 65535-octet flow-control window
// (RFC 9113 §6.9.2), so a response no larger than that can be written without
// waiting for a WINDOW_UPDATE. Staying under it is what lets this server skip
// flow control entirely; the guard makes that assumption fail loudly rather
// than as a hang if a response ever grows past it.
const maxResponseBody = 65535

// Capture reports are small JSON objects. Bound incoming bodies as well as
// outgoing ones so a peer cannot keep appending DATA frames until the process
// runs out of memory.
const maxRequestBody = 65535

// The default SETTINGS_MAX_FRAME_SIZE. Clients may raise it; none of them
// lower it, and there is no benefit here to sending bigger frames.
const maxFrameSize = 16384

// Header blocks are decoded before they can be inspected. Bound their decoded
// size so a peer cannot turn a small compressed block into an unbounded
// allocation by repeating a highly compressible value.
const maxHTTP2HeaderListSize = 64 << 10

type h2conn struct {
	framer *http2.Framer
	enc    *hpack.Encoder
	encBuf *bytes.Buffer
}

func newH2Conn(rw io.ReadWriter) *h2conn {
	framer := http2.NewFramer(rw, rw)
	// Decoding into MetaHeadersFrame keeps the fields in the order the client
	// sent them and reassembles CONTINUATION frames, which is exactly the two
	// things a hand-rolled decoder would have to get right.
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	framer.MaxHeaderListSize = maxHTTP2HeaderListSize
	buf := &bytes.Buffer{}
	return &h2conn{framer: framer, enc: hpack.NewEncoder(buf), encBuf: buf}
}

// serveHTTP2 runs one connection to completion.
func (s *Server) serveHTTP2(conn net.Conn, sess *Session) error {
	if err := readPreface(conn); err != nil {
		return err
	}
	h := newH2Conn(conn)
	if err := h.framer.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 250},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: maxHTTP2HeaderListSize},
	); err != nil {
		return err
	}

	// A request may arrive as HEADERS alone (GET) or HEADERS then DATA (the
	// capture page posting what it learned about itself), so the two halves are
	// held until the stream ends.
	pending := map[uint32]*request{}

	for {
		frame, err := h.framer.ReadFrame()
		if err != nil {
			// A browser closing the tab is the normal end of a connection, not a
			// failure worth reporting.
			if err == io.EOF || isClosed(err) {
				return nil
			}
			return err
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			sess.recordSettings(f)
			if err := h.framer.WriteSettingsAck(); err != nil {
				return err
			}

		case *http2.WindowUpdateFrame:
			// Only the connection-level update is part of the fingerprint; the
			// per-stream ones follow from it.
			if f.StreamID == 0 {
				sess.recordWindowUpdate(f.Increment)
			}

		case *http2.PriorityFrame:
			sess.recordPriority(f)

		case *http2.MetaHeadersFrame:
			if f.Truncated {
				return fmt.Errorf("echo: HTTP/2 header list exceeds %d bytes", maxHTTP2HeaderListSize)
			}
			req := requestFromFrame(f)
			sess.recordRequest(f)
			if f.StreamEnded() {
				if err := s.respond(h, sess, req); err != nil {
					return err
				}
				continue
			}
			pending[f.StreamID] = req

		case *http2.DataFrame:
			req, ok := pending[f.StreamID]
			if !ok {
				continue
			}
			if err := appendRequestBody(req, f.Data()); err != nil {
				return err
			}
			if f.StreamEnded() {
				delete(pending, f.StreamID)
				if err := s.respond(h, sess, req); err != nil {
					return err
				}
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				if err := h.framer.WritePing(true, f.Data); err != nil {
					return err
				}
			}

		case *http2.GoAwayFrame:
			return nil
		}
	}
}

func appendRequestBody(req *request, data []byte) error {
	if len(data) > maxRequestBody-len(req.body) {
		return fmt.Errorf("echo: request body exceeds %d bytes", maxRequestBody)
	}
	req.body = append(req.body, data...)
	return nil
}

// request is the little that a response needs to know.
type request struct {
	method string
	path   string
	stream uint32
	body   []byte
}

func requestFromFrame(f *http2.MetaHeadersFrame) *request {
	req := &request{stream: f.StreamID}
	for _, field := range f.Fields {
		switch field.Name {
		case ":method":
			req.method = field.Value
		case ":path":
			req.path = field.Value
		}
	}
	return req
}

func readPreface(r io.Reader) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(r, preface); err != nil {
		return fmt.Errorf("echo: reading HTTP/2 preface: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("echo: bad HTTP/2 preface")
	}
	return nil
}

// writeResponse sends a complete response on one stream.
func (h *h2conn) writeResponse(streamID uint32, status string, contentType string, body []byte) error {
	if len(body) > maxResponseBody {
		return fmt.Errorf("echo: response of %d bytes exceeds the %d-byte window this server assumes",
			len(body), maxResponseBody)
	}

	h.encBuf.Reset()
	for _, field := range []hpack.HeaderField{
		{Name: ":status", Value: status},
		{Name: "content-type", Value: contentType},
		{Name: "content-length", Value: fmt.Sprint(len(body))},
		// The capture page fetches this origin from itself; without the header
		// a browser blocks the read and the navigator data never arrives.
		{Name: "access-control-allow-origin", Value: "*"},
		{Name: "cache-control", Value: "no-store"},
	} {
		if err := h.enc.WriteField(field); err != nil {
			return err
		}
	}
	if err := h.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: append([]byte(nil), h.encBuf.Bytes()...),
		EndHeaders:    true,
		EndStream:     len(body) == 0,
	}); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}

	for len(body) > maxFrameSize {
		if err := h.framer.WriteData(streamID, false, body[:maxFrameSize]); err != nil {
			return err
		}
		body = body[maxFrameSize:]
	}
	return h.framer.WriteData(streamID, true, body)
}

// recordSettings stores the client's SETTINGS in the order sent. Order is part
// of the Akamai fingerprint, which is why this is a slice and not a map.
func (s *Session) recordSettings(f *http2.SettingsFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http2Recorded {
		return
	}
	// The returned error is the callback's own, and this callback cannot fail.
	_ = f.ForeachSetting(func(setting http2.Setting) error {
		s.http2.Settings = append(s.http2.Settings, fingerprint.Setting{
			ID: uint16(setting.ID), Value: setting.Val,
		})
		return nil
	})
}

func (s *Session) recordWindowUpdate(increment uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http2Recorded {
		return
	}
	s.http2.WindowUpdate = increment
}

func (s *Session) recordPriority(f *http2.PriorityFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http2Recorded {
		return
	}
	s.http2.Priorities = append(s.http2.Priorities, fingerprint.Priority{
		StreamID:  f.StreamID,
		Exclusive: f.Exclusive,
		DependsOn: f.StreamDep,
		Weight:    f.Weight,
	})
}

// recordRequest keeps the FIRST request seen on a connection and ignores the
// rest.
//
// That is the whole subtlety of capturing from a browser. The page navigation
// is the request worth measuring — it carries the header set and order Chrome
// uses for a document. The capture page then fetches /collect over the SAME
// connection to report what JavaScript sees, and a fetch() sends a different
// accept, different sec-fetch-* and no upgrade-insecure-requests. Recording the
// last request instead of the first would quietly hand back an XHR's headers
// labelled as a navigation's.
func (s *Session) recordRequest(f *http2.MetaHeadersFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http2Recorded {
		return
	}
	s.http2Recorded = true
	if p := f.Priority; p != (http2.PriorityParam{}) {
		s.http2.HeaderPriority = &fingerprint.Priority{
			StreamID:  f.StreamID,
			Exclusive: p.Exclusive,
			DependsOn: p.StreamDep,
			Weight:    p.Weight,
		}
	}
	for _, field := range f.Fields {
		s.http2.Headers = append(s.http2.Headers, fingerprint.HeaderField{
			Name: field.Name, Value: field.Value,
		})
	}
}
