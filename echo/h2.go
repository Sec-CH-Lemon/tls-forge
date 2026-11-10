package echo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/v2/fingerprint"
)

// A minimal HTTP/2 server, written by hand for one reason: net/http does not
// tell a handler what order the client sent its headers in, and that order is
// half of what this tool measures. By the time a request reaches an
// http.Handler its headers are a map — the ordering, the duplicate handling and
// the pseudo-header sequence have all been normalised away.
//
// So the frames are read directly. The scope is deliberately small: read the
// preface, answer one request per stream, keep to the client's flow-control
// windows and its SETTINGS, and refuse or reset what it does not take, as RFC
// 9113 says to. No server push, no prioritisation, and a request's trailers are
// read and dropped. It serves a handful of local endpoints to a browser sitting
// on the same machine, and every line it does not have is a line that cannot
// diverge from a real server in a way that changes what the client sends.

// An answer is built whole before it is sent, and none needs more than this.
// The guard makes one that ever grows past it fail loudly.
const maxResponseBody = 65535

// Capture reports are small JSON objects. Bound incoming bodies as well as
// outgoing ones so a peer cannot keep appending DATA frames until the process
// runs out of memory.
const maxRequestBody = 65535

// The default SETTINGS_MAX_FRAME_SIZE, which is also the most this side reads:
// it says no other. Clients may raise what they read; none of them lower it,
// and there is no benefit here to sending bigger frames.
const maxFrameSize = 16384

// Header blocks are decoded before they can be inspected. Bound their decoded
// size so a peer cannot turn a small compressed block into an unbounded
// allocation by repeating a highly compressible value.
const maxHTTP2HeaderListSize = 64 << 10

const (
	// maxConcurrentStreams is how many streams SETTINGS lets a client have
	// open at once, and how many it can: one past them is refused, which a
	// client takes as leave to send it again. RFC 9113 recommends no fewer
	// than 100.
	maxConcurrentStreams = 100
	// streamWindow is the flow-control window SETTINGS gives each stream:
	// more than a request body may be, so that a body past maxRequestBody is
	// seen to be and answered, rather than left waiting for a window.
	streamWindow = 1 << 20
	// maxHeldBytes bounds what one connection's streams hold at once: the
	// header lists and bodies of requests still arriving, and the answers
	// still to send. A request that finds it spent is refused.
	maxHeldBytes = 512 << 10
	// maxRecorded bounds the settings and the PRIORITY frames recorded before
	// a client's first request, which is when they are: a browser sends a
	// handful, and a client that sends more is not measured but stopped.
	maxRecorded = 64
	// maxWindow is the largest a flow-control window can be (RFC 9113,
	// section 6.9.1).
	maxWindow = 1<<31 - 1
)

type h2conn struct {
	// conn is what deadlines are set on, and in what frames are read from,
	// so that the first byte of the next can be waited for on its own.
	conn net.Conn
	in   *bufio.Reader
	// preamble keeps the frames as they come, until the first header block:
	// what a comparison reads of them, which the framer does not keep.
	preamble *preambleRecorder
	limits   limits
	framer   *http2.Framer
	enc      *hpack.Encoder
	encBuf   *bytes.Buffer
	// goneAway says the connection takes no new streams: a request on one is
	// refused, which a client takes as leave to make it again elsewhere.
	goneAway bool

	// lastStream is the highest stream the client has opened. Every stream
	// it opens is past it, and a GOAWAY names it.
	lastStream uint32
	// streams are the client's open streams: their requests still arriving,
	// or their answers still being sent.
	streams map[uint32]*stream
	// sending are the streams with answers still to send, in the order the
	// answers began.
	sending []*stream
	// held is what the open streams hold, in bytes.
	held int
	// resets are the latest streams this side reset, maxConcurrentStreams of
	// them: what the client sent on one before it heard is passed over
	// (RFC 9113, section 5.1), not taken for a stream used again.
	resets []uint32
	// window is what the client lets this side send on the connection, and
	// initialWindow what it lets it send on a stream it has just opened.
	window, initialWindow int64
	// answered is told of a request once its answer has gone, or gone as far
	// as it ever will.
	answered func(*request)
	// active is when the connection began or a stream last closed: one with
	// none open for as long as it may idle is done with, however the client
	// keeps it busy with frames of no stream's.
	active time.Time
}

// stream is one of the client's streams.
type stream struct {
	id  uint32
	req *request
	// opened is when it was: a request still arriving request time later is
	// reset.
	opened time.Time
	// size is what the stream holds, counted in h2conn.held: its request's
	// header list and body while they arrive, then what is left of its answer.
	size int
	// window is what the client lets this side send on the stream.
	window int64
	// begun says its answer has begun, and answer is what is left of its body.
	begun  bool
	answer []byte
	// thenReset asks the client to stop sending, once the answer is sent, a
	// request this side answered before it had arrived (RFC 9113, section 8.1).
	thenReset bool
}

func newH2Conn(conn net.Conn) *h2conn {
	in := bufio.NewReader(conn)
	// The framer reads each frame exactly, its header and then its payload,
	// so what it reads through the recorder is the frames and nothing more.
	preamble := &preambleRecorder{r: in, on: true}
	framer := http2.NewFramer(conn, preamble)
	// Decoding into MetaHeadersFrame keeps the fields in the order the client
	// sent them and reassembles CONTINUATION frames, which is exactly the two
	// things a hand-rolled decoder would have to get right.
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	framer.MaxHeaderListSize = maxHTTP2HeaderListSize
	// The framer reads frames of up to 16 MiB unless told otherwise, and keeps
	// a buffer the size of the largest it has read.
	framer.SetMaxReadFrameSize(maxFrameSize)
	buf := &bytes.Buffer{}
	return &h2conn{
		conn: conn, in: in, preamble: preamble, framer: framer, enc: hpack.NewEncoder(buf), encBuf: buf,
		streams: map[uint32]*stream{}, window: 65535, initialWindow: 65535,
		answered: func(*request) {},
	}
}

// serveHTTP2 runs one connection to completion.
func (s *Server) serveHTTP2(conn net.Conn, sess *Session) error {
	if err := readPreface(conn); err != nil {
		return err
	}
	return s.serveFrames(newH2Conn(conn), sess)
}

// serveFrames serves the frames that follow the preface.
func (s *Server) serveFrames(h *h2conn, sess *Session) error {
	h.answered = s.completeAfter
	h.limits = s.limits
	h.active = time.Now()
	// An answer the connection ends under has gone as far as it ever will, and
	// a capture it completes is complete: whoever waits for it is not left
	// waiting.
	defer h.abandon()
	if err := h.framer.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: maxConcurrentStreams},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: streamWindow},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: maxHTTP2HeaderListSize},
	); err != nil {
		return err
	}

	for {
		frame, err := h.nextFrame()
		var broken http2.StreamError
		switch {
		case errors.As(err, &broken):
			// One stream broke the protocol: it is reset, and the rest go on.
			// What came before it is not a request's preamble.
			h.preamble.take()
			err = h.reset(broken.StreamID, broken.Code)
		case err != nil:
			return h.ended(err)
		default:
			if _, over := frame.(*http2.GoAwayFrame); over {
				return nil
			}
			err = s.take(h, sess, frame)
		}
		if err == nil {
			// What the frame let go of: a window widened, a stream reset.
			err = h.flush()
		}
		if err == nil {
			err = h.expire()
		}
		if err != nil {
			return err
		}
		if len(h.streams) == 0 && time.Since(h.active) > h.limits.idle {
			// Nothing open for as long as a connection may idle: a client
			// keeping it busy with PINGs is told it is done with.
			return h.goAway()
		}
	}
}

// nextFrame reads the next frame. Its first byte is waited for as long as a
// connection may idle, and from then the frame, or the header block, has as
// long as a request may take: a peer sending either a byte at a time is
// ended there.
func (h *h2conn) nextFrame() (http2.Frame, error) {
	_ = h.conn.SetReadDeadline(time.Now().Add(h.limits.idle))
	if _, err := h.in.Peek(1); err != nil {
		return nil, err
	}
	_ = h.conn.SetReadDeadline(time.Now().Add(h.limits.request))
	return h.framer.ReadFrame()
}

// expire resets every stream whose request has not arrived whole as long
// after it opened as a request may take.
func (h *h2conn) expire() error {
	for id, st := range h.streams {
		if !st.begun && time.Since(st.opened) > h.limits.request {
			if err := h.reset(id, http2.ErrCodeCancel); err != nil {
				return err
			}
		}
	}
	return nil
}

// take does what one frame asks.
func (s *Server) take(h *h2conn, sess *Session, frame http2.Frame) error {
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		if !f.IsAck() {
			return h.settings(sess, f)
		}
	case *http2.WindowUpdateFrame:
		return h.windowUpdate(sess, f)
	case *http2.PriorityFrame:
		if !sess.recordPriority(f) {
			return h.fail(http2.ErrCodeEnhanceYourCalm, "more PRIORITY frames before a request than a browser sends")
		}
	case *http2.MetaHeadersFrame:
		return s.headers(h, sess, f)
	case *http2.DataFrame:
		return s.data(h, sess, f)
	case *http2.RSTStreamFrame:
		h.drop(f.StreamID)
	case *http2.PingFrame:
		if !f.IsAck() {
			return h.framer.WritePing(true, f.Data)
		}
	case *http2.PushPromiseFrame:
		return h.fail(http2.ErrCodeProtocol, "a client cannot push")
	}
	return nil
}

// ended says how a connection ends on what reading a frame failed with: the
// client hung up or went quiet, which is an ordinary end, or broke the
// protocol, which it is told of before the connection closes.
func (h *h2conn) ended(err error) error {
	var broken http2.ConnectionError
	switch {
	case errors.Is(err, http2.ErrFrameTooLarge):
		return h.fail(http2.ErrCodeFrameSize, fmt.Sprintf("a frame larger than %d bytes", maxFrameSize))
	case errors.As(err, &broken):
		why := err.Error()
		if detail := h.framer.ErrorDetail(); detail != nil {
			why = detail.Error()
		}
		return h.fail(http2.ErrCode(broken), why)
	case err == io.EOF || isClosed(err):
		return nil
	}
	return err
}

// fail ends the connection on an error of the connection's own (RFC 9113,
// section 5.4.1): the client is told which, and why, in a GOAWAY. One that
// cannot be written is a client that has gone, and the connection ends all
// the same.
func (h *h2conn) fail(code http2.ErrCode, why string) error {
	_ = h.framer.WriteGoAway(h.lastStream, code, []byte(why))
	// What the client still sends is read and dropped, for a moment, before
	// the connection closes: closing with bytes unread sends a reset, which
	// can lose the GOAWAY on its way.
	_ = h.conn.SetReadDeadline(time.Now().Add(h.limits.linger))
	_, _ = io.Copy(io.Discard, io.LimitReader(h.in, maxHeldBytes))
	return fmt.Errorf("echo: HTTP/2 %v: %s", code, why)
}

// settings takes the client's SETTINGS. Each is checked, the two that change
// what this side sends are kept to, all are recorded until its first request,
// and they are acknowledged.
func (h *h2conn) settings(sess *Session, f *http2.SettingsFrame) error {
	var why string
	err := f.ForeachSetting(func(setting http2.Setting) error {
		if err := setting.Valid(); err != nil {
			why = fmt.Sprintf("the setting %v is out of range", setting)
			return err
		}
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			// What the client lets this side send on each open stream moves
			// by as much as the setting does, below zero if need be (RFC 9113,
			// section 6.9.2).
			delta := int64(setting.Val) - h.initialWindow
			for _, st := range h.streams {
				if st.window+delta > maxWindow {
					why = fmt.Sprintf("stream %d's window would pass %d", st.id, maxWindow)
					return http2.ConnectionError(http2.ErrCodeFlowControl)
				}
			}
			for _, st := range h.streams {
				st.window += delta
			}
			h.initialWindow = int64(setting.Val)
		case http2.SettingHeaderTableSize:
			// The table the client decodes this side's header blocks with is
			// as large as it says, and no larger.
			h.enc.SetMaxDynamicTableSizeLimit(setting.Val)
		}
		return nil
	})
	var broken http2.ConnectionError
	if errors.As(err, &broken) {
		return h.fail(http2.ErrCode(broken), why)
	}
	if !sess.recordSettings(f) {
		return h.fail(http2.ErrCodeEnhanceYourCalm, "more settings before a request than a browser sends")
	}
	return h.framer.WriteSettingsAck()
}

// windowUpdate widens what the client lets this side send: on the connection,
// which is recorded until its first request, or on one of its streams.
func (h *h2conn) windowUpdate(sess *Session, f *http2.WindowUpdateFrame) error {
	increment := int64(f.Increment)
	if f.StreamID == 0 {
		// Only the connection-level update is part of the fingerprint; the
		// per-stream ones follow from it.
		sess.recordWindowUpdate(f.Increment)
		if h.window+increment > maxWindow {
			return h.fail(http2.ErrCodeFlowControl, fmt.Sprintf("the connection's window would pass %d", maxWindow))
		}
		h.window += increment
		return nil
	}
	st, open := h.streams[f.StreamID]
	switch {
	case !open:
		// A stream closed already, or not opened yet: nothing goes on it.
		return nil
	case st.window+increment > maxWindow:
		return h.reset(st.id, http2.ErrCodeFlowControl)
	}
	st.window += increment
	return nil
}

// headers takes a header block: a new request, the trailers of one, or one
// this side does not take.
func (s *Server) headers(h *h2conn, sess *Session, f *http2.MetaHeadersFrame) error {
	// The frames up to this block, the first: those of the request recorded,
	// if this is the one, and of none if it is refused.
	preamble := h.preamble.take()
	if st, open := h.streams[f.StreamID]; open {
		switch {
		case st.begun:
			// Answered before it arrived whole: what more it says goes nowhere.
			return nil
		case !f.StreamEnded():
			// Trailers, whose fields are not kept, end a request (RFC 9113,
			// section 8.1); a block that does not is malformed.
			return h.reset(st.id, http2.ErrCodeProtocol)
		}
		return s.arrived(h, sess, st)
	}
	switch {
	case f.StreamID%2 == 0:
		return h.fail(http2.ErrCodeProtocol, fmt.Sprintf("HEADERS on stream %d, which a client cannot open", f.StreamID))
	case f.StreamID <= h.lastStream && slices.Contains(h.resets, f.StreamID):
		return nil
	case f.StreamID <= h.lastStream:
		return h.fail(http2.ErrCodeStreamClosed, fmt.Sprintf("HEADERS on stream %d, which has closed", f.StreamID))
	}
	h.lastStream = f.StreamID
	if h.goneAway || len(h.streams) >= maxConcurrentStreams || h.held >= maxHeldBytes {
		// After a GOAWAY, past what SETTINGS allows, or past what a connection
		// holds: refused before anything is done with it, which a client takes
		// as leave to make it again.
		return h.resetClosed(f.StreamID, http2.ErrCodeRefusedStream)
	}
	st := &stream{id: f.StreamID, req: requestFromFrame(f), window: h.initialWindow, opened: time.Now()}
	h.streams[st.id] = st
	sess.recordRequest(f, preamble)
	if f.Truncated {
		// More than SETTINGS allows (RFC 9113, section 10.5.1). Not recorded,
		// being only part of what was sent.
		return h.answer(st, "431", "text/plain; charset=utf-8",
			[]byte(fmt.Sprintf("the header list exceeds %d bytes\n", maxHTTP2HeaderListSize)), !f.StreamEnded())
	}
	h.hold(st, headerListSize(f.Fields))
	if f.StreamEnded() {
		return s.arrived(h, sess, st)
	}
	return nil
}

// data takes a DATA frame: part of the body of a request still arriving, or
// something that goes nowhere.
func (s *Server) data(h *h2conn, sess *Session, f *http2.DataFrame) error {
	// Reading DATA uses up the connection's window whatever stream it is on,
	// its padding too (RFC 9113, section 6.9.1). It is given back as it is
	// read, so that a second request body cannot stall behind the first.
	if f.Length > 0 {
		if err := h.framer.WriteWindowUpdate(0, f.Length); err != nil {
			return err
		}
	}
	st, open := h.streams[f.StreamID]
	if !open || st.begun {
		// A stream closed or not opened yet, or one answered before its
		// request arrived whole: what comes on it goes nowhere.
		return nil
	}
	data := f.Data()
	switch {
	case len(data) > maxRequestBody-len(st.req.body):
		return h.answer(st, "413", "text/plain; charset=utf-8",
			[]byte(fmt.Sprintf("request body exceeds %d bytes\n", maxRequestBody)), !f.StreamEnded())
	case h.held+len(data) > maxHeldBytes:
		return h.reset(st.id, http2.ErrCodeRefusedStream)
	}
	st.req.body = append(st.req.body, data...)
	h.hold(st, len(data))
	if f.StreamEnded() {
		return s.arrived(h, sess, st)
	}
	return nil
}

// arrived answers a request that has arrived whole.
func (s *Server) arrived(h *h2conn, sess *Session, st *stream) error {
	status, contentType, body := s.route(sess, st.req)
	if err := h.answer(st, status, contentType, body, false); err != nil {
		return err
	}
	if st.req.last && !h.goneAway {
		return h.goAway()
	}
	return nil
}

// hold counts n more bytes as held by a stream.
func (h *h2conn) hold(st *stream, n int) {
	st.size += n
	h.held += n
}

// headerListSize is what a header list counts for, as SETTINGS_MAX_HEADER_LIST_SIZE counts it.
func headerListSize(fields []hpack.HeaderField) int {
	size := 0
	for _, field := range fields {
		size += int(field.Size())
	}
	return size
}

// reset ends a stream, whatever it holds, and tells the client with code.
func (h *h2conn) reset(id uint32, code http2.ErrCode) error {
	// A stream the framer found broken may be one the client was opening.
	h.lastStream = max(h.lastStream, id)
	h.drop(id)
	return h.resetClosed(id, code)
}

// resetClosed tells the client a stream this side holds nothing of is reset,
// and keeps it among the resets.
func (h *h2conn) resetClosed(id uint32, code http2.ErrCode) error {
	h.resets = append(h.resets, id)
	if len(h.resets) > maxConcurrentStreams {
		h.resets = slices.Delete(h.resets, 0, 1)
	}
	return h.framer.WriteRSTStream(id, code)
}

// drop forgets a stream and what it holds. An answer it was sending has gone
// as far as it will.
func (h *h2conn) drop(id uint32) {
	st, open := h.streams[id]
	if !open {
		return
	}
	delete(h.streams, id)
	h.active = time.Now()
	h.held -= st.size
	if st.begun {
		h.sending = slices.DeleteFunc(h.sending, func(other *stream) bool { return other == st })
		h.answered(st.req)
	}
}

// abandon is drop for every answer under way when the connection ends.
func (h *h2conn) abandon() {
	for _, st := range h.sending {
		h.answered(st.req)
	}
	h.sending = nil
}

// answer begins the answer on a stream: its header block at once, its body
// as the client's windows let it go. thenReset asks the client to stop
// sending, once the answer has gone, a request answered before it arrived
// whole (RFC 9113, section 8.1).
func (h *h2conn) answer(st *stream, status, contentType string, body []byte, thenReset bool) error {
	if len(body) > maxResponseBody {
		return fmt.Errorf("echo: an answer of %d bytes exceeds the %d this server sends", len(body), maxResponseBody)
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
		StreamID:      st.id,
		BlockFragment: append([]byte(nil), h.encBuf.Bytes()...),
		EndHeaders:    true,
		EndStream:     len(body) == 0,
	}); err != nil {
		return err
	}
	// What the request held is not needed once it is answered.
	st.req.body, st.req.headers = nil, nil
	h.held -= st.size
	st.size = 0
	st.begun, st.answer, st.thenReset = true, body, thenReset
	h.hold(st, len(body))
	h.sending = append(h.sending, st)
	return h.flush()
}

// flush sends what the windows let go of the answers under way, in the order
// they began, a frame at a time, and finishes each it sends the last of.
func (h *h2conn) flush() error {
	for i := 0; i < len(h.sending); {
		st := h.sending[i]
		for len(st.answer) > 0 && h.window > 0 && st.window > 0 {
			n := int(min(int64(len(st.answer)), maxFrameSize, h.window, st.window))
			if err := h.framer.WriteData(st.id, n == len(st.answer), st.answer[:n]); err != nil {
				return err
			}
			st.answer = st.answer[n:]
			h.window -= int64(n)
			st.window -= int64(n)
			h.hold(st, -n)
		}
		if len(st.answer) > 0 {
			i++
			continue
		}
		h.sending = slices.Delete(h.sending, i, i+1)
		delete(h.streams, st.id)
		h.active = time.Now()
		h.answered(st.req)
		if st.thenReset {
			if err := h.resetClosed(st.id, http2.ErrCodeNo); err != nil {
				return err
			}
		}
	}
	return nil
}

// goAway takes no new streams after those the client has opened: its next
// request opens a connection of its own. The connection ends when the client
// closes it, once what it already sent is answered or refused, rather than
// under it.
func (h *h2conn) goAway() error {
	h.goneAway = true
	return h.framer.WriteGoAway(h.lastStream, http2.ErrCodeNo, nil)
}

// request is the little that a response needs to know.
type request struct {
	method string
	path   string
	stream uint32
	body   []byte
	// headers are the fields a visit is judged by, by their names in lower
	// case, and last says the connection ends with this response.
	headers map[string]string
	last    bool
	// completes is the capture this request finishes, to be handed over once
	// it has been answered.
	completes *Session
}

func requestFromFrame(f *http2.MetaHeadersFrame) *request {
	req := &request{stream: f.StreamID, headers: map[string]string{}}
	for _, field := range f.Fields {
		switch field.Name {
		case ":method":
			req.method = field.Value
		case ":path":
			req.path = field.Value
		default:
			req.headers[strings.ToLower(field.Name)] = field.Value
		}
	}
	return req
}

// maxPreambleBytes bounds the frames kept before a first request: a header
// block as long as SETTINGS lets a header list be, and room for the frames
// before it. A client that sends more is served, but its frames are not kept.
const maxPreambleBytes = maxHTTP2HeaderListSize + 8<<10

// preambleRecorder keeps what is read through it, until it is told to stop or
// has kept maxPreambleBytes, and then nothing.
type preambleRecorder struct {
	r    io.Reader
	kept []byte
	on   bool
}

func (p *preambleRecorder) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if p.on {
		if len(p.kept)+n > maxPreambleBytes {
			p.on, p.kept = false, nil
		} else {
			p.kept = append(p.kept, b[:n]...)
		}
	}
	return n, err
}

// take is what was kept, the first time it is asked, and stops keeping.
func (p *preambleRecorder) take() []byte {
	kept := p.kept
	p.on, p.kept = false, nil
	return kept
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

// recordSettings stores the client's SETTINGS in the order sent, until its
// first request. Order is part of the Akamai fingerprint, which is why this is
// a slice and not a map. It says false, and records nothing more, past
// maxRecorded, which no browser comes near.
func (s *Session) recordSettings(f *http2.SettingsFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http2Recorded {
		return true
	}
	if len(s.http2.Settings)+f.NumSettings() > maxRecorded {
		return false
	}
	// The returned error is the callback's own, and this callback cannot fail.
	_ = f.ForeachSetting(func(setting http2.Setting) error {
		s.http2.Settings = append(s.http2.Settings, fingerprint.Setting{
			ID: uint16(setting.ID), Value: setting.Val,
		})
		return nil
	})
	return true
}

func (s *Session) recordWindowUpdate(increment uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http2Recorded {
		return
	}
	s.http2.WindowUpdate = increment
}

// recordPriority stores a PRIORITY frame, until the client's first request,
// and says false past maxRecorded, as recordSettings does.
func (s *Session) recordPriority(f *http2.PriorityFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http2Recorded {
		return true
	}
	if len(s.http2.Priorities) >= maxRecorded {
		return false
	}
	s.http2.Priorities = append(s.http2.Priorities, fingerprint.Priority{
		StreamID:  f.StreamID,
		Exclusive: f.Exclusive,
		DependsOn: f.StreamDep,
		Weight:    f.Weight,
	})
	return true
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
func (s *Session) recordRequest(f *http2.MetaHeadersFrame, preamble []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	// A header list cut short at its limit is not what was sent, and is not
	// recorded as though it were.
	if s.http2Recorded || f.Truncated {
		return
	}
	s.http2Recorded = true
	s.http2.Raw = preamble
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
