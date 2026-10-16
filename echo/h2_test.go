package echo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// sent is a frame the server sent, copied: a framer reuses a frame once it
// reads the next.
type sent struct {
	http2.FrameHeader
	fields    []hpack.HeaderField
	data      []byte
	code      http2.ErrCode
	last      uint32
	debug     string
	increment uint32
	ping      [8]byte
}

func (f sent) status() string {
	for _, field := range f.fields {
		if field.Name == ":status" {
			return field.Value
		}
	}
	return ""
}

// h2Peer is a client on the far end of a pipe from serveFrames, which serves
// on an h2conn the test holds. What the server holds may be looked at once it
// has answered a PING sent after the frames of interest: it serves frames in
// order, and touches nothing between them.
type h2Peer struct {
	t      *testing.T
	conn   net.Conn
	framer *http2.Framer
	enc    *hpack.Encoder
	block  *bytes.Buffer
	h      *h2conn
	frames chan sent
	// ended is what serveFrames returned, once it has.
	ended chan error
	pings atomic.Uint64
	// backlog is what came and was not yet waited for, in order.
	backlog []sent
}

// servedH2 serves a connection as the server serves one after its preface,
// to a peer whose decoder has a table of tableSize.
func servedH2(t *testing.T, server *Server, sess *Session, tableSize uint32) *h2Peer {
	t.Helper()
	ours, theirs := net.Pipe()
	block := &bytes.Buffer{}
	p := &h2Peer{t: t, conn: theirs, framer: http2.NewFramer(theirs, theirs), enc: hpack.NewEncoder(block),
		block: block, h: newH2Conn(ours), frames: make(chan sent, 4096), ended: make(chan error, 1)}
	p.framer.ReadMetaHeaders = hpack.NewDecoder(tableSize, nil)
	p.framer.MaxHeaderListSize = 1 << 20
	go func() {
		p.ended <- server.serveFrames(p.h, sess)
		_ = ours.Close()
	}()
	go p.read()
	t.Cleanup(func() {
		_ = theirs.Close()
		select {
		case <-p.ended:
		case <-time.After(5 * time.Second):
			t.Error("the server did not end with the connection")
		}
	})
	return p
}

// read copies every frame the server sends onto frames, until it hangs up.
func (p *h2Peer) read() {
	defer close(p.frames)
	for {
		frame, err := p.framer.ReadFrame()
		if err != nil {
			return
		}
		f := sent{FrameHeader: frame.Header()}
		switch frame := frame.(type) {
		case *http2.MetaHeadersFrame:
			f.fields = append(f.fields, frame.Fields...)
		case *http2.DataFrame:
			f.data = append(f.data, frame.Data()...)
		case *http2.RSTStreamFrame:
			f.code = frame.ErrCode
		case *http2.GoAwayFrame:
			f.code, f.last, f.debug = frame.ErrCode, frame.LastStreamID, string(frame.DebugData())
		case *http2.WindowUpdateFrame:
			f.increment = frame.Increment
		case *http2.PingFrame:
			f.ping = frame.Data
		}
		p.frames <- f
	}
}

// next is the first frame the server sent, and nobody has waited for, that
// want takes. Those before it are kept for whoever waits for them next.
func (p *h2Peer) next(want func(sent) bool) sent {
	p.t.Helper()
	for i, f := range p.backlog {
		if want(f) {
			p.backlog = slices.Delete(p.backlog, i, i+1)
			return f
		}
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case f, open := <-p.frames:
			if !open {
				p.t.Fatal("the server hung up first")
			}
			if want(f) {
				return f
			}
			p.backlog = append(p.backlog, f)
		case <-timeout:
			p.t.Fatal("the server never sent what was waited for")
		}
	}
}

// sync waits until the server has served every frame written so far.
func (p *h2Peer) sync() {
	p.t.Helper()
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], p.pings.Add(1))
	if err := p.framer.WritePing(false, data); err != nil {
		p.t.Fatalf("PING: %v", err)
	}
	p.next(func(f sent) bool {
		return f.Type == http2.FramePing && f.Flags.Has(http2.FlagPingAck) && f.ping == data
	})
}

// request opens stream with a request for path, its last frame if ended.
func (p *h2Peer) request(stream uint32, method, path string, ended bool, extra ...[2]string) {
	p.t.Helper()
	p.headerBlock(stream, ended, append([][2]string{
		{":method", method}, {":authority", "localhost"}, {":scheme", "https"}, {":path", path},
	}, extra...)...)
}

// headerBlock writes fields as one header block, in frames of at most the
// default size.
func (p *h2Peer) headerBlock(stream uint32, ended bool, fields ...[2]string) {
	p.t.Helper()
	p.block.Reset()
	for _, field := range fields {
		if err := p.enc.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
			p.t.Fatalf("encoding: %v", err)
		}
	}
	p.fragments(stream, ended, p.block.Bytes())
}

// fragments writes block as HEADERS and as many CONTINUATIONs as it takes.
func (p *h2Peer) fragments(stream uint32, ended bool, block []byte) {
	p.t.Helper()
	first := block[:min(len(block), maxFrameSize)]
	block = block[len(first):]
	if err := p.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: stream, BlockFragment: first, EndHeaders: len(block) == 0, EndStream: ended,
	}); err != nil {
		p.t.Fatalf("HEADERS: %v", err)
	}
	for len(block) > 0 {
		next := block[:min(len(block), maxFrameSize)]
		block = block[len(next):]
		if err := p.framer.WriteContinuation(stream, len(block) == 0, next); err != nil {
			p.t.Fatalf("CONTINUATION: %v", err)
		}
	}
}

// body writes data on stream, in frames of at most the default size.
func (p *h2Peer) body(stream uint32, data []byte, ended bool) {
	p.t.Helper()
	for {
		piece := data[:min(len(data), maxFrameSize)]
		data = data[len(piece):]
		if err := p.framer.WriteData(stream, ended && len(data) == 0, piece); err != nil {
			p.t.Fatalf("DATA: %v", err)
		}
		if len(data) == 0 {
			return
		}
	}
}

// answer is the answer the server sent on stream: its header block and as
// much of its body as comes until the stream ends.
func (p *h2Peer) answer(stream uint32) (sent, []byte) {
	p.t.Helper()
	headers := p.next(func(f sent) bool { return f.Type == http2.FrameHeaders && f.StreamID == stream })
	if headers.Flags.Has(http2.FlagHeadersEndStream) {
		return headers, nil
	}
	var body []byte
	for {
		data := p.next(func(f sent) bool { return f.Type == http2.FrameData && f.StreamID == stream })
		body = append(body, data.data...)
		if data.Flags.Has(http2.FlagDataEndStream) {
			return headers, body
		}
	}
}

// goneAway is the GOAWAY the server ends the connection with, and the end:
// what serveFrames returned once the peer, told, hung up.
func (p *h2Peer) goneAway() (sent, error) {
	p.t.Helper()
	f := p.next(func(f sent) bool { return f.Type == http2.FrameGoAway })
	_ = p.conn.Close()
	select {
	case err := <-p.ended:
		p.ended <- err
		return f, err
	case <-time.After(5 * time.Second):
		p.t.Fatal("the server sent GOAWAY and went on")
	}
	return f, nil
}

// reset is the RST_STREAM the server sent on stream.
func (p *h2Peer) reset(stream uint32) http2.ErrCode {
	p.t.Helper()
	return p.next(func(f sent) bool { return f.Type == http2.FrameRSTStream && f.StreamID == stream }).code
}

// held is what the server holds once it has served what was written.
func (p *h2Peer) held() (streams, sending, bytes int) {
	p.t.Helper()
	p.sync()
	return len(p.h.streams), len(p.h.sending), p.h.held
}

func TestHTTP2AResetBeforeTheEndFreesItsStream(t *testing.T) {
	// The request held while it arrived is let go the moment the client
	// resets it, and what comes on the stream after goes nowhere: the
	// connection's window is given back, and nothing is answered.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.request(1, "POST", "/collect", false)
	// Its header list, as SETTINGS_MAX_HEADER_LIST_SIZE counts one.
	list := 0
	for _, field := range [][2]string{{":method", "POST"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", "/collect"}} {
		list += int(hpack.HeaderField{Name: field[0], Value: field[1]}.Size())
	}
	if streams, _, held := p.held(); streams != 1 || held != list {
		t.Fatalf("held %d streams, %d bytes, of a header list of %d", streams, held, list)
	}
	p.body(1, []byte(`{"user_agent":`), false)
	if streams, _, held := p.held(); streams != 1 || held != list+14 {
		t.Fatalf("held %d streams, %d bytes, while the request arrived", streams, held)
	}
	if err := p.framer.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatalf("RST_STREAM: %v", err)
	}
	if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
		t.Fatalf("held %d streams, %d answers, %d bytes after the reset", streams, sending, held)
	}
	p.body(1, []byte(`"late"}`), true)
	if window := p.next(func(f sent) bool { return f.Type == http2.FrameWindowUpdate && f.increment == 7 }); window.StreamID != 0 {
		t.Errorf("the window given back was %+v", window)
	}
	p.request(3, "GET", "/api/all", true)
	if headers, _ := p.answer(3); headers.status() != "200" {
		t.Errorf("the next request was answered %v", headers.fields)
	}
	select {
	case f := <-p.frames:
		if f.StreamID == 1 {
			t.Errorf("a reset stream was answered: %+v", f)
		}
	default:
	}
}

func TestHTTP2RefusesAStreamPastItsLimitAndFreesThemAll(t *testing.T) {
	// As many open at once as SETTINGS says, and one more refused, which a
	// client takes as leave to send it again; once they end, nothing is held.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	for i := range maxConcurrentStreams {
		p.request(uint32(2*i+1), "POST", "/collect", false)
	}
	refused := uint32(2*maxConcurrentStreams + 1)
	p.request(refused, "POST", "/collect", false)
	if code := p.reset(refused); code != http2.ErrCodeRefusedStream {
		t.Errorf("the stream past the limit was reset with %v", code)
	}
	if streams, _, _ := p.held(); streams != maxConcurrentStreams {
		t.Errorf("%d streams are open", streams)
	}
	for i := range maxConcurrentStreams {
		if err := p.framer.WriteRSTStream(uint32(2*i+1), http2.ErrCodeCancel); err != nil {
			t.Fatalf("RST_STREAM: %v", err)
		}
	}
	if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
		t.Errorf("held %d streams, %d answers, %d bytes once every stream ended", streams, sending, held)
	}
	p.request(refused+2, "GET", "/api/all", true)
	if headers, _ := p.answer(refused + 2); headers.status() != "200" {
		t.Errorf("then answered %v", headers.fields)
	}
}

func TestHTTP2RefusesWhatAConnectionCannotHold(t *testing.T) {
	// Requests arriving on stream after stream, none of them ended, hold no
	// more than maxHeldBytes and a frame: the body that would take a
	// connection past it is refused, and so is a stream opened once it is
	// reached.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	// Half a request's body each, so that the first has room to take what
	// is left of the connection's.
	chunk := bytes.Repeat([]byte("a"), 30000)
	stream := uint32(1)
	for ; ; stream += 2 {
		p.request(stream, "POST", "/collect", false)
		p.body(stream, chunk, false)
		if streams, _, _ := p.held(); streams < int(stream+1)/2 {
			break
		}
	}
	if code := p.reset(stream); code != http2.ErrCodeRefusedStream {
		t.Errorf("the body past what a connection holds was reset with %v", code)
	}
	_, _, held := p.held()
	if held > maxHeldBytes {
		t.Errorf("%d bytes are held", held)
	}
	// What is left, to the byte, on a stream still open: then a new one is
	// refused.
	p.body(1, make([]byte, maxHeldBytes-held), false)
	if _, _, held := p.held(); held != maxHeldBytes {
		t.Fatalf("%d bytes are held, want all there is room for", held)
	}
	p.request(stream+2, "GET", "/api/all", true)
	if code := p.reset(stream + 2); code != http2.ErrCodeRefusedStream {
		t.Errorf("a stream opened with nothing left to hold was reset with %v", code)
	}
}

func TestHTTP2RefusesAFrameLargerThanItReads(t *testing.T) {
	// Read no further than its header: the rest of it is never taken, and
	// writing it fails once the connection has ended.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.request(1, "POST", "/collect", false)
	go func() { _ = p.framer.WriteData(1, true, make([]byte, maxFrameSize+1)) }()
	f, err := p.goneAway()
	if f.code != http2.ErrCodeFrameSize || f.last != 1 || err == nil {
		t.Errorf("GOAWAY %v, last %d (%q), ended with %v", f.code, f.last, f.debug, err)
	}
}

func TestHTTP2Answers431ToAHeaderListPastItsLimit(t *testing.T) {
	// RFC 9113, section 10.5.1, and not recorded: it is only part of what was
	// sent. A request that would have gone on is asked to stop once
	// answered, and what it sends after goes nowhere.
	sess := &Session{}
	p := servedH2(t, startServer(t), sess, 4096)
	big := [2]string{"x-oversized", strings.Repeat("a", maxHTTP2HeaderListSize)}
	p.request(1, "GET", "/", true, big)
	if headers, body := p.answer(1); headers.status() != "431" ||
		string(body) != fmt.Sprintf("the header list exceeds %d bytes\n", maxHTTP2HeaderListSize) {
		t.Errorf("answered %v: %q", headers.fields, body)
	}
	p.request(3, "POST", "/collect", false, big)
	if headers, _ := p.answer(3); headers.status() != "431" {
		t.Errorf("answered %v", headers.fields)
	}
	if code := p.reset(3); code != http2.ErrCodeNo {
		t.Errorf("the request was then reset with %v", code)
	}
	p.body(3, []byte("{}"), true)
	p.request(5, "GET", "/api/all", true)
	if headers, _ := p.answer(5); headers.status() != "200" {
		t.Errorf("then answered %v", headers.fields)
	}
	if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
		t.Errorf("held %d streams, %d answers, %d bytes", streams, sending, held)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.requests != 3 || len(sess.http2.Headers) != 4 || sess.http2.Headers[3].Value != "/api/all" {
		t.Errorf("%d requests, recorded %v", sess.requests, sess.http2.Headers)
	}
}

func TestHTTP2EndsAConnectionWhoseHeaderListRunsOnPastItsLimit(t *testing.T) {
	// A field past the limit, with more of the block after it: the framer
	// stops reading a block it would only throw away, and the connection
	// ends with why.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	fields := [][2]string{{":method", "GET"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", "/"}}
	for i := range 6 {
		fields = append(fields, [2]string{fmt.Sprintf("x-%d", i), strings.Repeat("abcdefgh", 2000)})
	}
	p.headerBlock(1, true, fields...)
	if f, _ := p.goneAway(); f.code != http2.ErrCodeProtocol || f.last != 0 {
		t.Errorf("GOAWAY %v, last %d (%q)", f.code, f.last, f.debug)
	}
}

func TestHTTP2EndsAConnectionWhoseHeaderBlockCannotBeDecoded(t *testing.T) {
	// An indexed field at index 0, which no table has (RFC 7541, section
	// 6.1): the decoder's state is lost with it, and the connection.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.fragments(1, true, []byte{0x80})
	if f, err := p.goneAway(); f.code != http2.ErrCodeCompression || err == nil {
		t.Errorf("GOAWAY %v (%q), ended with %v", f.code, f.debug, err)
	}
}

func TestHTTP2WaitsForTheClientsWindowOnAStream(t *testing.T) {
	// A client that lets nothing go on a new stream gets the answer's header
	// block and then its body as the window opens, to the byte; a change of
	// SETTINGS_INITIAL_WINDOW_SIZE moves the window of a stream already open,
	// below zero too (RFC 9113, section 6.9.2).
	p := servedH2(t, startServer(t), &Session{}, 4096)
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	p.request(1, "GET", "/api/all", true)
	headers := p.next(func(f sent) bool { return f.Type == http2.FrameHeaders && f.StreamID == 1 })
	length := 0
	for _, field := range headers.fields {
		if field.Name == "content-length" {
			_, _ = fmt.Sscan(field.Value, &length)
		}
	}
	if _, sending, _ := p.held(); sending != 1 || length < 200 {
		t.Fatalf("%d answers wait, of %d bytes", sending, length)
	}
	expect := func(n int) {
		t.Helper()
		data := p.next(func(f sent) bool { return f.Type == http2.FrameData && f.StreamID == 1 })
		if len(data.data) != n {
			t.Fatalf("DATA of %d bytes, want %d", len(data.data), n)
		}
	}
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 50}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	expect(50)
	// The window was 50 and all of it was sent; 10 now is 40 below zero.
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 10}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	if err := p.framer.WriteWindowUpdate(1, 40); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	if _, sending, _ := p.held(); sending != 1 {
		t.Fatal("the answer was finished at a window of zero")
	}
	if err := p.framer.WriteWindowUpdate(1, 100); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	expect(100)
	if err := p.framer.WriteWindowUpdate(1, 1<<20); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	last := p.next(func(f sent) bool { return f.Type == http2.FrameData && f.StreamID == 1 })
	if len(last.data) != length-150 || !last.Flags.Has(http2.FlagDataEndStream) {
		t.Errorf("the rest was %d bytes, ending %v, of %d", len(last.data), last.Flags, length)
	}
	if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
		t.Errorf("held %d streams, %d answers, %d bytes", streams, sending, held)
	}
}

// fill sends requests for the capture page until an answer waits for the
// connection's window, and is the stream it waits on.
func fill(t *testing.T, p *h2Peer) uint32 {
	t.Helper()
	for stream := uint32(1); stream < 200; stream += 2 {
		p.request(stream, "GET", "/", true)
		if _, sending, _ := p.held(); sending > 0 {
			return stream
		}
	}
	t.Fatal("the connection's window never ran out")
	return 0
}

func TestHTTP2WaitsForTheClientsWindowOnTheConnection(t *testing.T) {
	// 65535 bytes in all, until the client gives more: the answer that would
	// pass it stops there, and goes on when it does.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	waiting := fill(t, p)
	if p.h.window != 0 {
		t.Fatalf("an answer waits with %d bytes of window left", p.h.window)
	}
	if err := p.framer.WriteWindowUpdate(0, 1<<20); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	for {
		data := p.next(func(f sent) bool { return f.Type == http2.FrameData && f.StreamID == waiting })
		if data.Flags.Has(http2.FlagDataEndStream) {
			break
		}
	}
	if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
		t.Errorf("held %d streams, %d answers, %d bytes", streams, sending, held)
	}
}

func TestHTTP2RefusesAWindowPastItsLargest(t *testing.T) {
	t.Run("the connection's", func(t *testing.T) {
		p := servedH2(t, startServer(t), &Session{}, 4096)
		if err := p.framer.WriteWindowUpdate(0, maxWindow); err != nil {
			t.Fatalf("WINDOW_UPDATE: %v", err)
		}
		if f, _ := p.goneAway(); f.code != http2.ErrCodeFlowControl {
			t.Errorf("GOAWAY %v (%q)", f.code, f.debug)
		}
	})
	t.Run("a stream's", func(t *testing.T) {
		// It waits on the connection's window, its own at the most it can be;
		// one more is reset, and the answer with it, and the rest go on.
		p := servedH2(t, startServer(t), &Session{}, 4096)
		waiting := fill(t, p)
		if err := p.framer.WriteWindowUpdate(waiting, uint32(maxWindow-p.h.streams[waiting].window)); err != nil {
			t.Fatalf("WINDOW_UPDATE: %v", err)
		}
		if err := p.framer.WriteWindowUpdate(waiting, 1); err != nil {
			t.Fatalf("WINDOW_UPDATE: %v", err)
		}
		if code := p.reset(waiting); code != http2.ErrCodeFlowControl {
			t.Errorf("reset with %v", code)
		}
		if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
			t.Errorf("held %d streams, %d answers, %d bytes", streams, sending, held)
		}
	})
	t.Run("a stream's, by SETTINGS", func(t *testing.T) {
		p := servedH2(t, startServer(t), &Session{}, 4096)
		waiting := fill(t, p)
		if err := p.framer.WriteWindowUpdate(waiting, uint32(maxWindow-p.h.streams[waiting].window)); err != nil {
			t.Fatalf("WINDOW_UPDATE: %v", err)
		}
		if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65536}); err != nil {
			t.Fatalf("SETTINGS: %v", err)
		}
		if f, _ := p.goneAway(); f.code != http2.ErrCodeFlowControl ||
			f.debug != fmt.Sprintf("stream %d's window would pass %d", waiting, maxWindow) {
			t.Errorf("GOAWAY %v (%q)", f.code, f.debug)
		}
	})
}

func TestHTTP2RefusesASettingOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		setting http2.Setting
		code    http2.ErrCode
	}{
		{http2.Setting{ID: http2.SettingEnablePush, Val: 2}, http2.ErrCodeProtocol},
		{http2.Setting{ID: http2.SettingMaxFrameSize, Val: 100}, http2.ErrCodeProtocol},
		// The framer refuses this one itself.
		{http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 31}, http2.ErrCodeFlowControl},
	} {
		t.Run(tc.setting.String(), func(t *testing.T) {
			p := servedH2(t, startServer(t), &Session{}, 4096)
			if err := p.framer.WriteSettings(tc.setting); err != nil {
				t.Fatalf("SETTINGS: %v", err)
			}
			if f, _ := p.goneAway(); f.code != tc.code {
				t.Errorf("GOAWAY %v (%q)", f.code, f.debug)
			}
		})
	}
}

func TestHTTP2KeepsToTheClientsHeaderTable(t *testing.T) {
	// A client whose table holds nothing cannot decode a reference into one:
	// every answer it reads is a sign the server's header blocks kept to it.
	p := servedH2(t, startServer(t), &Session{}, 0)
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	for stream := uint32(1); stream <= 5; stream += 2 {
		p.request(stream, "GET", "/api/all", true)
		if headers, _ := p.answer(stream); headers.status() != "200" {
			t.Fatalf("answered %v", headers.fields)
		}
	}
}

func TestHTTP2GivesBackTheWindowPaddingUses(t *testing.T) {
	// The whole frame counts against the window, its padding and the byte
	// that says how long it is too (RFC 9113, section 6.9.1).
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.request(1, "POST", "/collect", false)
	if err := p.framer.WriteDataPadded(1, false, []byte("0123456789"), make([]byte, 200)); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if f := p.next(func(f sent) bool { return f.Type == http2.FrameWindowUpdate }); f.StreamID != 0 || f.increment != 211 {
		t.Errorf("gave back %d on stream %d", f.increment, f.StreamID)
	}
}

func TestHTTP2RefusesAStreamNoClientOpens(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(p *h2Peer)
		last  uint32
		debug string
	}{
		{"an even stream", func(p *h2Peer) { p.request(2, "GET", "/", true) }, 0,
			"HEADERS on stream 2, which a client cannot open"},
		{"a push", func(p *h2Peer) {
			if err := p.framer.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2,
				BlockFragment: []byte{0x82}, EndHeaders: true}); err != nil {
				p.t.Fatalf("PUSH_PROMISE: %v", err)
			}
		}, 0, "a client cannot push"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := servedH2(t, startServer(t), &Session{}, 4096)
			tc.write(p)
			if f, _ := p.goneAway(); f.code != http2.ErrCodeProtocol || f.last != tc.last || f.debug != tc.debug {
				t.Errorf("GOAWAY %v, last %d (%q)", f.code, f.last, f.debug)
			}
		})
	}
}

func TestHTTP2RefusesAStreamUsedAgainButNotOneItReset(t *testing.T) {
	// A stream that ended both ways is closed, and a request on it again is a
	// connection error (RFC 9113, section 5.1). One this side reset is not:
	// what the client sent before it heard is passed over, the latest
	// maxConcurrentStreams of them.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.request(1, "POST", "/collect", false, [2]string{"X-Upper", "1"})
	if code := p.reset(1); code != http2.ErrCodeProtocol {
		t.Fatalf("reset with %v", code)
	}
	// Stream 1 was opened, broken as it was: what follows on it is late.
	p.headerBlock(1, true, [2]string{"x-late", "1"})
	for _, f := range drained(p) {
		if f.StreamID == 1 || f.Type == http2.FrameGoAway {
			t.Fatalf("a late header block was answered: %+v", f)
		}
	}
	for i := range maxConcurrentStreams {
		p.request(uint32(2*i+3), "GET", "/api/all", true, [2]string{"X-Upper", "1"})
	}
	last := uint32(2*maxConcurrentStreams + 1)
	p.request(last+2, "GET", "/api/all", true)
	if headers, _ := p.answer(last + 2); headers.status() != "200" {
		t.Fatalf("answered %v", headers.fields)
	}
	// The first reset is one too many back to be remembered; the last is not.
	p.headerBlock(last, true, [2]string{"x-late", "1"})
	p.sync()
	p.headerBlock(1, true, [2]string{"x-late", "1"})
	if f, _ := p.goneAway(); f.code != http2.ErrCodeStreamClosed || f.last != last+2 ||
		f.debug != "HEADERS on stream 1, which has closed" {
		t.Errorf("GOAWAY %v, last %d (%q)", f.code, f.last, f.debug)
	}
}

func TestHTTP2DropsTrailersAndRefusesThemMalformed(t *testing.T) {
	sess := &Session{}
	server := startServer(t)
	p := servedH2(t, server, sess, 4096)
	p.request(1, "POST", "/collect", false)
	p.body(1, []byte(`{"user_agent":"trailed"}`), false)
	p.headerBlock(1, true, [2]string{"x-checksum", "1"})
	if headers, _ := p.answer(1); headers.status() != "200" {
		t.Errorf("answered %v", headers.fields)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got, err := server.Await(ctx); err != nil || got.Navigator().UserAgent != "trailed" {
		t.Errorf("Await = %v, %v", got, err)
	}

	// Trailers that do not end the request.
	p.request(3, "POST", "/collect", false)
	p.headerBlock(3, false, [2]string{"x-checksum", "1"})
	if code := p.reset(3); code != http2.ErrCodeProtocol {
		t.Errorf("reset with %v", code)
	}
	// Trailers on a request answered before it arrived, one with a body too
	// large: passed over, whether its answer is still going or it has been
	// reset since (RFC 9113, section 5.1). The stream after it is served.
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 10}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	p.request(5, "POST", "/collect", false)
	p.body(5, make([]byte, maxRequestBody+1), false)
	_, _, waiting := p.held()
	// More of a body answered already goes nowhere too.
	p.body(5, make([]byte, 100), false)
	p.headerBlock(5, true, [2]string{"x-checksum", "1"})
	if streams, sending, held := p.held(); streams != 1 || sending != 1 || held != waiting {
		t.Fatalf("%d streams, %d answers, %d bytes held, %d before", streams, sending, held, waiting)
	}
	if err := p.framer.WriteWindowUpdate(5, 1000); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	if code := p.reset(5); code != http2.ErrCodeNo {
		t.Errorf("reset with %v", code)
	}
	p.headerBlock(5, true, [2]string{"x-checksum", "2"})
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	p.request(7, "GET", "/api/all", true)
	if headers, _ := p.answer(7); headers.status() != "200" {
		t.Errorf("then answered %v", headers.fields)
	}
	for _, f := range drained(p) {
		if f.Type == http2.FrameRSTStream || f.Type == http2.FrameGoAway {
			t.Errorf("then sent %+v", f)
		}
	}
	if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
		t.Errorf("held %d streams, %d answers, %d bytes", streams, sending, held)
	}
}

func TestHTTP2ResetsABrokenStreamAndGoesOn(t *testing.T) {
	// A header name with a capital in it, and a window opened by nothing:
	// the stream is reset, and the connection serves the next.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.request(1, "GET", "/api/all", true, [2]string{"X-Upper", "1"})
	if code := p.reset(1); code != http2.ErrCodeProtocol {
		t.Errorf("reset with %v", code)
	}
	p.request(3, "POST", "/collect", false)
	if _, err := p.conn.Write([]byte{0, 0, 4, byte(http2.FrameWindowUpdate), 0, 0, 0, 0, 3, 0, 0, 0, 0}); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	if code := p.reset(3); code != http2.ErrCodeProtocol {
		t.Errorf("reset with %v", code)
	}
	p.request(5, "GET", "/api/all", true)
	if headers, _ := p.answer(5); headers.status() != "200" {
		t.Errorf("then answered %v", headers.fields)
	}
	if streams, _, held := p.held(); streams != 0 || held != 0 {
		t.Errorf("held %d streams, %d bytes", streams, held)
	}
}

func TestHTTP2StopsAClientThatSendsMoreThanABrowserBeforeItsRequest(t *testing.T) {
	// Everything before the first request is recorded, which is why there is
	// a most. After it, nothing is, and there is none.
	t.Run("PRIORITY", func(t *testing.T) {
		p := servedH2(t, startServer(t), &Session{}, 4096)
		for i := range maxRecorded + 1 {
			if err := p.framer.WritePriority(uint32(2*i+3), http2.PriorityParam{Weight: 1}); err != nil {
				t.Fatalf("PRIORITY: %v", err)
			}
		}
		if f, _ := p.goneAway(); f.code != http2.ErrCodeEnhanceYourCalm {
			t.Errorf("GOAWAY %v (%q)", f.code, f.debug)
		}
	})
	t.Run("SETTINGS", func(t *testing.T) {
		p := servedH2(t, startServer(t), &Session{}, 4096)
		for range maxRecorded / 4 {
			if err := p.framer.WriteSettings(make([]http2.Setting, 4)...); err != nil {
				t.Fatalf("SETTINGS: %v", err)
			}
		}
		p.sync()
		if err := p.framer.WriteSettings(http2.Setting{ID: 0x99, Val: 1}); err != nil {
			t.Fatalf("SETTINGS: %v", err)
		}
		if f, _ := p.goneAway(); f.code != http2.ErrCodeEnhanceYourCalm {
			t.Errorf("GOAWAY %v (%q)", f.code, f.debug)
		}
	})
	t.Run("after the first request", func(t *testing.T) {
		sess := &Session{}
		p := servedH2(t, startServer(t), sess, 4096)
		p.request(1, "GET", "/api/all", true)
		p.answer(1)
		for i := range maxRecorded + 1 {
			if err := p.framer.WritePriority(uint32(2*i+3), http2.PriorityParam{Weight: 1}); err != nil {
				t.Fatalf("PRIORITY: %v", err)
			}
			if err := p.framer.WriteSettings(http2.Setting{ID: 0x99, Val: 1}); err != nil {
				t.Fatalf("SETTINGS: %v", err)
			}
		}
		p.sync()
		sess.mu.Lock()
		defer sess.mu.Unlock()
		if len(sess.http2.Priorities) != 0 || len(sess.http2.Settings) != 0 {
			t.Errorf("recorded %v and %v", sess.http2.Priorities, sess.http2.Settings)
		}
	})
}

func TestHTTP2CompletesACaptureWhoseAnswerCannotGoAllTheWay(t *testing.T) {
	// The report is filed whether or not its answer gets there: whoever waits
	// for the capture is not to wait for ever on a client that stopped
	// reading, reset the stream, or went.
	for _, tc := range []struct {
		name string
		end  func(p *h2Peer)
	}{
		{"reset by the client", func(p *h2Peer) {
			if err := p.framer.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
				p.t.Fatalf("RST_STREAM: %v", err)
			}
		}},
		{"the connection gone", func(p *h2Peer) { _ = p.conn.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startServer(t)
			p := servedH2(t, server, &Session{}, 4096)
			if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
				t.Fatalf("SETTINGS: %v", err)
			}
			p.request(1, "POST", "/collect", false)
			p.body(1, []byte(`{"user_agent":"stalled"}`), true)
			if _, sending, _ := p.held(); sending != 1 {
				t.Fatalf("%d answers wait", sending)
			}
			server.mu.Lock()
			early := len(server.completed)
			server.mu.Unlock()
			if early != 0 {
				t.Fatal("the capture was handed over before its answer went")
			}
			tc.end(p)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if got, err := server.Await(ctx); err != nil || got.Navigator().UserAgent != "stalled" {
				t.Errorf("Await = %v, %v", got, err)
			}
		})
	}
}

func TestHTTP2Answers413ToABodyPastItsLimit(t *testing.T) {
	// Seen to be past it, since a stream's window is wider than the limit, and
	// answered with why. A request still going is then asked to stop, and what
	// it sends after goes nowhere; one that ended with that frame is not.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.request(1, "POST", "/collect", false)
	p.body(1, make([]byte, maxRequestBody+1), false)
	if headers, body := p.answer(1); headers.status() != "413" ||
		string(body) != fmt.Sprintf("request body exceeds %d bytes\n", maxRequestBody) {
		t.Errorf("answered %v: %q", headers.fields, body)
	}
	if code := p.reset(1); code != http2.ErrCodeNo {
		t.Errorf("then reset with %v", code)
	}
	p.body(1, []byte("more"), true)

	p.request(3, "POST", "/collect", false)
	p.body(3, make([]byte, maxRequestBody+1), true)
	if headers, _ := p.answer(3); headers.status() != "413" {
		t.Errorf("answered %v", headers.fields)
	}
	p.request(5, "GET", "/api/all", true)
	if headers, _ := p.answer(5); headers.status() != "200" {
		t.Errorf("then answered %v", headers.fields)
	}
	// A body of the limit exactly is read, and answered for what it says.
	p.request(7, "POST", "/collect", false)
	p.body(7, bytes.Repeat([]byte(" "), maxRequestBody), true)
	if headers, body := p.answer(7); headers.status() != "400" || !strings.Contains(string(body), "unexpected end of JSON") {
		t.Errorf("a body of the limit was answered %v: %q", headers.fields, body)
	}
	for _, f := range drained(p) {
		if f.Type == http2.FrameRSTStream {
			t.Errorf("reset %d with %v", f.StreamID, f.code)
		}
	}
	if streams, sending, held := p.held(); streams != 0 || sending != 0 || held != 0 {
		t.Errorf("held %d streams, %d answers, %d bytes", streams, sending, held)
	}
}

// drained is what the server sent that nobody waited for, once it has served
// everything written.
func drained(p *h2Peer) []sent {
	p.t.Helper()
	p.sync()
	out := p.backlog
	p.backlog = nil
	return out
}

func TestHTTP2Ended(t *testing.T) {
	h := newH2Conn(writtenTo())
	other := errors.New("no route to host")
	for _, tc := range []struct {
		err  error
		want string
	}{
		{io.EOF, ""},
		{net.ErrClosed, ""},
		{other, "no route to host"},
		{fmt.Errorf("reading: %w", http2.ErrFrameTooLarge), "echo: HTTP/2 FRAME_SIZE_ERROR: a frame larger than 16384 bytes"},
		{http2.ConnectionError(http2.ErrCodeProtocol), "echo: HTTP/2 PROTOCOL_ERROR: connection error: PROTOCOL_ERROR"},
	} {
		got := h.ended(tc.err)
		if tc.want == "" && got != nil || tc.want != "" && (got == nil || got.Error() != tc.want) {
			t.Errorf("ended(%v) = %v, want %q", tc.err, got, tc.want)
		}
	}
}

func TestHTTP2SaysWhatTheFramerFoundWrong(t *testing.T) {
	// The framer's own reason goes in the GOAWAY, for whoever has to work out
	// what their client did.
	p := servedH2(t, startServer(t), &Session{}, 4096)
	if _, err := p.conn.Write([]byte{0, 0, 1, byte(http2.FrameData), 0, 0, 0, 0, 0, 'x'}); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if f, _ := p.goneAway(); f.code != http2.ErrCodeProtocol || f.debug != "DATA frame with stream ID 0" {
		t.Errorf("GOAWAY %v (%q)", f.code, f.debug)
	}
}

func TestHTTP2StopsWhenTheClientHangsUpMidRefusal(t *testing.T) {
	// The answer to a body too large, and the reset that asks the client to
	// stop: the write fails at each of the points that write.
	server := startServer(t)
	script := func(framer *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer) {
		block.Reset()
		for _, field := range [][2]string{
			{":method", "POST"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", "/collect"},
		} {
			if err := encoder.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
				t.Fatalf("encoding: %v", err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(),
			EndHeaders: true}); err != nil {
			t.Fatalf("HEADERS: %v", err)
		}
		for range maxRequestBody/maxFrameSize + 1 {
			if err := framer.WriteData(1, false, make([]byte, maxFrameSize)); err != nil {
				t.Fatalf("DATA: %v", err)
			}
		}
	}
	failed, ended := 0, 0
	for budget := 0; budget < 400; budget++ {
		conn := &scriptedConn{reader: h2Script(t, script), writeBudget: budget}
		if err := server.serveHTTP2(conn, &Session{}); err != nil {
			failed++
		} else {
			ended++
		}
	}
	if failed == 0 || ended == 0 {
		t.Errorf("failed %d times, ended %d", failed, ended)
	}
}

func TestHTTP2SaysGoAwayOnce(t *testing.T) {
	// In manual mode every answer outside a measurement ends its connection.
	// Two requests opened before the first is answered are both answered, and
	// the connection goes away once, naming the later.
	server := startServer(t, WithManual(true))
	p := servedH2(t, server, &Session{remote: "192.0.2.1:1"}, 4096)
	p.request(1, "GET", "/favicon.ico", false)
	p.request(3, "GET", "/favicon.ico", false)
	p.body(1, nil, true)
	p.body(3, nil, true)
	for _, stream := range []uint32{1, 3} {
		if headers, _ := p.answer(stream); headers.status() != "404" {
			t.Errorf("stream %d answered %v", stream, headers.fields)
		}
	}
	var away []sent
	for _, f := range drained(p) {
		if f.Type == http2.FrameGoAway {
			away = append(away, f)
		}
	}
	if len(away) != 1 || away[0].last != 3 || away[0].code != http2.ErrCodeNo {
		t.Errorf("GOAWAY %+v", away)
	}
}
