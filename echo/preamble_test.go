package echo

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// framesOf are the frames a capture kept, as the comparison reads them.
func framesOf(t *testing.T, c *capture.Capture) *fingerprint.Preamble {
	t.Helper()
	if c.HTTP2 == nil {
		t.Fatal("no HTTP/2 recorded")
	}
	preamble, err := fingerprint.ParsePreamble(c.HTTP2.RawFrames)
	if err != nil {
		t.Fatalf("the frames kept: %v", err)
	}
	if !bytes.Equal(preamble.Raw, c.HTTP2.RawFrames) {
		t.Errorf("%d bytes kept past the first header block", len(c.HTTP2.RawFrames)-len(preamble.Raw))
	}
	return preamble
}

func TestTheFramesUpToTheFirstRequestAreKept(t *testing.T) {
	sess := &Session{}
	p := servedH2(t, startServer(t), sess, 4096)
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	if err := p.framer.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	if err := p.framer.WriteSettingsAck(); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	// A block long enough to need a CONTINUATION: "~" is longer in Huffman
	// code than it is, so the value is written as it is.
	p.request(1, "GET", "/", true, [2]string{"x-long", strings.Repeat("~", maxFrameSize)})
	p.answer(1)
	// What comes after the first request is not its preamble.
	p.request(3, "GET", "/another", true)
	p.answer(3)
	p.sync()

	preamble := framesOf(t, sess.Capture(capture.SourceBrowser))
	var said []string
	for _, frame := range preamble.Frames {
		said = append(said, frame.String())
	}
	want := []string{"SETTINGS on 0", "WINDOW_UPDATE on 0", "SETTINGS on 0, ACK", "HEADERS on 1, END_STREAM",
		"CONTINUATION on 1, END_HEADERS"}
	if !slices.Equal(said, want) {
		t.Errorf("frames %q, want %q", said, want)
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(preamble.Block)
	if err != nil || len(fields) != 5 || fields[3].Value != "/" {
		t.Errorf("the block of the first request decodes to %v, %v", fields, err)
	}
}

func TestNoFramesAreKeptForARequestTheyAreNotThePreambleOf(t *testing.T) {
	// A stream that broke the protocol first: the frames before the request
	// recorded are not all its own.
	sess := &Session{}
	p := servedH2(t, startServer(t), sess, 4096)
	p.headerBlock(1, true, [2]string{":method", "GET"}, [2]string{"Upper-Case", "no"})
	if code := p.reset(1); code != http2.ErrCodeProtocol {
		t.Fatalf("the broken stream was reset with %v", code)
	}
	p.request(3, "GET", "/", true)
	p.answer(3)
	p.sync()
	if c := sess.Capture(capture.SourceBrowser); c.HTTP2 == nil || len(c.HTTP2.RawFrames) != 0 {
		t.Errorf("frames were kept: %+v", c.HTTP2)
	}

	// The first request refused, after a GOAWAY: the next is not recorded at
	// all, and nothing is kept for it.
	sess = &Session{}
	p = servedH2(t, startServer(t), sess, 4096)
	p.h.goneAway = true
	p.request(1, "GET", "/", true)
	if code := p.reset(1); code != http2.ErrCodeRefusedStream {
		t.Fatalf("the request was answered with %v", code)
	}
	p.sync()
	if sess.http2Recorded || sess.http2.Raw != nil {
		t.Errorf("a refused request was recorded: %+v", sess.http2)
	}
}

func TestTheRecorderKeepsNoMoreThanItMay(t *testing.T) {
	recorder := &preambleRecorder{r: bytes.NewReader(make([]byte, maxPreambleBytes+1)), on: true}
	if n, err := io.ReadFull(recorder, make([]byte, maxPreambleBytes)); err != nil || n != maxPreambleBytes ||
		len(recorder.kept) != maxPreambleBytes {
		t.Fatalf("read %d, %v, kept %d", n, err, len(recorder.kept))
	}
	// One byte past it, and nothing is kept: frames cut short are no one's.
	if _, err := recorder.Read(make([]byte, 1)); err != nil || recorder.on || recorder.kept != nil {
		t.Errorf("past the bound: on %v, kept %d, %v", recorder.on, len(recorder.kept), err)
	}
	if got := recorder.take(); got != nil {
		t.Errorf("took %d bytes", len(got))
	}
	// Taken once, it keeps nothing more.
	recorder = &preambleRecorder{r: bytes.NewReader([]byte("abcd")), on: true}
	_, _ = recorder.Read(make([]byte, 2))
	if got := string(recorder.take()); got != "ab" {
		t.Errorf("took %q", got)
	}
	_, _ = recorder.Read(make([]byte, 2))
	if got := recorder.take(); got != nil {
		t.Errorf("took %q after the first", got)
	}
}
