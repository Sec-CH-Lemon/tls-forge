package tlsforge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// pingSite is an HTTP/2 server over TLS that says what each connection's
// client sent, frame by frame ("1 H3", "1 P1", "2 G0/1:Failed ping.", "1
// EOF"), and answers every request but the first to /hold, after which it
// acknowledges no PING on that connection.
type pingSite struct {
	url    string
	frames chan sentFrame
	held   atomic.Bool
}

// sentFrame is a frame the site read, and when.
type sentFrame struct {
	what string
	at   time.Time
}

func newPingSite(t *testing.T) *pingSite {
	t.Helper()
	listener := tlsListener(t, "h2")
	s := &pingSite{url: "https://" + listener.Addr().String(), frames: make(chan sentFrame, 64)}
	go func() {
		for n := 1; ; n++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.serve(n, conn)
		}
	}()
	return s
}

func (s *pingSite) serve(n int, conn net.Conn) {
	defer conn.Close()
	say := func(f string, args ...any) {
		s.frames <- sentFrame{fmt.Sprintf("%d ", n) + fmt.Sprintf(f, args...), time.Now()}
	}
	if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
		say("EOF")
		return
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	_ = fr.WriteSettings()
	muted := false
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			say("EOF")
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			say("H%d", f.StreamID)
			if f.PseudoValue("path") == "/hold" && s.held.CompareAndSwap(false, true) {
				muted = true
				continue
			}
			var block bytes.Buffer
			_ = hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, EndHeaders: true, BlockFragment: block.Bytes()})
			_ = fr.WriteData(f.StreamID, true, []byte("ok"))
		case *http2.PingFrame:
			say("P%d", binary.BigEndian.Uint64(f.Data[:]))
			if !muted {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.GoAwayFrame:
			say("G%d/%d:%s", f.LastStreamID, f.ErrCode, f.DebugData())
		}
	}
}

// expect reads the next frames the site was sent, which must be want, and
// says when the last came.
func (s *pingSite) expect(t *testing.T, want ...string) time.Time {
	t.Helper()
	var at time.Time
	for _, w := range want {
		select {
		case got := <-s.frames:
			if got.what != w {
				t.Fatalf("got %q, want %q of %q", got.what, w, want)
			}
			at = got.at
		case <-time.After(5 * time.Second):
			t.Fatalf("nothing came, want %q of %q", w, want)
		}
	}
	return at
}

// records are the lengths of the TLS application data records in sent.
func records(sent []byte) []int {
	var lengths []int
	for len(sent) >= 5 {
		n := int(binary.BigEndian.Uint16(sent[3:5]))
		if sent[0] == 23 {
			lengths = append(lengths, n)
		}
		if len(sent) < 5+n {
			break
		}
		sent = sent[5+n:]
	}
	return lengths
}

// TestAChromeProfilePingsAConnectionThatHasReadNothingForLong holds the
// shipped profile's PING to the wire, its times alone changed in the JSON:
// after the HEADERS of a request to a connection that has read nothing for
// longer than h2.preface_ping_idle_ms, in a TLS record of its own (34 bytes:
// its 17 and AES-GCM's), saying 1, then 2; none to a connection that has
// just read; and one left unanswered gives the connection up with Chrome's
// GOAWAY, the request going again on another connection.
func TestAChromeProfilePingsAConnectionThatHasReadNothingForLong(t *testing.T) {
	site := newPingSite(t)
	c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h2.preface_ping_idle_ms": 150, "h2.preface_ping_hung_ms": 400})), WithTimeout(5*time.Second))
	tap := &seeingTap{}
	ok := func(path string) {
		t.Helper()
		if res := get(t, c, site.url+path, tap); res.Text() != "ok" {
			t.Fatalf("%s: %q", path, res.Text())
		}
	}
	ok("/a")
	site.expect(t, "1 H1")
	time.Sleep(300 * time.Millisecond)
	dialed, _ := tap.seen()
	sent, _ := dialed[0].what()
	before := len(records(sent))
	ok("/b")
	pinged := site.expect(t, "1 H3", "1 P1")
	sent, _ = dialed[0].what()
	if after := records(sent)[before:]; len(after) != 2 || after[1] != 34 {
		t.Errorf("records %v after the request's, want its HEADERS and a PING of 34 bytes", after)
	}
	ok("/c")
	site.expect(t, "1 H5")
	// No PING goes while the check of the one before is pending.
	time.Sleep(time.Until(pinged.Add(600 * time.Millisecond)))
	ok("/hold")
	pinged = site.expect(t, "1 H7", "1 P2")
	if took := site.expect(t, "1 G0/1:Failed ping.").Sub(pinged); took < 350*time.Millisecond || took > 2*time.Second {
		t.Errorf("given up %v after its PING, want 400ms", took)
	}
	site.expect(t, "1 EOF", "2 H1")
}

// TestAChromeProfileWithoutItsPingNeverPings: the same profile with
// h2.preface_ping_idle_ms 0 sends none, however long a connection read
// nothing.
func TestAChromeProfileWithoutItsPingNeverPings(t *testing.T) {
	site := newPingSite(t)
	c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h2.preface_ping_idle_ms": 0})))
	for _, path := range []string{"/a", "/b", "/c"} {
		if res := get(t, c, site.url+path, nil); res.Text() != "ok" {
			t.Fatalf("%s: %q", path, res.Text())
		}
		time.Sleep(200 * time.Millisecond)
	}
	site.expect(t, "1 H1", "1 H3", "1 H5")
	select {
	case got := <-site.frames:
		t.Fatalf("then %q", got.what)
	case <-time.After(100 * time.Millisecond):
	}
}
