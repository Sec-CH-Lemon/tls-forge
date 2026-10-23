package tlsforge

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// heldSite is an HTTP/2 server over TLS of one connection that says the path
// and priority of every request's HEADERS, and answers a stream only when
// the test says.
type heldSite struct {
	url     string
	headers chan heldHeaders
	mu      sync.Mutex
	fr      *http2.Framer
}

type heldHeaders struct {
	path     string
	stream   uint32
	priority http2.PriorityParam
}

func newHeldSite(t *testing.T) *heldSite {
	t.Helper()
	listener := tlsListener(t, "h2")
	s := &heldSite{url: "https://" + listener.Addr().String(), headers: make(chan heldHeaders, 16)}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		s.serve(conn)
	}()
	return s
}

func (s *heldSite) serve(conn net.Conn) {
	if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
		return
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	s.write(func() { s.fr = fr; _ = fr.WriteSettings() })
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				s.write(func() { _ = fr.WriteSettingsAck() })
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				s.write(func() { _ = fr.WritePing(true, f.Data) })
			}
		case *http2.MetaHeadersFrame:
			s.headers <- heldHeaders{f.PseudoValue("path"), f.StreamID, f.Priority}
		}
	}
}

func (s *heldSite) write(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// answer ends stream with a 200 and a body.
func (s *heldSite) answer(stream uint32) {
	var block bytes.Buffer
	_ = hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	s.write(func() {
		_ = s.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, EndHeaders: true, BlockFragment: block.Bytes()})
		_ = s.fr.WriteData(stream, true, []byte("ok"))
	})
}

func (s *heldSite) next(t *testing.T) heldHeaders {
	t.Helper()
	select {
	case h := <-s.headers:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("no request came")
	}
	return heldHeaders{}
}

// TestAChromeProfileChainsItsStreamsAsChromeDoes holds the shipped profile's
// stream dependencies to Chrome's measured rule on the wire, only the JSON
// changed: fetch()es (weight 219) and requests without a context (255) open
// at once on one connection depend on the last open stream of the lowest
// weight not below their own, a stream answered on none, as Chrome's did
// (fhttp's chromePrio holds its whole measured connection); "root" puts every
// one on none.
func TestAChromeProfileChainsItsStreamsAsChromeDoes(t *testing.T) {
	for _, tc := range []struct {
		mode string
		deps []uint32 // of /A /C /D /G, then /H /I with A answered, then /K with all answered
	}{
		{"nearest-weight", []uint32{0, 0, 1, 5, 7, 3, 0}},
		{"root", []uint32{0, 0, 0, 0, 0, 0, 0}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			site := newHeldSite(t)
			c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h2.priority_dependency": tc.mode})), WithTimeout(5*time.Second))
			done := map[uint32]chan error{}
			want := tc.deps
			send := func(path string, fetch bool, weight uint8) {
				t.Helper()
				req := &Request{URL: site.url + path}
				if fetch {
					req.Browser = &BrowserContext{Kind: KindFetch, Initiator: site.url + "/"}
				}
				ended := make(chan error, 1)
				go func() {
					res, err := c.Do(req)
					if err == nil && res.Text() != "ok" {
						err = io.ErrUnexpectedEOF
					}
					ended <- err
				}()
				h := site.next(t)
				done[h.stream] = ended
				if h.path != path || h.priority.StreamDep != want[0] || h.priority.Weight != weight || !h.priority.Exclusive {
					t.Errorf("%s: stream %d %+v, want on %d, weight %d", path, h.stream, h.priority, want[0], weight)
				}
				want = want[1:]
			}
			answered := func(streams ...uint32) {
				t.Helper()
				for _, id := range streams {
					site.answer(id)
					select {
					case err := <-done[id]:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(5 * time.Second):
						t.Fatalf("stream %d was not answered", id)
					}
				}
			}
			send("/A", true, 219)
			send("/C", false, 255)
			send("/D", true, 219)
			send("/G", true, 219)
			answered(1)
			send("/H", true, 219)
			send("/I", false, 255)
			answered(3, 5, 7, 9, 11)
			send("/K", false, 255)
			answered(13)
		})
	}
}
