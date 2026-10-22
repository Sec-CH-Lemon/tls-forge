package tlsforge

import (
	"context"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v4/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v4/profile"
	tls_client "github.com/igor-lemon/tls-client"
)

// framesOf is how a header block of total bytes of payload, priority of them
// the HEADERS frame's, goes into frames that carry at most limit: as much as
// each can, and at least a byte of the block in the HEADERS frame.
func framesOf(total, limit, priority int) []int {
	block := total - priority
	first := min(block, max(limit-priority, 1))
	out := []int{first + priority}
	for block -= first; block > 0; block -= min(block, limit) {
		out = append(out, min(block, limit))
	}
	return out
}

func TestFramesOfCutsABlockAsMuchAsEachFrameCarries(t *testing.T) {
	for _, tc := range []struct {
		total, limit, priority int
		want                   []int
	}{
		{16374, 16374, 5, []int{16374}},
		{16375, 16374, 5, []int{16374, 1}},
		{32748, 16374, 5, []int{16374, 16374}},
		{32749, 16374, 5, []int{16374, 16374, 1}},
		{16385, 16384, 0, []int{16384, 1}},
		{10, 3, 5, []int{6, 3, 1}},
	} {
		if got := framesOf(tc.total, tc.limit, tc.priority); !slices.Equal(got, tc.want) {
			t.Errorf("framesOf(%d, %d, %d) = %v, want %v", tc.total, tc.limit, tc.priority, got, tc.want)
		}
	}
}

func TestAHeaderBlockAtAFramesLimitReachesAStrictServerWhole(t *testing.T) {
	// The bench's server that says frames may be 16,384 bytes, and refuses a
	// larger one with FRAME_SIZE_ERROR, sent header blocks of each size on
	// either side of where the HEADERS frame is full, of 16,379 to 16,384
	// bytes (which went in a HEADERS frame of 16,384 bytes of the block and
	// five of priority before 2026-10-19), and on either side of where two
	// frames are: each goes out in frames that carry no more than the
	// profile's limit, the block whole, and the stream ended where it should.
	server, err := harness.StartHPACKServer()
	if err != nil {
		t.Fatalf("StartHPACKServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	port := server.PortFor(harness.H2Settings{Frame: 16384})
	if port == 0 {
		t.Fatal("the bench has no server allowing frames of 16,384 bytes")
	}
	url := "https://www.example.com:" + strconv.Itoa(port) + "/p/frames"
	dial := WithTransportOption(tls_client.WithDialContext(
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, at, _ := net.SplitHostPort(addr)
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", at))
		}))
	type wearing struct {
		name    string
		profile Option
		// limit is the most a frame carries, and priority the HEADERS
		// frame's.
		limit, priority int
	}
	var each []wearing
	for _, name := range chromePlatforms {
		p, err := profile.Get(name)
		if err != nil {
			t.Fatalf("profile: %v", err)
		}
		each = append(each, wearing{name + ": Chrome's 16,374", WithProfileValue(headless(p)), 16374, 5})
	}
	each = append(each, wearing{"another browser's from the catalogue: the server's 16,384", WithProfile("firefox_148"), 16384, 5})
	for _, tc := range each {
		t.Run(tc.name, func(t *testing.T) {
			server.Reset()
			// A frame the server refuses ends the connection, and the request
			// is sent again until the client gives up: not for long.
			client := newTestClient(t, tc.profile, dial, WithTimeout(10*time.Second))
			// send asks for the page with an X-Foo of n letters, and a body
			// when there is one, and reads what the server was sent.
			send := func(n int, body string) harness.Entry {
				t.Helper()
				value := strings.Repeat("a", n)
				method := map[bool]string{false: "GET", true: "POST"}[body != ""]
				res, err := client.Do(&Request{Method: method, URL: url, Body: []byte(body),
					Header: []profile.Field{{Name: "X-Foo", Value: value}}})
				if err != nil || res.Status != 200 {
					t.Fatalf("an X-Foo of %d letters: %v, %+v", n, err, res)
				}
				entries, err := server.Requests()
				if err != nil {
					t.Fatalf("Requests: %v", err)
				}
				e := entries[len(entries)-1]
				i := slices.IndexFunc(e.Headers, func(f [2]string) bool { return f[0] == "x-foo" })
				if i < 0 || e.Headers[i][1] != value || e.Body != body {
					t.Fatalf("an X-Foo of %d letters came as %d letters, the body as %q", n, len(e.Headers[i][1]), e.Body)
				}
				return e
			}
			// held holds a request's frames to the limit: as many as the
			// block needs, each as full as it can be, and the stream ended
			// by the block, or by the body's DATA after it.
			held := func(e harness.Entry, body string) {
				t.Helper()
				total := 0
				for _, n := range e.Frames {
					total += n
				}
				if priority := total - len(e.Block); priority != tc.priority || (e.Priority != nil) != (priority > 0) {
					t.Fatalf("a block of %d: %d bytes of priority, %v", len(e.Block), priority, e.Priority)
				}
				if want := framesOf(total, tc.limit, tc.priority); !slices.Equal(e.Frames, want) {
					t.Errorf("a block of %d went in frames %v, want %v", len(e.Block), e.Frames, want)
				}
				want := map[bool][]int{false: nil, true: {len(body)}}[body != ""]
				if !slices.Equal(e.Data, want) {
					t.Errorf("a block of %d and a body of %d: DATA %v, want %v", len(e.Block), len(body), e.Data, want)
				}
			}
			// Each letter is five bits of a Huffman-coded value: a block of
			// size bytes is the one of n letters with the bytes the rest of
			// it takes, which the request before says.
			e := send(20000, "")
			rest := len(e.Block) - (5*20000+7)/8
			sized := func(size int, body string) {
				t.Helper()
				for range 3 {
					e := send(8*(size-rest)/5, body)
					if len(e.Block) == size {
						held(e, body)
						return
					}
					rest += len(e.Block) - size
				}
				t.Fatalf("no block of %d bytes", size)
			}
			full := tc.limit - tc.priority
			sizes := []int{full - 1, full, full + 1, full + 2, 16379, 16380, 16383, 16384, 16385,
				full + tc.limit - 1, full + tc.limit, full + tc.limit + 1}
			for _, size := range sizes {
				sized(size, "")
			}
			// A body: the stream is ended by its DATA, not by the block.
			sized(full+1, "a body")
		})
	}
}
