package tlsforge

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/conntap"
)

// seenConn is a connection as a tap sees it: what went over it, each way.
type seenConn struct {
	net.Conn
	began          time.Time
	mu             sync.Mutex
	sent, received bytes.Buffer
}

func (c *seenConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.received.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *seenConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.sent.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

// what is what went over the connection so far.
func (c *seenConn) what() (sent, received []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.sent.Bytes()), bytes.Clone(c.received.Bytes())
}

// seeingTap keeps the connections dialed for a request and the near end of
// each it went out on.
type seeingTap struct {
	mu     sync.Mutex
	dialed []*seenConn
	used   []string
}

func (t *seeingTap) Dialed(conn net.Conn, began time.Time) net.Conn {
	seen := &seenConn{Conn: conn, began: began}
	t.mu.Lock()
	t.dialed = append(t.dialed, seen)
	t.mu.Unlock()
	return seen
}

func (t *seeingTap) Used(conn net.Conn) {
	t.mu.Lock()
	t.used = append(t.used, conn.LocalAddr().String())
	t.mu.Unlock()
}

func (t *seeingTap) seen() ([]*seenConn, []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*seenConn{}, t.dialed...), append([]string{}, t.used...)
}

// tappedGet asks for url through client, the request carrying tap.
func tappedGet(t *testing.T, client *Client, url string, tap conntap.Tap) *Response {
	t.Helper()
	res, err := client.Do(&Request{URL: url, Context: conntap.With(context.Background(), tap)})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return res
}

// beginsWithAHandshake says whether what was sent begins as TLS does.
func beginsWithAHandshake(sent []byte) bool {
	return len(sent) > 5 && sent[0] == 22 && sent[1] == 3
}

func TestATapSeesEveryConnectionARequestIsDialedAndGoesOutOn(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"HTTP/2.0", true}, {"HTTP/1.1", false}} {
		t.Run(tc.name, func(t *testing.T) {
			site := keyedServer(t, tc.h2, io.Discard)
			client := newTestClient(t)
			tap := &seeingTap{}
			before := time.Now()
			if res := tappedGet(t, client, site.URL, tap); res.Text() != tc.name {
				t.Errorf("went over %s", res.Text())
			}
			dialed, used := tap.seen()
			if len(dialed) != 1 || len(used) != 1 || used[0] != dialed[0].LocalAddr().String() {
				t.Fatalf("dialed %d, went out on %v", len(dialed), used)
			}
			conn := dialed[0]
			if conn.began.Before(before) || conn.began.After(time.Now()) ||
				conn.RemoteAddr().String() != strings.TrimPrefix(site.URL, "https://") {
				t.Errorf("a dial begun at %v, to %s", conn.began, conn.RemoteAddr())
			}
			// What went over it is what the request was: its handshake, and
			// an answer.
			if sent, received := conn.what(); !beginsWithAHandshake(sent) || len(received) == 0 {
				t.Errorf("sent % x…, received %d bytes", sent[:min(len(sent), 8)], len(received))
			}

			// The same connection again: dialed for no one, gone out on again.
			tappedGet(t, client, site.URL, tap)
			if dialed, used := tap.seen(); len(dialed) != 1 || len(used) != 2 || used[1] != used[0] {
				t.Errorf("again: dialed %d, went out on %v", len(dialed), used)
			}
			// And a request that carries no tap tells it nothing.
			if _, err := client.Get(site.URL); err != nil {
				t.Fatalf("Get: %v", err)
			}
			if dialed, used := tap.seen(); len(dialed) != 1 || len(used) != 2 {
				t.Errorf("a request without the tap: dialed %d, went out on %v", len(dialed), used)
			}
		})
	}
}

func TestATapSeesTheConnectionToAProxy(t *testing.T) {
	// The connection to the proxy is the one dialed: through an HTTP proxy it
	// asks for its tunnel in the clear, then shakes hands with the site; to an
	// HTTPS proxy it shakes hands with the proxy first.
	site := keyedServer(t, true, io.Discard)
	for _, tc := range []struct {
		name  string
		proxy *connectProxy
		begin func([]byte) bool
	}{
		{"http", startConnectProxy(t, false, exitAnswer), func(sent []byte) bool {
			end := bytes.Index(sent, []byte("\r\n\r\n"))
			return bytes.HasPrefix(sent, []byte("CONNECT ")) && end > 0 && beginsWithAHandshake(sent[end+4:])
		}},
		{"https", keyedProxy(t, io.Discard), beginsWithAHandshake},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tap := &seeingTap{}
			tappedGet(t, newTestClient(t, WithProxy(tc.proxy.server.URL)), site.URL, tap)
			dialed, used := tap.seen()
			if len(dialed) != 1 || len(used) != 1 || used[0] != dialed[0].LocalAddr().String() {
				t.Fatalf("dialed %d, went out on %v", len(dialed), used)
			}
			sent, _ := dialed[0].what()
			if dialed[0].RemoteAddr().String() != tc.proxy.server.Listener.Addr().String() || !tc.begin(sent) {
				t.Errorf("dialed %s, and sent %q…", dialed[0].RemoteAddr(), sent[:min(len(sent), 40)])
			}
		})
	}
}

func TestATapSeesNoDialThatFailed(t *testing.T) {
	tap := &seeingTap{}
	_, err := newTestClient(t).Do(&Request{URL: "https://" + refused(t) + "/",
		Context: conntap.With(context.Background(), tap)})
	if dialed, used := tap.seen(); err == nil || len(dialed) != 0 || len(used) != 0 {
		t.Errorf("%v: dialed %d, went out on %v", err, len(dialed), used)
	}
}
