package tlsforge

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v4/internal/conntap"
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
	// HTTPS proxy it shakes hands with the proxy first; through a SOCKS proxy,
	// which the transport dials, it shakes hands with the proxy as SOCKS has
	// it, then with the site.
	site := keyedServer(t, true, io.Discard)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(site.URL, "https://"))
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	at := binary.BigEndian.AppendUint16(nil, uint16(number))
	// socks is what a SOCKS client sends before its ClientHello.
	socks := func(asked ...[]byte) func([]byte) bool {
		handshake := slices.Concat(asked...)
		return func(sent []byte) bool {
			return bytes.HasPrefix(sent, handshake) && beginsWithAHandshake(sent[len(handshake):])
		}
	}
	socks5 := []byte{5, 1, 0, 1, 127, 0, 0, 1}
	plain, _ := socksServer(t, "", "")
	credentialed, _ := socksServer(t, "alice", "s3cr3t")
	http, https := startConnectProxy(t, false, exitAnswer), keyedProxy(t, io.Discard)
	for _, tc := range []struct {
		name, proxyURL, addr string
		begin                func([]byte) bool
	}{
		{"http", http.server.URL, http.server.Listener.Addr().String(), func(sent []byte) bool {
			end := bytes.Index(sent, []byte("\r\n\r\n"))
			return bytes.HasPrefix(sent, []byte("CONNECT ")) && end > 0 && beginsWithAHandshake(sent[end+4:])
		}},
		{"https", https.server.URL, https.server.Listener.Addr().String(), beginsWithAHandshake},
		{"socks5", "socks5://" + plain, plain, socks([]byte{5, 1, 0}, socks5, at)},
		{"socks5 with a password", "socks5://alice:s3cr3t@" + credentialed, credentialed,
			socks([]byte{5, 2, 0, 2, 1, 5}, []byte("alice"), []byte{6}, []byte("s3cr3t"), socks5, at)},
		{"socks5h", "socks5h://" + plain, plain, socks([]byte{5, 1, 0}, socks5, at)},
		{"socks4", "socks4://" + plain, plain, socks([]byte{4, 1}, at, []byte{127, 0, 0, 1}, []byte("nobody@0.0.0.0\x00"))},
		{"socks4a", "socks4a://" + plain, plain,
			socks([]byte{4, 1}, at, []byte{0, 0, 0, 1}, []byte("nobody@0.0.0.0\x00"+host+"\x00"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tap := &seeingTap{}
			before := time.Now()
			tappedGet(t, newTestClient(t, WithProxy(tc.proxyURL)), site.URL, tap)
			dialed, used := tap.seen()
			if len(dialed) != 1 || len(used) != 1 || used[0] != dialed[0].LocalAddr().String() {
				t.Fatalf("dialed %d, went out on %v", len(dialed), used)
			}
			sent, received := dialed[0].what()
			if dialed[0].RemoteAddr().String() != tc.addr || !tc.begin(sent) || len(received) == 0 {
				t.Errorf("dialed %s, sent %q…, received %d bytes", dialed[0].RemoteAddr(), sent[:min(len(sent), 40)],
					len(received))
			}
			if dialed[0].began.Before(before) || dialed[0].began.After(time.Now()) {
				t.Errorf("a dial begun %v after the request", dialed[0].began.Sub(before))
			}
		})
	}
}

func TestATapSeesNoDialThatFailed(t *testing.T) {
	// Straight to the site and through a proxy nothing answers at, which
	// tls-forge dials or the transport does.
	for _, proxy := range []string{"", "http://" + refused(t), "socks5://" + refused(t), "socks4://" + refused(t)} {
		tap := &seeingTap{}
		_, err := newTestClient(t, WithProxy(proxy)).Do(&Request{URL: "https://" + refused(t) + "/",
			Context: conntap.With(context.Background(), tap)})
		if dialed, used := tap.seen(); err == nil || len(dialed) != 0 || len(used) != 0 {
			t.Errorf("%q: %v: dialed %d, went out on %v", proxy, err, len(dialed), used)
		}
	}
}
