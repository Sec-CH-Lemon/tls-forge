package tlsforge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

// tlsListener is a TLS listener on a loopback port, with a certificate made for
// it, offering protocols in ALPN.
func tlsListener(t *testing.T, protocols ...string) net.Listener {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   protocols,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestACancelledRequestEndsWhileTheServerHoldsIt(t *testing.T) {
	// Cancelled once the server has it, over either protocol: the call
	// returns at once with the cancellation, and the server is told, by the
	// connection closing or the stream being reset, rather than left to
	// answer nobody.
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"HTTP/1.1", false}, {"HTTP/2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			reached, told := make(chan struct{}), make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(reached)
				select {
				case <-r.Context().Done():
					close(told)
				case <-time.After(5 * time.Second):
					_, _ = w.Write([]byte("late"))
				}
			}))
			server.EnableHTTP2 = tc.h2
			server.StartTLS()
			t.Cleanup(server.Close)
			client := newTestClient(t, WithTimeout(10*time.Second))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				<-reached
				cancel()
			}()
			started := time.Now()
			_, err := client.Do(&Request{Context: ctx, URL: server.URL})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want the cancellation", err)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Errorf("the call returned after %v", elapsed)
			}
			select {
			case <-told:
			case <-time.After(3 * time.Second):
				t.Error("the server was never told the request had ended")
			}
		})
	}
}

func TestARequestCancelledBeforeItIsMadeIsNotMade(t *testing.T) {
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked.Add(1) }))
	t.Cleanup(server.Close)
	client := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Do(&Request{Context: ctx, URL: server.URL}); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want the cancellation", err)
	}
	if asked.Load() != 0 {
		t.Errorf("the server was asked %d times", asked.Load())
	}
}

func TestAHandshakeTheServerNeverAnswersEndsAtTheTimeout(t *testing.T) {
	// A server that takes the connection and says nothing: the request ends
	// at its timeout, and the log says it gave up in the handshake.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithTimeout(300*time.Millisecond), WithLogger(log))
	started := time.Now()
	if _, err := client.Get("https://" + listener.Addr().String() + "/"); err == nil {
		t.Fatal("a request to a server that never answered succeeded")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("the request ended after %v", elapsed)
	}
	if failed := book.one(t, "request failed"); failed.get("phase") != "tls" {
		t.Errorf("the log says it failed in %q:\n%s", failed.get("phase"), book.text())
	}
}

// h2Answering is an HTTP/2 server that reads the first request on a connection
// and answers it as answer says, by writing frames, and then reads what the
// client says until it hangs up, unless answer says to close.
func h2Answering(t *testing.T, answer func(framer *http2.Framer, stream uint32) (closes bool)) string {
	t.Helper()
	listener := tlsListener(t, "h2")
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					return
				}
				framer := http2.NewFramer(conn, conn)
				framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				if err := framer.WriteSettings(); err != nil {
					return
				}
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						return
					}
					switch f := frame.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							_ = framer.WriteSettingsAck()
						}
					case *http2.MetaHeadersFrame:
						if !answer(framer, f.StreamID) {
							_, _ = io.Copy(io.Discard, conn)
						}
						return
					}
				}
			}()
		}
	}()
	return "https://" + listener.Addr().String() + "/"
}

// halfAnswered writes the header of an answer of a thousand bytes, and the
// first hundred of them.
func halfAnswered(framer *http2.Framer, stream uint32) {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	_ = encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: "1000"})
	_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true})
	_ = framer.WriteData(stream, false, bytes.Repeat([]byte("x"), 100))
}

func TestAnAnswerCutOffHalfwayIsAFailureNotAPage(t *testing.T) {
	// Reset in the middle of its body, or its connection told to go away and
	// closed: the hundred bytes that came are not the page, and the request
	// fails at once rather than answering with them, or at its timeout.
	for _, tc := range []struct {
		name string
		then func(framer *http2.Framer, stream uint32) bool
	}{
		{"its stream reset", func(framer *http2.Framer, stream uint32) bool {
			_ = framer.WriteRSTStream(stream, http2.ErrCodeInternal)
			return false
		}},
		{"its connection gone away and closed", func(framer *http2.Framer, stream uint32) bool {
			_ = framer.WriteGoAway(stream, http2.ErrCodeInternal, []byte("going"))
			return true
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := h2Answering(t, func(framer *http2.Framer, stream uint32) bool {
				halfAnswered(framer, stream)
				return tc.then(framer, stream)
			})
			client := newTestClient(t, WithTimeout(10*time.Second))
			started := time.Now()
			res, err := client.Get(url)
			if err == nil {
				t.Fatalf("answered %d with %d bytes, want the failure", res.Status, len(res.Body))
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Errorf("the request failed after %v, at its timeout rather than when the answer was cut off: %v",
					elapsed, err)
			}
		})
	}
}

// socksServer is a SOCKS5 proxy (RFC 1928) on a loopback port. When user is
// not empty it asks for a user name and password (RFC 1929) and turns away
// any other. It keeps the address each CONNECT named, as it named it.
func socksServer(t *testing.T, user, pass string) (string, func() []string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var mu sync.Mutex
	var asked []string
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				target, ok := socksGreeting(conn, user, pass)
				if !ok {
					return
				}
				mu.Lock()
				asked = append(asked, target)
				mu.Unlock()
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer func() { _ = upstream.Close() }()
				if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	return listener.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(asked)
	}
}

// socksGreeting reads a SOCKS5 greeting, its authentication and its CONNECT,
// and is the address the CONNECT named.
func socksGreeting(conn net.Conn, user, pass string) (string, bool) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return "", false
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", false
	}
	method := byte(0)
	if user != "" {
		method = 2
	}
	if !slices.Contains(methods, method) {
		_, _ = conn.Write([]byte{5, 0xff})
		return "", false
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return "", false
	}
	if user != "" {
		given, ok := socksCredentials(conn)
		if !ok || given != user+":"+pass {
			_, _ = conn.Write([]byte{1, 1})
			return "", false
		}
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return "", false
		}
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil || request[1] != 1 {
		return "", false
	}
	var host string
	switch request[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", false
		}
		host = net.IP(ip).String()
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", false
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", false
		}
		host = string(name)
	default:
		return "", false
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), true
}

// socksCredentials reads a user name and password (RFC 1929) as user:pass.
func socksCredentials(conn net.Conn) (string, bool) {
	read := func() (string, bool) {
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", false
		}
		value := make([]byte, length[0])
		_, err := io.ReadFull(conn, value)
		return string(value), err == nil
	}
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil || version[0] != 1 {
		return "", false
	}
	name, ok := read()
	if !ok {
		return "", false
	}
	password, ok := read()
	return name + ":" + password, ok
}

func TestARequestGoesThroughASOCKS5Proxy(t *testing.T) {
	// With a password and without, and with the name of the host resolved by
	// the proxy, socks5h, or by the client: the request comes out the other
	// side, and the server answers what the client sent.
	server := startEcho(t)
	_, port, _ := net.SplitHostPort(server.Addr())
	for _, tc := range []struct{ name, scheme, user, pass string }{
		{"no password", "socks5", "", ""},
		{"a password", "socks5", "alice", "s3cr3t"},
		{"the proxy's name lookup", "socks5h", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, asked := socksServer(t, tc.user, tc.pass)
			proxyURL := tc.scheme + "://" + addr
			if tc.user != "" {
				proxyURL = tc.scheme + "://" + tc.user + ":" + tc.pass + "@" + addr
			}
			client := newTestClient(t, WithProxy(proxyURL), WithTimeout(10*time.Second))
			res, err := client.Get("https://localhost:" + port + "/api/all")
			if err != nil || !res.OK() {
				t.Fatalf("Get = %v, %v", res, err)
			}
			if got := asked(); len(got) != 1 || !strings.HasSuffix(got[0], ":"+port) {
				t.Errorf("the proxy was asked for %v", got)
			}
		})
	}
	t.Run("a password turned down", func(t *testing.T) {
		addr, asked := socksServer(t, "alice", "s3cr3t")
		client := newTestClient(t, WithProxy("socks5://alice:wrong@"+addr), WithTimeout(5*time.Second))
		_, err := client.Get("https://localhost:" + port + "/api/all")
		if err == nil || strings.Contains(err.Error(), "wrong") {
			t.Errorf("error = %v, want a failure without the password in it", err)
		}
		if got := asked(); len(got) != 0 {
			t.Errorf("the proxy connected %v for a password it turned down", got)
		}
	})
}

// keepsOrder says every name of got that layout has comes in the order layout
// has them in, in any case.
func keepsOrder(got, layout []string) bool {
	position := map[string]int{}
	for i, name := range layout {
		position[strings.ToLower(name)] = i
	}
	last := -1
	for _, name := range got {
		at, known := position[strings.ToLower(name)]
		if !known {
			continue
		}
		if at < last {
			return false
		}
		last = at
	}
	return true
}

func TestARedirectToAnotherProtocolWearsThatProtocolsLayout(t *testing.T) {
	// From HTTP/2 to a server that speaks only HTTP/1.1, and back: each hop
	// goes out in the header layout of the protocol it was made over, not in
	// the one the chain began with.
	echoServer := startEcho(t)
	redirectTo := func(h2 bool, target string) string {
		t.Helper()
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		}))
		server.EnableHTTP2 = h2
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.URL + "/"
	}
	client := newTestClient(t, WithTimeout(10*time.Second))
	profile := client.Profile()
	if profile.HTTP1 == nil || len(profile.HTTP1.HeaderOrder) == 0 {
		t.Fatalf("the default profile %s has no HTTP/1.1 layout to check against", profile.Name)
	}
	var h2Order []string
	for _, field := range client.Headers() {
		h2Order = append(h2Order, field.Name)
	}

	measured := func(url string) *capture.Capture {
		t.Helper()
		res, err := client.Get(url)
		if err != nil || !res.OK() {
			t.Fatalf("Get %s = %v, %v", url, res, err)
		}
		var c capture.Capture
		if err := json.Unmarshal(res.Body, &c); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		return &c
	}

	toH1 := measured(redirectTo(true, echoServer.CaptureURL()+"/api/all"))
	if toH1.HTTP1 == nil || toH1.HTTP1.Proto != "HTTP/1.1" {
		t.Fatalf("the hop to HTTP/1.1 was recorded as %+v", toH1.HTTP1)
	}
	if names := toH1.HTTP1.HeaderNames; len(names) == 0 || names[0] != "Host" || !keepsOrder(names, profile.HTTP1.HeaderOrder) {
		t.Errorf("the HTTP/1.1 hop went out as %v, want the order %v", names, profile.HTTP1.HeaderOrder)
	}

	toH2 := measured(redirectTo(false, echoServer.URL()+"/api/all"))
	if toH2.Negotiated != "h2" || toH2.HTTP2 == nil {
		t.Fatalf("the hop to HTTP/2 went over %q", toH2.Negotiated)
	}
	if names := toH2.HTTP2.HeaderOrder; !keepsOrder(names, h2Order) || slices.Contains(names, "host") || slices.Contains(names, "connection") {
		t.Errorf("the HTTP/2 hop went out as %v, want the order %v", names, h2Order)
	}
}

func TestNewRefusesAResponseBodyLimitThatIsNoLimit(t *testing.T) {
	for _, limit := range []int64{0, -1, math.MaxInt64} {
		if _, err := New(WithMaxResponseBody(limit)); err == nil {
			t.Errorf("New accepted a response body limit of %d", limit)
		}
	}
}
