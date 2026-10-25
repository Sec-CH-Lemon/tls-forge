package tlsforge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/conntap"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	utls "github.com/igor-lemon/utls"
	peerh2 "golang.org/x/net/http2"
)

var http2ErrNoCachedConn = http2.ErrNoCachedConn

type proxyPoolEvent struct{ method, peer, auth string }

func ownedH2Proxy(t *testing.T, origin string) (*httptest.Server, *[]proxyPoolEvent, *sync.Mutex) {
	t.Helper()
	events := []proxyPoolEvent{}
	mu := new(sync.Mutex)
	via := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		events = append(events, proxyPoolEvent{r.Method, r.RemoteAddr, r.Header.Get("Proxy-Authorization")})
		mu.Unlock()
		if r.ProtoMajor != 2 {
			http.Error(w, "H2 required", 400)
			return
		}
		if r.Method == "CONNECT" {
			if r.Host == "echo.netfp.test:443" {
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				b := make([]byte, 1024)
				for {
					n, e := r.Body.Read(b)
					if n > 0 {
						w.Write(b[:n])
						w.(http.Flusher).Flush()
					}
					if e != nil {
						return
					}
				}
			}
			if r.Host != strings.TrimPrefix(origin, "https://") {
				http.Error(w, "owned target required", http.StatusForbidden)
				return
			}
			up, err := net.DialTimeout("tcp", r.Host, time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer up.Close()
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			done := make(chan struct{})
			go func() { io.Copy(up, r.Body); up.(*net.TCPConn).CloseWrite(); close(done) }()
			io.Copy(flushingTunnelWriter{w}, up)
			r.Body.Close()
			up.Close()
			<-done
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "forward:%s", body)
	}))
	via.EnableHTTP2 = true
	via.StartTLS()
	t.Cleanup(via.Close)
	old := proxyRoots
	proxyRoots = x509.NewCertPool()
	proxyRoots.AddCert(via.Certificate())
	t.Cleanup(func() { proxyRoots = old })
	return via, &events, mu
}

func TestProxyPoolSharesCONNECTWithBothOriginCredentialModes(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "seed")
	}))
	defer origin.Close()
	via, events, mu := ownedH2Proxy(t, origin.URL)
	c := newTestClient(t, WithProxy(strings.Replace(via.URL, "://", "://owned:synthetic@", 1)), WithInsecureSkipVerify(), WithTimeout(2*time.Second))
	defer c.Close()
	if _, err := c.Get(origin.URL + "/seed"); err != nil {
		t.Fatal(err)
	}
	for _, credentials := range []string{"same-origin", "include"} {
		r, err := c.Do(&Request{URL: "http://127.0.0.1:19101/test", Method: "POST", Body: []byte("owned"), Browser: &BrowserContext{Kind: KindFetch, Initiator: origin.URL + "/seed", Credentials: credentials}})
		if err != nil || r.Status != 200 || !bytes.Equal(r.Body, []byte("forward:owned")) {
			t.Fatalf("%s: %+v %v", credentials, r, err)
		}
	}
	// Cancelling the seed's completed request must not discard its inner tunnel.
	if _, err := c.Get(origin.URL + "/again"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	before := append([]proxyPoolEvent(nil), (*events)...)
	mu.Unlock()
	if len(before) != 3 || before[0].method != "CONNECT" || before[1].method != "POST" || before[2].method != "POST" {
		t.Fatal(before)
	}
	for _, e := range before {
		if e.peer != before[0].peer || e.auth == "" {
			t.Fatalf("not one authenticated proxy channel: %+v", before)
		}
	}
	c.CloseIdleConnections()
	if _, err := c.Get(origin.URL + "/after-idle"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	after := append([]proxyPoolEvent(nil), (*events)...)
	mu.Unlock()
	if len(after) != 4 || after[3].peer == before[0].peer {
		t.Fatalf("idle pool did not reconnect: %+v", after)
	}
	fresh, err := c.Fresh()
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err = fresh.Get(origin.URL + "/fresh"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	last := (*events)[len(*events)-1]
	mu.Unlock()
	if last.peer == after[3].peer {
		t.Fatal("Fresh shared the old outer pool")
	}
}

func TestCONNECTDeadlineAndCloseAffectOnlyTheirStream(t *testing.T) {
	via, events, mu := ownedH2Proxy(t, "")
	u, _ := url.Parse(via.URL)
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile, _ = profile.Get("chrome_155_macos")
	defer d.CloseIdleProxyConnections()
	ctx, cancel := context.WithCancel(context.Background())
	a, err := d.DialContext(ctx, "tcp", "echo.netfp.test:443")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	b, err := d.DialContext(context.Background(), "tcp", "echo.netfp.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	echo := func(c net.Conn) {
		t.Helper()
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 4)
		if _, err := io.ReadFull(c, out); err != nil || string(out) != "ping" {
			t.Fatalf("echo:%q %v", out, err)
		}
	}
	echo(a)
	echo(b)
	a.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = a.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	echo(b)
	a.Close()
	a.Close()
	b.SetDeadline(time.Now().Add(20 * time.Millisecond))
	b.SetDeadline(time.Time{})
	time.Sleep(30 * time.Millisecond)
	echo(b)
	d.CloseIdleProxyConnections()
	echo(b)
	b.Close()
	c, err := d.DialContext(context.Background(), "tcp", "echo.netfp.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo(c)
	mu.Lock()
	defer mu.Unlock()
	v := *events
	if len(v) != 3 || v[0].peer != v[1].peer || v[1].peer == v[2].peer {
		t.Fatalf("stream deadline or idle close changed wrong channel:%+v", v)
	}
}

func TestProxyPoolDoesNotShareAcrossTopLevelSitesOrClients(t *testing.T) {
	via, events, mu := ownedH2Proxy(t, "")
	c := newTestClient(t, WithProxy(via.URL))
	defer c.Close()
	send := func(client *Client, initiator string) {
		t.Helper()
		_, err := client.Do(&Request{URL: "http://127.0.0.1:19101/test", Method: "POST", Body: []byte("owned"), Browser: &BrowserContext{Kind: KindFetch, Initiator: initiator, Credentials: "include"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	send(c, "https://a.netfp.test/page")
	send(c, "https://b.netfp-other.test/page")
	send(c, "https://a.netfp.test/again")
	other := newTestClient(t, WithProxy(strings.Replace(via.URL, "://", "://other:synthetic@", 1)))
	defer other.Close()
	send(other, "https://a.netfp.test/page")
	mu.Lock()
	defer mu.Unlock()
	v := *events
	if len(v) != 4 || v[0].peer == v[1].peer || v[0].peer != v[2].peer || v[0].peer == v[3].peer || v[3].auth == "" || v[0].auth != "" {
		t.Fatalf("proxy pool crossed a partition or credentials:%+v", v)
	}
}

func TestProxyPoolConcurrentColdCONNECTsUseOneOuterChannel(t *testing.T) {
	via, events, mu := ownedH2Proxy(t, "")
	u, _ := url.Parse(via.URL)
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile, _ = profile.Get("chrome_155_macos")
	defer d.CloseIdleProxyConnections()
	start := make(chan struct{})
	results := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := d.DialContext(ctx, "tcp", "echo.netfp.test:443")
			if err != nil {
				results <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			_, err = c.Write([]byte("ping"))
			if err == nil {
				b := make([]byte, 4)
				_, err = io.ReadFull(c, b)
				if err == nil && string(b) != "ping" {
					err = fmt.Errorf("wrong echo %q", b)
				}
			}
			results <- err
		}()
	}
	close(start)
	for range 8 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	v := *events
	if len(v) != 8 {
		t.Fatal(v)
	}
	for _, e := range v {
		if e.peer != v[0].peer {
			t.Fatalf("cold CONNECT burst created extra channels:%+v", v)
		}
	}
}

func TestProxyPoolRetriesRefusedForwardStream(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			cert := httptest.NewTLSServer(http.NotFoundHandler())
			config := cert.TLS.Clone()
			roots := x509.NewCertPool()
			roots.AddCert(cert.Certificate())
			cert.Close()
			config.NextProtos = []string{"h2"}
			ln, err := tls.Listen("tcp4", "127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			previous := proxyRoots
			proxyRoots = roots
			defer func() { proxyRoots = previous }()
			ids := make(chan uint32, 4)
			done := make(chan error, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				preface := make([]byte, len(peerh2.ClientPreface))
				if _, err = io.ReadFull(raw, preface); err != nil {
					done <- err
					return
				}
				if string(preface) != peerh2.ClientPreface {
					done <- fmt.Errorf("bad preface")
					return
				}
				fr := peerh2.NewFramer(raw, raw)
				if err = fr.WriteSettings(); err != nil {
					done <- err
					return
				}
				n := 0
				var received bytes.Buffer
				reply := func(sid uint32) {
					fr.WriteHeaders(peerh2.HeadersFrameParam{StreamID: sid, EndHeaders: true, EndStream: true, BlockFragment: []byte{0x88}})
				}
				for {
					f, e := fr.ReadFrame()
					if e != nil {
						if e == io.EOF {
							e = nil
						}
						done <- e
						return
					}
					switch f := f.(type) {
					case *peerh2.SettingsFrame:
						if !f.IsAck() {
							fr.WriteSettingsAck()
						}
					case *peerh2.HeadersFrame:
						n++
						ids <- f.StreamID
						if n == 1 {
							fr.WriteRSTStream(f.StreamID, peerh2.ErrCodeRefusedStream)
						} else if f.StreamEnded() {
							reply(f.StreamID)
						}
					case *peerh2.DataFrame:
						if f.StreamID == 3 {
							received.Write(f.Data())
							if f.StreamEnded() {
								if !bytes.Equal(received.Bytes(), bytes.Repeat([]byte{0, 1, 255, 'x'}, 257)) {
									done <- fmt.Errorf("replayed body changed")
									return
								}
								reply(f.StreamID)
							}
						}
					}
				}
			}()
			// A POST without a context, as given.
			c := newTestClient(t, WithProxy("https://"+ln.Addr().String()), WithTimeout(time.Second),
				WithProfileValue(asGivenProfile(t, DefaultProfile)))
			var payload []byte
			if method == "POST" {
				payload = bytes.Repeat([]byte{0, 1, 255, 'x'}, 257)
			}
			res, err := c.Do(&Request{Method: method, URL: "http://127.0.0.1:19101/owned", Body: payload})
			if err != nil || res.Status != 200 {
				c.Close()
				t.Fatalf("safe H2 retry: %+v %v", res, err)
			}
			c.Close()
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if a, b := <-ids, <-ids; a != 1 || b != 3 {
				t.Fatalf("refused-stream retry changed channel/IDs:%d,%d", a, b)
			}
		})
	}
}

func TestCONNECTUsesItsOwnChromePriority(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	config := cert.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	cert.Close()
	config.NextProtos = []string{"h2"}
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	previous := proxyRoots
	proxyRoots = roots
	defer func() { proxyRoots = previous }()
	seen := make(chan peerh2.PriorityParam, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, len(peerh2.ClientPreface))
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		fr := peerh2.NewFramer(c, c)
		fr.WriteSettings()
		for {
			f, e := fr.ReadFrame()
			if e != nil {
				return
			}
			switch f := f.(type) {
			case *peerh2.SettingsFrame:
				if !f.IsAck() {
					fr.WriteSettingsAck()
				}
			case *peerh2.HeadersFrame:
				seen <- f.Priority
				fr.WriteHeaders(peerh2.HeadersFrameParam{StreamID: f.StreamID, EndHeaders: true, BlockFragment: []byte{0x88}})
			}
		}
	}()
	u, _ := url.Parse("https://" + ln.Addr().String())
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile, _ = profile.Get("chrome_155_macos")
	c, err := d.DialContext(context.Background(), "tcp", "echo.netfp.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	d.CloseIdleProxyConnections()
	<-done
	select {
	case priority := <-seen:
		if !priority.Exclusive || priority.StreamDep != 0 || priority.Weight != 146 {
			t.Fatalf("CONNECT priority:%+v", priority)
		}
	default:
		t.Fatal("no CONNECT HEADERS")
	}
}

func TestACONNECTsWriteDeadlineEndsItsStreamAlone(t *testing.T) {
	via, _, _ := ownedH2Proxy(t, "")
	u, _ := url.Parse(via.URL)
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile, _ = profile.Get("chrome_155_macos")
	defer d.CloseIdleProxyConnections()
	dial := func() net.Conn {
		t.Helper()
		c, err := d.DialContext(context.Background(), "tcp", "echo.netfp.test:443")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	a, b := dial(), dial()
	if err := a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := a.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write after its deadline: %v", err)
	}
	// The other stream of the proxy's connection goes on.
	if _, err := b.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 4)
	if _, err := io.ReadFull(b, out); err != nil || string(out) != "ping" {
		t.Fatalf("echo %q, %v", out, err)
	}
}

// goingAwayProxy is a proxy's HTTP/2 connection whose every request is
// answered by GOAWAY before it was read: one the client may send again.
func goingAwayProxy(t *testing.T) net.Conn {
	t.Helper()
	conn, _ := countingGoingAwayProxy(t)
	return conn
}

// countingGoingAwayProxy is goingAwayProxy and how many requests it went
// away on.
func countingGoingAwayProxy(t *testing.T) (net.Conn, *atomic.Int32) {
	t.Helper()
	asked := new(atomic.Int32)
	// Over loopback TCP, not net.Pipe: each side writes its preface before it
	// reads the other's, which only a buffered connection lets them both do.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer server.Close()
		preface := make([]byte, len(peerh2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			return
		}
		fr := peerh2.NewFramer(server, server)
		if err := fr.WriteSettings(); err != nil {
			return
		}
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *peerh2.SettingsFrame:
				if !f.IsAck() {
					_ = fr.WriteSettingsAck()
				}
			case *peerh2.HeadersFrame:
				asked.Add(1)
				_ = fr.WriteGoAway(0, peerh2.ErrCodeNo, nil)
			}
		}
	}()
	t.Cleanup(func() { _ = client.Close() })
	return client, asked
}

// answeringProxy is a proxy's HTTP/2 connection, over loopback TCP, whose
// every forwarded request is answered 200 "proxied", and what it was asked:
// the method, the authority and path, and the body of each.
func answeringProxy(t *testing.T) (net.Conn, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var asked []string
	var prior http.Protocols
	prior.SetUnencryptedHTTP2(true)
	server := &http.Server{Protocols: &prior, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		asked = append(asked, r.Method+" "+r.Host+r.URL.Path+" "+string(body))
		mu.Unlock()
		_, _ = io.WriteString(w, "proxied")
	})}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(asked)
	}
}

// pooledProxy is a dialer of chrome_155_macos with conn adopted into its
// pool, idle.
func pooledProxy(t *testing.T, conn net.Conn) (*connectDialer, *proxyH2Conn) {
	t.Helper()
	u, _ := url.Parse("https://proxy.test:8443")
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile = shippedProfile(t, "chrome_155_macos")
	p, err := d.adoptProxyH2(conn)
	if err != nil {
		t.Fatal(err)
	}
	d.releaseProxyH2(p)
	t.Cleanup(d.CloseIdleProxyConnections)
	return d, p
}

type fallbackRecorder struct {
	mu    sync.Mutex
	asked []string
}

func (f *fallbackRecorder) RoundTrip(req *fhttp.Request) (*fhttp.Response, error) {
	body := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
	}
	f.mu.Lock()
	f.asked = append(f.asked, req.Method+" "+body)
	f.mu.Unlock()
	return &fhttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("fallback")), Request: req}, nil
}

func TestAForwardedRequestTheProxysHTTP2ConnectionWillNotTakeGoesOnHTTP1(t *testing.T) {
	d, _ := pooledProxy(t, goingAwayProxy(t))
	fallback := &fallbackRecorder{}
	req, _ := fhttp.NewRequest("POST", "http://www.example.com/x", strings.NewReader("body"))
	res, err := d.RoundTripProxyHTTP(req, fallback)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("%v %v", res, err)
	}
	if len(fallback.asked) != 1 || fallback.asked[0] != "POST body" {
		t.Errorf("fallback asked %q", fallback.asked)
	}
}

// replayable is a forwarded POST of body whose GetBody gives it again, saying
// first to then which time it is asked: the moment the request goes again.
func replayable(t *testing.T, body string, then func(n int) error) *fhttp.Request {
	t.Helper()
	req, err := fhttp.NewRequest("POST", "http://www.example.com/x", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	req.GetBody = func() (io.ReadCloser, error) {
		n++
		if err := then(n); err != nil {
			return nil, err
		}
		return io.NopCloser(strings.NewReader(body)), nil
	}
	return req
}

func TestAForwardedRequestThatCannotBeSentAgainIsRefused(t *testing.T) {
	// The transport has the body again (GetBody's first call) to ask the pool
	// for another connection; the pool has none, and the request goes back
	// for HTTP/1.1 only with the body again (the second).
	d, _ := pooledProxy(t, goingAwayProxy(t))
	fallback := &fallbackRecorder{}
	req, _ := fhttp.NewRequest("POST", "http://www.example.com/x", strings.NewReader("body"))
	req.GetBody = nil
	if _, err := d.RoundTripProxyHTTP(req, fallback); err == nil || !strings.Contains(err.Error(), "cannot retry") {
		t.Errorf("a body that cannot be had again: %v", err)
	}
	gone := errors.New("the body is gone")
	d, _ = pooledProxy(t, goingAwayProxy(t))
	req = replayable(t, "body", func(n int) error {
		if n == 2 {
			return gone
		}
		return nil
	})
	if _, err := d.RoundTripProxyHTTP(req, fallback); !errors.Is(err, gone) {
		t.Errorf("a body that fails to be had again: %v", err)
	}
	if len(fallback.asked) != 0 {
		t.Errorf("fallback asked %q", fallback.asked)
	}
}

func TestAForwardedBodyIsHadAgainOnlyWhenItCanBe(t *testing.T) {
	plain, _ := fhttp.NewRequest("GET", "http://www.example.com/", nil)
	if got, err := proxyReplay(plain); got != plain || err != nil {
		t.Errorf("no body: %v, %v", got, err)
	}
	once, _ := fhttp.NewRequest("POST", "http://www.example.com/", strings.NewReader("x"))
	once.GetBody = nil
	if _, err := proxyReplay(once); !errors.Is(err, http2ErrNoCachedConn) {
		t.Errorf("a body without GetBody: %v", err)
	}
	gone := errors.New("gone")
	failing, _ := fhttp.NewRequest("POST", "http://www.example.com/", strings.NewReader("x"))
	failing.GetBody = func() (io.ReadCloser, error) { return nil, gone }
	if _, err := proxyReplay(failing); !errors.Is(err, gone) {
		t.Errorf("GetBody failing: %v", err)
	}
	again, _ := fhttp.NewRequest("POST", "http://www.example.com/", strings.NewReader("x"))
	copied, err := proxyReplay(again)
	if err != nil || copied == again {
		t.Fatalf("%v %v", copied, err)
	}
	if b, _ := io.ReadAll(copied.Body); string(b) != "x" {
		t.Errorf("body again %q", b)
	}
}

func TestAForwardedRequestGoesOnAConnectionTheProxyGaveWhileItWaited(t *testing.T) {
	d, _ := pooledProxy(t, goingAwayProxy(t))
	second, asked := countingGoingAwayProxy(t)
	fallback := &fallbackRecorder{}
	// As the first connection turns the request away, another comes: the
	// request goes on it, and when that one turns it away too, on HTTP/1.1.
	req := replayable(t, "body", func(n int) error {
		if n == 2 {
			p, err := d.adoptProxyH2(second)
			if err != nil {
				return err
			}
			d.releaseProxyH2(p)
		}
		return nil
	})
	if res, err := d.RoundTripProxyHTTP(req, fallback); err != nil || res.StatusCode != 200 {
		t.Fatalf("%v %v", res, err)
	}
	if asked.Load() != 1 || len(fallback.asked) != 1 || fallback.asked[0] != "POST body" {
		t.Errorf("the second connection was asked %d times, the fallback %q", asked.Load(), fallback.asked)
	}
	// One whose body cannot be had again the second time is refused then.
	d, _ = pooledProxy(t, goingAwayProxy(t))
	third := goingAwayProxy(t)
	gone := errors.New("the body is gone")
	req = replayable(t, "body", func(n int) error {
		switch n {
		case 2:
			p, err := d.adoptProxyH2(third)
			if err == nil {
				d.releaseProxyH2(p)
			}
			return err
		case 4:
			return gone
		}
		return nil
	})
	if _, err := d.RoundTripProxyHTTP(req, fallback); !errors.Is(err, gone) {
		t.Errorf("second replay: %v", err)
	}
}

func TestAForwardedRequestIsAnsweredOnAConnectionTheProxyGaveWhileItWaited(t *testing.T) {
	d, _ := pooledProxy(t, goingAwayProxy(t))
	second, asked := answeringProxy(t)
	fallback := &fallbackRecorder{}
	// The first connection turns the request away; another comes while it
	// waits for the dial, and answers it there, with its body: HTTP/1.1 is
	// not asked.
	req := replayable(t, "body", func(n int) error {
		if n == 2 {
			p, err := d.adoptProxyH2(second)
			if err != nil {
				return err
			}
			d.releaseProxyH2(p)
		}
		return nil
	})
	res, err := d.RoundTripProxyHTTP(req, fallback)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "proxied" {
		t.Errorf("answered %d %q, want the second connection's", res.StatusCode, body)
	}
	if got := asked(); len(got) != 1 || got[0] != "POST www.example.com/x body" {
		t.Errorf("the second connection was asked %q", got)
	}
	if len(fallback.asked) != 0 {
		t.Errorf("HTTP/1.1 was asked %q", fallback.asked)
	}
}

func TestOnlyATLSConnectionThatNegotiatedH2SpeaksIt(t *testing.T) {
	plain, other := net.Pipe()
	defer plain.Close()
	defer other.Close()
	if speaksH2(plain) {
		t.Error("a connection with no TLS speaks HTTP/2")
	}
}

func TestAWaitForTheProxysDialEndsWithTheRequest(t *testing.T) {
	u, _ := url.Parse("https://proxy.test:8443")
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile = shippedProfile(t, "chrome_155_macos")
	if err := d.lockProxyDial(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.unlockProxyDial()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := fhttp.NewRequestWithContext(ctx, "GET", "http://www.example.com/", nil)
	if _, err := d.RoundTripProxyHTTP(req, &fallbackRecorder{}); !errors.Is(err, context.Canceled) {
		t.Errorf("forwarding: %v", err)
	}
	if _, err := d.chromeTunnel(ctx, "tcp", "www.example.com:443"); !errors.Is(err, context.Canceled) {
		t.Errorf("tunnelling: %v", err)
	}
}

func TestAProxyPoolSaysWhenItHasNoConnectionForARequest(t *testing.T) {
	u, _ := url.Parse("https://proxy.test:8443")
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile = shippedProfile(t, "chrome_155_macos")
	req, _ := fhttp.NewRequest("GET", "http://www.example.com/", nil)
	if _, err := (proxyH2RoundTripper{d}).RoundTrip(req); !errors.Is(err, http2ErrNoCachedConn) {
		t.Errorf("an empty pool: %v", err)
	}
	broke := errors.New("adopting failed")
	if _, err := (proxyRoundTripError{broke}).RoundTrip(req); err != broke {
		t.Errorf("a failed adoption: %v", err)
	}
	// Asked for a connection by a request that leased none of this pool.
	if _, err := d.proxyPool.GetClientConn(req, ""); !errors.Is(err, http2ErrNoCachedConn) {
		t.Errorf("no lease: %v", err)
	}
	other := newConnectDialer(u, time.Second, nil, nil)
	leased := req.WithContext(context.WithValue(req.Context(), proxyLeaseKey{}, &proxyLease{d: other}))
	if _, err := d.proxyPool.GetClientConn(leased, ""); !errors.Is(err, http2ErrNoCachedConn) {
		t.Errorf("another pool's lease: %v", err)
	}
}

func TestARequestThatEndsBeforeTheProxyAnswersLetsTheConnectionGo(t *testing.T) {
	d, p := pooledProxy(t, goingAwayProxy(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := fhttp.NewRequestWithContext(ctx, "GET", "http://www.example.com/", nil)
	if _, err := d.RoundTripProxyHTTP(req, &fallbackRecorder{}); !errors.Is(err, context.Canceled) {
		t.Errorf("forwarding: %v", err)
	}
	d.proxyPool.mu.Lock()
	active := p.active
	d.proxyPool.mu.Unlock()
	if active != 0 {
		t.Errorf("%d leases left", active)
	}
}

func TestACONNECTTheProxysConnectionTurnsAwayFails(t *testing.T) {
	d, _ := pooledProxy(t, goingAwayProxy(t))
	// The tunnel's body (its writer) cannot be had again: the dial fails, at
	// once, rather than waiting for a tunnel that will not open.
	if _, err := d.chromeTunnel(context.Background(), "tcp", "www.example.com:443"); err == nil || !strings.Contains(err.Error(), "GOAWAY") {
		t.Errorf("CONNECT: %v", err)
	}
}

func TestAProxyConnectionIsAdoptedOnlyAsItsProfileAllows(t *testing.T) {
	u, _ := url.Parse("https://proxy.test:8443")
	d := newConnectDialer(u, time.Second, nil, nil)
	other := shippedProfile(t, "chrome_155_macos").Clone()
	*other.EngineMajor = 2
	d.identity.profile = other
	client, server := net.Pipe()
	defer server.Close()
	if _, err := d.adoptProxyH2(client); err == nil || !strings.Contains(err.Error(), "engine_major 2") {
		t.Errorf("another engine's profile: %v", err)
	}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Error("the connection was left open")
	}
	tlsConn := utls.Client(server, &utls.Config{})
	if _, err := d.ProxyHTTP2Protocol(tlsConn).RoundTrip(mustRequest(t, "http://www.example.com/")); err == nil ||
		!strings.Contains(err.Error(), "engine_major 2") {
		t.Errorf("the forwarding transport's HTTP/2: %v", err)
	}
	// A connection the preface cannot be written to.
	d.identity.profile = shippedProfile(t, "chrome_155_macos")
	closed, peer := net.Pipe()
	_ = peer.Close()
	if _, err := d.adoptProxyH2(closed); err == nil {
		t.Error("adopted a connection the preface cannot be written to")
	}
	// A profile that says nothing of push takes pushes as the transport does.
	silent := shippedProfile(t, "chrome_155_macos").Clone()
	silent.HTTP2.Settings = slices.DeleteFunc(slices.Clone(silent.HTTP2.Settings), func(s profile.Setting) bool { return s.ID == 2 })
	d.identity.profile = silent
	p, err := d.adoptProxyH2(goingAwayProxy(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.transport.PushHandler == nil {
		t.Error("no push handler without an ENABLE_PUSH setting")
	}
}

func TestAProxyThatRefusesACONNECTOverHTTP2SaysSo(t *testing.T) {
	via, _, _ := ownedH2Proxy(t, "")
	u, _ := url.Parse(via.URL)
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile, _ = profile.Get("chrome_155_macos")
	defer d.CloseIdleProxyConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "elsewhere.test:443")
	if err == nil || !strings.Contains(err.Error(), "proxy responded with non 200 code: 403") {
		t.Errorf("CONNECT: %v", err)
	}
}

func TestADialThatEndsAsTheProxyAnswersItsCONNECTEndsWithIt(t *testing.T) {
	via, _, _ := ownedH2Proxy(t, "")
	u, _ := url.Parse(via.URL)
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile = shippedProfile(t, "chrome_155_macos")
	defer d.CloseIdleProxyConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := connectAnswered
	t.Cleanup(func() { connectAnswered = original })
	connectAnswered = cancel
	if _, err := d.DialContext(ctx, "tcp", "echo.netfp.test:443"); !errors.Is(err, context.Canceled) {
		t.Errorf("a dial that ended as the tunnel opened: %v", err)
	}
	// The next dial, on the same connection, opens its tunnel.
	connectAnswered = original
	c, err := d.DialContext(context.Background(), "tcp", "echo.netfp.test:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestAnHTTP1ProxyAProfileShakesHandsWithIsAskedForATunnelOverHTTP1(t *testing.T) {
	// A proxy that negotiates no HTTP/2 is asked as HTTP/1.1 is: a refusal is
	// the dial's error, and the connection to the proxy goes.
	via := startConnectProxy(t, true, func(int32) string {
		return "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
	})
	roots := x509.NewCertPool()
	roots.AddCert(via.server.Certificate())
	original := proxyRoots
	t.Cleanup(func() { proxyRoots = original })
	proxyRoots = roots
	u, _ := url.Parse(via.url())
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile = shippedProfile(t, "chrome_155_macos")
	if _, err := d.DialContext(context.Background(), "tcp", "example.test:443"); err == nil || !strings.Contains(err.Error(), "407") {
		t.Errorf("a refused tunnel: %v", err)
	}
}

func TestACONNECTOverAProxysHTTP2IsLoggedWithItsAnswer(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "page") }))
	defer origin.Close()
	via, _, _ := ownedH2Proxy(t, origin.URL)
	book, log := newLogBook(slog.LevelDebug)
	c := newTestClient(t, WithProxy(via.URL), WithInsecureSkipVerify(), WithLogger(log))
	if _, err := c.Get(origin.URL + "/"); err != nil {
		t.Fatal(err)
	}
	if answered := book.with(t, "proxy answer"); len(answered) != 1 {
		t.Errorf("proxy answers logged: %d of %v", len(answered), book.messages(t))
	}
}

// writesNoData is a connection to a proxy that takes the TLS handshake's
// records and fails the first record of application data: the HTTP/2
// preface of a connection the proxy has just agreed to.
type writesNoData struct{ net.Conn }

func (c writesNoData) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == 0x17 {
		return 0, errors.New("the proxy hung up")
	}
	return c.Conn.Write(p)
}

type noDataTap struct{}

func (noDataTap) Dialed(conn net.Conn, _ time.Time) net.Conn           { return writesNoData{conn} }
func (noDataTap) QUIC(net.Addr, net.Addr, time.Time) conntap.Datagrams { return nil }
func (noDataTap) Used(net.Conn)                                        {}

func TestAProxysHTTP2ConnectionThePrefaceCannotBeWrittenToFailsTheDial(t *testing.T) {
	via, _, _ := ownedH2Proxy(t, "")
	u, _ := url.Parse(via.URL)
	d := newConnectDialer(u, time.Second, nil, nil)
	d.identity.profile = shippedProfile(t, "chrome_155_macos")
	defer d.CloseIdleProxyConnections()
	ctx := conntap.With(context.Background(), noDataTap{})
	if _, err := d.DialContext(ctx, "tcp", "echo.netfp.test:443"); err == nil || !strings.Contains(err.Error(), "hung up") {
		t.Errorf("dial: %v", err)
	}
	// Nothing is left in the pool, nor held: the next dial dials.
	if p := d.takeProxyH2(); p != nil {
		t.Errorf("a connection was kept: %+v", p)
	}
}
