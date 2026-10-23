package tlsforge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
	peerh2 "golang.org/x/net/http2"
)

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
				http.Error(w, "owned target required", 403)
				return
			}
			up, err := net.DialTimeout("tcp", r.Host, time.Second)
			if err != nil {
				http.Error(w, err.Error(), 502)
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
			c := newTestClient(t, WithProxy("https://"+ln.Addr().String()), WithTimeout(time.Second))
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
