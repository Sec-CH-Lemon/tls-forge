package tlsforge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	fhttp "github.com/igor-lemon/fhttp"
	tc "github.com/igor-lemon/tls-client"
	"golang.org/x/net/dns/dnsmessage"
)

func TestA6SemanticGateEveryClientEntryBeforeIO(t *testing.T) {
	var sockets, handshakes, requests, proxy, dials, datagrams, builds, constructors atomic.Int32
	originalConstructor := newInnerClient
	t.Cleanup(func() { newInnerClient = originalConstructor })
	newInnerClient = func(logger tc.Logger, opts ...tc.HttpClientOption) (tc.HttpClient, error) {
		constructors.Add(1)
		return originalConstructor(logger, opts...)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); _, _ = w.Write([]byte("ok")) }))
	server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			sockets.Add(1)
		}
	}
	server.StartTLS()
	udp, err := net.ListenPacket("udp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		var b [2048]byte
		for {
			_, _, e := udp.ReadFrom(b[:])
			if e != nil {
				return
			}
			datagrams.Add(1)
		}
	}()
	defer func() { _ = udp.Close(); <-udpDone }()
	defer server.Close()
	// GetConfigForClient observes the actual ClientHello, even a failing TLS
	// handshake. This is separate from TCP acceptance and HTTP request counts.
	server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { handshakes.Add(1); return nil, nil }
	dns := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		if q.Type == dnsmessage.TypeA {
			return []dnsRecord{{name: q.Name.String(), ttl: 1, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
		}
		return nil, 0, 0
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			proxy.Add(1)
			_ = c.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	original, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"frame", "window", "duplicate", "stream", "dependency", "connection", "h3"} {
		for _, entry := range []string{"value", "file", "Fresh", "Do"} {
			for _, scheme := range []string{"direct", "http", "https", "socks5", "raw-dial", "quic"} {
				t.Run(variant+"/"+entry+"/"+scheme, func(t *testing.T) {
					p := original.Clone()
					p.Name = "neutral-entry-matrix"
					switch variant {
					case "frame":
						p.HTTP2.Settings = []profile.Setting{{ID: 5, Value: 1}}
					case "window":
						p.HTTP2.Settings = []profile.Setting{{ID: 4, Value: 1 << 31}}
					case "duplicate":
						p.HTTP2.Settings = []profile.Setting{{ID: 4, Value: 1}, {ID: 4, Value: 2}}
					case "stream":
						p.HTTP2.StreamID = 2
					case "dependency":
						p.HTTP2.HeaderPriority.DependsOn = 1
					case "connection":
						p.HTTP2.ConnectionFlow = 1<<31 - 1
					case "h3":
						p.Behavior["h3.grease_payload_lengths"] = json.RawMessage(`[4097]`)
					}
					opts := []Option{WithProfileValue(p), WithDNSServer(dns.addr), WithInsecureSkipVerify(), WithTimeout(300 * time.Millisecond)}
					if scheme == "http" || scheme == "https" || scheme == "socks5" {
						opts = append(opts, WithProxy(scheme+"://"+listener.Addr().String()))
					}
					opts = append(opts, WithTransportOption(tc.WithTransportWrapper(func(tr fhttp.RoundTripper) fhttp.RoundTripper { builds.Add(1); return tr })))
					if scheme == "quic" {
						opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
					}
					if scheme == "raw-dial" {
						opts = append(opts, WithTransportOption(tc.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
							dials.Add(1)
							var dialer net.Dialer
							return dialer.DialContext(ctx, network, server.Listener.Addr().String())
						})))
					}
					beforeBuild, beforeConstructor := builds.Load(), constructors.Load()
					if entry == "file" {
						raw, _ := json.Marshal(p)
						name := filepath.Join(t.TempDir(), "renamed.json")
						if err := os.WriteFile(name, raw, 0600); err != nil {
							t.Fatal(err)
						}
						opts[0] = WithProfile(name)
					}
					if entry == "Fresh" || entry == "Do" {
						opts[0] = WithProfileValue(original)
					}
					c, err := New(opts...)
					if err == nil && (entry == "Fresh" || entry == "Do") {
						beforeBuild, beforeConstructor = builds.Load(), constructors.Load()
						c.profile = p
						if entry == "Fresh" {
							var next *Client
							next, err = c.Fresh()
							if next != nil {
								_ = next.Close()
							}
						} else {
							_, err = c.Get(server.URL)
						}
					}
					if c != nil {
						_ = c.Close()
					}
					if builds.Load() != beforeBuild || constructors.Load() != beforeConstructor {
						t.Error("invalid profile reached transport construction")
					}
					if err == nil || !strings.Contains(err.Error(), p.Name) {
						t.Errorf("entry accepted bad profile: %v", err)
					}
				})
			}
		}
	}
	if got := fmt.Sprint(dns.queries(), sockets.Load(), handshakes.Load(), requests.Load(), proxy.Load(), dials.Load(), datagrams.Load()); len(dns.queries()) != 0 || sockets.Load() != 0 || handshakes.Load() != 0 || requests.Load() != 0 || proxy.Load() != 0 || dials.Load() != 0 || datagrams.Load() != 0 {
		t.Fatal("I/O before rejection:", got)
	}
	// Positive control proves that the DNS/TCP/TLS/origin counters observe
	// the production path rather than just remaining zero on an inert fixture.
	valid, err := New(WithProfileValue(original), WithDNSServer(dns.addr), WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	if _, err = valid.Get("https://semantic-control.test:" + port + "/"); err != nil {
		t.Fatal(err)
	}
	if len(dns.queries()) == 0 || sockets.Load() == 0 || handshakes.Load() == 0 || requests.Load() != 1 {
		t.Fatal("I/O counter positive control failed")
	}
	packet, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = packet.Write([]byte{1})
	_ = packet.Close()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for datagrams.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if datagrams.Load() != 1 {
		t.Fatal("UDP observer positive control failed", datagrams.Load())
	}
	t.Log("RESULT: rejection DNS=0 TCP=0 UDP-datagrams=0 proxy=0 TLS-ClientHello=0 origin=0 constructors=0;168 entry/route variants; actual DNS/TCP/TLS/HTTP and UDP observer positive controls")
}

func TestA6AcceptedProfileSnapshotCannotBeMutated(t *testing.T) {
	address, _, done, _ := a6RawPeer(t)
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	expected := p.Clone()
	c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.HTTP2.Settings[0].Value = 1
	p.HTTP2.StreamID = 2
	p.Behavior["h3.grease_payload_lengths"] = json.RawMessage(`[4097]`)
	view := c.Profile()
	view.HTTP2.Settings[0].Value = 0
	view.HTTP2.ConnectionFlow = 1 << 31
	fresh, err := c.Fresh()
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err = fresh.Get(address); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || got.settings[0] != expected.HTTP2.Settings[0] || got.flow != expected.HTTP2.ConnectionFlow || got.stream != 1 {
		t.Fatalf("caller changed accepted snapshot: %+v", got)
	}
}
