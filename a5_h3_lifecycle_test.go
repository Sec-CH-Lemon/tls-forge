package tlsforge

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	tc "github.com/igor-lemon/tls-client"
	utls "github.com/igor-lemon/utls"
)

func TestEvictedQUICConnectionsAreClosed(t *testing.T) {
	for _, credentials := range []string{"include", "omit"} {
		for _, early := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/close-before-body=%v", credentials, early), func(t *testing.T) {
				seed := httptest.NewTLSServer(nil)
				cert := seed.TLS.Certificates[0]
				seed.Close()
				udp, tcp := udpAndTCP(t)
				_ = tcp.Close()
				var mu sync.Mutex
				var peers []*quic.Conn
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				finish := func() { once.Do(func() { close(release) }) }
				defer finish()
				server := &http3.Server{TLSConfig: &utls.Config{Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, EnableDatagrams: true, QUICConfig: &quic.Config{EnableDatagrams: true},
					ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
						mu.Lock()
						peers = append(peers, c)
						mu.Unlock()
						return ctx
					},
					Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
						w.Header().Set("Cache-Control", "no-store")
						w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
						w.Header().Set("Access-Control-Allow-Credentials", "true")
						w.Header().Set("Content-Length", "2")
						if r.URL.Path == "/hold" {
							w.WriteHeader(200)
							w.(fhttp.Flusher).Flush()
							close(entered)
							<-release
						}
						_, _ = io.WriteString(w, "ok")
					}),
				}
				go func() { _ = server.Serve(udp) }()
				t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })
				c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"http.max_site_pools": 1})), WithTransportOption(tc.WithProtocolRacing()))
				request := func(page, path string) error {
					res, err := c.Do(&Request{URL: "https://" + udp.LocalAddr().String() + path, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://" + page + "/", Credentials: credentials}})
					if err == nil && string(res.Body) != "ok" {
						return fmt.Errorf("unexpected body %q", res.Body)
					}
					return err
				}
				done := make(chan error, 1)
				go func() { done <- request("a.example", "/hold") }()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("H3 request never arrived")
				}
				if err := request("b.example", "/"); err != nil {
					t.Fatal(err)
				}
				if early {
					_ = c.Close()
				}
				finish()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if !early {
					_ = c.Close()
				}
				mu.Lock()
				all := append([]*quic.Conn(nil), peers...)
				mu.Unlock()
				if len(all) != 2 {
					t.Fatalf("%d QUIC connections, want two partitions", len(all))
				}
				for _, peer := range all {
					select {
					case <-peer.Context().Done():
					case <-time.After(time.Second):
						t.Fatal("evicted QUIC connection survived completion/Close")
					}
				}
				t.Log("RESULT: 0 of 2 QUIC connections open after completion/Close")
			})
		}
	}
}
