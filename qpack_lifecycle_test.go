package tlsforge

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
)

// The independent peer completes a static-only exchange and observes every
// received client critical-stream type until the connection ends. Eager is the
// positive wire control: the same JSON-selected production path must expose
// both prefixes there, while deferred/lazy expose neither without instructions.
func TestQPACKCriticalStreamsFollowJSONLifecycle(t *testing.T) {
	for _, mode := range []string{"deferred", "eager", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			seed := httptest.NewTLSServer(nil)
			cert := seed.TLS.Certificates[0]
			seed.Close()
			ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			defer ln.Close()
			type result struct {
				streams map[uint64]quic.StreamID
				err     error
			}
			done := make(chan result, 1)
			go func() {
				observed := map[uint64]quic.StreamID{}
				finish := func(err error) { done <- result{streams: observed, err: err} }
				conn, e := ln.Accept(ctx)
				if e != nil {
					finish(e)
					return
				}
				defer conn.CloseWithError(0, "")
				var mu sync.Mutex
				var readers sync.WaitGroup
				watch := make(chan struct{})
				go func() {
					defer close(watch)
					for {
						str, e := conn.AcceptUniStream(ctx)
						if e != nil {
							return
						}
						readers.Add(1)
						go func() {
							defer readers.Done()
							kind, e := quicvarint.Read(quicvarint.NewReader(str))
							if e == nil {
								mu.Lock()
								observed[kind] = str.StreamID()
								mu.Unlock()
							}
						}()
					}
				}()
				control, e := conn.OpenUniStreamSync(ctx)
				if e == nil {
					_, e = control.Write([]byte{0, 4, 0})
				}
				var str *quic.Stream
				if e == nil {
					str, e = conn.AcceptStream(ctx)
				}
				if e == nil {
					reader := quicvarint.NewReader(str)
					for {
						kind, er := quicvarint.Read(reader)
						if er != nil {
							e = er
							break
						}
						n, er := quicvarint.Read(reader)
						if er != nil {
							e = er
							break
						}
						if n > 1<<20 {
							e = fmt.Errorf("unbounded request frame: %d", n)
							break
						}
						if _, er = io.CopyN(io.Discard, str, int64(n)); er != nil {
							e = er
							break
						}
						if kind == 1 {
							break
						}
					}
				}
				if e == nil {
					_, e = str.Write([]byte{1, 3, 0, 0, 0xd9, 0, 2, 'o', 'k'})
				}
				if e == nil {
					e = str.Close()
				}
				if e != nil {
					_ = conn.CloseWithError(0, "peer failure")
				}
				select {
				case <-conn.Context().Done():
				case <-ctx.Done():
					if e == nil {
						e = ctx.Err()
					}
				}
				<-watch
				readers.Wait()
				finish(e)
			}()
			p := policyFile(t, map[string]any{"h3.qpack.streams": mode})
			c := newTestClient(t, WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(3*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			response, err := c.Do(&Request{URL: "https://" + ln.Addr().String() + "/cold"})
			if err != nil || string(response.Body) != "ok" {
				t.Fatalf("static response %v: %v", response, err)
			}
			_ = c.Close()
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatal(got.err)
				}
				if _, ok := got.streams[0]; !ok {
					t.Fatal("no actual client control stream")
				}
				_, encoder := got.streams[2]
				_, decoder := got.streams[3]
				if mode == "eager" {
					if !encoder || !decoder || got.streams[3] != 6 || got.streams[2] != 10 {
						t.Fatalf("eager wire control: %v", got.streams)
					}
				} else if encoder || decoder {
					t.Fatalf("premature critical streams for %s: %v", mode, got.streams)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("owned peer did not finish")
			}
		})
	}
}
