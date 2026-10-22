package tlsforge

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
)

// Literal RFC9204 instructions and field sections come from this raw peer,
// independent of the production table/encoder. Test the public Client.Do path.
func TestDynamicQPACKResponseOnProductionQUIC(t *testing.T) {
	for _, cancelBlocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "unblock-and-ack", true: "cancel-blocked"}[cancelBlocked], func(t *testing.T) {
			seed := httptest.NewTLSServer(nil)
			cert := seed.TLS.Certificates[0]
			seed.Close()
			ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 4*time.Second)
			defer stop()
			defer ln.Close()
			blocked := make(chan struct{})
			release := make(chan struct{})
			feedback := make(chan byte, 1)
			feedbackIDs := make(chan quic.StreamID, 1)
			peerDone := make(chan error, 1)
			go func() {
				conn, e := ln.Accept(ctx)
				if e != nil {
					peerDone <- e
					return
				}
				defer conn.CloseWithError(0, "")
				go func() {
					for {
						str, e := conn.AcceptUniStream(ctx)
						if e != nil {
							return
						}
						go func() {
							typ, e := quicvarint.Read(quicvarint.NewReader(str))
							if e != nil {
								return
							}
							if typ == 3 {
								b := make([]byte, 1)
								if _, e = io.ReadFull(str, b); e == nil {
									feedbackIDs <- str.StreamID()
									feedback <- b[0]
								}
							}
						}()
					}
				}()
				control, e := conn.OpenUniStreamSync(ctx)
				if e != nil {
					peerDone <- e
					return
				}
				if _, e = control.Write([]byte{0, 4, 0}); e != nil {
					peerDone <- e
					return
				}
				enc, e := conn.OpenUniStreamSync(ctx)
				if e != nil {
					peerDone <- e
					return
				}
				if _, e = enc.Write([]byte{2}); e != nil {
					peerDone <- e
					return
				}
				str, e := conn.AcceptStream(ctx)
				if e != nil {
					peerDone <- e
					return
				}
				r := quicvarint.NewReader(str)
				_, e = quicvarint.Read(r)
				if e != nil {
					peerDone <- e
					return
				}
				n, e := quicvarint.Read(r)
				if e != nil {
					peerDone <- e
					return
				}
				if _, e = io.CopyN(io.Discard, str, int64(n)); e != nil {
					peerDone <- e
					return
				}
				// HEADERS requires insertion1. It must block until that insertion arrives.
				if _, e = str.Write([]byte{1, 4, 2, 0, 0xd9, 0x80}); e != nil {
					peerDone <- e
					return
				}
				close(blocked)
				select {
				case <-release:
				case <-ctx.Done():
					peerDone <- ctx.Err()
					return
				}
				if !cancelBlocked {
					_, e = enc.Write([]byte{0x3f, 0x21, 0x47, 'x', '-', 'p', 'r', 'o', 'o', 'f', 2, 'y', 'e'})
					if e != nil {
						peerDone <- e
						return
					}
					_, e = str.Write([]byte{0, 2, 'o', 'k'})
					if e == nil {
						e = str.Close()
					}
					if e != nil {
						peerDone <- e
						return
					}
				}
				select {
				case <-conn.Context().Done():
					peerDone <- nil
				case <-ctx.Done():
					peerDone <- ctx.Err()
				}
			}()
			client := newTestClient(t, WithProfile("chrome_155_macos"), WithTimeout(3*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			requestContext, cancel := context.WithCancel(ctx)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				res, e := client.Do(&Request{Context: requestContext, URL: "https://" + ln.Addr().String() + "/"})
				if e == nil && (res.Status != 200 || string(res.Body) != "ok" || !func() bool {
					for k, v := range res.Header {
						if strings.EqualFold(k, "x-proof") && len(v) == 1 && v[0] == "ye" {
							return true
						}
					}
					return false
				}()) {
					e = errors.New("incorrect dynamic response fields/body")
				}
				result <- e
			}()
			select {
			case <-blocked:
			case e := <-result:
				t.Fatalf("premature response: %v", e)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case e := <-result:
				t.Fatalf("returned before insertion: %v", e)
			case <-time.After(20 * time.Millisecond):
			}
			want := byte(0x80)
			if cancelBlocked {
				cancel()
				want = 0x40
			}
			close(release)
			select {
			case e := <-result:
				if cancelBlocked && !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				if !cancelBlocked && e != nil {
					t.Fatal(e)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case b := <-feedback:
				if b != want {
					t.Fatalf("QPACK feedback %x want %x", b, want)
				}
			case <-ctx.Done():
				t.Fatal("missing QPACK ACK/cancellation")
			}
			if id := <-feedbackIDs; id != 6 {
				t.Fatalf("profile decoder-first stream ID=%d want6", id)
			}
			client.Close()
			select {
			case e := <-peerDone:
				if e != nil {
					t.Fatal(e)
				}
			case <-ctx.Done():
				t.Fatal("peer leaked")
			}
		})
	}
}
