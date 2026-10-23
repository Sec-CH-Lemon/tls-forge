package tlsforge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
)

// A raw QUIC peer drives Client.Do, not the candidate HTTP/3 parser. All retry
// counters are accepted handshakes that received an actual request HEADERS.
func TestQPACKErrorCloseAndRetryOnProductionQUIC(t *testing.T) {
	for _, tt := range []struct {
		name, method, space, attempts string
		want, code                    int
		cancel                        bool
	}{
		{"transport-fin-three", "GET", "transport", "3", 3, 10, false},
		{"application-fin-one", "GET", "application", "1", 1, 260, false},
		{"bad-reference-three", "GET", "transport", "3", 3, 512, false},
		{"JSON-one-attempt", "GET", "transport", "1", 1, 512, false},
		{"non-idempotent-no-replay", "POST", "transport", "3", 1, 512, false},
		{"cancelled-no-replay", "GET", "transport", "3", 1, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			seed := httptest.NewTLSServer(nil)
			cert := seed.TLS.Certificates[0]
			seed.Close()
			ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			defer ln.Close()
			var mu sync.Mutex
			var seen []error
			peerDone := make(chan struct{})
			requestArrived := make(chan struct{}, 1)
			go func() {
				defer close(peerDone)
				for {
					conn, e := ln.Accept(ctx)
					if e != nil {
						return
					}
					// Keep critical streams open and send empty SETTINGS.
					control, e := conn.OpenUniStreamSync(ctx)
					if e != nil {
						return
					}
					if _, e = control.Write([]byte{0, 4, 0}); e != nil {
						return
					}
					str, e := conn.AcceptStream(ctx)
					if e != nil {
						return
					}
					r := quicvarint.NewReader(str)
					typ, e := quicvarint.Read(r)
					if e != nil || typ != 1 {
						return
					}
					n, e := quicvarint.Read(r)
					if e != nil {
						return
					}
					if _, e = io.CopyN(io.Discard, str, int64(n)); e != nil {
						return
					}
					select {
					case requestArrived <- struct{}{}:
					default:
					}
					if tt.cancel {
						<-conn.Context().Done()
					} else if tt.code == 512 {
						// Zero Required Insert Count with a forbidden dynamic reference.
						_, _ = str.Write([]byte{1, 4, 0, 0, 0xd9, 0x80})
						<-conn.Context().Done()
					} else {
						enc, e := conn.OpenUniStreamSync(ctx)
						if e != nil {
							return
						}
						_, _ = enc.Write([]byte{2})
						_ = enc.Close()
						<-conn.Context().Done()
					}
					mu.Lock()
					seen = append(seen, context.Cause(conn.Context()))
					mu.Unlock()
				}
			}()
			p, err := profile.Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			p.Name = "neutral-profile-name"
			p.Behavior["h3.retry_attempts"] = json.RawMessage(tt.attempts)
			// A malicious profile selecting POST must still not override replay safety.
			p.Behavior["h3.retry_methods"] = json.RawMessage(`["GET","HEAD","POST"]`)
			p.Behavior["h3.qpack.critical_close_space"], _ = json.Marshal(tt.space)
			if tt.space == "application" {
				p.Behavior["h3.qpack.critical_close_code"] = json.RawMessage(`260`)
			}
			client := newTestClient(t, WithProfileValue(p), WithTimeout(4*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			callCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, e := client.Do(&Request{Context: callCtx, URL: "https://" + ln.Addr().String() + "/", Method: tt.method, Body: []byte("replay-check")})
				result <- e
			}()
			if tt.cancel {
				select {
				case <-requestArrived:
					cancel()
				case <-ctx.Done():
					t.Fatal("no request")
				}
			}
			select {
			case err = <-result:
				if err == nil {
					t.Fatal("malformed response accepted")
				}
				if tt.cancel && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("request did not terminate")
			}
			client.Close()
			ln.Close()
			select {
			case <-peerDone:
			case <-ctx.Done():
				t.Fatal("peer did not terminate")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != tt.want {
				t.Fatalf("attempts%d want%d: %v", len(seen), tt.want, seen)
			}
			if !tt.cancel {
				for _, e := range seen {
					if tt.space == "transport" && tt.code == 10 {
						var wire *quic.TransportError
						if !errors.As(e, &wire) || wire.ErrorCode != 10 || wire.FrameType != 15 || wire.ErrorMessage != "17:Attempt to close a static stream" {
							t.Fatalf("wrong transport close %v", e)
						}
					} else {
						var wire *quic.ApplicationError
						if !errors.As(e, &wire) || int(wire.ErrorCode) != tt.code {
							t.Fatalf("wrong application close %v", e)
						}
					}
				}
			}
		})
	}
}
