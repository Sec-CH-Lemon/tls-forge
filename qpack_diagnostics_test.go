package tlsforge

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Sec-CH-Lemon/tls-forge/v5/profile"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQPACKDiagnosticJSONOnProductionQUIC(t *testing.T) {
	for _, tt := range []struct {
		name, kind, key, value, want string
		code                         int
		prime                        bool
	}{
		{"relative", "relative", "", "", "126:Error decoding headers on stream 0: Invalid relative index.", 512, false},
		{"relative-after-success", "relative", "", "", "126:Error decoding headers on stream 4: Invalid relative index.", 512, true},
		{"relative-JSON-only", "relative", "invalid_relative_index", "policy/{stream_id}/{detail}", "policy/4/invalid QPACK representation", 512, true},
		{"capacity", "capacity", "", "", "185:Encoder stream error: Error updating dynamic table capacity.", 513, false},
		{"capacity-JSON-only", "capacity", "capacity_exceeded", "capacity policy", "capacity policy", 513, false},
		{"zero-increment", "zero", "", "", "187:Decoder stream error: Invalid increment value 0.", 514, false},
		{"zero-JSON-only", "zero", "zero_increment", "decoder policy", "decoder policy", 514, false},
		{"nonzero-not-zero", "nonzero", "", "", "invalid or closed QPACK critical stream", 514, false},
		{"static-not-relative", "static", "decompression", "unclassified policy", "unclassified policy", 512, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			seed := httptest.NewTLSServer(nil)
			cert := seed.TLS.Certificates[0]
			seed.Close()
			ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			defer ln.Close()
			seen := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, e := ln.Accept(ctx)
				if e != nil {
					seen <- e
					return
				}
				defer conn.CloseWithError(0, "")
				control, e := conn.OpenUniStreamSync(ctx)
				if e != nil {
					seen <- e
					return
				}
				if _, e = control.Write([]byte{0, 4, 0}); e != nil {
					seen <- e
					return
				}
				for i := 0; ; i++ {
					str, e := conn.AcceptStream(ctx)
					if e != nil {
						seen <- e
						return
					}
					r := quicvarint.NewReader(str)
					typ, e := quicvarint.Read(r)
					if e != nil || typ != 1 {
						seen <- e
						return
					}
					n, e := quicvarint.Read(r)
					if e != nil {
						seen <- e
						return
					}
					if _, e = io.CopyN(io.Discard, str, int64(n)); e != nil {
						seen <- e
						return
					}
					if tt.prime && i == 0 {
						_, _ = str.Write([]byte{1, 3, 0, 0, 0xd9, 0, 2, 'o', 'k'})
						_ = str.Close()
						continue
					}
					switch tt.kind {
					case "relative":
						_, _ = str.Write([]byte{1, 4, 0, 0, 0xd9, 0x80})
					case "static":
						_, _ = str.Write([]byte{1, 4, 0, 0, 0xff, 0x24})
					case "capacity":
						enc, e := conn.OpenUniStreamSync(ctx)
						if e != nil {
							seen <- e
							return
						}
						_, _ = enc.Write([]byte{2, 0x3f, 0xe2, 0xff, 3})
					case "zero", "nonzero":
						dec, e := conn.OpenUniStreamSync(ctx)
						if e != nil {
							seen <- e
							return
						}
						b := byte(0)
						if tt.kind == "nonzero" {
							b = 1
						}
						_, _ = dec.Write([]byte{3, b})
					}
					select {
					case <-conn.Context().Done():
						seen <- context.Cause(conn.Context())
					case <-ctx.Done():
						seen <- ctx.Err()
					}
					return
				}
			}()
			p, e := profile.Get("chrome_155_macos")
			if e != nil {
				t.Fatal(e)
			}
			p.Name = "neutral-profile"
			p.Behavior["h3.retry_attempts"] = json.RawMessage(`1`)
			if tt.key != "" {
				p.Behavior["h3.qpack.error_"+tt.key+"_reason"], _ = json.Marshal(tt.value)
			}
			b, e := p.Save()
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "browser.json")
			if e = os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			client := newTestClient(t, WithProfile(path), WithTimeout(4*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			url := "https://" + ln.Addr().String() + "/"
			if tt.prime {
				res, e := client.Do(&Request{Context: ctx, URL: url})
				if e != nil || string(res.Body) != "ok" {
					t.Fatal(e)
				}
			}
			if _, e = client.Do(&Request{Context: ctx, URL: url}); e == nil {
				t.Fatal("malformed peer accepted")
			}
			select {
			case e = <-seen:
				var wire *quic.ApplicationError
				if !errors.As(e, &wire) || int(wire.ErrorCode) != tt.code || wire.ErrorMessage != tt.want {
					t.Fatalf("wire %v;want%d %q", e, tt.code, tt.want)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			client.Close()
			ln.Close()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("peer leak")
			}
		})
	}
}
