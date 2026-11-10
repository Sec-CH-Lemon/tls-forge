package tlsforge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
)

func TestA13CatalogueJSONControlsActualDraftSettingFailure(t *testing.T) {
	for _, test := range []struct{ template, want string }{{"", ""}, {"JSON-A {id} value {value}", "JSON-A 16765559 value 2"}, {"JSON-B {value} at {id}", "JSON-B 2 at 16765559"}} {
		t.Run(test.template, func(t *testing.T) {
			p, err := profile.Get("firefox_148")
			if err != nil {
				t.Fatal(err)
			}
			p = p.Clone()
			p.Name = "neutral-error-profile"
			p.UserAgent = "independent metadata"
			p.Behavior["h3.datagram_setting_error_reason"], err = json.Marshal(test.template)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			p, err = profile.Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			seed := httptest.NewTLSServer(nil)
			cert := seed.TLS.Certificates[0]
			seed.Close()
			ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			peer := make(chan error, 1)
			go func() {
				conn, e := ln.Accept(ctx)
				if e != nil {
					peer <- e
					return
				}
				str, e := conn.OpenUniStreamSync(ctx)
				if e != nil {
					peer <- e
					return
				}
				payload := quicvarint.Append(nil, 16765559)
				payload = quicvarint.Append(payload, 2)
				raw := quicvarint.Append([]byte{0, 4}, uint64(len(payload)))
				raw = append(raw, payload...)
				if _, e = str.Write(raw); e != nil {
					peer <- e
					return
				}
				select {
				case <-conn.Context().Done():
					peer <- context.Cause(conn.Context())
				case <-ctx.Done():
					peer <- ctx.Err()
				}
			}()
			c := newTestClient(t, WithProfileValue(p), WithTimeout(4*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			if _, err = c.Get("https://" + ln.Addr().String() + "/"); err == nil {
				t.Fatal("invalid peer SETTINGS accepted")
			}
			select {
			case err = <-peer:
				var remote *quic.ApplicationError
				if !errors.As(err, &remote) || !remote.Remote || remote.ErrorCode != 0x109 || remote.ErrorMessage != test.want {
					t.Fatalf("authenticated close: %v; want %q", err, test.want)
				}
			case <-ctx.Done():
				t.Fatal("missing authenticated peer close", ctx.Err())
			}
		})
	}
}
