package tlsforge

import (
	"fmt"
	"io"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	tc "github.com/igor-lemon/tls-client"
	utls "github.com/igor-lemon/utls"
)

func TestA6LargeHTTP3SetupAndClose(t *testing.T) {
	for _, mode := range []string{"small", "grease-buffer-edge", "grease4096", "many-settings"} {
		t.Run(mode, func(t *testing.T) {
			seed := httptest.NewTLSServer(nil)
			cert := seed.TLS.Certificates[0]
			seed.Close()
			udp, tcp := udpAndTCP(t)
			_ = tcp.Close()
			var calls atomic.Int32
			server := &http3.Server{TLSConfig: &utls.Config{Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, QUICConfig: &quic.Config{EnableDatagrams: true}, EnableDatagrams: true,
				Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { calls.Add(1); _, _ = io.WriteString(w, "ok") })}
			go func() { _ = server.Serve(udp) }()
			t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })
			mutations := map[string]any{"h3.grease_payload_lengths": []uint64{0}}
			if mode == "grease-buffer-edge" {
				mutations["h3.grease_payload_lengths"] = []uint64{1452}
			}
			if mode == "grease4096" {
				mutations["h3.grease_payload_lengths"] = []uint64{4096}
			}
			if mode == "many-settings" {
				settings := []map[string]uint64{{"id": 1, "value": 65536}, {"id": 7, "value": 100}, {"id": 6, "value": 262144}, {"id": 51, "value": 1}}
				for n := uint64(0); n < 256; n++ {
					settings = append(settings, map[string]uint64{"id": 33 + 31*n, "value": 1<<62 - 1})
				}
				mutations["h3.settings"] = settings
			}
			c, err := New(WithProfileValue(policyFile(t, mutations)), WithInsecureSkipVerify(), WithTimeout(time.Second), WithTransportOption(tc.WithProtocolRacing()))
			if err != nil {
				t.Fatal(err)
			}
			answer := make(chan error, 1)
			go func() {
				res, err := c.Get("https://" + udp.LocalAddr().String() + "/")
				if err == nil && string(res.Body) != "ok" {
					err = fmt.Errorf("body %q", res.Body)
				}
				answer <- err
			}()
			select {
			case err = <-answer:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(2 * time.Second):
				t.Error("valid profile blocked request cancellation")
			}
			closed := make(chan error, 1)
			go func() { closed <- c.Close() }()
			select {
			case err = <-closed:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(time.Second):
				t.Error("valid profile blocked Client.Close")
			}
			if calls.Load() != 1 {
				t.Errorf("%d origin requests;want a complete finite exchange", calls.Load())
			}
		})
	}
}
