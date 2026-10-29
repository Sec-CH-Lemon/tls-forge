package tlsforge

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	utls "github.com/igor-lemon/utls"
)

func TestH3WithoutAdvertisedLimitRejectsOversizedTrailer(t *testing.T) {
	seed := httptest.NewTLSServer(nil)
	cert := seed.TLS.Certificates[0]
	seed.Close()
	udp, tcp := udpAndTCP(t)
	_ = tcp.Close()
	server := &http3.Server{
		TLSConfig:  &utls.Config{Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}},
		QUICConfig: &quic.Config{EnableDatagrams: true}, EnableDatagrams: true,
		Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
			stream := w.(http3.HTTPStreamer).HTTPStream()
			frame := quicvarint.Append(nil, 1)
			frame = quicvarint.Append(frame, (uint64(1)<<62)-1)
			_, _ = stream.QUICStream().Write(frame)
		}),
	}
	go func() { _ = server.Serve(udp) }()
	t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })
	p := policyFile(t, map[string]any{"h3.settings": []map[string]uint64{{"id": 1, "value": 65536}, {"id": 7, "value": 100}, {"id": 51, "value": 1}}})
	c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(3*time.Second),
		WithTransportOption(tc.WithProtocolRacing()),
		WithTransportOption(tc.WithTransportOptions(&tc.TransportOptions{MaxResponseHeaderBytes: -1})))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Get("https://" + udp.LocalAddr().String() + "/")
	if err == nil || !strings.Contains(err.Error(), "HEADERS frame too large") {
		t.Fatalf("want bounded rejection, got %v", err)
	}
}
func TestH3ResponseLimitFollowsJSON(t *testing.T) {
	for _, allow := range []bool{false, true} {
		name := "small-limit"
		if allow {
			name = "large-limit"
		}
		t.Run(name, func(t *testing.T) {
			seed := httptest.NewTLSServer(nil)
			cert := seed.TLS.Certificates[0]
			seed.Close()
			udp, tcp := udpAndTCP(t)
			_ = tcp.Close()
			server := &http3.Server{TLSConfig: &utls.Config{Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, QUICConfig: &quic.Config{EnableDatagrams: true}, EnableDatagrams: true, Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
				w.Header().Set("X-Audit", strings.Repeat("a", 300000))
				_, _ = io.WriteString(w, "ok")
			})}
			go func() { _ = server.Serve(udp) }()
			t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })
			mutation := map[string]any{"h3.grease_payload_lengths": []uint64{0}, "h3.settings": []map[string]uint64{{"id": 1, "value": 65536}, {"id": 6, "value": 1048576}, {"id": 7, "value": 100}, {"id": 51, "value": 1}}}
			if !allow {
				mutation["h3.settings"] = []map[string]uint64{{"id": 1, "value": 65536}, {"id": 6, "value": 262144}, {"id": 7, "value": 100}, {"id": 51, "value": 1}}
			}
			p := policyFile(t, mutation)
			cp, err := p.ClientProfile()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("profile h3 settings: %v", cp.GetHttp3Settings())
			c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(3*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			res, err := c.Get("https://" + udp.LocalAddr().String() + "/")
			if !allow {
				if err == nil {
					t.Fatal("small JSON limit accepted oversized field section")
				}
				return
			}
			if err != nil {
				t.Fatalf("valid H3 field section under JSON 1MiB limit rejected: %v", err)
			}
			t.Logf("accepted HTTP/3 response, x-audit=%d body=%q", len(res.Header["x-audit"][0]), res.Body)
		})
	}
}

type firstReadError struct {
	reads int
	err   error
}

func (r *firstReadError) Read(b []byte) (int, error) {
	r.reads++
	if r.reads == 1 {
		return 0, r.err
	}
	return copy(b, "unexpected second read"), io.EOF
}
func (r *firstReadError) Close() error { return nil }
func TestReadBodyPreservesFirstTransportError(t *testing.T) {
	sentinel := errors.New("first transport error")
	reader := &firstReadError{err: sentinel}
	res := &fhttp.Response{StatusCode: 200, Header: fhttp.Header{}, Body: reader}
	_, _, err := readBody(res, "GET", 1024)
	if !errors.Is(err, sentinel) || reader.reads != 1 {
		t.Fatalf("reads=%d, error=%v", reader.reads, err)
	}
}
