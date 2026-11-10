package tlsforge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
	"github.com/quic-go/qpack"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// bidiPeer is an HTTP/3 server that answers one request, then, once open is
// closed, opens a bidirectional stream of its own, which HTTP/3 lets no
// server open (RFC 9114, section 6.1), and says how the client ended the
// connection within wait: nil when it did not.
func bidiPeer(t *testing.T, wait time.Duration, open <-chan struct{}) (string, <-chan error) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	cert := seed.TLS.Certificates[0]
	seed.Close()
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate,
		PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ended := make(chan error, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		control, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			return
		}
		_, _ = control.Write([]byte{0x00, 0x04, 0x00}) // the control stream, empty SETTINGS
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		r := quicvarint.NewReader(str)
		for {
			typ, err := quicvarint.Read(r)
			if err != nil {
				return
			}
			n, err := quicvarint.Read(r)
			if err != nil || n > 1<<20 {
				return
			}
			if _, err := io.CopyN(io.Discard, str, int64(n)); err != nil {
				return
			}
			if typ == 1 {
				break
			}
		}
		var block bytes.Buffer
		_ = qpack.NewEncoder(&block).WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
		frame := quicvarint.Append(quicvarint.Append(nil, 1), uint64(block.Len()))
		frame = append(append(frame, block.Bytes()...), 0, 2, 'o', 'k')
		if _, err := str.Write(frame); err != nil {
			return
		}
		_ = str.Close()
		select {
		case <-open:
		case <-ctx.Done():
			return
		}
		bidi, err := conn.OpenStreamSync(ctx)
		if err != nil {
			ended <- err
			return
		}
		_, _ = bidi.Write([]byte("probe"))
		select {
		case <-conn.Context().Done():
			ended <- context.Cause(conn.Context())
		case <-time.After(wait):
			ended <- nil
		}
	}()
	return "https://" + ln.Addr().String(), ended
}

// A server's bidirectional stream closes the connection with
// H3_STREAM_CREATION_ERROR and quiche's reason, "154:Server created
// bidirectional stream." (QuicSpdyClientSession::ShouldCreateIncomingStream,
// QUIC_HTTP_SERVER_INITIATED_BIDIRECTIONAL_STREAM), as Chrome closes it where
// the profile says h3.server_bidi_stream_close_reason. Without the key the
// stream is passed over and the connection stays up.
func TestAServersBidirectionalStreamClosesTheConnectionAsChromeClosesIt(t *testing.T) {
	shipped, err := profile.Get("chrome_156_macos")
	if err != nil {
		t.Fatal(err)
	}
	reason := shipped.Behavior.Text("h3.server_bidi_stream_close_reason")
	if reason != "154:Server created bidirectional stream." {
		t.Fatalf("the shipped profile's reason is %q", reason)
	}
	without := shipped.Clone()
	delete(without.Behavior, "h3.server_bidi_stream_close_reason")
	for _, p := range []*profile.Profile{shipped, without} {
		closes := p.Behavior.Has("h3.server_bidi_stream_close_reason")
		wait := 2 * time.Second
		if !closes {
			wait = 300 * time.Millisecond
		}
		open := make(chan struct{})
		url, ended := bidiPeer(t, wait, open)
		c := newTestClient(t, WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(4*time.Second),
			WithTransportOption(tc.WithProtocolRacing()))
		res, err := c.Do(&Request{URL: url})
		if err != nil || string(res.Body) != "ok" { // the peer speaks QUIC alone
			t.Fatalf("%v %+v", err, res)
		}
		close(open)
		var why error
		select {
		case why = <-ended:
		case <-time.After(5 * time.Second):
			t.Fatal("the server never opened its stream")
		}
		var closed *quic.ApplicationError
		switch {
		case closes && (!errors.As(why, &closed) || !closed.Remote || closed.ErrorCode != 0x103 || closed.ErrorMessage != reason):
			t.Errorf("the connection ended with %v, want H3_STREAM_CREATION_ERROR %q", why, reason)
		case !closes && why != nil:
			t.Errorf("without a reason the connection ended with %v", why)
		}
	}
}
