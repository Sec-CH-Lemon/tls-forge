package tlsforge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	utls "github.com/igor-lemon/utls"
)

type proxyIdentity struct {
	profile *profile.Profile
}

type proxyTLSCache = utls.ClientSessionCache

func newProxyTLSCache() proxyTLSCache { return utls.NewLRUClientSessionCache(32) }

// The transport forwards plain HTTP through HTTP or HTTPS proxies; HTTPS
// origins still use CONNECT and retain the origin's TLS profile.
func (d *connectDialer) ForwardProxyURL() *url.URL {
	if d.identity.profile != nil && d.identity.profile.Chromium() {
		copy := *d.forward
		return &copy
	}
	return nil
}

func (d *connectDialer) DialProxyContext(ctx context.Context, network, _ string) (net.Conn, error) {
	conn, err := d.reach(ctx, network)
	if secure, ok := conn.(*utls.UConn); ok {
		// The proxy handshake is complete. fhttp's TLSNextProto contract takes
		// *utls.Conn; keep its ALPN state visible so forwarding can use H2.
		return secure.Conn, err
	}
	return conn, err
}

func (d *connectDialer) chromeProxyTLS(ctx context.Context, raw net.Conn) (net.Conn, error) {
	prof, err := d.identity.profile.ClientProfileShuffled(d.identity.profile.ShufflesExtensions())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn := utls.UClient(raw, &utls.Config{ServerName: d.name, RootCAs: proxyRoots,
		ClientSessionCache: d.cache, OmitEmptyPsk: true, KeyLogWriter: d.keys, ChromeBehavior: true},
		prof.GetClientHelloId(), false, false, true)
	err = conn.HandshakeContext(ctx)
	var refused *utls.CertificateVerificationError
	if errors.As(err, &refused) {
		err = &tls.CertificateVerificationError{UnverifiedCertificates: refused.UnverifiedCertificates, Err: refused.Err}
	}
	state := conn.ConnectionState()
	if r := requestLogOf(ctx); r != nil {
		r.proxyTLS(tls.ConnectionState{Version: state.Version, CipherSuite: state.CipherSuite,
			NegotiatedProtocol: state.NegotiatedProtocol, PeerCertificates: state.PeerCertificates}, err)
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func speaksH2(conn net.Conn) bool {
	if c, ok := conn.(interface{ ConnectionState() utls.ConnectionState }); ok {
		return c.ConnectionState().NegotiatedProtocol == "h2"
	}
	return false
}

// A CONNECT stream is a duplex byte connection. Outer HTTP/2 framing is
// independent of the inner origin protocol and uses its own flow control.
func (d *connectDialer) openH2(ctx context.Context, conn net.Conn, address string) (*tunnel, error) {
	prof, err := d.identity.profile.ClientProfile()
	if err != nil {
		return nil, err
	}
	transport := &http2.Transport{ChromeBehavior: true, Settings: prof.GetSettings(),
		SettingsOrder: prof.GetSettingsOrder(), ConnectionFlow: prof.GetConnectionFlow(),
		PseudoHeaderOrder: []string{":method", ":authority"}, DisableCompression: true,
		WindowUpdateDelay:         prof.GetWindowUpdateDelay(),
		HeaderRepresentation:      prof.GetHeaderRepresentation(),
		MaxEncoderHeaderTableSize: prof.GetMaxEncoderHeaderTableSize()}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	ask := (&fhttp.Request{Method: "CONNECT", URL: &url.URL{Host: address}, Host: address,
		Header: d.header.Clone(), Body: reader, ContentLength: -1}).WithContext(ctx)
	ask.Header.Del("Proxy-Connection")
	answer, err := cc.RoundTrip(ask)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		_ = cc.Close()
		return nil, err
	}
	if answer.StatusCode != 200 {
		_ = answer.Body.Close()
		_ = writer.Close()
		_ = cc.Close()
		return nil, fmt.Errorf("proxy responded with non 200 code: %s", answer.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	stream := &proxyStream{Conn: conn, reader: answer.Body, writer: writer, client: cc}
	opened := &tunnel{Conn: stream, reader: stream, header: answerHeader(answer.Header), id: tunnels.Add(1)}
	if r := requestLogOf(ctx); r != nil {
		r.proxyAnswer(answer, opened.id)
	}
	return opened, nil
}

type proxyStream struct {
	net.Conn
	reader io.ReadCloser
	writer *io.PipeWriter
	client *http2.ClientConn
}

func (c *proxyStream) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *proxyStream) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *proxyStream) Close() error {
	_ = c.writer.Close()
	_ = c.reader.Close()
	return c.client.Close()
}
