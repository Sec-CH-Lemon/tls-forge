package tlsforge

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/igor-lemon/utls/behavior"
	"net"
	"net/url"

	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
	utls "github.com/igor-lemon/utls"
)

type proxyIdentity struct {
	profile *profile.Profile
	pool    *proxyH2Pool
}

type proxyTLSCache = utls.ClientSessionCache

func newProxyTLSCache(policies ...behavior.Policy) proxyTLSCache {
	return utls.NewLRUClientSessionCache(policyArgument(policies).Int("proxy.tls_cache_entries"))
}

// The transport forwards plain HTTP through HTTP or HTTPS proxies; HTTPS
// origins still use CONNECT and retain the origin's TLS profile.
func (d *connectDialer) ForwardProxyURL() *url.URL {
	if d.identity.profile != nil && d.identity.profile.RuntimeBehavior().Flag("proxy.forward_http") {
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
		DynamicRecordSizingDisabled: prof.GetDynamicRecordSizingDisabled(), FalseStart: prof.GetFalseStart(),
		ClientSessionCache: d.cache, OmitEmptyPsk: true, KeyLogWriter: d.keys, Behavior: d.identity.profile.RuntimeBehavior().Clone()},
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
	p, err := d.adoptProxyH2(conn)
	if err != nil {
		return nil, err
	}
	return d.openProxyStream(ctx, p, address)
}
