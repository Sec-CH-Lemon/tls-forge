package tlsforge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"golang.org/x/net/proxy"

	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
)

// Through an HTTP proxy, a request is a tunnel. The client asks the proxy to
// CONNECT it to the host, and everything after that, the handshake included,
// goes through unread. So nothing a request can see of itself says where it
// came out: the other end of its socket is the proxy. Only the proxy knows, and
// some proxies say so in their answer to CONNECT.
//
// The transport opens such tunnels itself, and reads that answer for its status
// alone. They are opened here instead, so that what the proxy said stays with
// the connection, for every request that goes out on it.

// tunnel is a connection through an HTTP proxy, with what the proxy answered
// when it opened it.
type tunnel struct {
	net.Conn
	// reader is whatever was read past the answer, and then the connection.
	reader io.Reader
	header Header
	// id is the tunnel's number, which no other tunnel of this process has.
	id uint64
}

// tunnels is how many tunnels have been opened, which numbers the next.
var tunnels atomic.Uint64

func (t *tunnel) Read(p []byte) (int, error) { return t.reader.Read(p) }

// tunnelOf is the tunnel a connection goes through, under the TLS a request to
// an HTTPS site wraps it in, or nil when it goes through none.
func tunnelOf(conn net.Conn) *tunnel {
	for {
		switch c := conn.(type) {
		case *tunnel:
			return c
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		default:
			return nil
		}
	}
}

// proxyRoots are what an HTTPS proxy's certificate is checked against: the
// system's, unless a test stands in a proxy of its own.
var proxyRoots *x509.CertPool

// connectDialer opens tunnels through one HTTP or HTTPS proxy.
type connectDialer struct {
	// address is the proxy's, with a port, and secure says it is spoken to over
	// TLS, as name.
	address string
	secure  bool
	name    string
	// header goes with every CONNECT: the credentials, and whatever the caller
	// added to them.
	header  fhttp.Header
	timeout time.Duration
	dialer  net.Dialer
	// keys are where the secrets of a connection to an HTTPS proxy go, or nil.
	keys      io.Writer
	identity  proxyIdentity
	forward   *url.URL
	cache     proxyTLSCache
	proxyPool *proxyH2Pool
}

// dialOptions are how a client's connections are dialled. Through an HTTP or
// HTTPS proxy, by a tunnel opened here. Through any other, and to a proxy URL
// that will not parse, by the transport, which knows what to say about them: a
// SOCKS proxy answers with no header fields to keep, and the transport hands
// each connection it dials to one to the request's tap. Without a proxy, by a
// dialer of this package's, and a request to a name goes out on an HTTP/2
// connection to another that fits it, as Chrome sends one; unless the caller
// gave the transport options of its own (own is false), one of which may be a
// dialer or a proxy of its own, whose names are not to be looked up here.
// Every connection is dialed for a request, within its context, which says
// what the dial does in the request's log.
func dialOptions(proxyURL string, own bool, keys io.Writer, identity ...proxyIdentity) []tls_client.HttpClientOption {
	if proxyURL == "" {
		if !own {
			return nil
		}
		return []tls_client.HttpClientOption{
			tls_client.WithProxyDialerFactory(func(_ string, timeout time.Duration, local *net.TCPAddr,
				_ fhttp.Header, _ tls_client.Logger,
			) (proxy.ContextDialer, error) {
				return newDirectDialer(timeout, local), nil
			}),
			tls_client.WithConnectionCoalescing(lookupNames),
		}
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return []tls_client.HttpClientOption{tls_client.WithProxyUrl(proxyURL), tls_client.WithProxyConnWrapper(tapped)}
	}
	return []tls_client.HttpClientOption{
		tls_client.WithProxyDialerFactory(func(_ string, timeout time.Duration, local *net.TCPAddr,
			header fhttp.Header, _ tls_client.Logger,
		) (proxy.ContextDialer, error) {
			d := newConnectDialer(u, timeout, local, header)
			d.keys = keys
			if len(identity) > 0 {
				d.identity = identity[0]
				if d.identity.pool != nil {
					d.proxyPool = d.identity.pool
					d.cache = d.proxyPool.cache
				}
			}
			return d, nil
		}),
		// The transport tells by the proxy's URL that QUIC cannot go through it,
		// and it is given a dialer here instead of the URL. Without this, a
		// request it moved to HTTP/3 would leave the proxy behind and go out
		// from the machine's own address.
		tls_client.WithDisableHttp3(),
	}
}

// lookupNames finds the addresses of host as a directDialer does, with the
// machine's resolver, which says what it does to the trace of the request it
// is for: Chrome looks a name up before it sends a request over an HTTP/2
// connection to another, at an address the name has, on its certificate.
func lookupNames(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// directDialer dials a site with nothing between, as the transport's own
// dialer does.
type directDialer struct {
	dialer net.Dialer
}

func newDirectDialer(timeout time.Duration, local *net.TCPAddr) *directDialer {
	d := &directDialer{}
	d.dialer.Timeout = timeout
	if local != nil {
		d.dialer.LocalAddr = local
	}
	return d
}

func (d *directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	began := time.Now()
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return tapped(ctx, conn, began), nil
}

func newConnectDialer(u *url.URL, timeout time.Duration, local *net.TCPAddr, extra fhttp.Header) *connectDialer {
	d := &connectDialer{
		address: u.Host, secure: u.Scheme == "https", name: u.Hostname(),
		header: fhttp.Header{}, timeout: timeout, forward: u, cache: newProxyTLSCache(), proxyPool: newProxyH2Pool(),
	}
	if u.Port() == "" {
		port := "80"
		if d.secure {
			port = "443"
		}
		d.address = net.JoinHostPort(u.Hostname(), port)
	}
	for name, values := range extra {
		d.header[name] = values
	}
	if user := u.User.Username(); user != "" {
		password, _ := u.User.Password()
		d.header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	}
	d.dialer.Timeout = timeout
	if local != nil {
		d.dialer.LocalAddr = local
	}
	return d
}

// DialContext opens a tunnel to address. The network is what the proxy is
// dialled over: tcp, or tcp4 or tcp6 when the other is turned off.
func (d *connectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.secure && d.identity.profile != nil && d.identity.profile.RuntimeBehavior().Flag("proxy.profile_tls") {
		return d.chromeTunnel(ctx, network, address)
	}
	conn, err := d.reach(ctx, network)
	if err != nil {
		return nil, err
	}
	opened, err := d.open(ctx, conn, address)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return opened, nil
}

// reach connects to the proxy itself.
func (d *connectDialer) reach(ctx context.Context, network string) (net.Conn, error) {
	if !d.secure {
		return d.dial(ctx, network)
	}
	// The dial and the handshake together no longer than the timeout, as
	// tls.Dialer has them, and apart, so that the log can tell which failed.
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	raw, err := d.dial(ctx, network)
	if err != nil {
		return nil, err
	}
	if d.identity.profile != nil && d.identity.profile.RuntimeBehavior().Flag("proxy.profile_tls") {
		return d.chromeProxyTLS(ctx, raw)
	}
	// HTTP/1.1 only, so that every tunnel is a connection of its own, and the
	// answer that opened it belongs to it alone.
	conn := tls.Client(raw, &tls.Config{ServerName: d.name, NextProtos: []string{"http/1.1"}, RootCAs: proxyRoots,
		KeyLogWriter: d.keys})
	err = conn.HandshakeContext(ctx)
	if r := requestLogOf(ctx); r != nil {
		r.proxyTLS(conn.ConnectionState(), err)
	}
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// dial connects to the proxy, over a connection the request's tap sees.
func (d *connectDialer) dial(ctx context.Context, network string) (net.Conn, error) {
	began := time.Now()
	raw, err := d.dialer.DialContext(ctx, network, d.address)
	if err != nil {
		return nil, err
	}
	return tapped(ctx, raw, began), nil
}

// open asks the proxy, over a connection to it, for a tunnel to address.
//
// No longer than the client's timeout, and no longer than the request is
// wanted: a proxy that never answers holds up neither.
func (d *connectDialer) open(ctx context.Context, conn net.Conn, address string) (*tunnel, error) {
	if speaksH2(conn) {
		return d.openH2(ctx, conn, address)
	}
	_ = conn.SetDeadline(time.Now().Add(d.timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	ask := &fhttp.Request{
		Method: fhttp.MethodConnect, URL: &url.URL{Host: address}, Host: address,
		Header: d.header.Clone(), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
	r := requestLogOf(ctx)
	if r != nil {
		r.proxyAsk(address, ask.Header)
	}
	if err := ask.Write(conn); err != nil {
		if r != nil {
			r.proxyFailed(err)
		}
		return nil, err
	}
	reader := bufio.NewReader(conn)
	answer, err := fhttp.ReadResponse(reader, ask)
	if err != nil {
		if r != nil {
			r.proxyFailed(err)
		}
		return nil, err
	}
	if answer.StatusCode != fhttp.StatusOK {
		if r != nil {
			r.proxyRefused(answer, refusalBody(answer))
		}
		return nil, fmt.Errorf("proxy responded with non 200 code: %s", answer.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	// Whatever was read past the answer is the tunnel's already.
	rest, _ := reader.Peek(reader.Buffered())
	opened := &tunnel{
		Conn: conn, reader: io.MultiReader(bytes.NewReader(rest), conn), header: answerHeader(answer.Header),
		id: tunnels.Add(1),
	}
	if r != nil {
		r.proxyAnswer(answer, opened.id)
	}
	return opened, nil
}

// answerHeader is a proxy's answer as the header fields a response comes with:
// in lower case, and in an order that does not change from one call to the
// next, which a map's does.
func answerHeader(fields fhttp.Header) Header {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var out Header
	for _, name := range names {
		for _, value := range fields[name] {
			out = append(out, profile.Field{Name: strings.ToLower(name), Value: value})
		}
	}
	return out
}
