package tlsforge

import (
	"context"
	"net"
	"time"

	fhttptrace "github.com/igor-lemon/fhttp/httptrace"
	tls_client "github.com/igor-lemon/tls-client"

	"github.com/Sec-CH-Lemon/tls-forge/internal/conntap"
)

// The connections a request goes out on, for whoever made it to see: the
// tap its context carries is handed every connection tls-forge dials for it,
// to a site or to a proxy, and told of every one it goes out on. A SOCKS
// proxy's connections are the transport's to dial, and it hands each to the
// tap as tls-forge's own dialers do (WithProxyConnWrapper); a QUIC
// connection's socket tells it of each datagram (HTTP3FromDNS.Tap).

// tapped is conn, dialed for the request ctx is of from began, as the tap the
// request carries would have it go out, or as it is.
func tapped(ctx context.Context, conn net.Conn, began time.Time) net.Conn {
	if tap := conntap.From(ctx); tap != nil {
		return tap.Dialed(conn, began)
	}
	return conn
}

// quicTapped is how a QUIC connection made for the request ctx is of, its
// socket's from local to remote, tells the tap the request carries of its
// datagrams; nil when the request carries none.
func quicTapped(ctx context.Context, local, remote net.Addr) tls_client.QUICPacketTap {
	if tap := conntap.From(ctx); tap != nil {
		return tap.QUIC(local, remote, time.Now())
	}
	return nil
}

// watched is ctx with a hook that tells tap of every connection the request
// goes out on.
func watched(ctx context.Context, tap conntap.Tap) context.Context {
	return fhttptrace.WithClientTrace(ctx, &fhttptrace.ClientTrace{
		GotConn: func(info fhttptrace.GotConnInfo) { tap.Used(info.Conn) },
	})
}
