package tlsforge

import (
	"context"
	"net"
	"time"

	fhttptrace "github.com/igor-lemon/fhttp/httptrace"

	"github.com/Sec-CH-Lemon/tls-forge/v6/internal/conntap"
)

// The connections a request goes out on, for whoever made it to see: the
// tap its context carries is handed every connection tls-forge dials for it,
// to a site or to a proxy, and told of every one it goes out on. A SOCKS
// proxy's connections are the transport's to dial, and it hands each to the
// tap as tls-forge's own dialers do (WithProxyConnWrapper).

// tapped is conn, dialed for the request ctx is of from began, as the tap the
// request carries would have it go out, or as it is.
func tapped(ctx context.Context, conn net.Conn, began time.Time) net.Conn {
	if tap := conntap.From(ctx); tap != nil {
		return tap.Dialed(conn, began)
	}
	return conn
}

// watched is ctx with a hook that tells tap of every connection the request
// goes out on.
func watched(ctx context.Context, tap conntap.Tap) context.Context {
	return fhttptrace.WithClientTrace(ctx, &fhttptrace.ClientTrace{
		GotConn: func(info fhttptrace.GotConnInfo) { tap.Used(info.Conn) },
	})
}
