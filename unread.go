package tlsforge

import (
	"context"
	"fmt"
	"io"
	"math"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
)

// leave lets go of res, an answer a request goes on from without reading its
// body, as the profile says of answers of its kind over its protocol
// (h1.KIND_body, h2.KIND_body; docs/profile-behavior.md): "dropped", a
// redirect followed or refused and a 401 answered no more; "auth", a 401
// answered again; "restart", a navigation started again for its critical
// client hints; "preflight", a preflight its request goes on from.
//
//   - "close": at once. What is left of the body, all in the transport's
//     buffer already or come within the protocol's grace
//     (hN.unread_grace_us), is read and the connection kept; otherwise an
//     HTTP/1.1 connection is closed and an HTTP/2 stream the server has not
//     ended is reset (CANCEL).
//   - "drain": in the background, apart from the request, at most
//     http.drain_bytes within http.drain_ms: the connection is kept when the
//     body ended within both, else let go of as "close" lets go of it. The
//     request goes on once the body ended or the grace is over.
//   - "first-bytes": in the background, until the first of its bytes come,
//     within http.first_bytes_ms (0: as long as the connection lasts); then as
//     "close" lets go of it. The request goes on at once.
//   - "read-all": read to its end before the request goes on, the connection
//     kept; one the server closes after it (Connection: close, or a body that
//     ends with the connection) is closed at once.
//   - "read", no key, or another protocol: as tls-forge always did, at most
//     limit bytes read, then closed; a negative limit leaves the body to the
//     transport (a redirect's, which it reads 2 KiB of).
//
// What goes on in the background ends when the client closes its idle
// connections, or is closed. The body is fhttp.NoBody after, but where it is
// left to the transport.
func (c *Client) leave(kind string, res *fhttp.Response, limit int64) {
	p := c.behavior()
	// Keys of HTTP/1.1 and HTTP/2 alone: another protocol's say nothing.
	proto := fmt.Sprintf("h%d.", res.ProtoMajor)
	rule := p.Text(proto + kind + "_body")
	grace := time.Duration(p.Uint(proto+"unread_grace_us")) * time.Microsecond
	switch rule {
	case "close":
		c.transports.letGo(func(ending context.Context) <-chan struct{} {
			return fhttp.DrainBody(ending, res, math.MaxInt64, grace, grace)
		})
		return
	case "drain":
		c.transports.letGo(func(ending context.Context) <-chan struct{} {
			return fhttp.DrainBody(ending, res, int64(p.Uint("http.drain_bytes")), milliseconds(p.Uint("http.drain_ms")), grace)
		})
		return
	case "first-bytes":
		c.transports.letGo(func(ending context.Context) <-chan struct{} {
			return fhttp.AwaitBody(ending, res, milliseconds(p.Uint("http.first_bytes_ms")), grace)
		})
		return
	case "read-all":
		if !res.Close {
			_, _ = io.Copy(io.Discard, res.Body)
		}
	default:
		if limit < 0 {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, limit))
	}
	_ = res.Body.Close()
	res.Body = fhttp.NoBody
}

// milliseconds is n milliseconds.
func milliseconds(n uint64) time.Duration { return time.Duration(n) * time.Millisecond }
