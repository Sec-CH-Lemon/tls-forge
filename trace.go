package tlsforge

import (
	"context"
	"net"
	"net/http/httptrace"
	"sync"

	fhttptrace "github.com/bogdanfinn/fhttp/httptrace"
	utls "github.com/bogdanfinn/utls"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// Trace is told what a request does on the wire, while it does it.
//
// A response says how a request ended. It does not say whether a name was
// looked up or a connection was already open, which address answered, what the
// handshake settled on, or in what order the headers actually left, and those
// are the questions a request that went wrong raises. One that failed has no
// response to ask at all.
//
// Every hook is optional. They are called from whichever goroutine is doing
// the work, so two can run at once, and one can still be called after Do has
// returned: a dial that lost a race reports in when it gets round to it. A
// redirected request calls them again for every hop.
type Trace struct {
	// DNSStart and DNSDone surround the lookup of a name. A request to a
	// literal address has neither, and nor has one that found a connection
	// already open.
	DNSStart func(host string)
	DNSDone  func(addrs []string, err error)

	// ConnectStart and ConnectDone surround one TCP dial: to the proxy when
	// there is one, because that is where the socket goes. A host with several
	// addresses is dialled more than once, and those dials can overlap.
	ConnectStart func(network, addr string)
	ConnectDone  func(network, addr string, err error)

	// GotConn is called when a connection is ready to carry the request, with
	// its handshake done if it has one.
	GotConn func(ConnInfo)

	// WroteRequest is called when the request has been written, with the
	// header fields in the order they went onto the wire. The pseudo-headers
	// and the jar's Cookie are among them: this is the request as the server
	// saw it rather than as it was asked for.
	WroteRequest func(sent Header, err error)

	// FirstByte is called when the first byte of the response arrives.
	FirstByte func()

	// Redirect is called when a response is a redirect that is about to be
	// followed, with the status that said so and the URL it leads to.
	Redirect func(status int, location string)
}

// ConnInfo is the connection a request went out on.
type ConnInfo struct {
	// Reused reports a connection that had carried a request before, so that
	// nothing was looked up, dialled or negotiated for this one.
	Reused bool
	// RemoteAddr is the other end of the socket, which is the proxy when there
	// is a proxy.
	RemoteAddr string
	// TLSVersion, CipherSuite and ALPN are what the handshake settled on, by
	// name. All three are empty over plain HTTP, and ALPN is empty as well
	// when the server negotiated no protocol.
	TLSVersion  string
	CipherSuite string
	ALPN        string
	// Resumed reports a handshake that picked up an earlier session.
	Resumed bool
}

// The hooks, each behind the check for whether anybody asked for it.

func (t *Trace) dnsStart(host string) {
	if t.DNSStart != nil {
		t.DNSStart(host)
	}
}

func (t *Trace) dnsDone(addrs []string, err error) {
	if t.DNSDone != nil {
		t.DNSDone(addrs, err)
	}
}

func (t *Trace) connectStart(network, addr string) {
	if t.ConnectStart != nil {
		t.ConnectStart(network, addr)
	}
}

func (t *Trace) connectDone(network, addr string, err error) {
	if t.ConnectDone != nil {
		t.ConnectDone(network, addr, err)
	}
}

func (t *Trace) gotConn(conn ConnInfo) {
	if t.GotConn != nil {
		t.GotConn(conn)
	}
}

func (t *Trace) wroteRequest(sent Header, err error) {
	if t.WroteRequest != nil {
		t.WroteRequest(sent, err)
	}
}

func (t *Trace) firstByte() {
	if t.FirstByte != nil {
		t.FirstByte()
	}
}

func (t *Trace) redirect(status int, location string) {
	if t.Redirect != nil {
		t.Redirect(status, location)
	}
}

type traceKey struct{}

// attach hangs the hooks on a request's context, which is the one thing that
// reaches every layer a request passes through.
func (t *Trace) attach(ctx context.Context) context.Context {
	// For the redirect policy, which is handed the next request and nothing
	// else of the call that started it.
	ctx = context.WithValue(ctx, traceKey{}, t)

	// Lookups and dials are made by the standard library's dialer, and it reads
	// its hooks from the standard library's trace. The transport's fork of
	// httptrace files the same hooks under a key of its own that no dialer
	// looks for. Measured: its DNS and connect hooks never ran. Its TLS hooks
	// cannot run either, because the handshake is made by the transport's
	// caller and not by the transport, which is why what the handshake settled
	// on is read off the connection in GotConn instead.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) { t.dnsStart(info.Host) },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			addrs := make([]string, 0, len(info.Addrs))
			for _, addr := range info.Addrs {
				addrs = append(addrs, addr.String())
			}
			t.dnsDone(addrs, info.Err)
		},
		ConnectStart: t.connectStart,
		ConnectDone:  t.connectDone,
	})

	// The fields of one request, gathered as each is written. Started afresh
	// with every connection handed over, so a hop of a redirect reports its own
	// headers and not those of the hops before it.
	var mu sync.Mutex
	var sent Header
	return fhttptrace.WithClientTrace(ctx, &fhttptrace.ClientTrace{
		GotConn: func(info fhttptrace.GotConnInfo) {
			mu.Lock()
			sent = nil
			mu.Unlock()
			t.gotConn(connOf(info.Conn, info.Reused))
		},
		WroteHeaderField: func(name string, values []string) {
			mu.Lock()
			defer mu.Unlock()
			for _, value := range values {
				sent = append(sent, profile.Field{Name: name, Value: value})
			}
		},
		WroteRequest: func(info fhttptrace.WroteRequestInfo) {
			mu.Lock()
			written := sent
			sent = nil
			mu.Unlock()
			t.wroteRequest(written, info.Err)
		},
		GotFirstResponseByte: t.firstByte,
	})
}

// connectionStater is a connection that went through a handshake and can say
// how it came out.
type connectionStater interface {
	ConnectionState() utls.ConnectionState
}

// connOf describes a connection from what the transport holds for it.
func connOf(conn net.Conn, reused bool) ConnInfo {
	out := ConnInfo{Reused: reused}
	if addr := conn.RemoteAddr(); addr != nil {
		out.RemoteAddr = addr.String()
	}
	if secure, ok := conn.(connectionStater); ok {
		state := secure.ConnectionState()
		out.TLSVersion = utls.VersionName(state.Version)
		out.CipherSuite = utls.CipherSuiteName(state.CipherSuite)
		out.ALPN = state.NegotiatedProtocol
		out.Resumed = state.DidResume
	}
	return out
}
