package tlsforge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"

	tls_client "github.com/igor-lemon/tls-client"
	"golang.org/x/net/dns/dnsmessage"
)

// quicEndpoint resolves addr (host:port) for a request that may go over
// HTTP/3 (tls_client.HTTP3FromDNS), as Chrome's QUIC job and its TCP one share
// one host resolution: the name's addresses, and its HTTPS records waited
// for as a connection waits for them. The context it gives back carries both
// for the request's TCP dial, which asks nothing again (resolvedFor); the
// endpoint is where QUIC goes, and whether the record the connection takes
// names h3. A name whose records are not asked for, or that does not resolve,
// says no: its TCP dial resolves it as ever, and says why it did not.
func (r *resolving) quicEndpoint(ctx context.Context, addr string) (context.Context, tls_client.QUICEndpoint, bool) {
	host, _, err := net.SplitHostPort(addr)
	if r == nil || err != nil || !r.asksFor(host) {
		return ctx, tls_client.QUICEndpoint{}, false
	}
	l := r.ask(ctx, addr)
	addrs, err := r.lookupNames(ctx, host)
	if err != nil || len(addrs) == 0 {
		l.cancel()
		return ctx, tls_client.QUICEndpoint{}, false
	}
	l.settle(ctx)
	ctx = context.WithValue(ctx, resolvedKey{}, &resolvedName{host: host, addrs: addrs, https: l})
	return ctx, tls_client.QUICEndpoint{Addrs: addrs, ECH: l.h3taken}, l.h3
}

type resolvedKey struct{}

// resolvedName is what a request's QUIC endpoint found of its host, which its
// TCP dial takes rather than ask again.
type resolvedName struct {
	host  string
	addrs []netip.Addr
	https *httpsLookup
}

// resolvedFor is what ctx carries of host's resolution, or nil.
func resolvedFor(ctx context.Context, host string) *resolvedName {
	known, _ := ctx.Value(resolvedKey{}).(*resolvedName)
	if known == nil || !strings.EqualFold(known.host, host) {
		return nil
	}
	return known
}

// resolver is a resolver that finds the name at the addresses found already
// and nowhere else, so that a dial goes to them as Go's dialer goes to what a
// resolver finds (the hosts file first, then a DNS server): Chrome's TCP
// connection finds them in the host cache its QUIC one's lookup filled.
func (n *resolvedName) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go n.answer(server)
		return client, nil
	}}
}

// answer answers each query on conn, framed as over TCP (Go's resolver frames
// it so on a connection that is no PacketConn): the addresses of the name's
// kind for the name, nothing at all for another.
func (n *resolvedName) answer(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		reply := n.reply(query)
		if reply == nil {
			return
		}
		if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...)); err != nil {
			return
		}
	}
}

func (n *resolvedName) reply(query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	ours := strings.EqualFold(strings.TrimSuffix(q.Name.String(), "."), strings.TrimSuffix(n.host, "."))
	rcode := dnsmessage.RCodeSuccess
	if !ours {
		rcode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, RCode: rcode})
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	head := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 1}
	for _, a := range n.addrs {
		switch a = a.Unmap(); {
		case !ours:
		case q.Type == dnsmessage.TypeA && a.Is4():
			_ = b.AResource(head, dnsmessage.AResource{A: a.As4()})
		case q.Type == dnsmessage.TypeAAAA && a.Is6():
			_ = b.AAAAResource(head, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	// A builder fails only where it is misused; the answer is whatever it
	// made then.
	reply, _ := b.Finish()
	return reply
}
