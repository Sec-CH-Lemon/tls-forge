package tlsforge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"net/url"
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
	known := takePreparedDNS(ctx, addr)
	var l *httpsLookup
	var addrs []netip.Addr
	if known != nil {
		if known.err != nil {
			return context.WithValue(ctx, resolvedKey{}, known), tls_client.QUICEndpoint{}, false
		}
		l, addrs = known.https, known.addrs
	} else {
		l = r.ask(ctx, addr)
		var err error
		addrs, err = r.lookupNames(ctx, host)
		if err != nil || len(addrs) == 0 {
			l.cancel()
			return ctx, tls_client.QUICEndpoint{}, false
		}
		l.settle(ctx)
	}
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
	err   error
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

// preparedDNS is a bounded ownership handoff, not an address TTL cache. It is
// private to one request chain and consumed by its first actual connection.
type preparedDNS struct {
	name     *resolvedName
	target   origin
	redirect bool
}

func prepareDNS(ctx context.Context, name *resolvedName, target origin, redirect bool) {
	ch, _ := ctx.Value(chainKey{}).(*chain)
	if ch == nil {
		return
	}
	ch.mu.Lock()
	ch.dns = &preparedDNS{name: name, target: target, redirect: redirect}
	ch.mu.Unlock()
}

func preparedDNSFor(ctx context.Context, host string) *resolvedName {
	ch, _ := ctx.Value(chainKey{}).(*chain)
	if ch == nil {
		return nil
	}
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.dns != nil && strings.EqualFold(ch.dns.name.host, host) {
		return ch.dns.name
	}
	return nil
}

func takePreparedDNS(ctx context.Context, address string) *resolvedName {
	ch, _ := ctx.Value(chainKey{}).(*chain)
	if ch == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	p := ch.dns
	ch.dns = nil
	if err == nil && p != nil && strings.EqualFold(p.name.host, host) && p.target.port == port {
		return p.name
	}
	return nil
}

// nextDNSHop retains a prepared result only for its immediate synthetic
// HTTPS redirect. Any other redirect, restart or new request discards it.
func (ch *chain) nextDNSHop(u *url.URL) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.dns != nil && ch.dns.redirect && ch.dns.target == originOf(u) {
		ch.dns.redirect = false
		return
	}
	ch.dns = nil
}
