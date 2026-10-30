package tlsforge

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"testing"
)

func TestA12DNSHandoffBelongsToOneHopAndOneChain(t *testing.T) {
	target := originOf(&url.URL{Scheme: "https", Host: "one.example.test"})
	known := &resolvedName{host: target.host, addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	noChain := context.Background()
	prepareDNS(noChain, known, target, true)
	if preparedDNSFor(noChain, target.host) != nil || takePreparedDNS(noChain, "one.example.test:443") != nil {
		t.Fatal("handoff escaped its chain")
	}
	ch := &chain{}
	ctx := context.WithValue(noChain, chainKey{}, ch)
	other := context.WithValue(noChain, chainKey{}, &chain{})
	prepareDNS(ctx, known, target, true)
	if preparedDNSFor(other, target.host) != nil || preparedDNSFor(ctx, "other.example.test") != nil {
		t.Fatal("handoff crossed owner/host")
	}
	ch.nextDNSHop(&url.URL{Scheme: "https", Host: "one.example.test"})
	if preparedDNSFor(ctx, target.host) != known {
		t.Fatal("synthetic redirect lost the lookup")
	}
	if takePreparedDNS(ctx, "ONE.example.test:443") != known || takePreparedDNS(ctx, "one.example.test:443") != nil {
		t.Fatal("handoff not consumed exactly once")
	}
	prepareDNS(ctx, known, target, true)
	ch.nextDNSHop(&url.URL{Scheme: "https", Host: "one.example.test"})
	ch.nextDNSHop(&url.URL{Scheme: "https", Host: "one.example.test"})
	if preparedDNSFor(ctx, target.host) != nil {
		t.Fatal("lookup survived another hop")
	}
	for _, address := range []string{"other.example.test:443", "one.example.test:8443", "not-an-address"} {
		prepareDNS(ctx, known, target, false)
		if takePreparedDNS(ctx, address) != nil || preparedDNSFor(ctx, target.host) != nil {
			t.Fatalf("mismatched destination retained lookup:%s", address)
		}
	}
	prepareDNS(ctx, known, target, true)
	ch.nextDNSHop(&url.URL{Scheme: "http", Host: "one.example.test"})
	if preparedDNSFor(ctx, target.host) != nil {
		t.Fatal("wrong redirect retained lookup")
	}
}

func TestA12DNSHandoffPreservesLookupErrorsWithoutNetwork(t *testing.T) {
	target := originOf(&url.URL{Scheme: "https", Host: "failed.example.test"})
	sentinel := errors.New("owned address lookup failed")
	known := &resolvedName{host: target.host, err: sentinel}
	ch := &chain{}
	ctx := context.WithValue(context.Background(), chainKey{}, ch)
	r := newResolving("127.0.0.1:1", chromeDNS(t))
	prepareDNS(ctx, known, target, false)
	if addrs, err := r.lookupNames(ctx, target.host); addrs != nil || !errors.Is(err, sentinel) {
		t.Fatalf("cached failure:%v,%v", addrs, err)
	}
	resolved, endpoint, ok := r.quicEndpoint(ctx, "failed.example.test:443")
	if ok || len(endpoint.Addrs) != 0 || resolvedFor(resolved, target.host) != known {
		t.Fatal("failed lookup became QUIC endpoint")
	}
	dialer := newDirectDialer(0, nil)
	dialer.resolving = r
	if conn, err := dialer.DialContext(resolved, "tcp", "failed.example.test:443"); conn != nil || !errors.Is(err, sentinel) {
		t.Fatalf("TCP did not preserve lookup error:%v,%v", conn, err)
	}
}
