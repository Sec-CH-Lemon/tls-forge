package tlsforge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/utls/behavior"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsRecord is an answer of dnsFake's: an address, a CNAME or an HTTPS
// record of a name.
type dnsRecord struct {
	name  string
	ttl   uint32
	a     netip.Addr
	cname string
	https *dnsmessage.SVCBResource
}

// dnsFake answers DNS queries over UDP and TCP on one port, as answer says:
// the records, how late, and the code; it keeps what it was asked.
type dnsFake struct {
	addr   string
	mu     sync.Mutex
	asked  []string // "TYPE name", in the order asked
	answer func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode)
	// truncated has every UDP answer say it is cut short, with nothing in it.
	truncated bool
}

func startDNS(t *testing.T, answer func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode)) *dnsFake {
	t.Helper()
	f := &dnsFake{answer: answer}
	for {
		udp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)).String())
		if err != nil {
			_ = udp.Close()
			continue
		}
		t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
		f.addr = tcp.Addr().String()
		go func() {
			for {
				buf := make([]byte, 65535)
				n, from, err := udp.ReadFrom(buf)
				if err != nil {
					return
				}
				go func(q []byte) {
					if reply := f.reply(q, true); reply != nil {
						_, _ = udp.WriteTo(reply, from)
					}
				}(buf[:n])
			}
		}()
		go func() {
			for {
				c, err := tcp.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					for {
						var size [2]byte
						if _, err := io.ReadFull(c, size[:]); err != nil {
							return
						}
						q := make([]byte, binary.BigEndian.Uint16(size[:]))
						if _, err := io.ReadFull(c, q); err != nil {
							return
						}
						if reply := f.reply(q, false); reply != nil {
							_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...))
						}
					}
				}()
			}
		}()
		return f
	}
}

func (f *dnsFake) reply(query []byte, udp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	f.mu.Lock()
	f.asked = append(f.asked, q.Type.String()[4:]+" "+q.Name.String())
	truncated := f.truncated && udp
	f.mu.Unlock()
	records, delay, rcode := f.answer(q)
	time.Sleep(delay)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, RCode: rcode, Truncated: truncated})
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	for _, r := range records {
		if truncated {
			break
		}
		rh := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(fqdn(r.name)), Class: dnsmessage.ClassINET, TTL: r.ttl}
		switch {
		case r.a.Is4():
			_ = b.AResource(rh, dnsmessage.AResource{A: r.a.As4()})
		case r.cname != "":
			_ = b.CNAMEResource(rh, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(fqdn(r.cname))})
		case r.https != nil:
			_ = b.HTTPSResource(rh, dnsmessage.HTTPSResource{SVCBResource: *r.https})
		}
	}
	out, _ := b.Finish()
	return out
}

func (f *dnsFake) queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

// service is a ServiceMode record of priority, target, and params.
func service(priority uint16, target string, params ...dnsmessage.SVCParam) *dnsmessage.SVCBResource {
	if target != "." {
		target = fqdn(target)
	}
	r := &dnsmessage.SVCBResource{Priority: priority, Target: dnsmessage.MustNewName(target)}
	for _, p := range params {
		r.SetParam(p.Key, p.Value)
	}
	return r
}

func alpnParam(protocols ...string) dnsmessage.SVCParam {
	var v []byte
	for _, p := range protocols {
		v = append(append(v, byte(len(p))), p...)
	}
	return dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: v}
}

func echParam(configs string) dnsmessage.SVCParam {
	return dnsmessage.SVCParam{Key: dnsmessage.SVCParamECH, Value: []byte(configs)}
}

// replyOf is the answer to the HTTPS query for name: rcode and records.
func replyOf(t *testing.T, name string, rcode dnsmessage.RCode, records ...dnsRecord) []byte {
	t.Helper()
	f := &dnsFake{answer: func(dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		return records, 0, rcode
	}}
	query, _, err := httpsQuery(name)
	if err != nil {
		t.Fatal(err)
	}
	return f.reply(query, false)
}

func TestTheHTTPSRecordsOfANameAreReadAsChromeReadsThem(t *testing.T) {
	const host = "www.example.test"
	h2 := alpnParam("h2")
	mandatory := func(keys ...uint16) dnsmessage.SVCParam {
		var v []byte
		for _, k := range keys {
			v = binary.BigEndian.AppendUint16(v, k)
		}
		return dnsmessage.SVCParam{Key: 0, Value: v}
	}
	port := func(n uint16) dnsmessage.SVCParam {
		return dnsmessage.SVCParam{Key: dnsmessage.SVCParamPort, Value: binary.BigEndian.AppendUint16(nil, n)}
	}
	noDefault := dnsmessage.SVCParam{Key: dnsmessage.SVCParamNoDefaultALPN}
	prefixed := "_8443._https." + host
	for _, tc := range []struct {
		name    string
		asked   string // the name asked about: host, or prefixed
		port    int
		rcode   dnsmessage.RCode
		records []dnsRecord
		record  bool
		configs string
		ttl     time.Duration
	}{
		{"no record", host, 443, dnsmessage.RCodeSuccess, nil, false, "", 0},
		{"no such name", host, 443, dnsmessage.RCodeNameError, nil, false, "", 0},
		{"\".\" for the name itself", host, 443, 0, []dnsRecord{{name: host, ttl: 300,
			https: service(1, ".", h2, echParam("A"))}}, true, "A", 300 * time.Second},
		{"the name itself", host, 443, 0, []dnsRecord{{name: host, https: service(1, host, h2, echParam("A"))}}, true, "A", 0},
		{"another target", host, 443, 0, []dnsRecord{{name: host, https: service(1, "cdn.test", h2, echParam("A"))}},
			true, "", 0},
		{"\".\" for a name of a port: its own name", prefixed, 8443, 0, []dnsRecord{{name: prefixed,
			https: service(1, ".", h2, echParam("A"))}}, true, "", 0},
		{"the server for a name of a port", prefixed, 8443, 0, []dnsRecord{{name: prefixed,
			https: service(1, host, h2, echParam("A"))}}, true, "A", 0},
		{"another name's record", host, 443, 0, []dnsRecord{{name: "other.test", https: service(1, ".", echParam("A"))}},
			false, "", 0},
		{"the lowest priority", host, 443, 0, []dnsRecord{{name: host, ttl: 60, https: service(2, ".", echParam("B"))},
			{name: host, ttl: 30, https: service(1, ".", echParam("A"))}, {name: host, ttl: 40, https: service(1, ".", echParam("C"))}},
			true, "A", 30 * time.Second},
		{"no ech", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".", h2)}}, true, "", 0},
		{"an alias leaves nothing", host, 443, 0, []dnsRecord{{name: host, https: service(0, "cdn.test")},
			{name: host, https: service(1, ".", echParam("A"))}}, true, "", 0},
		{"a mandatory parameter Chrome knows", host, 443, 0, []dnsRecord{{name: host,
			https: service(1, ".", mandatory(1, 5), h2, echParam("A"))}}, true, "A", 0},
		{"a mandatory parameter Chrome does not know", host, 443, 0, []dnsRecord{{name: host,
			https: service(1, ".", mandatory(7), echParam("A"))}}, false, "", 0},
		{"its port", prefixed, 8443, 0, []dnsRecord{{name: prefixed, https: service(1, host, port(8443), echParam("A"))}},
			true, "A", 0},
		{"another port", prefixed, 8443, 0, []dnsRecord{{name: prefixed, https: service(1, host, port(9443), echParam("A"))}},
			true, "", 0},
		{"a port of no length", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".",
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamPort, Value: []byte{1}}, echParam("A"))}}, true, "", 0},
		{"a port of three bytes", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".",
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamPort, Value: []byte{0x01, 0xbb, 0}}, echParam("A"))}}, true, "", 0},
		// Every record without the default ALPN: none is taken
		// (ExtractHttpsResults; measured for h3 alone, bench/h3 h3only).
		{"HTTP/3 alone", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".", alpnParam("h3"), noDefault,
			echParam("A"))}}, true, "", 0},
		{"HTTP/2 without the default", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".", alpnParam("h3", "h2"),
			noDefault, echParam("A"))}}, true, "", 0},
		{"HTTP/1.1 without the default", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".",
			alpnParam("http/1.1"), noDefault, echParam("A"))}}, true, "", 0},
		{"no ALPN at all", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".", noDefault, echParam("A"))}},
			true, "", 0},
		{"an ALPN cut short", host, 443, 0, []dnsRecord{{name: host, https: service(1, ".", noDefault,
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: []byte{9, 'h'}}, echParam("A"))}}, true, "", 0},
		{"through CNAMEs", host, 443, 0, []dnsRecord{{name: host, cname: "a.cdn.test", ttl: 20},
			{name: "a.cdn.test", cname: "b.cdn.test"}, {name: "b.cdn.test", ttl: 10, https: service(1, ".", echParam("A"))}},
			true, "A", 10 * time.Second},
		{"through CNAMEs, the server named", host, 443, 0, []dnsRecord{{name: host, cname: "b.cdn.test"},
			{name: "b.cdn.test", https: service(1, host, echParam("A"))}}, true, "", 0},
	} {
		got := httpsOf(replyOf(t, tc.asked, tc.rcode, tc.records...), host, tc.asked, tc.port)
		if got.err != nil || got.record != tc.record || string(got.configs) != tc.configs || got.ttl != tc.ttl {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
	// The record a QUIC connection takes: the one of the lowest priority, of
	// those a TCP connection could take but for their protocols, whose alpn
	// names h3 (QuicSessionPool::SelectQuicVersion), and its configs.
	for _, tc := range []struct {
		name      string
		asked     string
		port      int
		records   []dnsRecord
		configs   string // the TCP connection's
		h3        bool
		h3configs string
	}{
		{"h2 alone", host, 443, []dnsRecord{{name: host, https: service(1, ".", h2, echParam("A"))}}, "A", false, ""},
		{"h3 alone without the default", host, 443, []dnsRecord{{name: host, https: service(1, ".", alpnParam("h3"),
			noDefault, echParam("A"))}}, "", false, ""},
		{"one without the default and one with", host, 443, []dnsRecord{
			{name: host, https: service(1, ".", alpnParam("h3"), noDefault, echParam("B"))},
			{name: host, https: service(2, ".", h2, echParam("A"))}}, "A", true, "B"},
		{"one with the default and one without", host, 443, []dnsRecord{
			{name: host, https: service(1, ".", h2, echParam("A"))},
			{name: host, https: service(2, ".", alpnParam("h3"), noDefault, echParam("B"))}}, "A", true, "B"},
		{"HTTP/2 without the default beside one with", host, 443, []dnsRecord{
			{name: host, https: service(1, ".", alpnParam("h2"), noDefault, echParam("B"))},
			{name: host, https: service(2, ".", alpnParam("h3"), echParam("A"))}}, "B", true, "A"},
		{"h3 and h2", host, 443, []dnsRecord{{name: host, https: service(1, ".", alpnParam("h3", "h2"),
			echParam("A"))}}, "A", true, "A"},
		{"h3 with the default", host, 443, []dnsRecord{{name: host, https: service(1, ".", alpnParam("h3"),
			echParam("A"))}}, "A", true, "A"},
		{"h3 at a priority of its own", host, 443, []dnsRecord{
			{name: host, https: service(1, ".", h2, echParam("A"))},
			{name: host, https: service(3, ".", alpnParam("h3"), echParam("C"))},
			{name: host, https: service(2, ".", alpnParam("h3", "h2"), echParam("B"))}}, "A", true, "B"},
		{"h3 of the name of a port", prefixed, 8443, []dnsRecord{{name: prefixed,
			https: service(1, host, alpnParam("h3", "h2"), echParam("A"))}}, "A", true, "A"},
		{"h3 for another port", prefixed, 8443, []dnsRecord{{name: prefixed,
			https: service(1, host, alpnParam("h3", "h2"), port(9443), echParam("A"))}}, "", false, ""},
		{"h3 of another target", host, 443, []dnsRecord{{name: host,
			https: service(1, "cdn.test", alpnParam("h3", "h2"), echParam("A"))}}, "", false, ""},
		{"h3 beside an alias", host, 443, []dnsRecord{{name: host, https: service(0, "cdn.test")},
			{name: host, https: service(1, ".", alpnParam("h3", "h2"), echParam("A"))}}, "", false, ""},
		{"h3 without ech", host, 443, []dnsRecord{{name: host, https: service(1, ".", alpnParam("h3", "h2"))}},
			"", true, ""},
	} {
		got := httpsOf(replyOf(t, tc.asked, 0, tc.records...), host, tc.asked, tc.port)
		if got.err != nil || !got.record || string(got.configs) != tc.configs || got.h3 != tc.h3 || string(got.h3configs) != tc.h3configs {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
	// A name in capitals is the name.
	if got := httpsOf(replyOf(t, host, 0, dnsRecord{name: host, https: service(1, ".", echParam("A"))}), "WWW.Example.TEST",
		"WWW.Example.TEST", 443); string(got.configs) != "A" {
		t.Errorf("a name in capitals: %+v", got)
	}
	// An answer that does not read, or says the server failed, is an error.
	good := replyOf(t, host, 0, dnsRecord{name: host, https: service(1, ".", echParam("A"))})
	for name, reply := range map[string][]byte{
		"cut short":          good[:len(good)-3],
		"no header":          good[:5],
		"a question cut":     good[:15],
		"a server's failure": replyOf(t, host, dnsmessage.RCodeServerFailure),
		"a record cut short": func() []byte {
			b := slices.Clone(good)
			return b[:len(b)-1]
		}(),
	} {
		if got := httpsOf(reply, host, host, 443); got.err == nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// A CNAME and an A record that do not read.
	cname := replyOf(t, host, 0, dnsRecord{name: host, cname: "x.test"})
	if got := httpsOf(cname[:len(cname)-2], host, host, 443); got.err == nil {
		t.Errorf("a CNAME cut short: %+v", got)
	}
	a := replyOf(t, host, 0, dnsRecord{name: host, a: netip.MustParseAddr("192.0.2.1")})
	if got := httpsOf(a, host, host, 443); got.err != nil || got.record {
		t.Errorf("an address passed over: %+v", got)
	}
}

func TestTheNameAskedAboutIsThePortsAsChromesIs(t *testing.T) {
	for _, tc := range []struct {
		port int
		want string
	}{{443, "www.example.test"}, {8443, "_8443._https.www.example.test"}, {80, "_80._https.www.example.test"}} {
		if got := httpsQueryName("www.example.test", tc.port); got != tc.want {
			t.Errorf("%d: %q", tc.port, got)
		}
	}
	namingServers(t, "192.0.2.53:53")
	r := newResolving("", chromeDNS(t))
	for host, want := range map[string]bool{
		"www.example.test": true, "": false, "192.0.2.1": false, "::1": false, "localhost": false,
		"LOCALHOST.": false, "app.localhost": false, "printer.local": false, "local.example.test": true,
	} {
		if got := r.asksFor(host); got != want {
			t.Errorf("%q: %v", host, got)
		}
	}
	if newResolving("", nil).asksFor("www.example.test") {
		t.Error("a profile that asks for no records asks")
	}
	var none *resolving
	if none.ask(context.Background(), "www.example.test:443") != nil {
		t.Error("no resolving asked")
	}
	for _, address := range []string{"www.example.test", "www.example.test:https", "192.0.2.1:443"} {
		if r.ask(context.Background(), address) != nil {
			t.Errorf("%q asked", address)
		}
	}
}

func TestTheResolverIsTheOneChromesHostResolverWouldUse(t *testing.T) {
	// A profile of the built-in resolver asks the network's names itself,
	// and leaves localhost, the names under it and under .local, and
	// addresses to the machine, as Chrome does.
	namingServers(t, "192.0.2.53:53")
	r := newResolving("", chromeDNS(t))
	if r.resolver != builtInResolver || !r.https {
		t.Fatalf("built-in: %v, records %v", r.resolver, r.https)
	}
	for host, own := range map[string]bool{
		"www.example.test": true, "WWW.Example.Test.": true, "local.example.test": true, "localhost.example.test": true,
		"www.carlocal": true, "www.notlocalhost": true,
		"": false, "localhost": false, "LOCALHOST.": false, "app.localhost": false, "printer.local": false,
		"printer.local.": false, "192.0.2.1": false, "::1": false,
	} {
		if got := r.resolverFor(host) == builtInResolver; got != own {
			t.Errorf("%q: its own %v", host, got)
		}
		if !own && r.resolverFor(host) != machineResolver {
			t.Errorf("%q: not the machine's", host)
		}
	}
	// A server named answers every name.
	named := newResolving("192.0.2.53:53", chromeDNS(t))
	if named.resolver == builtInResolver || named.resolver == machineResolver || !named.https {
		t.Fatal("the server's")
	}
	for _, host := range []string{"www.example.test", "localhost", "printer.local"} {
		if named.resolverFor(host) != named.resolver {
			t.Errorf("%q: not the server's", host)
		}
	}
	// Where the machine names no server, the built-in client cannot ask:
	// the machine's resolver answers, and no record is asked for.
	namingServers(t)
	none := newResolving("", chromeDNS(t))
	if none.resolver != machineResolver || none.https || none.ask(context.Background(), "www.example.test:443") != nil {
		t.Errorf("no server named: %v, records %v", none.resolver, none.https)
	}
	// A profile of the machine's resolver, and one that says nothing.
	namingServers(t, "192.0.2.53:53")
	system := behavior.Policy{"dns.resolver": []byte(`"system"`)}
	for _, p := range []behavior.Policy{system, nil} {
		if r := newResolving("", p); r.resolver != machineResolver || r.https {
			t.Errorf("%s: %v, records %v", p, r.resolver, r.https)
		}
	}
}

func TestTheBuiltInResolverAsksTheMachinesServers(t *testing.T) {
	// Its queries go where Go's resolver sends them, the machine's servers,
	// through dialDNS; a name the hosts file or the server knows is found.
	f := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		if q.Type == dnsmessage.TypeA && strings.HasSuffix(q.Name.String(), ".example.test.") {
			return []dnsRecord{{name: strings.TrimSuffix(q.Name.String(), "."), ttl: 60,
				a: netip.MustParseAddr("192.0.2.7")}}, 0, 0
		}
		return nil, 0, 0
	})
	var mu sync.Mutex
	var dialed []string
	real := dialDNS
	t.Cleanup(func() { dialDNS = real })
	dialDNS = func(ctx context.Context, network, server string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network+" "+server)
		mu.Unlock()
		return real(ctx, network, f.addr)
	}
	namingServers(t, "192.0.2.53:53")
	r := newResolving("", chromeDNS(t))
	got, err := r.lookupNames(context.Background(), "www.example.test")
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.7")}) {
		t.Fatalf("%v %v", got, err)
	}
	if q := f.queries(); !slices.Contains(q, "A www.example.test.") {
		t.Errorf("asked %v", q)
	}
	mu.Lock()
	if len(dialed) == 0 {
		t.Error("no server dialed")
	}
	dialed = nil
	mu.Unlock()
	// A name under .local is the machine's to find, whatever it finds.
	was := machineResolver
	t.Cleanup(func() { machineResolver = was })
	var machine atomic.Int32
	machineResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		machine.Add(1)
		return nil, errors.New("the machine's")
	}}
	_, _ = r.lookupNames(context.Background(), "printer.local")
	mu.Lock()
	defer mu.Unlock()
	if machine.Load() == 0 || len(dialed) != 0 {
		t.Errorf("printer.local: the machine asked %d times, the client's own %v", machine.Load(), dialed)
	}
}

// namingServers has the machine name servers for the test: the HTTPS
// records' servers, and whether a profile's built-in resolver can ask.
func namingServers(t *testing.T, servers ...string) {
	t.Helper()
	was := systemDNSServers
	t.Cleanup(func() { systemDNSServers = was })
	systemDNSServers = func() []string { return servers }
}

// chromeDNS is the DNS policy of Chrome's profiles.
func chromeDNS(t *testing.T) behavior.Policy {
	t.Helper()
	p := behavior.Policy{}
	for k, v := range map[string]string{"dns.https_records": "true", "dns.https_wait_percent": "20",
		"dns.https_wait_min_ms": "5", "dns.https_wait_max_ms": "50", "dns.resolver": `"built-in"`} {
		p[k] = []byte(v)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheRecordsAreWaitedForAsChromeWaits(t *testing.T) {
	r := newResolving("", chromeDNS(t))
	for _, tc := range []struct{ elapsed, want time.Duration }{
		{0, 5 * time.Millisecond},
		{10 * time.Millisecond, 5 * time.Millisecond},
		{100 * time.Millisecond, 20 * time.Millisecond},
		{250 * time.Millisecond, 50 * time.Millisecond},
		{10 * time.Second, 50 * time.Millisecond},
	} {
		if got := r.wait(tc.elapsed); got != tc.want {
			t.Errorf("after %v: %v, want %v", tc.elapsed, got, tc.want)
		}
	}
	p := chromeDNS(t)
	p["dns.https_wait_max_ms"] = []byte("0")
	if got := newResolving("", p).wait(10 * time.Second); got != 2*time.Second {
		t.Errorf("no ceiling: %v", got)
	}
}

func TestADNSServerIsAnAddressWithAPort(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "192.0.2.1": "192.0.2.1:53", "192.0.2.1:5353": "192.0.2.1:5353", "::1": "[::1]:53",
		"[::1]": "[::1]:53", "[::1]:5353": "[::1]:5353",
	} {
		if got, err := dnsServerOf(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"dns.example.test", "192.0.2.1:0", "192.0.2.1:x", "[::1]:"} {
		if got, err := dnsServerOf(in); err == nil || !strings.Contains(err.Error(), "no IP address") {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	if _, err := New(WithDNSServer("dns.example.test")); err == nil {
		t.Error("a client takes a DNS server of no address")
	}
}

func TestAQueryForHTTPSRecordsIsAsChromesResolverAsks(t *testing.T) {
	query, id, err := httpsQuery("_8443._https.www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.ID != id || !h.RecursionDesired || h.Response {
		t.Fatalf("header %+v, %v", h, err)
	}
	q, err := p.Question()
	if err != nil || q.Name.String() != "_8443._https.www.example.test." || q.Type != dnsmessage.TypeHTTPS ||
		q.Class != dnsmessage.ClassINET {
		t.Fatalf("question %+v, %v", q, err)
	}
	_ = p.SkipAllQuestions()
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	opt, err := p.AdditionalHeader()
	if err != nil || opt.Type != dnsmessage.TypeOPT || opt.Class != 4096 {
		t.Errorf("EDNS0 %+v, %v", opt, err)
	}
	for _, name := range []string{strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 130) + "test"} {
		if _, _, err := httpsQuery(name); err == nil || !strings.Contains(err.Error(), "is no name to ask about") {
			t.Errorf("%d bytes: %v", len(name), err)
		}
	}
}

func TestAnHTTPSQueryGoesOverUDPAndOverTCPWhenCutShort(t *testing.T) {
	answer := func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		return []dnsRecord{{name: "www.example.test", https: service(1, ".", echParam("A"))}}, 0, 0
	}
	for _, truncated := range []bool{false, true} {
		f := startDNS(t, answer)
		f.mu.Lock()
		f.truncated = truncated
		f.mu.Unlock()
		r := newResolving(f.addr, chromeDNS(t))
		got := r.httpsRecords(context.Background(), "www.example.test", 443)
		if got.err != nil || string(got.configs) != "A" {
			t.Errorf("cut short %v: %+v", truncated, got)
		}
		want := []string{"HTTPS www.example.test."}
		if truncated {
			want = append(want, want[0])
		}
		if !slices.Equal(f.queries(), want) {
			t.Errorf("cut short %v: asked %v", truncated, f.queries())
		}
	}
}

func TestAnAnswerToAnotherQueryIsNotTheQuerys(t *testing.T) {
	// A server that answers with another ID: over UDP the next datagram may be
	// the answer, over TCP the query has none.
	for _, network := range []string{"udp", "tcp"} {
		var ln net.Listener
		var pc net.PacketConn
		var err error
		if network == "udp" {
			pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		} else {
			ln, err = net.Listen("tcp", "127.0.0.1:0")
		}
		if err != nil {
			t.Fatal(err)
		}
		query, id, _ := httpsQuery("www.example.test")
		wrong := slices.Clone(query)
		binary.BigEndian.PutUint16(wrong, id+1)
		wrong[2] |= 0x80
		right := slices.Clone(query)
		right[2] |= 0x80
		var addr string
		if network == "udp" {
			addr = pc.LocalAddr().String()
			go func() {
				buf := make([]byte, 512)
				_, from, err := pc.ReadFrom(buf)
				if err == nil {
					_, _ = pc.WriteTo(wrong, from)
					_, _ = pc.WriteTo(right[:5], from)
					_, _ = pc.WriteTo(query, from) // no answer: the response bit unset
					_, _ = pc.WriteTo(right, from)
				}
			}()
		} else {
			addr = ln.Addr().String()
			go func() {
				c, err := ln.Accept()
				if err == nil {
					buf := make([]byte, 512)
					_, _ = c.Read(buf)
					_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(wrong))), wrong...))
					time.Sleep(100 * time.Millisecond)
					_ = c.Close()
				}
			}()
		}
		got, err := exchangeOver(context.Background(), network, addr, query, id)
		if network == "udp" && (err != nil || binary.BigEndian.Uint16(got) != id || got[2]&0x80 == 0) {
			t.Errorf("udp: %x, %v", got, err)
		}
		if network == "tcp" && (err == nil || !strings.Contains(err.Error(), "answered another query")) {
			t.Errorf("tcp: %x, %v", got, err)
		}
		if pc != nil {
			_ = pc.Close()
		}
		if ln != nil {
			_ = ln.Close()
		}
	}
}

func TestAServerThatDoesNotAnswerIsGivenUp(t *testing.T) {
	// The query goes to the next server; and nothing answers past the
	// context, or a server's own time.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	f := startDNS(t, func(dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		return []dnsRecord{{name: "www.example.test", https: service(1, ".", echParam("A"))}}, 0, 0
	})
	real := exchangeDNS
	defer func() { exchangeDNS = real }()
	namingServers(t, "127.0.0.1:53", "127.0.0.2:53")
	var tried []string
	exchangeDNS = func(ctx context.Context, server string, query []byte, id uint16) ([]byte, error) {
		tried = append(tried, server)
		if server == "127.0.0.1:53" {
			return nil, errors.New("refused")
		}
		return exchangeOver(ctx, "udp", f.addr, query, id)
	}
	got := newResolving("", chromeDNS(t)).httpsRecords(context.Background(), "www.example.test", 443)
	if got.err != nil || string(got.configs) != "A" || !slices.Equal(tried, []string{"127.0.0.1:53", "127.0.0.2:53"}) {
		t.Errorf("%+v after %v", got, tried)
	}
	// Every server failing says why each did, and a context that ends stops
	// asking.
	tried = nil
	exchangeDNS = func(ctx context.Context, server string, query []byte, id uint16) ([]byte, error) {
		tried = append(tried, server)
		return nil, errors.New("no " + server)
	}
	got = newResolving("", chromeDNS(t)).httpsRecords(context.Background(), "www.example.test", 443)
	if got.err == nil || !strings.Contains(got.err.Error(), "no 127.0.0.2:53") || len(tried) != 2 {
		t.Errorf("%+v after %v", got, tried)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tried = nil
	if got = newResolving("", chromeDNS(t)).httpsRecords(ctx, "www.example.test", 443); got.err == nil || len(tried) != 1 {
		t.Errorf("an ended context: %+v after %v", got, tried)
	}
	if got = newResolving("", chromeDNS(t)).httpsRecords(ctx, strings.Repeat("a", 64)+".test", 443); got.err == nil {
		t.Errorf("a name that is no name: %+v", got)
	}
	exchangeDNS = real
	// A server that never answers is given up at the context's end.
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	began := time.Now()
	if _, err := exchangeDNS(ctx, pc.LocalAddr().String(), []byte{0, 1, 2}, 1); err == nil || time.Since(began) > time.Second {
		t.Errorf("%v after %v", err, time.Since(began))
	}
	if _, err := exchangeOver(ctx, "tcp", "127.0.0.1:1", []byte{0}, 1); err == nil {
		t.Error("a server that refuses answered")
	}
	// A query that cannot be sent (larger than a datagram) and a server that
	// hangs up without a word.
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exchangeOver(ctx, "udp", pc.LocalAddr().String(), make([]byte, 70000), 1); err == nil ||
		errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a query larger than a datagram: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_, _ = c.Read(make([]byte, 64))
			_ = c.Close()
		}
	}()
	if _, err := exchangeOver(ctx, "tcp", ln.Addr().String(), []byte{0, 1, 2}, 1); err == nil {
		t.Error("a server that hung up answered")
	}
}

func TestALookupGivesWhatCameInTime(t *testing.T) {
	// A dial whose context ends while it waits takes nothing; the hook of a
	// dialer that has one of its own runs that too.
	f := startDNS(t, func(dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		return []dnsRecord{{name: "www.example.test", https: service(1, ".", echParam("A"))}}, time.Second, 0
	})
	r := newResolving(f.addr, chromeDNS(t))
	l := r.ask(context.Background(), "www.example.test:443")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	hook := l.control(func(context.Context, string, string, syscall.RawConn) error { called = true; return nil })
	if err := hook(ctx, "tcp", "127.0.0.1:443", nil); err != nil || !called || l.taken != nil || l.record {
		t.Errorf("%v, called %v, taken %q", err, called, l.taken)
	}
}

func TestPlainHTTPGoesToHTTPSWhereARecordSays(t *testing.T) {
	f := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		name := strings.TrimSuffix(q.Name.String(), ".")
		switch {
		case q.Type == dnsmessage.TypeA && strings.HasSuffix(name, ".example.test") && name != "gone.example.test":
			return []dnsRecord{{name: name, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
		case q.Type == dnsmessage.TypeHTTPS && (name == "www.example.test" || name == "_8443._https.www.example.test"):
			return []dnsRecord{{name: name, https: service(1, ".", alpnParam("h2"))}}, 0, 0
		}
		return nil, 0, dnsmessage.RCodeNameError
	})
	sent := 0
	next := roundTripFunc(func(*fhttp.Request) (*fhttp.Response, error) { sent++; return &fhttp.Response{StatusCode: 200}, nil })
	u := dnsUpgrade{newResolving(f.addr, chromeDNS(t)), next}
	for _, tc := range []struct {
		url, to string
	}{
		{"http://www.example.test/x?y=1", "https://www.example.test/x?y=1"},
		{"http://www.example.test:80/x", "https://www.example.test/x"},
		{"http://www.example.test:8443/x", "https://www.example.test:8443/x"},
		{"http://www.example.test:8080/x", ""}, // no record of that port
		{"http://gone.example.test/x", ""},     // no address: no request at all
		{"http://127.0.0.1/x", ""},             // an address
		{"https://www.example.test/x", ""},     // already https
	} {
		req, err := fhttp.NewRequest("GET", tc.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		withPort(req)
		before := sent
		res, err := u.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if tc.to == "" {
			if sent != before+1 || res.StatusCode != 200 {
				t.Errorf("%s: sent %d, %d", tc.url, sent-before, res.StatusCode)
			}
			continue
		}
		if sent != before || res.StatusCode != 307 || res.Header.Get("Location") != tc.to ||
			res.Header.Get("Non-Authoritative-Reason") != "DNS" || res.Request != req {
			t.Errorf("%s: %d %v", tc.url, res.StatusCode, res.Header)
		}
	}
	// No resolving: nothing goes to https.
	if res, err := (dnsUpgrade{nil, next}).RoundTrip(must(fhttp.NewRequest("GET", "http://www.example.test/", nil))); err != nil ||
		res.StatusCode != 200 {
		t.Errorf("no resolving: %v", err)
	}
}

type roundTripFunc func(*fhttp.Request) (*fhttp.Response, error)

func (f roundTripFunc) RoundTrip(r *fhttp.Request) (*fhttp.Response, error) { return f(r) }

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestRecordsAreKeptForTheirTimeToLive(t *testing.T) {
	// A record is asked for once while it lives; an answer of none, or of no
	// time to live, is asked for again.
	var ttl atomic.Uint32
	var none atomic.Bool
	ttl.Store(60)
	f := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		if none.Load() {
			return nil, 0, 0
		}
		return []dnsRecord{{name: "www.example.test", ttl: ttl.Load(), https: service(1, ".", echParam("A"))}}, 0, 0
	})
	r := newResolving(f.addr, chromeDNS(t))
	ask := func() string {
		l := r.ask(context.Background(), "www.example.test:443")
		<-l.done
		return string(l.answer.configs)
	}
	asked := func() int {
		n := 0
		for _, q := range f.queries() {
			if strings.HasPrefix(q, "HTTPS") {
				n++
			}
		}
		return n
	}
	first, again := ask(), ask()
	if first != "A" || again != "A" || asked() != 1 {
		t.Fatalf("asked %d times", asked())
	}
	// Past its time.
	r.mu.Lock()
	kept := r.kept["www.example.test"]
	kept.until = time.Now().Add(-time.Second)
	r.kept["www.example.test"] = kept
	r.mu.Unlock()
	if ask() != "A" || asked() != 2 {
		t.Errorf("past its time: asked %d times", asked())
	}
	// No time to live, and no record.
	r = newResolving(f.addr, chromeDNS(t))
	ttl.Store(0)
	ask()
	ask()
	if asked() != 4 || len(r.kept) != 0 {
		t.Errorf("no time to live: asked %d times, kept %v", asked(), r.kept)
	}
	none.Store(true)
	r = newResolving(f.addr, chromeDNS(t))
	ask()
	ask()
	if asked() != 6 || len(r.kept) != 0 {
		t.Errorf("no record: asked %d times, kept %v", asked(), r.kept)
	}
}
