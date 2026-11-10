package tlsforge

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	"golang.org/x/net/dns/dnsmessage"
)

type a12DNSPacket struct {
	Network string
	At      time.Time
	Raw     []byte
}
type a12DNSWire struct {
	addr    string
	mu      sync.Mutex
	packets []a12DNSPacket
	seen    chan string
}
type a12DNSMode struct {
	truncate, wrongID, blackhole bool
	records                      bool
}

type a12DNSCloseObserverKey struct{}

// Install the observer before any test starts. Only a request carrying this
// private context value is observed; DNS goroutines can finish after Do returns
// without racing a per-test replacement/restoration of the shared dial seam.
func init() {
	realDial := dialDNS
	dialDNS = func(ctx context.Context, network, server string) (net.Conn, error) {
		conn, err := realDial(ctx, network, server)
		closed, observe := ctx.Value(a12DNSCloseObserverKey{}).(chan string)
		if err == nil && observe {
			return &a12ClosingDNSConn{Conn: conn, network: network, closed: closed}, nil
		}
		return conn, err
	}
}

func (p *a12DNSWire) record(network string, raw []byte) {
	p.mu.Lock()
	p.packets = append(p.packets, a12DNSPacket{network, time.Now(), bytes.Clone(raw)})
	p.mu.Unlock()
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err == nil {
		if q, err := parser.Question(); err == nil && q.Type == dnsmessage.TypeHTTPS {
			select {
			case p.seen <- network:
			default:
			}
		}
	}
}
func (p *a12DNSWire) snapshot() []a12DNSPacket {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.packets)
}

// The observer receives original DNS bytes independently of any profile. Its
// backend supplies fixed owned addresses/records; it never receives expected RD,
// payload or timeout values from the client being checked.
func startA12DNSWire(t *testing.T, mode a12DNSMode) *a12DNSWire {
	t.Helper()
	backend := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		name := strings.TrimSuffix(q.Name.String(), ".")
		switch q.Type {
		case dnsmessage.TypeA:
			return []dnsRecord{{name: name, ttl: 30, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
		case dnsmessage.TypeHTTPS:
			if mode.records {
				return []dnsRecord{{name: name, ttl: 30, https: service(1, name, alpnParam("h2", "http/1.1"))}}, 0, 0
			}
		}
		return nil, 0, 0
	})
	var udp net.PacketConn
	var tcp net.Listener
	var err error
	for {
		udp, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err = net.Listen("tcp", udp.LocalAddr().String())
		if err == nil {
			break
		}
		_ = udp.Close()
	}
	p := &a12DNSWire{addr: udp.LocalAddr().String(), seen: make(chan string, 16)}
	t.Cleanup(func() {
		if t.Failed() {
			a12KeepDNS(t, p)
		}
	})
	done := make(chan struct{})
	var connsMu sync.Mutex
	conns := map[net.Conn]bool{}
	t.Cleanup(func() {
		close(done)
		_ = udp.Close()
		_ = tcp.Close()
		connsMu.Lock()
		defer connsMu.Unlock()
		for c := range conns {
			_ = c.Close()
		}
	})
	isHTTPS := func(raw []byte) bool {
		var parser dnsmessage.Parser
		if _, err := parser.Start(raw); err != nil {
			return false
		}
		q, err := parser.Question()
		return err == nil && q.Type == dnsmessage.TypeHTTPS
	}
	go func() {
		for {
			raw := make([]byte, 65535)
			n, from, err := udp.ReadFrom(raw)
			if err != nil {
				return
			}
			raw = raw[:n]
			p.record("udp", raw)
			go func(raw []byte, from net.Addr) {
				if isHTTPS(raw) && mode.truncate {
					reply := bytes.Clone(raw)
					reply[2] |= 0x82
					reply[3] |= 0x80
					_, _ = udp.WriteTo(reply, from)
					return
				}
				if isHTTPS(raw) && mode.blackhole {
					return
				}
				c, err := net.DialTimeout("udp", backend.addr, time.Second)
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				if _, err = c.Write(raw); err != nil {
					return
				}
				reply := make([]byte, 65535)
				n, err := c.Read(reply)
				if err != nil {
					return
				}
				reply = reply[:n]
				if isHTTPS(raw) && mode.wrongID {
					foreign := bytes.Clone(reply)
					binary.BigEndian.PutUint16(foreign, binary.BigEndian.Uint16(foreign)^0xffff)
					foreign[2] |= 2
					_, _ = udp.WriteTo(foreign, from)
					select {
					case <-time.After(5 * time.Millisecond):
					case <-done:
						return
					}
				}
				_, _ = udp.WriteTo(reply, from)
			}(raw, from)
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			connsMu.Lock()
			conns[c] = true
			connsMu.Unlock()
			go func(c net.Conn) {
				defer func() { _ = c.Close(); connsMu.Lock(); delete(conns, c); connsMu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				raw := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, raw); err != nil {
					return
				}
				p.record("tcp", raw)
				if isHTTPS(raw) && mode.blackhole {
					_, _ = io.Copy(io.Discard, c)
					return
				}
				upstream, err := net.DialTimeout("tcp", backend.addr, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(time.Second))
				if _, err = upstream.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(raw))), raw...)); err != nil {
					return
				}
				if _, err = io.ReadFull(upstream, size[:]); err != nil {
					return
				}
				reply := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err = io.ReadFull(upstream, reply); err != nil {
					return
				}
				_, _ = c.Write(append(size[:], reply...))
			}(c)
		}
	}()
	return p
}

func a12HTTPSPackets(p *a12DNSWire) []a12DNSPacket {
	var result []a12DNSPacket
	for _, sample := range p.snapshot() {
		var parser dnsmessage.Parser
		if _, err := parser.Start(sample.Raw); err != nil {
			continue
		}
		q, err := parser.Question()
		if err == nil && q.Type == dnsmessage.TypeHTTPS {
			result = append(result, sample)
		}
	}
	return result
}
func a12CheckQuery(t *testing.T, raw []byte, rd bool, payload uint16) {
	t.Helper()
	var parser dnsmessage.Parser
	h, err := parser.Start(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Response || h.RecursionDesired != rd || binary.BigEndian.Uint16(raw[2:])&0x0100 != func() uint16 {
		if rd {
			return 0x0100
		}
		return 0
	}() {
		t.Fatalf("raw DNS header=%+v, RDwant%v", h, rd)
	}
	q, err := parser.Question()
	if err != nil || q.Type != dnsmessage.TypeHTTPS || q.Class != dnsmessage.ClassINET {
		t.Fatalf("question=%+v,%v", q, err)
	}
	if err = parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	if err = parser.SkipAllAnswers(); err != nil {
		t.Fatal(err)
	}
	if err = parser.SkipAllAuthorities(); err != nil {
		t.Fatal(err)
	}
	opt, err := parser.AdditionalHeader()
	if err != nil || opt.Type != dnsmessage.TypeOPT || uint16(opt.Class) != payload || opt.Name.String() != "." {
		t.Fatalf("OPT=%+v,%v, payloadwant%d", opt, err, payload)
	}
	if _, err = parser.OPTResource(); err != nil {
		t.Fatal(err)
	}
	if _, err = parser.AdditionalHeader(); err != dnsmessage.ErrSectionDone {
		t.Fatalf("unexpected extra DNS section:%v", err)
	}
}
func a12KeepDNS(t *testing.T, p *a12DNSWire) {
	t.Helper()
	root := os.Getenv("TLSFORGE_A12_EVIDENCE")
	if root == "" {
		return
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(map[string]any{"schema": 1, "case": t.Name(), "completed_at": time.Now(), "packets": p.snapshot(), "resolver": p.addr}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	name := strings.NewReplacer("/", "-", " ", "_").Replace(t.Name())
	if err = os.WriteFile(filepath.Join(root, fmt.Sprintf("%s-%d.json", name, time.Now().UnixNano())), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func a12TLSOrigin(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	count := new(atomic.Int32)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("wire"))
	}))
	t.Cleanup(s.Close)
	return s, count
}
func a12Client(t *testing.T, p *a12DNSWire, changes map[string]any) *Client {
	t.Helper()
	base, err := profile.Get("chrome_156_macos")
	if err != nil {
		t.Fatal(err)
	}
	base.Name = "a12-independent-json-choice"
	for key, value := range changes {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		base.Behavior[key] = raw
	}
	raw, err := base.Save()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := profile.Load(saved)
	if err != nil {
		t.Fatal(err)
	}
	if root := os.Getenv("TLSFORGE_A12_EVIDENCE"); root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		name := strings.NewReplacer("/", "-", " ", "_").Replace(t.Name())
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%s-profile-%d.json", name, time.Now().UnixNano())), saved, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := New(WithProfileValue(loaded), WithDNSServer(p.addr), WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func a12URL(origin *httptest.Server, host string) string {
	return strings.Replace(origin.URL, "127.0.0.1", host, 1)
}

func TestA12BaselineHTTPSQueryWire(t *testing.T) {
	p := startA12DNSWire(t, a12DNSMode{})
	origin, _ := a12TLSOrigin(t)
	c, err := New(WithProfile("chrome_156_macos"), WithDNSServer(p.addr), WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	result, err := c.Do(&Request{URL: a12URL(origin, "baseline.a12.example.test")})
	if err != nil || string(result.Body) != "wire" {
		t.Fatalf("request:%+v,%v", result, err)
	}
	packets := a12HTTPSPackets(p)
	if len(packets) != 1 {
		t.Fatalf("HTTPS queries%d", len(packets))
	}
	a12CheckQuery(t, packets[0].Raw, true, 4096)
	a12KeepDNS(t, p)
}
func TestA12JSONDNSChoicesReachProductionWire(t *testing.T) {
	for _, tc := range []struct {
		rd      bool
		payload int
		mode    a12DNSMode
	}{{false, 512, a12DNSMode{}}, {true, 1232, a12DNSMode{wrongID: true}}, {false, 65535, a12DNSMode{truncate: true}}} {
		t.Run(fmt.Sprintf("rd%v-payload%d", tc.rd, tc.payload), func(t *testing.T) {
			p := startA12DNSWire(t, tc.mode)
			origin, _ := a12TLSOrigin(t)
			c := a12Client(t, p, map[string]any{"dns.https_query_recursion_desired": tc.rd, "dns.https_query_udp_payload_bytes": tc.payload})
			result, err := c.Do(&Request{URL: a12URL(origin, "choice.a12.example.test")})
			if err != nil || string(result.Body) != "wire" {
				t.Fatalf("request:%+v,%v", result, err)
			}
			packets := a12HTTPSPackets(p)
			want := 1
			if tc.mode.truncate {
				want = 2
			}
			if len(packets) != want {
				t.Fatalf("HTTPS wire exchanges=%d,want%d", len(packets), want)
			}
			for _, sample := range packets {
				a12CheckQuery(t, sample.Raw, tc.rd, uint16(tc.payload))
			}
			if tc.mode.truncate && (packets[0].Network != "udp" || packets[1].Network != "tcp" || !bytes.Equal(packets[0].Raw, packets[1].Raw)) {
				t.Fatal("TCP retry changed the actual query/ID")
			}
			a12KeepDNS(t, p)
		})
	}
}
func TestA12JSONDNSExchangeTimeoutReachesProduction(t *testing.T) {
	for _, ms := range []int{40, 160} {
		t.Run(fmt.Sprint(ms), func(t *testing.T) {
			p := startA12DNSWire(t, a12DNSMode{blackhole: true})
			origin, _ := a12TLSOrigin(t)
			c := a12Client(t, p, map[string]any{"dns.https_query_timeout_ms": ms, "dns.https_wait_min_ms": 1000, "dns.https_wait_max_ms": 1000})
			started := time.Now()
			result, err := c.Do(&Request{URL: a12URL(origin, "timeout.a12.example.test")})
			elapsed := time.Since(started)
			if err != nil || string(result.Body) != "wire" {
				t.Fatalf("fallback:%+v,%v", result, err)
			}
			if elapsed < time.Duration(ms)*time.Millisecond || elapsed > time.Duration(ms)*time.Millisecond+500*time.Millisecond {
				t.Fatalf("selected%dms,request elapsed%s", ms, elapsed)
			}
			if len(a12HTTPSPackets(p)) != 1 {
				t.Fatal("timeout triggered an unbounded DNS replay")
			}
			a12KeepDNS(t, p)
		})
	}
}

type a12ClosingDNSConn struct {
	net.Conn
	network string
	closed  chan<- string
	once    sync.Once
}

func (c *a12ClosingDNSConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.closed <- c.network })
	return err
}

func TestA12DNSCancellationStopsUDPAndTCPWaits(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("tcp%v", tcp), func(t *testing.T) {
			p := startA12DNSWire(t, a12DNSMode{blackhole: true, truncate: tcp})
			closed := make(chan string, 8)
			origin, count := a12TLSOrigin(t)
			c := a12Client(t, p, map[string]any{"dns.https_query_timeout_ms": 60000, "dns.https_wait_min_ms": 60000, "dns.https_wait_max_ms": 60000})
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), a12DNSCloseObserverKey{}, closed))
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := c.Do(&Request{URL: a12URL(origin, "cancel.a12.example.test"), Context: ctx})
				result <- err
			}()
			want := "udp"
			if tcp {
				want = "tcp"
			}
			deadline := time.After(2 * time.Second)
		wait:
			for {
				select {
				case network := <-p.seen:
					if network == want {
						break wait
					}
				case <-deadline:
					t.Fatal("DNS phase not observed")
				}
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation:%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation waited for profile timer")
			}
			if count.Load() != 0 {
				t.Fatal("cancelled DNS reached origin")
			}
			closeDeadline := time.After(time.Second)
		closedSocket:
			for {
				select {
				case network := <-closed:
					if network == want {
						break closedSocket
					}
				case <-closeDeadline:
					t.Fatal("cancelled exchange retained its actual DNS socket")
				}
			}

			a12KeepDNS(t, p)
		})
	}
}

func TestA12DNSPoliciesStayIndependentAcrossConcurrentRequests(t *testing.T) {
	p := startA12DNSWire(t, a12DNSMode{})
	origin, count := a12TLSOrigin(t)
	first := a12Client(t, p, map[string]any{"dns.https_query_recursion_desired": false, "dns.https_query_udp_payload_bytes": 512})
	second := a12Client(t, p, map[string]any{"dns.https_query_recursion_desired": true, "dns.https_query_udp_payload_bytes": 4096})
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for i, c := range []*Client{first, second} {
		wg.Add(1)
		go func(i int, c *Client) {
			defer wg.Done()
			for range 2 {
				result, err := c.Do(&Request{URL: a12URL(origin, fmt.Sprintf("client%d.a12.example.test", i))})
				if err != nil {
					failures <- err
					continue
				}
				if string(result.Body) != "wire" {
					failures <- fmt.Errorf("client%d body%q", i, result.Body)
				}
			}
		}(i, c)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if count.Load() != 4 {
		t.Fatalf("origin requests%d", count.Load())
	}
	packets := a12HTTPSPackets(p)
	if len(packets) != 4 {
		t.Fatalf("DNS request isolation lost:%d queries", len(packets))
	}
	for _, sample := range packets {
		var parser dnsmessage.Parser
		if _, err := parser.Start(sample.Raw); err != nil {
			t.Fatal(err)
		}
		q, err := parser.Question()
		if err != nil {
			t.Fatal(err)
		}
		_, port, err := net.SplitHostPort(origin.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		prefix := "_" + port + "._https."
		if !strings.HasPrefix(q.Name.String(), prefix) {
			t.Fatalf("non-default port missing from HTTPS question: %s", q.Name)
		}
		switch strings.TrimPrefix(q.Name.String(), prefix) {
		case "client0.a12.example.test.":
			a12CheckQuery(t, sample.Raw, false, 512)
		case "client1.a12.example.test.":
			a12CheckQuery(t, sample.Raw, true, 4096)
		default:
			t.Fatalf("foreign DNS question%s", q.Name)
		}
	}
	a12KeepDNS(t, p)
}

func TestA12DNSPerServerBudgetAndParentDeadlineAreSeparate(t *testing.T) {
	first := startA12DNSWire(t, a12DNSMode{blackhole: true})
	second := startA12DNSWire(t, a12DNSMode{records: true})
	namingServers(t, first.addr, second.addr)
	policy := chromeDNS(t)
	policy["dns.https_query_timeout_ms"] = json.RawMessage("40")
	r := newResolving("", policy)
	began := time.Now()
	answer := r.httpsRecords(context.Background(), "fallback.a12.example.test", 443)
	elapsed := time.Since(began)
	if answer.err != nil || !answer.record {
		t.Fatalf("resolver failover:%+v", answer)
	}
	if len(a12HTTPSPackets(first)) != 1 || len(a12HTTPSPackets(second)) != 1 || elapsed < 40*time.Millisecond || elapsed > 600*time.Millisecond {
		t.Fatalf("per-server failover after%s", elapsed)
	}
	a12KeepDNS(t, first)
	a12KeepDNS(t, second)
	namingServers(t, first.addr, first.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	policy["dns.https_query_timeout_ms"] = json.RawMessage("60000")
	r = newResolving("", policy)
	began = time.Now()
	answer = r.httpsRecords(ctx, "bounded.a12.example.test", 443)
	elapsed = time.Since(began)
	if answer.err == nil || ctx.Err() == nil || elapsed > 500*time.Millisecond {
		t.Fatalf("parent deadline:%+v after%s", answer, elapsed)
	}
	if len(a12HTTPSPackets(first)) != 2 {
		t.Fatal("expired parent continued to another DNS server")
	}
	a12KeepDNS(t, first)
}

func TestA12CancelledRequestSendsNoDNSOrOriginTraffic(t *testing.T) {
	p := startA12DNSWire(t, a12DNSMode{})
	origin, count := a12TLSOrigin(t)
	c := a12Client(t, p, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Do(&Request{URL: a12URL(origin, "never.a12.example.test"), Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel:%v", err)
	}
	if len(p.snapshot()) != 0 || count.Load() != 0 {
		t.Fatal("pre-cancelled request caused traffic")
	}
	a12KeepDNS(t, p)
}
