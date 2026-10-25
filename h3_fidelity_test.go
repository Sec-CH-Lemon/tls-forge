package tlsforge

import (
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
)

// Both transports reach the same owned origin. The TCP listener makes a losing
// HTTP attempt observable, including one delayed until after Do has returned.
func h3Origin(t *testing.T, handler http.Handler, observe ...func([]byte, net.Addr)) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	seed := httptest.NewTLSServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	cert := seed.TLS.Certificates[0]
	seed.Close()
	udp, tcp := udpAndTCP(t)
	addr := udp.LocalAddr().String()
	tcpRequests, connections := new(atomic.Int32), new(atomic.Int32)
	srv := &stdhttp.Server{Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		tcpRequests.Add(1)
		_, _ = io.WriteString(w, "tcp duplicate")
	}), TLSConfig: seed.TLS.Clone()}
	go func() { _ = srv.ServeTLS(tcp, "", "") }()
	h3 := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, EnableDatagrams: true,
		QUICConfig: &quic.Config{EnableDatagrams: true}, Handler: handler,
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context { connections.Add(1); return ctx },
	}
	packets := udp
	if len(observe) > 0 {
		packets = &h3ObservedPackets{PacketConn: udp, observe: observe[0]}
	}
	go func() { _ = h3.Serve(packets) }()
	t.Cleanup(func() { _ = h3.Close(); _ = udp.Close(); _ = srv.Close() })
	return "https://" + addr, tcpRequests, connections
}

// udpAndTCP are a UDP socket and a TCP listener on one loopback port: the
// port the system gave the UDP socket, which TCP may hold already, in which
// case another is asked for, a few times at most.
func udpAndTCP(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for tries := 1; ; tries++ {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
		if err == nil {
			return udp, tcp
		}
		_ = udp.Close()
		if tries == 10 {
			t.Fatal(err)
		}
	}
}

func racingChrome(t *testing.T) *Client {
	t.Helper()
	// Requests without a context by any method, as given.
	c, err := New(WithProfileValue(asGivenProfile(t, "chrome_155_macos")), WithInsecureSkipVerify(), WithTimeout(5*time.Second), WithTransportOption(tc.WithProtocolRacing()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestH3RacesConnectionsAndReusesTheWinner(t *testing.T) {
	var requests atomic.Int32
	url, tcp, conns := h3Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s:%s", r.Method, body)
	}))
	c := racingChrome(t)
	for _, method := range []string{"GET", "POST", "POST", "GET"} {
		res, err := c.Do(&Request{URL: url, Method: method, Body: []byte("one effect")})
		if err != nil {
			t.Fatal(err)
		}
		if string(res.Body) != method+":one effect" {
			t.Fatalf("wrong answer: %q", res.Body)
		}
	}
	// The previous loser slept 300ms and sent the same request over TCP.
	time.Sleep(450 * time.Millisecond)
	if tcp.Load() != 0 || requests.Load() != 4 || conns.Load() != 1 {
		t.Fatalf("TCP requests=%d H3 requests=%d QUIC connections=%d", tcp.Load(), requests.Load(), conns.Load())
	}
}

func TestH3LateCancellationLeavesOtherRequestsUsable(t *testing.T) {
	prefix := make(chan struct{})
	var once sync.Once
	url, tcp, conns := h3Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cancel" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.Header().Set("content-length", "16384")
		_, _ = io.WriteString(w, strings.Repeat("x", 8192))
		w.(http.Flusher).Flush()
		once.Do(func() { close(prefix) })
		<-r.Context().Done()
	}))
	c := racingChrome(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Do(&Request{URL: url + "/cancel", Context: ctx}); done <- err }()
	select {
	case <-prefix:
	case <-time.After(5 * time.Second):
		t.Fatal("no response prefix")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled response succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("late cancel did not finish")
	}
	res, err := c.Do(&Request{URL: url + "/after"})
	if err != nil || string(res.Body) != "ok" {
		t.Fatalf("following request: %v %#v", err, res)
	}
	time.Sleep(450 * time.Millisecond)
	if tcp.Load() != 0 || conns.Load() != 1 {
		t.Fatalf("TCP requests=%d QUIC connections=%d", tcp.Load(), conns.Load())
	}
}

func TestH3CancellationDoesNotWaitForTheTCPFallback(t *testing.T) {
	udp, tcp := udpAndTCP(t)
	defer udp.Close()
	defer tcp.Close()
	initial := make(chan struct{})
	go func() {
		b := make([]byte, 65536)
		if _, _, err := udp.ReadFrom(b); err == nil {
			close(initial)
		}
	}()
	contact := make(chan struct{}, 1)
	go func() {
		c, err := tcp.Accept()
		if err == nil {
			contact <- struct{}{}
			_ = c.Close()
		}
	}()
	c := racingChrome(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.Do(&Request{URL: "https://" + udp.LocalAddr().String(), Context: ctx})
		done <- err
	}()
	select {
	case <-initial:
	case <-time.After(3 * time.Second):
		t.Fatal("no Initial packet")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled connect succeeded")
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("cancellation waited for fallback")
	}
	select {
	case <-contact:
		t.Fatal("cancelled fallback dialled TCP")
	case <-time.After(350 * time.Millisecond):
	}
}

// Observe original datagrams at the actual owned server, not a serialized preset.
type h3ObservedPackets struct {
	net.PacketConn
	observe func([]byte, net.Addr)
}

func (p *h3ObservedPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err == nil {
		p.observe(append([]byte{}, b[:n]...), addr)
	}
	return n, addr, err
}
func TestH3ChromeCIDsUseDedicatedSocketsAcrossOrigins(t *testing.T) {
	type initial struct {
		dcid   string
		scid   int
		remote string
	}
	observed := make(chan initial, 32)
	see := func(b []byte, addr net.Addr) {
		if len(b) < 7 || b[0]&0xf0 != 0xc0 {
			return
		}
		n := int(b[5])
		if len(b) < 7+n {
			return
		}
		observed <- initial{dcid: string(b[6 : 6+n]), scid: int(b[6+n]), remote: addr.String()}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "h3") })
	a, ta, ca := h3Origin(t, handler, see)
	b, tb, cb := h3Origin(t, handler, see)
	c := racingChrome(t)
	for _, origin := range []string{a, b, a, b} {
		r, err := c.Do(&Request{URL: origin})
		if err != nil || string(r.Body) != "h3" {
			t.Fatalf("request: %v %v", r, err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	unique := map[string]string{}
	seen := map[string]bool{}
	for len(observed) > 0 {
		h := <-observed
		// Only the client's first Initial chooses the original destination CID.
		// Subsequent Initials correctly use the CID received from the peer.
		if seen[h.remote] {
			continue
		}
		seen[h.remote] = true
		if len(h.dcid) != 8 || h.scid != 0 {
			t.Fatalf("DCID=%d SCID=%d", len(h.dcid), h.scid)
		}
		unique[h.dcid] = h.remote
	}
	if len(unique) != 2 {
		t.Fatalf("initial identities: %v", unique)
	}
	ports := map[string]bool{}
	for _, remote := range unique {
		ports[remote] = true
	}
	if len(ports) != 2 {
		t.Fatalf("source-ID-free origins shared a UDP socket: %v", unique)
	}
	if ta.Load() != 0 || tb.Load() != 0 || ca.Load() != 1 || cb.Load() != 1 {
		t.Fatalf("TCP=%d/%d H3=%d/%d", ta.Load(), tb.Load(), ca.Load(), cb.Load())
	}
}
