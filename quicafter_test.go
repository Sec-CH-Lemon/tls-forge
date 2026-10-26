package tlsforge

import (
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	tls "github.com/igor-lemon/utls"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// What a Chrome profile's QUIC client sends after its handshake, as Chrome
// 155's (bench/h3 and bench/h3alps in ../net-fp-server/captures/review-20261023,
// cohorts h3a, h3b, hpa and hpb; quiche at Chrome 155's DEPS revision): no
// ECN mark, no path MTU probe, the server's first connection ID kept, its
// control stream in the datagram of its Finished, and nothing sent on a
// request stream the server resets but a QPACK Stream Cancellation.

// quicQlog keeps every packet a QUIC server got from its clients, as its
// qlog tells them.
type quicQlog struct {
	mu      sync.Mutex
	packets []qlog.PacketReceived
}

func (h *quicQlog) AddProducer() qlogwriter.Recorder { return h }
func (h *quicQlog) SupportsSchemas(string) bool      { return true }
func (h *quicQlog) Close() error                     { return nil }

func (h *quicQlog) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.PacketReceived); ok {
		h.mu.Lock()
		h.packets = append(h.packets, p)
		h.mu.Unlock()
	}
}

func (h *quicQlog) heard() []qlog.PacketReceived {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]qlog.PacketReceived(nil), h.packets...)
}

// afterSite is an https origin whose TCP answers a round trip late, so that
// QUIC is up first, and whose QUIC server keeps what its clients send in
// heard: an HTTP/3 server whose answers say the protocol they came over, or,
// with reset, one that resets each request stream as it comes, as one that
// cannot decode its headers does.
func afterSite(t *testing.T, reset bool) (string, *quicQlog) {
	t.Helper()
	udp, tcp := udpAndTCP(t)
	_, port, _ := net.SplitHostPort(tcp.Addr().String())
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	server.Listener = &slowFirstWord{Listener: tcp, lag: 100 * time.Millisecond}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.TLS.Certificates[0]
	heard := &quicQlog{}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos: []string{"h3"}}
	ln, err := quic.ListenEarly(udp, cfg, &quic.Config{
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return heard },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = udp.Close() })
	h3 := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			if !reset {
				go func() { _ = h3.ServeQUICConn(conn) }()
				continue
			}
			go func() {
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					str.CancelWrite(0x200) // QPACK_DECOMPRESSION_FAILED
				}
			}()
		}
	}()
	return port, heard
}

// afterHandshake is what the QUIC server of an afterSite heard of a request
// of a client wearing p, then of the client's connection for hold, and of a
// second request after it but where the server resets the first (that one
// goes over TCP, QUIC broken); and what the first came over. quic-go sends a
// path MTU probe only when it sends something once five round trips have
// passed since the handshake, which the first request's packets did, or did
// not, as a loaded machine had it: the second's do.
func afterHandshake(t *testing.T, p *profile.Profile, reset bool, hold time.Duration) ([]qlog.PacketReceived, string) {
	t.Helper()
	port, heard := afterSite(t, reset)
	c := echClient(t, alpsNames(t), WithProfileValue(p))
	url := "https://h3.h3.test:" + port + "/"
	got := came(t, c, url)
	time.Sleep(hold)
	if !reset {
		if again := came(t, c, url); again != got {
			t.Fatalf("the second request came over %q, the first over %q", again, got)
		}
	}
	_ = c.Close()
	return heard.heard(), got
}

// heardFrames are the frames of a kind of the packets heard.
func heardFrames[F any](packets ...qlog.PacketReceived) []F {
	var out []F
	for _, p := range packets {
		for _, frame := range p.Frames {
			if f, ok := frame.Frame.(F); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// ecnMarked and biggest are the 1-RTT packets heard marked ECT(0) and the
// length of the largest packet heard.
func ecnMarked(packets []qlog.PacketReceived) (marked, biggest int) {
	for _, p := range packets {
		if p.Header.PacketType == qlog.PacketType1RTT && p.ECN == qlog.ECT0 {
			marked++
		}
		biggest = max(biggest, p.Raw.Length)
	}
	return marked, biggest
}

// withTheFinished is whether the control stream's first bytes came in the
// datagram whose Handshake packet carried the client's Finished.
func withTheFinished(packets []qlog.PacketReceived) bool {
	finished := map[qlog.DatagramID]bool{}
	for _, p := range packets {
		if p.Header.PacketType == qlog.PacketTypeHandshake && len(heardFrames[*qlog.CryptoFrame](p)) > 0 {
			finished[p.DatagramID] = true
		}
	}
	for _, p := range packets {
		for _, s := range heardFrames[*qlog.StreamFrame](p) {
			if s.StreamID == 2 && s.Offset == 0 {
				return p.Header.PacketType == qlog.PacketType1RTT && finished[p.DatagramID]
			}
		}
	}
	return false
}

func TestAQUICClientSendsAfterItsHandshakeWhatChromeSends(t *testing.T) {
	packets, got := afterHandshake(t, quicProfile(t, nil), false, 300*time.Millisecond)
	if !strings.HasPrefix(got, "HTTP/3.0") {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	marked, biggest := ecnMarked(packets)
	if marked > 0 {
		t.Errorf("%d packets marked ECT(0), Chrome's none", marked)
	}
	if biggest > 1250 {
		t.Errorf("a packet of %d bytes: a path MTU probe, Chrome sends none", biggest)
	}
	if retired := heardFrames[*qlog.RetireConnectionIDFrame](packets...); len(retired) > 0 {
		t.Errorf("%d RETIRE_CONNECTION_ID, Chrome's none", len(retired))
	}
	if !withTheFinished(packets) {
		t.Error("the control stream did not go with the Finished, as Chrome's does")
	}
}

func TestWhatAQUICClientSendsAfterItsHandshakeIsTheProfilesToSay(t *testing.T) {
	// the JSON alone: quic-go's ways
	p := quicProfile(t, map[string]string{"quic.ecn": `"ect0"`, "quic.mtu_probes": `"search"`,
		"quic.connection_id_change": `"after-handshake"`, "h3.control_stream": `"after-handshake"`})
	packets, got := afterHandshake(t, p, false, 300*time.Millisecond)
	if !strings.HasPrefix(got, "HTTP/3.0") {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	marked, biggest := ecnMarked(packets)
	if marked == 0 {
		t.Log("no packet marked ECT(0): this host's sockets mark none")
	}
	if biggest <= 1250 {
		t.Errorf("no path MTU probe, the largest packet %d bytes", biggest)
	}
	if retired := heardFrames[*qlog.RetireConnectionIDFrame](packets...); len(retired) != 1 {
		t.Errorf("%d RETIRE_CONNECTION_ID, want quic-go's one", len(retired))
	}
}

// requestResets are the RESET_STREAM frames heard of request streams.
func requestResets(packets []qlog.PacketReceived) []*qlog.ResetStreamFrame {
	var resets []*qlog.ResetStreamFrame
	for _, f := range heardFrames[*qlog.ResetStreamFrame](packets...) {
		if f.StreamID%4 == 0 {
			resets = append(resets, f)
		}
	}
	return resets
}

func TestARequestStreamItsServerResetsIsLeftAsChromeLeavesIt(t *testing.T) {
	// the request goes again over TCP (quic.retry_over_tcp), and over QUIC
	// nothing more of it is sent
	packets, got := afterHandshake(t, quicProfile(t, nil), true, 100*time.Millisecond)
	if got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if resets := requestResets(packets); len(resets) > 0 {
		t.Errorf("RESET_STREAM %v, Chrome sends none", resets[0])
	}
	// the JSON alone: quic-go's reset of its own side too
	packets, got = afterHandshake(t, quicProfile(t, map[string]string{"h3.peer_reset": `"frame-error"`}), true, 100*time.Millisecond)
	if got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if resets := requestResets(packets); len(resets) != 1 || resets[0].ErrorCode != 0x106 {
		t.Errorf("RESET_STREAM %v, want quic-go's one of H3_FRAME_ERROR", resets)
	}
}
