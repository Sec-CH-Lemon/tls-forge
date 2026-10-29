package tlsforge

import (
	"bytes"
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls "github.com/igor-lemon/utls"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// How a Chrome profile's HTTP/3 client puts its writes in packets, as
// Chrome 155's (bench/h3 and bench/h3alps in
// ../net-fp-server/captures/review-20261023, cohorts h3a, h3b, hpa and hpb;
// quiche at Chrome 155's DEPS revision, Chromium 155.0.8059.85): a request's
// PRIORITY_UPDATE, QPACK encoder instructions and HEADERS with its FIN in one
// packet, and its QPACK decoder's Stream Cancellation of a request the server
// resets in the packet that acknowledges the reset.

// bundleHeard keeps every packet a QUIC server got from its clients, and
// when, and every packet it sent.
type bundleHeard struct {
	mu      sync.Mutex
	got     []qlog.PacketReceived
	sent    []qlog.PacketSent
	decoder []byte
}

func (h *bundleHeard) AddProducer() qlogwriter.Recorder { return h }
func (h *bundleHeard) SupportsSchemas(string) bool      { return true }
func (h *bundleHeard) Close() error                     { return nil }

func (h *bundleHeard) RecordEvent(e qlogwriter.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch e := e.(type) {
	case qlog.PacketReceived:
		h.got = append(h.got, e)
	case qlog.PacketSent:
		h.sent = append(h.sent, e)
	}
}

// carrying is the first packet heard with a STREAM frame of id at offset.
func (h *bundleHeard) carrying(id quic.StreamID, offset int64) *qlog.PacketReceived {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, p := range h.got {
		for _, f := range p.Frames {
			if s, ok := f.Frame.(*qlog.StreamFrame); ok && s.StreamID == id && s.Offset == offset {
				return &h.got[i]
			}
		}
	}
	return nil
}

func (h *bundleHeard) instruction() *qlog.PacketReceived {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !bytes.Equal(h.decoder, []byte{3, 0x40}) {
		return nil
	}
	for i, p := range h.got {
		for _, f := range p.Frames {
			if st, ok := f.Frame.(*qlog.StreamFrame); ok && st.StreamID == 6 && st.Offset <= 1 && 1 < st.Offset+st.Length {
				return &h.got[i]
			}
		}
	}
	return nil
}
func (h *bundleHeard) acknowledging(reset qlog.PacketNumber) (*qlog.PacketReceived, *qlog.AckFrame) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var packet *qlog.PacketReceived
	var found *qlog.AckFrame
	for i, p := range h.got {
		if p.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		for _, f := range p.Frames {
			if ack, ok := f.Frame.(*qlog.AckFrame); ok && ack.AcksPacket(reset) && (packet == nil || p.Header.PacketNumber < packet.Header.PacketNumber) {
				packet = &h.got[i]
				found = ack
			}
		}
	}
	return packet, found
}

// resetIn is the number of the packet the server's RESET_STREAM of id went in.
func (h *bundleHeard) resetIn(id quic.StreamID) qlog.PacketNumber {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.sent {
		for _, f := range p.Frames {
			if r, ok := f.Frame.(*qlog.ResetStreamFrame); ok && r.StreamID == id {
				return p.Header.PacketNumber
			}
		}
	}
	return -1
}

// streamsIn are the streams of a packet's STREAM frames, in its order, and
// whether its last one ends its stream.
func streamsIn(p *qlog.PacketReceived) ([]quic.StreamID, bool) {
	var ids []quic.StreamID
	var fin bool
	for _, f := range p.Frames {
		if s, ok := f.Frame.(*qlog.StreamFrame); ok {
			ids = append(ids, s.StreamID)
			fin = s.Fin
		}
	}
	return ids, fin
}

// qpackTable is SETTINGS of a QPACK table of 4096 and 100 blocked streams.
var qpackTable = h3Frame(0x04, 0x01, 0x50, 0x00, 0x07, 0x40, 0x64)

// bundleSite is an https origin whose TCP answers a round trip late, so that
// QUIC is up first, and whose QUIC server gives qpackTable in ALPS and on its
// control stream, as bench/h3alps' qpack does, keeps what it hears in heard,
// and gives each request stream to serve, with its control stream.
func bundleSite(t *testing.T, serve func(control *quic.SendStream, str *quic.Stream)) (string, *bundleHeard) {
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
	heard := &bundleHeard{}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos: []string{"h3"}, ApplicationSettings: map[string][]byte{"h3": qpackTable}}
	// no path MTU probe of the server's, which would draw an ACK
	ln, err := quic.ListenEarly(udp, cfg, &quic.Config{DisablePathMTUDiscovery: true,
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return heard }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = udp.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				control, err := conn.OpenUniStreamSync(context.Background())
				if err != nil {
					return
				}
				_, _ = control.Write(append([]byte{0x00}, qpackTable...))
				go func() {
					for {
						str, err := conn.AcceptUniStream(context.Background())
						if err != nil {
							return
						}
						go func() {
							if str.StreamID() == 6 {
								var prefix [2]byte
								if _, err := io.ReadFull(str, prefix[:]); err == nil {
									heard.mu.Lock()
									heard.decoder = append([]byte(nil), prefix[:]...)
									heard.mu.Unlock()
								}
							}
							_, _ = io.Copy(io.Discard, str)
						}()
					}
				}()
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go serve(control, str)
				}
			}()
		}
	}()
	return port, heard
}

// undecodable resets a request stream as a server that cannot decode its
// headers does, once it has read them.
func undecodable(_ *quic.SendStream, str *quic.Stream) {
	_, _ = str.Read(make([]byte, 1))
	str.CancelWrite(0x200) // QPACK_DECOMPRESSION_FAILED
}

// requestPacket is the packet the HEADERS of a request of a client wearing p
// went in, to a bundleSite; the request goes again over TCP.
func requestPacket(t *testing.T, p *profile.Profile) *qlog.PacketReceived {
	t.Helper()
	port, heard := bundleSite(t, undecodable)
	c := echClient(t, alpsNames(t), WithProfileValue(p))
	if got := came(t, c, "https://h3.h3.test:"+port+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's after the reset", got)
	}
	headers := heard.carrying(0, 0)
	if headers == nil {
		t.Fatal("no request over QUIC")
	}
	return headers
}

func TestARequestsFirstPacketIsChromes(t *testing.T) {
	// STREAM(2@46+12) STREAM(10@0+437) STREAM(0@0, fin), as Chrome's
	ids, fin := streamsIn(requestPacket(t, quicProfile(t, nil)))
	if !slices.Equal(ids, []quic.StreamID{2, 10, 0}) || !fin {
		t.Errorf("the request's packet carried streams %v (fin %v), want Chrome's 2, 10, 0 with its FIN", ids, fin)
	}
}

func TestARequestsWritesAreFlushedAsItsProfileSays(t *testing.T) {
	// the JSON alone: each write as it comes, as quic-go's; the
	// PRIORITY_UPDATE then goes on its own, but for a run in which the
	// packet waits for the rest
	for range 3 {
		ids, _ := streamsIn(requestPacket(t, quicProfile(t, map[string]string{"h3.request_writes": ""})))
		if !slices.Equal(ids, []quic.StreamID{2, 10, 0}) {
			return
		}
	}
	t.Error("written as quic-go writes them, the request went in one packet in three runs of three")
}

// cancellationACK is the ACK the client wearing p (probedLate) sends with
// the decoded QPACK Stream Cancellation of the request a
// bundleSite resets by after, and whether it acknowledges the reset. A
// server of quic-go's skips a packet number now and then, which the client
// acknowledges at once: such a run says nothing of when the ACK goes, and is
// run again.
func cancellationACK(t *testing.T, p *profile.Profile, after func(control *quic.SendStream), immediate bool) (*qlog.AckFrame, []quic.StreamID, bool) {
	t.Helper()
	p = probedLate(p)
	for range 3 {
		port, heard := bundleSite(t, func(control *quic.SendStream, str *quic.Stream) {
			_, _ = str.Read(make([]byte, 1))
			// everything acknowledged, the reset alone in its packet
			time.Sleep(100 * time.Millisecond)
			str.CancelWrite(0x200)
			after(control)
		})
		c := echClient(t, alpsNames(t), WithProfileValue(p))
		if got := came(t, c, "https://h3.h3.test:"+port+"/"); got != "HTTP/2.0" {
			t.Fatalf("came over %q, want TCP's after the reset", got)
		}
		var packet *qlog.PacketReceived
		for deadline := time.Now().Add(2 * time.Second); packet == nil && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
			packet = heard.instruction()
		}
		if packet == nil {
			t.Fatal("no Stream Cancellation")
		}
		ack, _ := packet.Frames[0].Frame.(*qlog.AckFrame)
		beforeACK := false
		if immediate {
			var ackPacket *qlog.PacketReceived
			for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
				ackPacket, ack = heard.acknowledging(heard.resetIn(0))
				if ack != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if ack == nil || packet.Header.PacketNumber > ackPacket.Header.PacketNumber {
				t.Fatal("Cancellation was not sent before or with the reset ACK")
			}
			beforeACK = packet.Header.PacketNumber < ackPacket.Header.PacketNumber
		} else if ack == nil || !ack.AcksPacket(heard.resetIn(0)) {
			t.Fatalf("instruction not bundled with reset ACK: %+v", packet.Frames)
		}
		t.Logf("instruction_packet=%d ack_delay=%s before_ack=%v", packet.Header.PacketNumber, ack.DelayTime, beforeACK)
		ids, _ := streamsIn(packet)
		if len(ack.AckRanges) == 1 {
			return ack, ids, beforeACK
		}
	}
	t.Fatal("a packet number skipped in every run")
	return nil, nil, false
}

func TestAStreamCancellationGoesWithTheResetsACKAsChromes(t *testing.T) {
	// a lone reset's ACK, delayed: the cancellation waits for it
	ack, ids, _ := cancellationACK(t, quicProfile(t, nil), func(*quic.SendStream) {}, false)
	if ack.DelayTime < 15*time.Millisecond {
		t.Errorf("sent %s after the reset, not with the ACK delayed for it", ack.DelayTime)
	}
	if !slices.Equal(ids, []quic.StreamID{6}) {
		t.Errorf("streams %v with the ACK, want the decoder's", ids)
	}
	// the reset with more of the server's: the ACK at once, and the
	// cancellation in it, made as the reset was taken
	ack, _, _ = cancellationACK(t, quicProfile(t, nil), func(control *quic.SendStream) {
		// an unknown frame on the control stream, which the client passes
		// over: packets the client acknowledges at once
		frame := quicvarint.Append(quicvarint.Append(nil, 0x21), 4000)
		_, _ = control.Write(append(frame, bytes.Repeat([]byte{1}, 4000)...))
	}, false)
	if ack.DelayTime >= 15*time.Millisecond {
		t.Errorf("sent %s after the reset, not with the ACK of it at once", ack.DelayTime)
	}
}

func TestWhenAStreamCancellationGoesIsTheProfilesToSay(t *testing.T) {
	// the JSON alone: at once, as quic-go's writes it
	ack, _, beforeACK := cancellationACK(t, quicProfile(t, map[string]string{"h3.qpack.decoder_writes": ""}), func(*quic.SendStream) {}, true)
	if !beforeACK && ack.DelayTime >= 15*time.Millisecond {
		t.Errorf("sent %s after the reset, not at once", ack.DelayTime)
	}
}

func TestDelayedCancellationRejectsImmediateExpectation(t *testing.T) {
	ack, _, beforeACK := cancellationACK(t, quicProfile(t, nil), func(*quic.SendStream) {}, true)
	if beforeACK || ack.DelayTime < 15*time.Millisecond {
		t.Fatal("delayed wire control incorrectly satisfies immediate expectation")
	}
}
