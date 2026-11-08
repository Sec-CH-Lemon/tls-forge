package tlsforge

import (
	"fmt"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/qlog"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// How long a Chrome profile's QUIC client waits before it acknowledges a
// lone packet, as Chrome 155's on macOS (bench/h3alps and bench/h3 in
// ../net-fp-server/captures/review-20261023, ack-chrome.sh cohorts of
// 2026-10-26; quiche at Chrome 155's DEPS revision): its timer and the
// lateness the kernel gives its network thread's timers, which its probes
// and idle close have too (quic.alarm_slack_ms).

// sentWith is the number of the 1-RTT packet the server sent a STREAM
// frame of id at offset in.
func (h *bundleHeard) sentWith(id quic.StreamID, offset int64) qlog.PacketNumber {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.sent {
		for _, f := range p.Frames {
			if s, ok := f.Frame.(*qlog.StreamFrame); ok && p.Header.PacketType == qlog.PacketType1RTT &&
				s.StreamID == id && s.Offset == offset {
				return p.Header.PacketNumber
			}
		}
	}
	return -1
}

// sentNumber says whether the server sent a 1-RTT packet numbered pn.
func (h *bundleHeard) sentNumber(pn qlog.PacketNumber) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.sent {
		if p.Header.PacketType == qlog.PacketType1RTT && p.Header.PacketNumber == pn {
			return true
		}
	}
	return false
}

// ackOf is the first ACK the server heard of its 1-RTT packet pn.
func (h *bundleHeard) ackOf(pn qlog.PacketNumber) *qlog.AckFrame {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.got {
		for _, f := range p.Frames {
			if a, ok := f.Frame.(*qlog.AckFrame); ok && p.Header.PacketType == qlog.PacketType1RTT && a.AcksPacket(pn) {
				return a
			}
		}
	}
	return nil
}

// alongside says why the client's first ACK of the lone packet pn tells
// nothing of how long an ACK of a lone packet waits, or nothing: the ACK
// acknowledges for the first time another ack-eliciting packet of the
// server's, which was still waiting for its ACK when pn came (every second
// such packet is acknowledged at once, and the first one's timer may be the
// one that fired), or it went in a packet the client sent for something of
// its own.
func (h *bundleHeard) alongside(pn qlog.PacketNumber) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	acked := map[qlog.PacketNumber]bool{}
	for _, p := range h.got {
		if p.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		for _, f := range p.Frames {
			a, ok := f.Frame.(*qlog.AckFrame)
			if !ok {
				continue
			}
			if !a.AcksPacket(pn) {
				for _, s := range h.sent {
					if s.Header.PacketType == qlog.PacketType1RTT && a.AcksPacket(s.Header.PacketNumber) {
						acked[s.Header.PacketNumber] = true
					}
				}
				continue
			}
			for _, s := range h.sent {
				n := s.Header.PacketNumber
				if s.Header.PacketType == qlog.PacketType1RTT && n != pn && !acked[n] && a.AcksPacket(n) && elicits(s.Frames) {
					return fmt.Sprintf("its ACK acknowledged packet %d first too", n)
				}
			}
			if elicits(p.Frames) {
				return "its ACK went with frames of the client's own"
			}
			return ""
		}
	}
	return ""
}

// elicits says whether a packet of these frames asks for an ACK.
func elicits(frames []qlog.Frame) bool {
	for _, f := range frames {
		switch f.Frame.(type) {
		case *qlog.AckFrame, *qlog.ConnectionCloseFrame:
		default:
			return true
		}
	}
	return false
}

// probedLate is p saying its ACKs may wait 200 ms, its max_ack_delay, a
// transport parameter alone. A server's probe timeout counts it: told 25 ms,
// a server of quic-go's probes a packet before an ACK that waits longer, as
// Chrome's does, and the client acknowledges the probe, with a number
// skipped before it, at once; the ACK the packet was waiting for is never
// sent.
func probedLate(p *profile.Profile) *profile.Profile {
	p = p.Clone()
	p.Behavior["quic.max_ack_delay_ms"] = []byte("200")
	return p
}

// loneACK is the ACK a client wearing p (probedLate) sends of a lone packet
// of a bundleSite's, an unknown frame on its control stream once the client
// has nothing left to send. A server of quic-go's skips a packet number now
// and then: one skipped right before the lone packet is a new gap, which the
// client acknowledges at once. A packet of the server's still waiting for
// its ACK when the lone one comes, on a runner under load, has the client
// acknowledge both at once, or as the first one's timer says (alongside).
// Such runs say nothing of how long an ACK waits, and are run again.
func loneACK(t *testing.T, p *profile.Profile) *qlog.AckFrame {
	t.Helper()
	p = probedLate(p)
	// the control stream's type and SETTINGS come first on it
	offset := int64(1 + len(qpackTable))
	for range 3 {
		port, heard := bundleSite(t, func(control *quic.SendStream, str *quic.Stream) {
			_, _ = str.Read(make([]byte, 1))
			// everything acknowledged, then the lone packet
			time.Sleep(200 * time.Millisecond)
			_, _ = control.Write(h3Frame(0x21, 0))
			// its ACK gone, the request goes again over TCP
			time.Sleep(300 * time.Millisecond)
			str.CancelWrite(0x200)
		})
		c := echClient(t, alpsNames(t), WithProfileValue(p))
		if got := came(t, c, "https://h3.h3.test:"+port+"/"); got != "HTTP/2.0" {
			t.Fatalf("came over %q, want TCP's after the reset", got)
		}
		lone := heard.sentWith(3, offset)
		if lone < 0 {
			t.Fatal("the server sent no frame on its control stream")
		}
		var ack *qlog.AckFrame
		for deadline := time.Now().Add(2 * time.Second); ack == nil && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
			ack = heard.ackOf(lone)
		}
		if ack == nil {
			t.Fatal("the lone packet was never acknowledged")
		}
		if heard.sentNumber(lone-1) && ack.LargestAcked() == lone && heard.alongside(lone) == "" {
			return ack
		}
	}
	t.Fatal("a packet number skipped before the lone packet, a packet after it, or one acknowledged with it, in every run")
	return nil
}

func TestAnACKThatWasNotForALonePacketAloneIsSaid(t *testing.T) {
	sent := func(pn qlog.PacketNumber, frames ...any) qlog.PacketSent {
		p := qlog.PacketSent{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: pn}}
		for _, f := range frames {
			p.Frames = append(p.Frames, qlog.Frame{Frame: f})
		}
		return p
	}
	got := func(frames ...any) qlog.PacketReceived {
		p := qlog.PacketReceived{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT}}
		for _, f := range frames {
			p.Frames = append(p.Frames, qlog.Frame{Frame: f})
		}
		return p
	}
	acking := func(smallest, largest qlog.PacketNumber) *qlog.AckFrame {
		return &qlog.AckFrame{AckRanges: []qlog.AckRange{{Smallest: smallest, Largest: largest}}}
	}
	stream := &qlog.StreamFrame{StreamID: 3}
	for _, tc := range []struct {
		name string
		got  []qlog.PacketReceived
		said string
	}{
		{"alone", []qlog.PacketReceived{got(acking(0, 5)), got(acking(0, 6))}, ""},
		// packet 5 acknowledged in a packet the server did not take for an ACK
		{"the one before only now", []qlog.PacketReceived{got(acking(0, 4)), got(acking(0, 6))}, "its ACK acknowledged packet 5 first too"},
		{"with a frame of its own", []qlog.PacketReceived{got(acking(0, 5)), got(acking(0, 6), &qlog.PingFrame{})}, "its ACK went with frames of the client's own"},
		{"never", []qlog.PacketReceived{got(acking(0, 5))}, ""},
	} {
		h := &bundleHeard{
			sent: []qlog.PacketSent{sent(4, stream), sent(5, stream), sent(6, stream)},
			got:  tc.got,
		}
		if said := h.alongside(6); said != tc.said {
			t.Errorf("%s: said %q, want %q", tc.name, said, tc.said)
		}
	}
	// a packet of ACKs alone the client need not acknowledge on its own
	h := &bundleHeard{
		sent: []qlog.PacketSent{sent(4, stream), sent(5, acking(0, 1)), sent(6, stream)},
		got:  []qlog.PacketReceived{got(acking(0, 4)), got(acking(0, 6))},
	}
	if said := h.alongside(6); said != "" {
		t.Errorf("an ACK-only packet before the lone one: said %q", said)
	}
}

func TestALonePacketIsAcknowledgedAsLateAsChromes(t *testing.T) {
	// the profile's 24 ms timer and Chrome's 4 ms on macOS: Chrome 155
	// said 28.9 ms, the median of its delayed ACKs on the bench; a timer
	// never fires early
	if ack := loneACK(t, quicProfile(t, nil)); ack.DelayTime < 28*time.Millisecond || ack.DelayTime >= 74*time.Millisecond {
		t.Errorf("acknowledged after %s, want 28 ms or a little more", ack.DelayTime)
	}
}

func TestHowLateALonePacketIsAcknowledgedIsTheProfilesToSay(t *testing.T) {
	// the JSON alone: alarms 50 ms late, the ACK's no part of its delay at
	// most (quic.ack_alarm_slack_percent, which «How a QUIC client
	// acknowledges a long download» holds)
	if ack := loneACK(t, quicProfile(t, map[string]string{"quic.alarm_slack_ms": "50", "quic.ack_alarm_slack_percent": ""})); ack.DelayTime < 74*time.Millisecond {
		t.Errorf("acknowledged after %s, want 74 ms at least", ack.DelayTime)
	}
	// none said: on its timer, as quic-go's alarms, and the Linux and
	// Windows profiles', which say none. A run of a machine under load may
	// go late, but no timer fires early: one ACK sooner than 28 ms of eight
	// says no slack is added, which a slack of 4 ms could never give
	// (2026-11-08: all three of three went late on a loaded macOS runner).
	for name, p := range map[string]*profile.Profile{
		"none said": quicProfile(t, map[string]string{"quic.alarm_slack_ms": "", "quic.ack_alarm_slack_percent": ""}),
		"linux":     shippedProfile(t, "chrome_155_linux"),
		"windows":   shippedProfile(t, "chrome_155_windows"),
	} {
		late := true
		for i := 0; i < 8 && late; i++ {
			late = loneACK(t, p).DelayTime >= 28*time.Millisecond
		}
		if late {
			t.Errorf("%s: acknowledged after its timer and 4 ms more in eight runs of eight", name)
		}
	}
}
