package tlsforge

import (
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
// client acknowledges at once. Such runs say nothing of how long an ACK
// waits, and are run again.
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
		if heard.sentNumber(lone-1) && ack.LargestAcked() == lone {
			return ack
		}
	}
	t.Fatal("a packet number skipped before the lone packet, or a packet after it, in every run")
	return nil
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
	// the JSON alone: alarms 50 ms late
	if ack := loneACK(t, quicProfile(t, map[string]string{"quic.alarm_slack_ms": "50"})); ack.DelayTime < 74*time.Millisecond {
		t.Errorf("acknowledged after %s, want 74 ms at least", ack.DelayTime)
	}
	// none said: on its timer, as quic-go's alarms, and the Linux and
	// Windows profiles', which say none; a run of a machine under load may
	// go late
	for name, p := range map[string]*profile.Profile{
		"none said": quicProfile(t, map[string]string{"quic.alarm_slack_ms": ""}),
		"linux":     shippedProfile(t, "chrome_155_linux"),
		"windows":   shippedProfile(t, "chrome_155_windows"),
	} {
		late := true
		for i := 0; i < 3 && late; i++ {
			late = loneACK(t, p).DelayTime >= 28*time.Millisecond
		}
		if late {
			t.Errorf("%s: acknowledged after its timer and 4 ms more in three runs of three", name)
		}
	}
}
