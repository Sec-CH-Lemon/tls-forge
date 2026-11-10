package tlsforge

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/qlog"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
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

// gapPackets is how many packets after a gap a client wearing a Chrome
// profile acknowledges at once, each (quic.ack_gap_packets).
const gapPackets = 4

// waitingLocked is the packet the client's first ACK of the server's packet
// pn went in, or nil, and why that ACK may have gone at once, whatever the
// client's rule of ACKs that wait, or nothing: it acknowledged for the first
// time another packet of the server's sent before pn that asked for an ACK,
// which was still waiting for it when pn came (every second such packet is
// acknowledged at once, and an alarm overdue on a loaded machine fires as pn
// is taken), or one of the gapPackets packets before pn was never
// acknowledged, a number the server skipped or a packet lost: each packet
// that many after a gap is acknowledged at once. h.mu is held.
func (h *bundleHeard) waitingLocked(pn qlog.PacketNumber) (*qlog.PacketReceived, string) {
	var before []*qlog.AckFrame
	ackedBefore := func(n qlog.PacketNumber) bool {
		return slices.ContainsFunc(before, func(a *qlog.AckFrame) bool { return a.AcksPacket(n) })
	}
	for i, p := range h.got {
		if p.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		for _, f := range p.Frames {
			a, ok := f.Frame.(*qlog.AckFrame)
			if !ok {
				continue
			}
			if !a.AcksPacket(pn) {
				before = append(before, a)
				continue
			}
			for _, s := range h.sent {
				n := s.Header.PacketNumber
				if s.Header.PacketType == qlog.PacketType1RTT && n < pn && a.AcksPacket(n) && !ackedBefore(n) && elicits(s.Frames) {
					return &h.got[i], fmt.Sprintf("its ACK acknowledged packet %d first too", n)
				}
			}
			for n := max(pn-gapPackets, 0); n < pn; n++ {
				if !a.AcksPacket(n) && !ackedBefore(n) {
					return &h.got[i], fmt.Sprintf("packet %d before it was never acknowledged", n)
				}
			}
			return &h.got[i], ""
		}
	}
	return nil, ""
}

// waiting says why the client's first ACK of the server's packet pn may
// have gone at once, or nothing (waitingLocked).
func (h *bundleHeard) waiting(pn qlog.PacketNumber) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, why := h.waitingLocked(pn)
	return why
}

// alongside says why the client's first ACK of the lone packet pn tells
// nothing of how long an ACK of a lone packet waits, or nothing: it may have
// gone at once (waitingLocked), or it went in a packet the client sent for
// something of its own.
func (h *bundleHeard) alongside(pn qlog.PacketNumber) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	got, why := h.waitingLocked(pn)
	if got != nil && why == "" && elicits(got.Frames) {
		return "its ACK went with frames of the client's own"
	}
	return why
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

// loneRuns is how many connections loneDelays makes at most, and loneCount
// how many lone packets each sends at most.
const loneRuns, loneCount = 8, 12

// lones are the 1-RTT packets the server sent a STREAM frame of its control
// stream in at offset from or after, the first time each such offset went.
func (h *bundleHeard) lones(from int64) []qlog.PacketNumber {
	h.mu.Lock()
	defer h.mu.Unlock()
	var lones []qlog.PacketNumber
	seen := map[int64]bool{}
	for _, p := range h.sent {
		for _, f := range p.Frames {
			s, ok := f.Frame.(*qlog.StreamFrame)
			if !ok || p.Header.PacketType != qlog.PacketType1RTT || s.StreamID != 3 || s.Offset < from || seen[s.Offset] {
				continue
			}
			seen[s.Offset] = true
			if !slices.Contains(lones, p.Header.PacketNumber) {
				lones = append(lones, p.Header.PacketNumber)
			}
		}
	}
	return lones
}

// delaysOf is how long the client waited to acknowledge each lone packet
// (lones) whose first ACK says so, and why each other says nothing: no ACK
// heard; an ACK of a later packet too; an ACK that may have gone at once,
// or with frames of the client's own (alongside).
func (h *bundleHeard) delaysOf(from int64) (delays []time.Duration, why []string) {
	for _, pn := range h.lones(from) {
		ack := h.ackOf(pn)
		switch w := h.alongside(pn); {
		case ack == nil:
			why = append(why, fmt.Sprintf("%d: never acknowledged", pn))
		case ack.LargestAcked() != pn:
			why = append(why, fmt.Sprintf("%d: its ACK acknowledged %d too", pn, ack.LargestAcked()))
		case w != "":
			why = append(why, fmt.Sprintf("%d: %s", pn, w))
		default:
			delays = append(delays, ack.DelayTime)
		}
	}
	return delays, why
}

// loneDelays is how long a client wearing p (probedLate) waited to
// acknowledge a bundleSite's lone packets, unknown frames on its control
// stream, one every apart once the client has nothing left to send, each
// whose ACK says so, and why each other says nothing. A connection sends
// loneCount of them at most, and loneRuns connections are made at most,
// until enough says so of the delays heard so far. A server of quic-go's
// skips a packet number now and then, after which the client acknowledges
// packets at once; a packet of the server's still waiting for its ACK when
// a lone one comes, on a runner under load, has the client acknowledge both
// at once, or as the first one's timer says; the client sends a frame of its
// own with an ACK now and then: such ACKs say nothing of how long an ACK
// waits. On a loaded machine the client's timer is late, by more than a
// slack a profile could say, for a while: many lone packets, a few
// milliseconds apart, tell sooner than many connections how late it fires
// when it is not (2026-11-08: eight connections, a lone packet each, all
// late by 4 ms or more on a macOS runner).
func loneDelays(t *testing.T, p *profile.Profile, apart time.Duration, enough func([]time.Duration) bool) ([]time.Duration, []string) {
	t.Helper()
	p = probedLate(p)
	// the control stream's type and SETTINGS come first on it
	from := int64(1 + len(qpackTable))
	var delays []time.Duration
	var why []string
	for range loneRuns {
		heardNow, saidNow := loneRun(t, p, from, apart, func(d []time.Duration) bool {
			return enough(append(slices.Clone(delays), d...))
		})
		delays, why = append(delays, heardNow...), append(why, saidNow...)
		if enough(delays) {
			break
		}
	}
	t.Logf("lone packets acknowledged after %v; %s", delays, saidNothing(why))
	return delays, why
}

// loneRun is one connection of loneDelays: its lone packets go until
// enough says so of what their ACKs say, loneCount at most.
func loneRun(t *testing.T, p *profile.Profile, from int64, apart time.Duration, enough func([]time.Duration) bool) ([]time.Duration, []string) {
	t.Helper()
	stop := make(chan struct{})
	var halt sync.Once
	port, heard := bundleSite(t, func(control *quic.SendStream, str *quic.Stream) {
		_, _ = str.Read(make([]byte, 1))
		// everything acknowledged, then the lone packets
		time.Sleep(200 * time.Millisecond)
		for range loneCount {
			_, _ = control.Write(h3Frame(0x21, 0))
			select {
			case <-stop:
			case <-time.After(apart):
				continue
			}
			break
		}
		// the request goes again over TCP
		str.CancelWrite(0x200)
	})
	done, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if d, _ := heard.delaysOf(from); enough(d) {
				halt.Do(func() { close(stop) })
				return
			}
		}
	}()
	func() {
		defer func() { close(done); <-watched }()
		c := echClient(t, alpsNames(t), WithProfileValue(p))
		if got := came(t, c, "https://h3.h3.test:"+port+"/"); got != "HTTP/2.0" {
			t.Fatalf("came over %q, want TCP's after the reset", got)
		}
	}()
	lones := heard.lones(from)
	if len(lones) == 0 {
		// TCP's answer, a round trip late, before QUIC was up: on a loaded
		// machine a handshake takes longer than that now and then
		return nil, []string{"the request went over TCP before QUIC was up"}
	}
	// the last lone packet's ACK, which may be the reset's
	for deadline := time.Now().Add(2 * time.Second); heard.ackOf(lones[len(lones)-1]) == nil && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	return heard.delaysOf(from)
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
	// two ranges, the higher first, as an ACK frame says them
	ranges := func(smallest, largest, lowest, below qlog.PacketNumber) *qlog.AckFrame {
		return &qlog.AckFrame{AckRanges: []qlog.AckRange{{Smallest: smallest, Largest: largest}, {Smallest: lowest, Largest: below}}}
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
		// one of the four before it never had: each packet four after a
		// gap is acknowledged at once
		{"after a gap", []qlog.PacketReceived{got(ranges(3, 5, 0, 1)), got(ranges(3, 6, 0, 1))}, "packet 2 before it was never acknowledged"},
		{"a gap in its own ACK", []qlog.PacketReceived{got(ranges(4, 5, 0, 2)), got(ranges(4, 6, 0, 2))}, "packet 3 before it was never acknowledged"},
		{"a gap before the four", []qlog.PacketReceived{got(ranges(2, 5, 0, 0)), got(ranges(2, 6, 0, 0))}, ""},
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
	// a packet sent after it, which its ACK acknowledges too, is no
	// packet that waited before it: an ACK of both goes as the second's
	h = &bundleHeard{
		sent: []qlog.PacketSent{sent(4, stream), sent(5, stream), sent(6, stream)},
		got:  []qlog.PacketReceived{got(acking(0, 4)), got(acking(0, 6))},
	}
	if said := h.waiting(5); said != "" {
		t.Errorf("a packet after it: said %q", said)
	}
	// the first numbers have none four before them
	h = &bundleHeard{sent: []qlog.PacketSent{sent(0, stream), sent(1, stream)}, got: []qlog.PacketReceived{got(acking(0, 0)), got(acking(0, 1))}}
	if said := h.waiting(1); said != "" {
		t.Errorf("the second packet: said %q", said)
	}
}

func TestLonePacketsSayHowLongTheirACKsWaited(t *testing.T) {
	stream := func(offset int64) qlog.Frame {
		return qlog.Frame{Frame: &qlog.StreamFrame{StreamID: 3, Offset: offset}}
	}
	sent := func(pn qlog.PacketNumber, frames ...qlog.Frame) qlog.PacketSent {
		return qlog.PacketSent{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: pn}, Frames: frames}
	}
	got := func(smallest, largest qlog.PacketNumber, delay time.Duration, own ...qlog.Frame) qlog.PacketReceived {
		ack := &qlog.AckFrame{DelayTime: delay, AckRanges: []qlog.AckRange{{Smallest: smallest, Largest: largest}}}
		return qlog.PacketReceived{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT}, Frames: append([]qlog.Frame{{Frame: ack}}, own...)}
	}
	h := &bundleHeard{
		sent: []qlog.PacketSent{
			sent(0, stream(0)), sent(1, stream(5)), sent(2, stream(10)), sent(3, stream(13)),
			// sent again: the same offset is no other lone packet
			sent(4, stream(13)),
			sent(5, stream(16)), sent(6, stream(19)), sent(8, stream(22)), sent(9, stream(25)),
			{Header: qlog.PacketHeader{PacketType: qlog.PacketTypeHandshake, PacketNumber: 10}, Frames: []qlog.Frame{stream(28)}},
		},
		got: []qlog.PacketReceived{
			got(0, 1, 0), got(0, 2, 25*time.Millisecond), got(0, 4, time.Millisecond),
			got(0, 5, 26*time.Millisecond, qlog.Frame{Frame: &qlog.PingFrame{}}),
			got(0, 6, 27*time.Millisecond), got(8, 8, 0), got(8, 9, 0),
		},
	}
	if lones := h.lones(10); !slices.Equal(lones, []qlog.PacketNumber{2, 3, 5, 6, 8, 9}) {
		t.Errorf("lone packets %v", lones)
	}
	delays, why := h.delaysOf(10)
	if !slices.Equal(delays, []time.Duration{25 * time.Millisecond, 27 * time.Millisecond}) {
		t.Errorf("delays %v", delays)
	}
	want := []string{"3: its ACK acknowledged 4 too", "5: its ACK went with frames of the client's own",
		"8: packet 7 before it was never acknowledged", "9: packet 7 before it was never acknowledged"}
	if !slices.Equal(why, want) {
		t.Errorf("said nothing: %q, want %q", why, want)
	}
	h.got = h.got[:1]
	if _, why := h.delaysOf(10); len(why) != 6 || why[0] != "2: never acknowledged" {
		t.Errorf("none acknowledged: %q", why)
	}
	if said := saidNothing(nil); said != "none said nothing" {
		t.Errorf("saidNothing(nil) = %q", said)
	}
	if said := saidNothing([]string{"a", "b"}); said != "2 said nothing: a; b" {
		t.Errorf("saidNothing = %q", said)
	}
}

// before is whether one of delays is less than d.
func before(d time.Duration) func([]time.Duration) bool {
	return func(delays []time.Duration) bool {
		return slices.ContainsFunc(delays, func(x time.Duration) bool { return x < d })
	}
}

// saidNothing is what loneDelays heard of lone packets that said nothing.
func saidNothing(why []string) string {
	if len(why) == 0 {
		return "none said nothing"
	}
	return fmt.Sprintf("%d said nothing: %s", len(why), strings.Join(why, "; "))
}

func TestALonePacketIsAcknowledgedAsLateAsChromes(t *testing.T) {
	// the profile's 24 ms timer and Chrome's 4 ms on macOS: Chrome 155
	// said 28.9 ms, the median of its delayed ACKs on the bench; a timer
	// never fires early, and a loaded machine fires it later now and then
	delays, why := loneDelays(t, quicProfile(t, nil), 100*time.Millisecond, before(74*time.Millisecond))
	if !before(74 * time.Millisecond)(delays) {
		t.Fatalf("acknowledged after %v, want 28 ms or a little more; %s", delays, saidNothing(why))
	}
	for _, d := range delays {
		if d < 28*time.Millisecond {
			t.Errorf("acknowledged after %s, want 28 ms or a little more", d)
		}
	}
}

func TestHowLateALonePacketIsAcknowledgedIsTheProfilesToSay(t *testing.T) {
	// the JSON alone: alarms 50 ms late, the ACK's no part of its delay at
	// most (quic.ack_alarm_slack_percent, which «How a QUIC client
	// acknowledges a long download» holds)
	delays, why := loneDelays(t, quicProfile(t, map[string]string{"quic.alarm_slack_ms": "50", "quic.ack_alarm_slack_percent": ""}),
		200*time.Millisecond, func(d []time.Duration) bool { return len(d) > 0 })
	if len(delays) == 0 {
		t.Errorf("alarms 50 ms late: no lone packet's ACK said how long it waited; %s", saidNothing(why))
	}
	for _, d := range delays {
		if d < 74*time.Millisecond {
			t.Errorf("acknowledged after %s, want 74 ms at least", d)
		}
	}
	// none said: on its timer, as quic-go's alarms, and the Linux and
	// Windows profiles', which say none. A loaded machine fires a timer
	// late, now and then by more than 4 ms for seconds on end, but no timer
	// fires early: one ACK sooner than 28 ms says no slack is added, which a
	// slack of 4 ms could never give, and none sooner than 24 ms, the timer
	for name, p := range map[string]*profile.Profile{
		"none said": quicProfile(t, map[string]string{"quic.alarm_slack_ms": "", "quic.ack_alarm_slack_percent": ""}),
		"linux":     shippedProfile(t, "chrome_155_linux"),
		"windows":   shippedProfile(t, "chrome_155_windows"),
	} {
		delays, why := loneDelays(t, p, 60*time.Millisecond, before(28*time.Millisecond))
		if !before(28 * time.Millisecond)(delays) {
			t.Errorf("%s: acknowledged after its timer and 4 ms more each time, %v; %s", name, delays, saidNothing(why))
		}
		for _, d := range delays {
			if d < 24*time.Millisecond {
				t.Errorf("%s: acknowledged after %s, before its timer", name, d)
			}
		}
	}
}
