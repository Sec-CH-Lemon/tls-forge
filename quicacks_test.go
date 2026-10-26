package tlsforge

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/quicvarint"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// How a Chrome profile's QUIC client acknowledges a long download, as Chrome
// 155's (bench/h3's /big in ../net-fp-server/captures/review-20261023,
// ackdec-chrome.sh cohorts c2 to c4 of 2026-10-26; quiche at Chrome 155's
// DEPS revision): every second ack-eliciting packet until the server's
// first packet number plus 100, every tenth after, each ACK sent before the
// next packet is taken; each of the four packets after a number the server
// skipped at once; the twentieth ACK-only packet in a row carrying MAX_DATA;
// and a lone packet after the 100th acknowledged a quarter of the least
// round trip after it came, a millisecond at least, and a fifth of that late.

// downloadSize is a long answer's: more than 520 of the server's packets,
// so that quic-go's server skips a packet number in it (its first skip is
// within its first 514).
const downloadSize = 1 << 20

// downloadSeen is what a server of a long download heard of its client's
// ACKs, in order, and what it sent: its first 1-RTT packet number, the ones
// it skipped, and the packet it sent alone at the end, after a pause.
type downloadSeen struct {
	acks    []seenACK
	first   qlog.PacketNumber
	last    qlog.PacketNumber
	skipped []qlog.PacketNumber
	lone    qlog.PacketNumber
	heard   *bundleHeard
}

// seenACK is an ACK of the client's 1-RTT packets: the largest it
// acknowledges, how many of the server's ack-eliciting packets it
// acknowledged first, the delay it said, and the other frames of its
// packet that made it ack-eliciting.
type seenACK struct {
	largest qlog.PacketNumber
	fresh   int
	delay   time.Duration
	others  []any
}

// longDownload answers a bundleSite's request with downloadSize bytes, then,
// once everything is acknowledged, sends a frame no client reads on its
// control stream, a packet alone.
func longDownload(control *quic.SendStream, str *quic.Stream) {
	_, _ = io.Copy(io.Discard, str)
	// HEADERS of :status 200, the static table's 25, then the body
	answer := h3Frame(0x01, 0x00, 0x00, 0xd9)
	answer = quicvarint.Append(quicvarint.Append(answer, 0x00), downloadSize)
	_, _ = str.Write(append(answer, make([]byte, downloadSize)...))
	_ = str.Close()
	time.Sleep(300 * time.Millisecond)
	_, _ = control.Write(h3Frame(0x21, 0))
}

// download is what a bundleSite of longDownload heard of a client wearing p
// downloading it, the client's ACK of the lone packet included. A loaded
// machine may set QUIC up after the site's TCP, which answers a round trip
// late, and the answer comes over TCP: such a run is run again.
func download(t *testing.T, p *profile.Profile) *downloadSeen {
	t.Helper()
	var heard *bundleHeard
	var c *Client
	for try := 1; ; try++ {
		var port string
		port, heard = bundleSite(t, longDownload)
		c = echClient(t, alpsNames(t), WithProfileValue(p))
		res, err := c.Do(&Request{URL: "https://h3.h3.test:" + port + "/"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Body) == downloadSize {
			break
		}
		if !strings.HasPrefix(res.Text(), "HTTP/") {
			t.Fatalf("came %q, want the long answer over QUIC", res.Body[:min(len(res.Body), 20)])
		}
		if try == 3 {
			t.Fatalf("came over TCP (%s) in each of three runs, want the long answer over QUIC", res.Text())
		}
		_ = c.Close()
	}
	// the control stream's type and SETTINGS come first on it
	lone := heard.sentWith(3, int64(1+len(qpackTable)))
	for deadline := time.Now().Add(2 * time.Second); (lone < 0 || heard.ackOf(lone) == nil) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		lone = heard.sentWith(3, int64(1+len(qpackTable)))
	}
	if lone < 0 || heard.ackOf(lone) == nil {
		t.Fatal("the lone packet was never acknowledged")
	}
	_ = c.Close()
	seen := &downloadSeen{lone: lone, heard: heard, first: -1}
	heard.mu.Lock()
	defer heard.mu.Unlock()
	eliciting := map[qlog.PacketNumber]bool{}
	for _, s := range heard.sent {
		if s.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		pn := s.Header.PacketNumber
		if seen.first < 0 || pn < seen.first {
			seen.first = pn
		}
		seen.last = max(seen.last, pn)
		for _, f := range s.Frames {
			switch f.Frame.(type) {
			case *qlog.AckFrame, *qlog.ConnectionCloseFrame:
			default:
				eliciting[pn] = true
			}
		}
		if _, ok := eliciting[pn]; !ok {
			eliciting[pn] = false
		}
	}
	for pn := seen.first; pn <= seen.last; pn++ {
		if _, ok := eliciting[pn]; !ok {
			seen.skipped = append(seen.skipped, pn)
		}
	}
	acked := map[qlog.PacketNumber]bool{}
	for _, g := range heard.got {
		if g.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		var ack *qlog.AckFrame
		var others []any
		for _, f := range g.Frames {
			if a, ok := f.Frame.(*qlog.AckFrame); ok {
				ack = a
			} else {
				others = append(others, f.Frame)
			}
		}
		if ack == nil {
			if len(others) > 0 {
				seen.acks = append(seen.acks, seenACK{largest: -1, others: others})
			}
			continue
		}
		a := seenACK{largest: ack.LargestAcked(), delay: ack.DelayTime, others: others}
		for _, r := range ack.AckRanges {
			for pn := r.Smallest; pn <= r.Largest; pn++ {
				if !acked[pn] && eliciting[pn] {
					a.fresh++
				}
				acked[pn] = true
			}
		}
		seen.acks = append(seen.acks, a)
	}
	return seen
}

// mostFresh is the most of the server's ack-eliciting packets an ACK
// acknowledged first, before the server's first 1-RTT packet number plus
// 100 and after, and how many acknowledged exactly n after.
func (s *downloadSeen) mostFresh(n int) (before, after, exactly int) {
	for _, a := range s.acks {
		if a.largest < 0 {
			continue
		}
		if a.largest < s.first+100 {
			before = max(before, a.fresh)
			continue
		}
		after = max(after, a.fresh)
		if a.fresh == n {
			exactly++
		}
	}
	return before, after, exactly
}

// gap is the first number the server skipped with four packets after it,
// or -1.
func (s *downloadSeen) gap() qlog.PacketNumber {
	for _, pn := range s.skipped {
		if pn > s.first && pn+4 <= s.last {
			return pn
		}
	}
	return -1
}

// eachAfterTheGap says whether each of the four packets after the first
// number the server skipped had an ACK of its own, the largest of it.
func (s *downloadSeen) eachAfterTheGap(t *testing.T) bool {
	t.Helper()
	skip := s.gap()
	if skip < 0 {
		t.Fatalf("the server skipped no packet number of %d..%d (%v)", s.first, s.last, s.skipped)
	}
	largest := map[qlog.PacketNumber]bool{}
	for _, a := range s.acks {
		largest[a.largest] = true
	}
	for k := qlog.PacketNumber(1); k <= 4; k++ {
		if !largest[skip+k] {
			return false
		}
	}
	return true
}

// ackOnlyFrames are the frames that made a packet with an ACK of the
// client's ack-eliciting, each with how many ACK-only packets came before
// it in a row.
func (s *downloadSeen) ackOnlyFrames() (frames []any, after []int) {
	run := 0
	for _, a := range s.acks {
		if len(a.others) == 0 {
			run++
			continue
		}
		if a.largest >= 0 && len(a.others) == 1 {
			switch a.others[0].(type) {
			case *qlog.PingFrame, *qlog.MaxDataFrame:
				frames = append(frames, a.others[0])
				after = append(after, run)
			}
		}
		run = 0
	}
	return frames, after
}

// loneDelay is the delay the ACK of the lone packet said.
func (s *downloadSeen) loneDelay() time.Duration {
	return s.heard.ackOf(s.lone).DelayTime
}

// disturbance is why the ACK of the lone packet says nothing of how long
// the client waits for one, or "": a number among the four before it that
// the client never acknowledged, skipped or lost, made it one of the four
// after a gap (quic.ack_gap_packets), acknowledged at once; or the ACK is
// of a later packet too, a probe the server sent before a loaded machine
// fired the client's alarm.
func (s *downloadSeen) disturbance() string {
	for pn := s.lone - 4; pn < s.lone; pn++ {
		if s.heard.ackOf(pn) == nil {
			return fmt.Sprintf("%d, before the lone packet %d, never acknowledged", pn, s.lone)
		}
	}
	if largest := s.heard.ackOf(s.lone).LargestAcked(); largest != s.lone {
		return fmt.Sprintf("the lone packet %d acknowledged with %d", s.lone, largest)
	}
	return ""
}

// probed is why the client's packets say nothing of which of them it makes
// ack-eliciting, or "": a number of the client's the server never heard,
// which it skips before a probe, whose frames, MAX_DATA among them, go
// again (a loaded server may acknowledge a packet later than the probe is
// due), or a packet of the client's lost.
func (s *downloadSeen) probed() string {
	s.heard.mu.Lock()
	defer s.heard.mu.Unlock()
	var last qlog.PacketNumber = -1
	for _, g := range s.heard.got {
		if g.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		if pn := g.Header.PacketNumber; last >= 0 && pn != last+1 {
			return fmt.Sprintf("the client's %d never heard", last+1)
		}
		last = g.Header.PacketNumber
	}
	return ""
}

// gapForgotten is why the four packets after the number eachAfterTheGap
// looks at say nothing of how the client acknowledges a gap, or "": one of
// them lost, or one acknowledging a packet of the client's whose ACK went
// past the gap, as a loaded server, slow to send them, may; the client then
// knows the server knows of the gap and forgets it (IgnoreBelow), as
// quiche's DontWaitForPacketsBefore does.
func (s *downloadSeen) gapForgotten() string {
	skip := s.gap()
	if skip < 0 {
		return ""
	}
	for pn := skip + 1; pn <= skip+4; pn++ {
		if s.heard.ackOf(pn) == nil {
			return fmt.Sprintf("%d, after the skipped %d, never acknowledged", pn, skip)
		}
	}
	s.heard.mu.Lock()
	defer s.heard.mu.Unlock()
	past := map[qlog.PacketNumber]bool{}
	for _, g := range s.heard.got {
		for _, f := range g.Frames {
			if a, ok := f.Frame.(*qlog.AckFrame); ok && g.Header.PacketType == qlog.PacketType1RTT && a.LargestAcked() > skip {
				past[g.Header.PacketNumber] = true
			}
		}
	}
	for _, p := range s.heard.sent {
		pn := p.Header.PacketNumber
		if p.Header.PacketType != qlog.PacketType1RTT || pn <= skip || pn > skip+4 {
			continue
		}
		for _, f := range p.Frames {
			if a, ok := f.Frame.(*qlog.AckFrame); ok {
				for c := range past {
					if a.AcksPacket(c) {
						return fmt.Sprintf("%d, after the skipped %d, acknowledged the client's %d, whose ACK went past it", pn, skip, c)
					}
				}
			}
		}
	}
	return ""
}

// asChromes is why a download of a client wearing a profile as shipped
// says nothing of what Chrome does, or "": a disturbance of the lone
// packet's ACK; that ACK as late as the slack whole would make it, 5 ms or
// more, which a loaded machine does too, firing the client's alarm late and
// making its round trips, its min RTT among them, longer, a quarter of which
// an ACK after the 100th packet waits (none waits less, a timer never firing
// early); the client probed; or the gap forgotten.
func (s *downloadSeen) asChromes() string {
	if w := s.disturbance(); w != "" {
		return w
	}
	if d := s.loneDelay(); d >= 5*time.Millisecond {
		return fmt.Sprintf("the lone packet acknowledged after %s", d)
	}
	if w := s.probed(); w != "" {
		return w
	}
	return s.gapForgotten()
}

// undisturbed is download of a client wearing p (probedLate, so that the
// server's probe is due 200 ms after the lone packet, past any alarm of the
// client's) of which disturbed says nothing: a run it says something of is
// run again, tries times at most.
func undisturbed(t *testing.T, p *profile.Profile, tries int, disturbed func(*downloadSeen) string) *downloadSeen {
	t.Helper()
	p = probedLate(p)
	var why []string
	for range tries {
		s := download(t, p)
		w := disturbed(s)
		if w == "" {
			return s
		}
		why = append(why, w)
	}
	t.Fatalf("disturbed in every run: %s", strings.Join(why, "; "))
	return nil
}

// loneDownload is a download undisturbed of a client wearing p, whose ACK
// of the lone packet says how long it waited (disturbance).
func loneDownload(t *testing.T, p *profile.Profile) *downloadSeen {
	t.Helper()
	return undisturbed(t, p, 4, (*downloadSeen).disturbance)
}

func TestALongDownloadIsAcknowledgedAsChromeAcknowledgesIt(t *testing.T) {
	// a download run again while a loaded machine had a part in it
	s := undisturbed(t, quicProfile(t, nil), 8, (*downloadSeen).asChromes)
	// two by two to the server's first packet number plus 100, ten by ten
	// after, never more: an ACK goes before the next packet is taken
	before, after, tens := s.mostFresh(10)
	if before != 2 || after != 10 || tens < 40 {
		t.Errorf("ACKs of at most %d packets before the 100th, %d after (%d of ten), want 2, 10 and most of ten", before, after, tens)
	}
	// each of the four packets after a skipped number at once
	if !s.eachAfterTheGap(t) {
		t.Error("the four packets after a skipped number were not each acknowledged at once")
	}
	// the twentieth ACK-only packet in a row carries MAX_DATA, the
	// connection's window as it stands
	frames, runs := s.ackOnlyFrames()
	if len(frames) < 3 {
		t.Fatalf("%d ACK packets made ack-eliciting, want one in twenty", len(frames))
	}
	for i, f := range frames {
		if md, ok := f.(*qlog.MaxDataFrame); !ok || md.MaximumData != 15728640 || runs[i] != 19 {
			t.Errorf("%T %+v after %d ACK-only packets, want MAX_DATA 15728640 after 19", f, f, runs[i])
		}
	}
	// a lone packet after the 100th: a quarter of a round trip on loopback
	// is less than the floor, 1 ms, and 0.2 ms late, a fifth of it, not the
	// whole 4 ms (asChromes); a timer never fires early
	if d := s.loneDelay(); d < 1200*time.Microsecond {
		t.Errorf("the lone packet acknowledged after %s, want 1.2 ms or a little more", d)
	}
}

func TestHowALongDownloadIsAcknowledgedIsTheProfilesToSay(t *testing.T) {
	// the JSON alone: no decimation, two by two to the end, and a lone
	// packet as its timer says, 24 ms and 4 late
	off := map[string]string{}
	for _, k := range []string{"quic.ack_decimation_after", "quic.ack_decimation_packets",
		"quic.ack_decimation_rtt_percent", "quic.ack_decimation_min_ms"} {
		off[k] = ""
	}
	s := loneDownload(t, quicProfile(t, off))
	if before, after, _ := s.mostFresh(10); before != 2 || after != 2 {
		t.Errorf("without decimation, ACKs of at most %d and %d packets, want 2 throughout", before, after)
	}
	if d := s.loneDelay(); d < 28*time.Millisecond {
		t.Errorf("without decimation, the lone packet acknowledged after %s, want 28 ms at least", d)
	}
	// five by five, and a floor of 10 ms, 2 late; a timer of 100 ms, so that
	// the floor is told from the timer however late a loaded machine fires
	// the alarm
	s = loneDownload(t, quicProfile(t, map[string]string{"quic.ack_decimation_packets": "5",
		"quic.ack_decimation_min_ms": "10", "quic.ack_timer_ms": "100"}))
	if _, after, fives := s.mostFresh(5); after != 5 || fives < 80 {
		t.Errorf("ACKs of at most %d packets after the 100th (%d of five), want 5", after, fives)
	}
	if d := s.loneDelay(); d < 12*time.Millisecond || d >= 100*time.Millisecond {
		t.Errorf("a floor of 10 ms: the lone packet acknowledged after %s, want 12 ms or a little more", d)
	}
	// the slack whole, 4 ms, not a fifth of the delay
	if d := loneDownload(t, quicProfile(t, map[string]string{"quic.ack_alarm_slack_percent": ""})).loneDelay(); d < 5*time.Millisecond {
		t.Errorf("the slack whole: the lone packet acknowledged after %s, want 5 ms at least", d)
	}
	// a PING in every fifth ACK packet
	frames, runs := download(t, quicProfile(t, map[string]string{"quic.ack_only_frame": `"ping"`, "quic.ack_only_max": "4"})).ackOnlyFrames()
	if len(frames) < 10 {
		t.Fatalf("%d ACK packets made ack-eliciting, want one in five", len(frames))
	}
	for i, f := range frames {
		if _, ok := f.(*qlog.PingFrame); !ok || runs[i] != 4 {
			t.Errorf("%T after %d ACK-only packets, want a PING after 4", f, runs[i])
		}
	}
	// quic-go's rule of a gap: at once when it is new, not each packet
	// after it
	if download(t, quicProfile(t, map[string]string{"quic.ack_gap_packets": ""})).eachAfterTheGap(t) {
		t.Error("quic-go's rule of a gap: each of the four packets after it acknowledged at once")
	}
}

func TestPacketsReadTogetherAreAcknowledgedTogetherWithoutTheProfilesWord(t *testing.T) {
	// the JSON alone: the packets read at once, then the ACK, as quic-go's;
	// on loopback a burst comes faster than the client reads it, so an ACK
	// acknowledges more than its count now and then
	for range 3 {
		before, after, _ := download(t, quicProfile(t, map[string]string{"quic.ack_sent_after": ""})).mostFresh(10)
		if before > 2 || after > 10 {
			return
		}
	}
	t.Error("read together, no ACK acknowledged more than its count in three downloads of three")
}
