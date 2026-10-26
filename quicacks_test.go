package tlsforge

import (
	"io"
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
// downloading it, the client's ACK of the lone packet included.
func download(t *testing.T, p *profile.Profile) *downloadSeen {
	t.Helper()
	port, heard := bundleSite(t, longDownload)
	c := echClient(t, alpsNames(t), WithProfileValue(p))
	res, err := c.Do(&Request{URL: "https://h3.h3.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Body) != downloadSize {
		t.Fatalf("came %q, want the long answer over QUIC", res.Body[:min(len(res.Body), 20)])
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

// eachAfterTheGap says whether each of the four packets after the first
// number the server skipped had an ACK of its own, the largest of it.
func (s *downloadSeen) eachAfterTheGap(t *testing.T) bool {
	t.Helper()
	var skip qlog.PacketNumber = -1
	for _, pn := range s.skipped {
		if pn > s.first && pn+4 <= s.last {
			skip = pn
			break
		}
	}
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

func TestALongDownloadIsAcknowledgedAsChromeAcknowledgesIt(t *testing.T) {
	s := download(t, quicProfile(t, nil))
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
	// is less than the floor, 1 ms, and 0.2 ms late, a fifth of it; a timer
	// never fires early
	if d := s.loneDelay(); d < 1200*time.Microsecond || d >= 5*time.Millisecond {
		t.Errorf("the lone packet acknowledged after %s, want 1.2 ms or a little more", d)
	}
}

func TestHowALongDownloadIsAcknowledgedIsTheProfilesToSay(t *testing.T) {
	// the JSON alone: no decimation, two by two to the end, and a lone
	// packet as its timer says, 24 ms and 4 late (probedLate: a server's
	// probe would otherwise come first)
	off := map[string]string{}
	for _, k := range []string{"quic.ack_decimation_after", "quic.ack_decimation_packets",
		"quic.ack_decimation_rtt_percent", "quic.ack_decimation_min_ms"} {
		off[k] = ""
	}
	s := download(t, probedLate(quicProfile(t, off)))
	if before, after, _ := s.mostFresh(10); before != 2 || after != 2 {
		t.Errorf("without decimation, ACKs of at most %d and %d packets, want 2 throughout", before, after)
	}
	if d := s.loneDelay(); d < 28*time.Millisecond {
		t.Errorf("without decimation, the lone packet acknowledged after %s, want 28 ms at least", d)
	}
	// five by five, and a floor of 10 ms, 2 late
	s = download(t, quicProfile(t, map[string]string{"quic.ack_decimation_packets": "5", "quic.ack_decimation_min_ms": "10"}))
	if _, after, fives := s.mostFresh(5); after != 5 || fives < 80 {
		t.Errorf("ACKs of at most %d packets after the 100th (%d of five), want 5", after, fives)
	}
	if d := s.loneDelay(); d < 12*time.Millisecond || d >= 28*time.Millisecond {
		t.Errorf("a floor of 10 ms: the lone packet acknowledged after %s, want 12 ms or a little more", d)
	}
	// the slack whole, 4 ms, not a fifth of the delay
	if d := download(t, quicProfile(t, map[string]string{"quic.ack_alarm_slack_percent": ""})).loneDelay(); d < 5*time.Millisecond {
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
