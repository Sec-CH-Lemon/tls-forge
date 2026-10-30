package tlsforge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"net"
	"regexp"
	"sync"
	"testing"
	"time"

	stdhttp "net/http"
	"net/http/httptest"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
)

// A QUIC client's Initial packets read off the wire as a server reads them
// (RFC 9001, section 5: keys of the first DCID, header protection, AEAD), so
// that the first flight, probes and closes a profile's JSON makes are held
// to Chrome's measured ones (bench/h3, cohorts h3a and h3b).

// initialSalt is QUIC v1's (RFC 9001, section 5.2).
var initialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// expandLabel is TLS 1.3's HKDF-Expand-Label with no context.
func expandLabel(t *testing.T, secret []byte, label string, n int) []byte {
	t.Helper()
	full := "tls13 " + label
	info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// clientInitialKeys are a client's Initial AEAD and header protection keys
// for the DCID of its first Initial.
func clientInitialKeys(t *testing.T, dcid []byte) (cipher.AEAD, []byte, cipher.Block) {
	t.Helper()
	initial, err := hkdf.Extract(sha256.New, dcid, initialSalt)
	if err != nil {
		t.Fatal(err)
	}
	secret := expandLabel(t, initial, "client in", 32)
	block, err := aes.NewCipher(expandLabel(t, secret, "quic key", 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	hp, err := aes.NewCipher(expandLabel(t, secret, "quic hp", 16))
	if err != nil {
		t.Fatal(err)
	}
	return aead, expandLabel(t, secret, "quic iv", 12), hp
}

// quicInitial is a client's Initial opened: its number, how many bytes the
// number took, its frames.
type quicInitial struct {
	pn     uint64
	pnLen  int
	frames []quicFrame
}

// quicFrame is a frame of an Initial: its type, and for CRYPTO its offset
// and data, for CONNECTION_CLOSE its code and reason.
type quicFrame struct {
	typ    uint64
	offset uint64
	data   []byte
	code   uint64
	reason string
}

// openInitial opens the Initial at the start of d, a datagram of the client
// whose first Initial had dcid; it says the rest of the datagram (the
// coalesced packets after it).
func openInitial(t *testing.T, d, dcid []byte) (quicInitial, []byte) {
	t.Helper()
	d = append([]byte(nil), d...)
	if len(d) < 7 || d[0]&0xf0 != 0xc0 {
		t.Fatalf("no Initial: %x", d[:min(len(d), 8)])
	}
	at := 5
	at += 1 + int(d[at]) // DCID
	at += 1 + int(d[at]) // SCID
	token, n, err := quicvarint.Parse(d[at:])
	if err != nil {
		t.Fatal(err)
	}
	at += n + int(token)
	length, n, err := quicvarint.Parse(d[at:])
	if err != nil {
		t.Fatal(err)
	}
	at += n
	aead, iv, hp := clientInitialKeys(t, dcid)
	mask := make([]byte, 16)
	hp.Encrypt(mask, d[at+4:at+20])
	d[0] ^= mask[0] & 0x0f
	pnLen := int(d[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		d[at+i] ^= mask[1+i]
		pn = pn<<8 | uint64(d[at+i])
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	end := at + int(length)
	payload, err := aead.Open(nil, nonce, d[at+pnLen:end], d[:at+pnLen])
	if err != nil {
		t.Fatalf("the Initial does not open: %v", err)
	}
	return quicInitial{pn: pn, pnLen: pnLen, frames: quicFramesOf(t, payload)}, d[end:]
}

// quicFramesOf reads the frames an Initial may carry: PADDING (a run of it
// one frame), PING, ACK, CRYPTO and CONNECTION_CLOSE.
func quicFramesOf(t *testing.T, p []byte) []quicFrame {
	t.Helper()
	var frames []quicFrame
	read := func() uint64 {
		v, n, err := quicvarint.Parse(p)
		if err != nil {
			t.Fatalf("a frame cut short: %v", err)
		}
		p = p[n:]
		return v
	}
	for len(p) > 0 {
		typ := read()
		f := quicFrame{typ: typ}
		switch typ {
		case 0x00:
			for len(p) > 0 && p[0] == 0 {
				p = p[1:]
			}
		case 0x01:
		case 0x02, 0x03:
			read() // largest
			read() // delay
			ranges := read()
			read() // first range
			for i := uint64(0); i < 2*ranges; i++ {
				read()
			}
			if typ == 0x03 {
				read()
				read()
				read()
			}
		case 0x06:
			f.offset = read()
			n := read()
			f.data, p = p[:n], p[n:]
		case 0x1c, 0x1d:
			f.code = read()
			if typ == 0x1c {
				read() // frame type
			}
			n := read()
			f.reason, p = string(p[:n]), p[n:]
		default:
			t.Fatalf("frame type %#x in an Initial", typ)
		}
		frames = append(frames, f)
	}
	return frames
}

// count is how many frames of typ an Initial has.
func (q quicInitial) count(typ uint64) int {
	n := 0
	for _, f := range q.frames {
		if f.typ == typ {
			n++
		}
	}
	return n
}

// dcidOf is the DCID of a client's first Initial.
func dcidOf(d []byte) []byte { return append([]byte(nil), d[6:6+int(d[5])]...) }

// quicHeard is what a server heard of a client's QUIC: each datagram and
// when, from the first.
type quicHeard struct {
	mu        sync.Mutex
	datagrams [][]byte
	at        []time.Duration
	began     time.Time
	first     chan struct{}
}

func (h *quicHeard) heard() ([][]byte, []time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]byte(nil), h.datagrams...), append([]time.Duration(nil), h.at...)
}

// silentSite is a site whose TCP answers and whose UDP, on the same port,
// hears every datagram and answers none: QUIC into silence.
func silentSite(t *testing.T) (string, *quicHeard) {
	t.Helper()
	udp, tcp := udpAndTCP(t)
	h := &quicHeard{first: make(chan struct{})}
	_, port, _ := net.SplitHostPort(tcp.Addr().String())
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		// This fixture measures Initial policy, not detached-job scheduling.
		// Keep TCP's success response behind the actual first UDP observation,
		// retaining the same startup deadline and all packet assertions.
		select {
		case <-h.first:
		case <-time.After(2 * time.Second):
			t.Error("QUIC sent no first datagram before the TCP observation barrier")
			return
		}
		_, _ = w.Write([]byte(r.Proto))
	}))
	server.Listener = tcp
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	go func() {
		for {
			b := make([]byte, 2048)
			n, _, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			h.mu.Lock()
			if h.began.IsZero() {
				h.began = time.Now()
				close(h.first)
			}
			h.datagrams = append(h.datagrams, b[:n])
			h.at = append(h.at, time.Since(h.began))
			h.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = udp.Close() })
	return port, h
}

// quicProfile is chrome_155_macos with set laid over its behavior (a key
// to nil left out).
func quicProfile(t *testing.T, set map[string]string) *profile.Profile {
	t.Helper()
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	q := p.Clone()
	for k, v := range set {
		if v == "" {
			delete(q.Behavior, k)
		} else {
			q.Behavior[k] = []byte(v)
		}
	}
	return q
}

// firstFlight is the client's QUIC datagrams to a silent site the time it
// takes, wearing p.
func firstFlight(t *testing.T, p *profile.Profile, wait time.Duration) ([][]byte, []time.Duration) {
	t.Helper()
	port, heard := silentSite(t)
	dns := alpsNames(t)
	c := echClient(t, dns, WithProfileValue(p))
	if got := came(t, c, "https://h3.h3.test:"+port+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	// TCP can answer before the detached QUIC job is scheduled on a busy
	// runner. Observe its actual first datagram before counting the unchanged
	// packet collection interval; silence still fails within a bounded startup.
	select {
	case <-heard.first:
	case <-time.After(2 * time.Second):
		t.Fatal("QUIC sent no first datagram within startup deadline")
	}
	time.Sleep(wait)
	return heard.heard()
}

func TestAQUICClientsFirstFlightIsLaidOutAsChromes(t *testing.T) {
	sent, _ := firstFlight(t, quicProfile(t, nil), 100*time.Millisecond)
	if len(sent) < 2 {
		t.Fatalf("%d datagrams", len(sent))
	}
	dcid := dcidOf(sent[0])
	first, _ := openInitial(t, sent[0], dcid)
	second, _ := openInitial(t, sent[1], dcid)
	// one counter from 1, the first number of one byte, the second of two:
	// the window rule with the datagram's room
	if first.pn != 1 || first.pnLen != 1 || second.pn != 2 || second.pnLen != 2 {
		t.Errorf("numbers %d (%d bytes) and %d (%d bytes), want 1 (1) and 2 (2)", first.pn, first.pnLen, second.pn, second.pnLen)
	}
	if len(sent[0]) != 1250 || len(sent[1]) != 1250 {
		t.Errorf("datagrams of %d and %d bytes", len(sent[0]), len(sent[1]))
	}
	// chaos: each Initial with 2 to 10 PINGs and its CRYPTO split; the
	// first the ClientHello's first 55 to 86 bytes and its end, the second
	// its middle
	hello := map[uint64][]byte{}
	var length uint64
	for i, q := range []quicInitial{first, second} {
		if n := q.count(0x01); n < 2 || n > 10 {
			t.Errorf("Initial %d: %d PINGs", i+1, n)
		}
		if q.count(0x06) < 2 {
			t.Errorf("Initial %d: %d CRYPTO frames", i+1, q.count(0x06))
		}
		for _, f := range q.frames {
			if f.typ == 0x06 {
				hello[f.offset] = f.data
			}
		}
	}
	// the hello's length, from its first bytes (a CRYPTO piece may be a byte)
	var head4 []byte
	for at := uint64(0); len(head4) < 4; {
		d, ok := hello[at]
		if !ok {
			t.Fatalf("no CRYPTO data at %d", at)
		}
		head4 = append(head4, d...)
		at += uint64(len(d))
	}
	length = 4 + (uint64(head4[1])<<16 | uint64(head4[2])<<8 | uint64(head4[3]))
	var lowest, highest uint64 = 1 << 62, 0
	for _, f := range first.frames {
		if f.typ == 0x06 {
			lowest = min(lowest, f.offset)
			highest = max(highest, f.offset+uint64(len(f.data)))
		}
	}
	if lowest != 0 || highest != length {
		t.Errorf("the first Initial carries %d..%d of a hello of %d", lowest, highest, length)
	}
	var head uint64
	for _, f := range first.frames {
		if f.typ == 0x06 && f.offset < 100 {
			head = max(head, f.offset+uint64(len(f.data)))
		}
	}
	if head < 55 || head > 86 {
		t.Errorf("the first Initial's head of the hello is %d bytes, want 55 to 86", head)
	}
	covered := uint64(0)
	for covered < length {
		d, ok := hello[covered]
		if !ok {
			t.Fatalf("the hello has a hole at %d of %d", covered, length)
		}
		covered += uint64(len(d))
	}
}

func TestAQUICClientsFirstFlightIsTheProfilesToSay(t *testing.T) {
	// the JSON alone: separate numbers and quic-go's scramble, no PING
	p := quicProfile(t, map[string]string{"quic.packet_numbers": `"separate"`, "quic.first_packet_number": "",
		"quic.packet_number_length": "", "quic.pto_skip": "", "quic.initial_layout": `"scramble"`,
		"quic.chaos_first_frame_min": "", "quic.chaos_first_frame_spread": "", "quic.chaos_crypto_splits_min": "",
		"quic.chaos_crypto_splits_max": "", "quic.chaos_pings_min": "", "quic.chaos_pings_max": ""})
	sent, _ := firstFlight(t, p, 100*time.Millisecond)
	first, _ := openInitial(t, sent[0], dcidOf(sent[0]))
	if first.pn != 0 || first.count(0x01) != 0 {
		t.Errorf("number %d, %d PINGs, want quic-go's 0 and none", first.pn, first.count(0x01))
	}
}

var idleReason = regexp.MustCompile(`^25:No recent network activity after (\d+)us\. Timeout:1s num_undecryptable_packets: 0 \{\}$`)

func TestAQUICClientProbesSilenceAndClosesAsChromeDoes(t *testing.T) {
	// Chrome's probes and close, its handshake's idle time shortened to a
	// second by the JSON alone, so that the test waits that
	p := quicProfile(t, map[string]string{"quic.handshake_idle_timeout_ms": "1000"})
	sent, at := firstFlight(t, p, 1300*time.Millisecond)
	dcid := dcidOf(sent[0])
	var numbers []uint64
	var close *quicFrame
	var probes []time.Duration
	for i, d := range sent {
		q, rest := openInitial(t, d, dcid)
		numbers = append(numbers, q.pn)
		for _, f := range q.frames {
			if f.typ == 0x1c {
				f := f
				close = &f
				if len(rest) != 0 {
					t.Errorf("the close's datagram coalesces %d bytes more", len(rest))
				}
			}
		}
		if i >= 2 && close == nil {
			probes = append(probes, at[i])
		}
	}
	// a probe 300 ms after the first flight and one 600 ms after it, each
	// one packet, a number skipped before each (one counter); then the close
	if len(probes) != 2 {
		t.Fatalf("probes at %v (numbers %v)", probes, numbers)
	}
	if probes[0] < 290*time.Millisecond || probes[0] > 400*time.Millisecond ||
		probes[1] < 880*time.Millisecond || probes[1] > 1000*time.Millisecond {
		t.Errorf("probes at %v, want about 305 ms and 910 ms", probes)
	}
	if want := []uint64{1, 2, 4, 6, 7}; fmt.Sprint(numbers) != fmt.Sprint(want) {
		t.Errorf("numbers %v, want %v", numbers, want)
	}
	if close == nil {
		t.Fatal("no CONNECTION_CLOSE")
	}
	if close.code != 0 || !idleReason.MatchString(close.reason) {
		t.Errorf("closed with %d %q", close.code, close.reason)
	}
}

func TestAQUICClientsProbesAndCloseAreTheProfilesToSay(t *testing.T) {
	// the JSON alone: two probes each time, as quic-go sends them, and a
	// silent end
	p := quicProfile(t, map[string]string{"quic.handshake_idle_timeout_ms": "1000", "quic.pto_probes": "2",
		"quic.idle_close": `"silent"`, "quic.idle_close_code": "", "quic.idle_close_reason": "",
		"quic.handshake_idle_close_reason": "", "quic.undecryptable_level_names": ""})
	sent, at := firstFlight(t, p, 1300*time.Millisecond)
	dcid := dcidOf(sent[0])
	n := 0
	for i, d := range sent {
		q, _ := openInitial(t, d, dcid)
		if q.count(0x1c) > 0 {
			t.Errorf("datagram %d closes", i)
		}
		if at[i] > 250*time.Millisecond && at[i] < 500*time.Millisecond {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d datagrams at the first probe timeout, want 2", n)
	}
}
