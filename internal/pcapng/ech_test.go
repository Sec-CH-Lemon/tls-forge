package pcapng

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	tls "github.com/igor-lemon/utls"
	"golang.org/x/crypto/cryptobyte"
)

// echConfigOf is an ECHConfig of key: X25519, HKDF-SHA256 and aead.
func echConfigOf(key *ecdh.PrivateKey, aead uint16) []byte {
	var b cryptobyte.Builder
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(3)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(aead) })
		b.AddUint8(0)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.test")) })
		b.AddUint16(0)
	})
	return b.BytesOrPanic()
}

// sentConn keeps what is written to it.
type sentConn struct {
	net.Conn
	mu   sync.Mutex
	sent []byte
}

func (c *sentConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, p...)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// lines is a key log, its lines.
type lines struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

// of is the random and the secret, in hex, of the lines of label.
func (l *lines) of(label string) [][2]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out [][2]string
	for _, line := range strings.Split(l.text.String(), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == label {
			out = append(out, [2]string{f[1], f[2]})
		}
	}
	return out
}

// echOffer is a connection whose ECH a server accepted: what its client sent,
// what its key log said of the offer, and the random of the inner hello, by
// which the key log wrote the handshake's secrets.
type echOffer struct {
	sent, secret, config []byte
	outer, inner         string
}

// offered is a uTLS client's ECH offer of aead to a server that accepts it.
func offered(t *testing.T, aead uint16) echOffer {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := echConfigOf(key, aead)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	done := make(chan error, 1)
	go func() {
		srv := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)},
			EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes()}}})
		_ = srv.SetDeadline(time.Now().Add(10 * time.Second))
		done <- srv.Handshake()
	}()
	conn := &sentConn{Conn: a}
	log := &lines{}
	list := append(binary.BigEndian.AppendUint16(nil, uint16(len(config))), config...)
	client := tls.Client(conn, &tls.Config{ServerName: "secret.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		EncryptedClientHelloConfigList: list, KeyLogWriter: log})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !client.ConnectionState().ECHAccepted {
		t.Fatal("ECH not accepted")
	}
	secret, offer, handshake := log.of(ECHSecretLabel), log.of(ECHConfigLabel), log.of("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
	if len(secret) != 1 || len(offer) != 1 || len(handshake) != 1 {
		t.Fatalf("key log %q", log.text.String())
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	s, _ := hex.DecodeString(secret[0][1])
	return echOffer{sent: conn.sent, secret: s, config: config, outer: secret[0][0], inner: handshake[0][0]}
}

// The inner hello of an ECH offer is opened with what the key log said of
// it, as Wireshark opens it: its random the one the handshake's secrets were
// written by, of every AEAD uTLS offers.
func TestTheInnerHelloOfAnECHOfferIsOpenedWithItsKeyLogLines(t *testing.T) {
	for _, aead := range []uint16{1, 2, 3} {
		o := offered(t, aead)
		hello, ok := ClientHello(o.sent)
		if !ok {
			t.Fatalf("AEAD %d: no ClientHello", aead)
		}
		if outer, _ := ClientRandom(o.sent); outer != o.outer {
			t.Errorf("AEAD %d: the offer is of %s, the hello sent %s", aead, o.outer, outer)
		}
		if inner, ok := ECHInnerRandom(hello, o.secret, o.config); !ok || inner != o.inner || inner == o.outer {
			t.Errorf("AEAD %d: opened %q, %v, want %s", aead, inner, ok, o.inner)
		}
	}
}

// changed is hello with what change does to a copy of it.
func changed(hello []byte, change func([]byte) []byte) []byte {
	return change(bytes.Clone(hello))
}

// What does not open an offer is no inner hello: a hello not whole or not one,
// one of no outer offer, an offer that does not read, a config that does not,
// a suite it does not know, or what does not open its payload.
func TestWhatDoesNotOpenAnECHOfferIsNoInnerHello(t *testing.T) {
	o := offered(t, 1)
	hello, _ := ClientHello(o.sent)
	body := hello[4:]
	ext, at, ok := extensionOf(body, extensionECH)
	if !ok {
		t.Fatal("no ECH extension")
	}
	// Where the offer begins in the message, and where its payload's length
	// is: after its kind, KDF, AEAD, config ID and encapsulated key.
	at += 4
	payloadLen := at + 8 + int(binary.BigEndian.Uint16(ext[6:8]))
	for _, tc := range []struct {
		name           string
		hello          []byte
		secret, config []byte
	}{
		{"a length that is not the hello's", changed(hello, func(h []byte) []byte { h[3]++; return h }), o.secret, o.config},
		{"no ClientHello", changed(hello, func(h []byte) []byte { h[0] = 2; return h }), o.secret, o.config},
		{"no outer offer", changed(hello, func(h []byte) []byte { h[at-4], h[at-3] = 0xfa, 0xfa; return h }), o.secret, o.config},
		{"an extension that does not read", changed(hello, func(h []byte) []byte { h[at-2], h[at-1] = 0xff, 0xff; return h }),
			o.secret, o.config},
		{"extensions cut short", func() []byte {
			h := bytes.Clone(hello[:at-4+2])
			binary.BigEndian.PutUint16(h[2:4], uint16(len(h)-4))
			h[1] = 0
			return h
		}(), o.secret, o.config},
		{"an offer cut short", changed(hello, func(h []byte) []byte {
			binary.BigEndian.PutUint16(h[payloadLen:], 0xffff)
			return h
		}), o.secret, o.config},
		{"an inner offer", changed(hello, func(h []byte) []byte { h[at] = 1; return h }), o.secret, o.config},
		{"more after the payload", changed(hello, func(h []byte) []byte {
			binary.BigEndian.PutUint16(h[payloadLen:], binary.BigEndian.Uint16(h[payloadLen:])-1)
			return h
		}), o.secret, o.config},
		{"a KDF it does not know", changed(hello, func(h []byte) []byte { h[at+2] = 2; return h }), o.secret, o.config},
		{"an AEAD it does not know", changed(hello, func(h []byte) []byte { h[at+4] = 9; return h }), o.secret, o.config},
		{"a config of another version", hello, o.secret, changed(o.config, func(c []byte) []byte { c[1] = 0x0c; return c })},
		{"a config cut short", hello, o.secret, o.config[:6]},
		{"another secret", hello, changed(o.secret, func(s []byte) []byte { s[0] ^= 1; return s }), o.config},
	} {
		if inner, ok := ECHInnerRandom(tc.hello, tc.secret, tc.config); ok {
			t.Errorf("%s: opened %s", tc.name, inner)
		}
	}
}

// A ClientHello whole is read from what a client sent, after a tunnel and
// across the records it came in; not while it is cut short, nor what is none.
func TestAClientHelloIsReadWholeFromWhatWasSent(t *testing.T) {
	message := append([]byte{1, 0, 0, 40}, bytes.Repeat([]byte{7}, 40)...)
	record := func(b []byte) []byte { return append([]byte{22, 3, 1, byte(len(b) >> 8), byte(len(b))}, b...) }
	for _, tc := range []struct {
		name string
		sent []byte
		ok   bool
	}{
		{"one record", record(message), true},
		{"and more after it", append(record(message), 23, 3, 3, 0, 1, 0), true},
		{"two records", append(record(message[:10]), record(message[10:])...), true},
		{"after a CONNECT", append([]byte("CONNECT a:443 HTTP/1.1\r\n\r\n"), record(message)...), true},
		{"a CONNECT cut short", []byte("CONNECT a:443 HTTP/1.1\r\n"), false},
		{"a record cut short", record(message)[:30], false},
		{"all of it but its last byte", record(message[:len(message)-1]), false},
		{"its second record not yet", record(message[:10]), false},
		{"another message", record(append([]byte{2}, message[1:]...)), false},
		{"another record", append([]byte{23}, record(message)[1:]...), false},
		{"nothing", nil, false},
	} {
		got, ok := ClientHello(tc.sent)
		if ok != tc.ok || ok && !bytes.Equal(got, message) {
			t.Errorf("%s: %x, %v", tc.name, got, ok)
		}
	}
}

// So is one from a QUIC client's Initial packets, once they hold it whole.
func TestAQUICClientHelloIsReadWholeFromItsInitialPackets(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	whole := append(hello(bytes.Repeat([]byte{5}, 32)), bytes.Repeat([]byte{9}, 256-36)...)
	initial := func(number uint64, frames ...[]byte) []byte {
		return sealed(dcid, number, 1, bytes.Join(frames, nil), initialPacket, quicVersion1, nil, true)
	}
	for _, tc := range []struct {
		name string
		sent [][]byte
		ok   bool
	}{
		{"one packet", [][]byte{initial(1, frame(0, whole))}, true},
		{"two datagrams", [][]byte{initial(1, frame(0, whole[:100])), initial(2, frame(100, whole[100:]))}, true},
		{"its first datagram alone", [][]byte{initial(1, frame(0, whole[:100]))}, false},
		{"no ClientHello", [][]byte{initial(1, frame(0, append([]byte{2}, whole[1:]...)))}, false},
	} {
		got, ok := QUICClientHello(tc.sent)
		if ok != tc.ok || ok && !bytes.Equal(got, whole) {
			t.Errorf("%s: %d bytes, %v", tc.name, len(got), ok)
		}
	}
}
