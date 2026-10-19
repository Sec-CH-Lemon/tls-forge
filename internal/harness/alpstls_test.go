package harness

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"hash"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/bogdanfinn/utls"
	"golang.org/x/crypto/cryptobyte"
)

// testHello is a ClientHello a test makes: what it offers, and raw extensions
// after them, for one that does not read.
type testHello struct {
	sessionID     []byte
	suites        []uint16
	versions      []uint16
	schemes       []uint16
	share         []byte
	alpn          []string
	alps          uint16
	alpsProtocols []string
	extra         []byte
}

// chromeLike is a ClientHello of what the bench's TLS takes, offering ALPS for
// h2 as Chrome does, with share as its share of X25519.
func chromeLike(share []byte) testHello {
	return testHello{sessionID: bytes.Repeat([]byte{7}, 32), suites: []uint16{0x1302, 0x1301}, versions: []uint16{0x0304},
		schemes: []uint16{0x0804, 0x0403}, share: share, alpn: []string{"h2", "http/1.1"}, alps: extALPS,
		alpsProtocols: []string{"h2"}}
}

func names(b *cryptobyte.Builder, list []string) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, n := range list {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(n)) })
		}
	})
}

func (h testHello) body() []byte {
	var b cryptobyte.Builder
	b.AddUint16(0x0303)
	b.AddBytes(make([]byte, 32))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(h.sessionID) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, s := range h.suites {
			b.AddUint16(s)
		}
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		ext := func(typ uint16, f func(*cryptobyte.Builder)) {
			b.AddUint16(typ)
			b.AddUint16LengthPrefixed(f)
		}
		ext(extSupportedVersions, func(b *cryptobyte.Builder) {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, v := range h.versions {
					b.AddUint16(v)
				}
			})
		})
		ext(extSignatureAlgorithms, func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, v := range h.schemes {
					b.AddUint16(v)
				}
			})
		})
		ext(extKeyShare, func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x11ec)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 4)) })
				if h.share != nil {
					b.AddUint16(0x001d)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(h.share) })
				}
			})
		})
		if h.alpn != nil {
			ext(extALPN, func(b *cryptobyte.Builder) { names(b, h.alpn) })
		}
		if h.alps != 0 {
			ext(h.alps, func(b *cryptobyte.Builder) { names(b, h.alpsProtocols) })
		}
		b.AddBytes(h.extra)
	})
	return b.BytesOrPanic()
}

// plainRecord is a record of type typ carrying body in the clear.
func plainRecord(typ byte, body []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

// handshaken is how a test's handshake with the bench's ALPS server came out.
type handshaken struct {
	conn *alpsConn
	seen *ALPSHandshake
	err  error
}

// scripted is the client end of a handshake with the bench's ALPS server that
// a test writes itself: its transcript, its handshake keys, and the
// application keys of both ends once its Finished is sent.
type scripted struct {
	conn         net.Conn
	transcript   hash.Hash
	clientSecret []byte
	out          *recordCipher
	master       []byte
	application  []byte
	negotiated   bool
	done         chan handshaken
}

// shake begins a handshake with srv: it sends h, a ClientHello whose share of
// X25519 is filled in unless it has one, reads the server's flight, and is
// the client ready to send its own.
func shake(t *testing.T, srv *alpsServer, h testHello) *scripted {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = serverEnd.Close(); _ = clientEnd.Close() })
	_ = clientEnd.SetDeadline(time.Now().Add(10 * time.Second))
	c := &scripted{conn: clientEnd, done: make(chan handshaken, 1)}
	go func() {
		conn, seen, err := srv.handshake(serverEnd)
		c.done <- handshaken{conn, seen, err}
	}()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if h.share == nil {
		h.share = key.PublicKey().Bytes()
	}
	hello := handshakeMessage(msgClientHello, h.body())
	if _, err := clientEnd.Write(plainRecord(recordHandshake, hello)); err != nil {
		t.Fatalf("writing the ClientHello: %v", err)
	}
	_, sh, err := readRecord(clientEnd)
	if err != nil {
		t.Fatalf("reading the ServerHello: %v", err)
	}
	s := cryptobyte.String(sh[4:])
	var sid, extensions cryptobyte.String
	var share []byte
	if !s.Skip(2+32) || !s.ReadUint8LengthPrefixed(&sid) || !s.Skip(3) || !s.ReadUint16LengthPrefixed(&extensions) {
		t.Fatalf("a ServerHello that does not read: %x", sh)
	}
	for !extensions.Empty() {
		var typ uint16
		var data cryptobyte.String
		extensions.ReadUint16(&typ)
		extensions.ReadUint16LengthPrefixed(&data)
		if typ == extKeyShare {
			share = data[4:]
		}
	}
	peer, _ := ecdh.X25519().NewPublicKey(share)
	shared, _ := key.ECDH(peer)
	c.transcript = sha256.New()
	c.transcript.Write(hello)
	c.transcript.Write(sh)
	zeros := make([]byte, 32)
	empty := sha256.Sum256(nil)
	secret := hkdfExtract(expandLabel(hkdfExtract(zeros, zeros), "derived", empty[:], 32), shared)
	c.clientSecret = expandLabel(secret, "c hs traffic", c.transcript.Sum(nil), 32)
	serverSecret := expandLabel(secret, "s hs traffic", c.transcript.Sum(nil), 32)
	c.master = hkdfExtract(expandLabel(secret, "derived", empty[:], 32), zeros)
	c.out = newRecordCipher(c.clientSecret)
	typ, body, err := readRecord(clientEnd)
	if typ == recordChangeCipher {
		typ, body, err = readRecord(clientEnd)
	}
	if err != nil || typ != recordApplication {
		t.Fatalf("reading the server's flight: %d, %v", typ, err)
	}
	_, flight, err := newRecordCipher(serverSecret).open(body)
	if err != nil {
		t.Fatalf("opening the server's flight: %v", err)
	}
	for msg, rest := nextMessage(flight); msg != nil; msg, rest = nextMessage(rest) {
		c.transcript.Write(msg)
		if msg[0] == msgEncryptedExtensions {
			c.negotiated = bytes.Contains(msg, []byte{byte(h.alps >> 8), byte(h.alps)}) && h.alps != 0
		}
	}
	c.application = c.transcript.Sum(nil)
	return c
}

// encryptedExtensions is a client's EncryptedExtensions giving settings as
// ALPS, and an extension of type 99 besides.
func encryptedExtensions(settings []byte) []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(99)
		b.AddUint16(0)
		b.AddUint16(extALPS)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(settings) })
	})
	return handshakeMessage(msgEncryptedExtensions, b.BytesOrPanic())
}

// finishedMessage is the client's Finished over its transcript so far, which
// it joins.
func (c *scripted) finishedMessage() []byte {
	msg := handshakeMessage(msgFinished, finished(c.clientSecret, c.transcript.Sum(nil)))
	c.transcript.Write(msg)
	return msg
}

// send writes records to the server.
func (c *scripted) send(t *testing.T, records ...[]byte) {
	t.Helper()
	if _, err := c.conn.Write(bytes.Join(records, nil)); err != nil {
		t.Fatalf("writing: %v", err)
	}
}

// ended is how the handshake came out.
func (c *scripted) ended(t *testing.T) handshaken {
	t.Helper()
	select {
	case h := <-c.done:
		return h
	case <-time.After(10 * time.Second):
		t.Fatal("the handshake did not end")
		return handshaken{}
	}
}

// keys are the client's application keys: what it seals, and what it opens.
func (c *scripted) keys() (*recordCipher, *recordCipher) {
	return newRecordCipher(expandLabel(c.master, "c ap traffic", c.application, 32)),
		newRecordCipher(expandLabel(c.master, "s ap traffic", c.application, 32))
}

// alpsTestServer is the bench's ALPS server with the bench's certificate,
// giving settings as ALPS for h2.
func alpsTestServer(t *testing.T, settings []byte) *alpsServer {
	t.Helper()
	cert, err := certificate()
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return &alpsServer{cert: cert, protos: []string{"h2", "http/1.1"}, settings: map[string][]byte{"h2": settings}}
}

func TestTheALPSServerShakesHandsWithGoAndUTLS(t *testing.T) {
	srv := alpsTestServer(t, []byte{1, 2, 3})
	for _, tc := range []struct {
		name   string
		client func(net.Conn) (net.Conn, error)
		want   ALPSHandshake
	}{
		{"Go, offering h2", func(c net.Conn) (net.Conn, error) {
			conn := tls.Client(c, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // the bench's
			return conn, conn.Handshake()
		}, ALPSHandshake{ALPN: "h2", Flight: []string{"F"}}},
		{"Go, offering HTTP/1.1", func(c net.Conn) (net.Conn, error) {
			conn := tls.Client(c, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // the bench's
			return conn, conn.Handshake()
		}, ALPSHandshake{ALPN: "http/1.1", Flight: []string{"F"}}},
		{"Go, offering no protocol", func(c net.Conn) (net.Conn, error) {
			conn := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the bench's
			return conn, conn.Handshake()
		}, ALPSHandshake{Flight: []string{"F"}}},
		{"utls as Chrome", func(c net.Conn) (net.Conn, error) {
			conn := utls.UClient(c, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_133, false, false, false) //nolint:gosec // the bench's
			if err := conn.Handshake(); err != nil {
				return nil, err
			}
			if got := conn.ConnectionState().PeerApplicationSettings; !bytes.Equal(got, []byte{1, 2, 3}) {
				return nil, errors.New("the client was given " + string(got))
			}
			return conn, nil
		}, ALPSHandshake{Codepoint: extALPS, Protocols: []string{"h2"}, ALPN: "h2", Negotiated: true, Flight: []string{"EE", "F"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverEnd, clientEnd := net.Pipe()
			t.Cleanup(func() { _ = serverEnd.Close(); _ = clientEnd.Close() })
			done := make(chan handshaken, 1)
			go func() {
				conn, seen, err := srv.handshake(serverEnd)
				done <- handshaken{conn, seen, err}
			}()
			client, err := tc.client(clientEnd)
			if err != nil {
				t.Fatalf("the client's handshake: %v", err)
			}
			h := <-done
			if h.err != nil || h.seen.String() != tc.want.String() {
				t.Fatalf("the server's: %v, saw %s, want %s", h.err, h.seen, tc.want)
			}
			// Application data both ways, more than a record of it from
			// the server, a little at a time from the client.
			big := bytes.Repeat([]byte("x"), 3*maxRecord/2)
			go func() { _, _ = h.conn.Write(big) }()
			if got, err := io.ReadAll(io.LimitReader(client, int64(len(big)))); err != nil || !bytes.Equal(got, big) {
				t.Fatalf("read %d bytes, %v", len(got), err)
			}
			go func() { _, _ = client.Write([]byte("hello")) }()
			buf := make([]byte, 2)
			var said []byte
			for len(said) < 5 {
				n, err := h.conn.Read(buf)
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
				said = append(said, buf[:n]...)
			}
			if string(said) != "hello" {
				t.Errorf("read %q", said)
			}
			// The client's close_notify ends what the server reads.
			go func() { _ = client.Close() }()
			if _, err := h.conn.Read(buf); err != io.EOF {
				t.Errorf("after the client's close: %v", err)
			}
		})
	}
}

func TestTheALPSServerReadsAClientHelloAsSent(t *testing.T) {
	good := chromeLike(make([]byte, 32))
	ch, err := parseClientHello(good.body())
	if err != nil || !ch.usable || !bytes.Equal(ch.sessionID, good.sessionID) || len(ch.x25519) != 32 ||
		!slices.Equal(ch.alpn, []string{"h2", "http/1.1"}) || ch.alps != extALPS || !slices.Equal(ch.alpsProtocols, []string{"h2"}) {
		t.Fatalf("parseClientHello: %+v, %v", ch, err)
	}
	old := good
	old.alps = extALPSOld
	if ch, err := parseClientHello(old.body()); err != nil || ch.alps != extALPSOld {
		t.Errorf("the old code point: %+v, %v", ch, err)
	}
	for name, h := range map[string]testHello{
		"no TLS 1.3":                func() testHello { h := good; h.versions = []uint16{0x0303}; return h }(),
		"no TLS_AES_128_GCM_SHA256": func() testHello { h := good; h.suites = []uint16{0x1302}; return h }(),
		"no ecdsa_secp256r1_sha256": func() testHello { h := good; h.schemes = []uint16{0x0804}; return h }(),
		"no share of X25519":        func() testHello { h := good; h.share = nil; return h }(),
	} {
		if ch, err := parseClientHello(h.body()); err != nil || ch.usable {
			t.Errorf("%s: usable %v, %v", name, ch.usable, err)
		}
	}
	for name, body := range map[string][]byte{
		"cut short":           good.body()[:40],
		"more after it":       append(good.body(), 0),
		"an extension cut":    func() []byte { h := good; h.extra = []byte{0, 99, 0, 5, 1}; return h.body() }(),
		"versions cut":        extended(extSupportedVersions, []byte{4, 3}),
		"schemes cut":         extended(extSignatureAlgorithms, []byte{0, 4, 4}),
		"shares cut":          extended(extKeyShare, []byte{0, 9}),
		"a share cut":         extended(extKeyShare, []byte{0, 3, 0, 29, 0}),
		"ALPN cut":            extended(extALPN, []byte{0, 3, 2, 'h'}),
		"a protocol name cut": extended(extALPN, []byte{0, 2, 5, 'h'}),
		"ALPS cut":            extended(extALPS, []byte{1}),
	} {
		if _, err := parseClientHello(body); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// extended is a ClientHello body with one extension, typ, of data alone.
func extended(typ uint16, data []byte) []byte {
	var b cryptobyte.Builder
	b.AddUint16(0x0303)
	b.AddBytes(make([]byte, 32))
	b.AddUint8(0)
	b.AddUint16(2)
	b.AddUint16(0x1301)
	b.AddUint8(1)
	b.AddUint8(0)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(typ)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
	})
	return b.BytesOrPanic()
}

func TestTheALPSServerTakesAClientsFlightAsItCame(t *testing.T) {
	srv := alpsTestServer(t, []byte{})
	// EncryptedExtensions and Finished in one record, a change of cipher
	// spec first.
	c := shake(t, srv, chromeLike(nil))
	ee := encryptedExtensions([]byte{9, 8})
	c.transcript.Write(ee)
	c.send(t, plainRecord(recordChangeCipher, []byte{1}), c.out.seal(recordHandshake, append(ee, c.finishedMessage()...)))
	h := c.ended(t)
	if h.err != nil || !h.seen.Negotiated || h.seen.ClientSettings != "0908" || !slices.Equal(h.seen.Flight, []string{"EE+F"}) {
		t.Fatalf("one record: %+v, %v", h.seen, h.err)
	}
	// A Finished in two records: the first ends no message.
	c = shake(t, srv, chromeLike(nil))
	ee = encryptedExtensions(nil)
	c.transcript.Write(ee)
	fin := c.finishedMessage()
	c.send(t, c.out.seal(recordHandshake, ee), c.out.seal(recordHandshake, fin[:10]), c.out.seal(recordHandshake, fin[10:]))
	if h := c.ended(t); h.err != nil || !slices.Equal(h.seen.Flight, []string{"EE", "part", "F"}) {
		t.Errorf("a Finished in two: %+v, %v", h.seen, h.err)
	}
	// A client not offering ALPS is given none.
	plain := chromeLike(nil)
	plain.alps = 0
	c = shake(t, srv, plain)
	c.send(t, c.out.seal(recordHandshake, c.finishedMessage()))
	if h := c.ended(t); h.err != nil || h.seen.Negotiated || !slices.Equal(h.seen.Flight, []string{"F"}) {
		t.Errorf("no ALPS: %+v, %v", h.seen, h.err)
	}
}

func TestTheALPSServerRefusesAFlightItCannotTake(t *testing.T) {
	srv := alpsTestServer(t, []byte{})
	for _, tc := range []struct {
		name string
		send func(c *scripted) [][]byte
		says string
	}{
		{"a record in the clear", func(c *scripted) [][]byte { return [][]byte{plainRecord(recordHandshake, []byte{1})} },
			"a record of type 22 in the client's flight"},
		{"a record that does not open", func(c *scripted) [][]byte {
			return [][]byte{plainRecord(recordApplication, make([]byte, 40))}
		}, "a record that does not open"},
		{"application data", func(c *scripted) [][]byte { return [][]byte{c.out.seal(recordApplication, []byte("GET"))} },
			"a record carrying type 23 in the client's flight"},
		{"a Certificate", func(c *scripted) [][]byte {
			return [][]byte{c.out.seal(recordHandshake, handshakeMessage(msgCertificate, []byte{0, 0, 0, 0}))}
		}, "a handshake message of type 11 in the client's flight"},
		{"a Finished that does not verify", func(c *scripted) [][]byte {
			return [][]byte{c.out.seal(recordHandshake, handshakeMessage(msgFinished, make([]byte, 32)))}
		}, "a client Finished that does not verify"},
		{"EncryptedExtensions cut short", func(c *scripted) [][]byte {
			return [][]byte{c.out.seal(recordHandshake, handshakeMessage(msgEncryptedExtensions, []byte{0}))}
		}, "a client's EncryptedExtensions that do not read"},
		{"an extension cut short", func(c *scripted) [][]byte {
			return [][]byte{c.out.seal(recordHandshake, handshakeMessage(msgEncryptedExtensions, []byte{0, 3, 0, 1, 0}))}
		}, "a client's EncryptedExtensions that do not read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := shake(t, srv, chromeLike(nil))
			c.send(t, tc.send(c)...)
			if h := c.ended(t); h.err == nil || !strings.Contains(h.err.Error(), tc.says) {
				t.Errorf("ended %v, want %q", h.err, tc.says)
			}
		})
	}
	// A client that hangs up before its flight.
	c := shake(t, srv, chromeLike(nil))
	_ = c.conn.Close()
	if h := c.ended(t); !errors.Is(h.err, io.EOF) {
		t.Errorf("hung up: %v", h.err)
	}
}

func TestTheALPSServerRefusesAHelloItCannotAnswer(t *testing.T) {
	srv := alpsTestServer(t, []byte{})
	hello := handshakeMessage(msgClientHello, chromeLike(make([]byte, 32)).body())
	for _, tc := range []struct {
		name  string
		bytes []byte
		says  string
	}{
		{"nothing", nil, "EOF"},
		{"application data", plainRecord(recordApplication, []byte{1}), "a record of type 23 for a ClientHello"},
		{"a ServerHello", plainRecord(recordHandshake, handshakeMessage(msgServerHello, []byte{0})), "no ClientHello alone"},
		{"more after it", plainRecord(recordHandshake, append(slices.Clone(hello), 0)), "no ClientHello alone"},
		{"a hello that does not read", plainRecord(recordHandshake, handshakeMessage(msgClientHello, []byte{3, 3})),
			"a ClientHello that does not read"},
		{"no X25519", plainRecord(recordHandshake, handshakeMessage(msgClientHello,
			func() testHello { h := chromeLike(nil); h.share = []byte{}; return h }().body())), errNotTLS13.Error()},
		{"a share the length of none", plainRecord(recordHandshake, handshakeMessage(msgClientHello, chromeLike(make([]byte, 31)).body())),
			errNotTLS13.Error()},
		{"a record too long", []byte{recordHandshake, 3, 3, 0xff, 0xff}, "a record of 65535 bytes"},
		{"a record cut short", []byte{recordHandshake, 3, 3, 0, 9, 1}, "EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverEnd, clientEnd := net.Pipe()
			done := make(chan error, 1)
			go func() {
				_, _, err := srv.handshake(serverEnd)
				done <- err
			}()
			_, _ = clientEnd.Write(tc.bytes)
			_ = clientEnd.Close()
			if err := <-done; err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("ended %v, want %q", err, tc.says)
			}
		})
	}
	// A hello in two records is read whole; and a server that cannot write
	// its answer ends there.
	serverEnd, clientEnd := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, err := srv.handshake(serverEnd)
		done <- err
	}()
	_, _ = clientEnd.Write(append(plainRecord(recordHandshake, hello[:100]), plainRecord(recordHandshake, hello[100:])...))
	_ = clientEnd.Close()
	if err := <-done; !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("a hello in two records, then no one to write to: %v", err)
	}
}

func TestAnALPSConnectionReadsWhatComesAsItComes(t *testing.T) {
	srv := alpsTestServer(t, []byte{})
	for _, tc := range []struct {
		name string
		send func(seal, wrong *recordCipher) []byte
		says string
	}{
		{"a record that does not open", func(_, wrong *recordCipher) []byte { return wrong.seal(recordApplication, []byte("x")) },
			"a record that does not open"},
		{"a record of handshake", func(seal, _ *recordCipher) []byte { return seal.seal(recordHandshake, []byte("x")) },
			"a record of type 23, 22, after the handshake"},
		{"a record in the clear", func(_, _ *recordCipher) []byte { return plainRecord(recordAlert, []byte{1, 0}) },
			"a record that does not open"},
		{"padding alone", func(seal, _ *recordCipher) []byte {
			sealed := seal.seal(0, nil)
			return sealed
		}, "a record with no content type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := shake(t, srv, chromeLike(nil))
			c.send(t, c.out.seal(recordHandshake, c.finishedMessage()))
			h := c.ended(t)
			seal, _ := c.keys()
			c.send(t, tc.send(seal, newRecordCipher(make([]byte, 32))))
			if _, err := h.conn.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("Read: %v, want %q", err, tc.says)
			}
		})
	}
	// A write to a connection that is gone fails.
	c := shake(t, srv, chromeLike(nil))
	c.send(t, c.out.seal(recordHandshake, c.finishedMessage()))
	h := c.ended(t)
	_ = c.conn.Close()
	if _, err := h.conn.Write([]byte("x")); err == nil {
		t.Error("written to a closed connection")
	}
}
