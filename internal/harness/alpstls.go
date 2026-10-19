package harness

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/cryptobyte"
)

// The TLS 1.3 the bench speaks itself to give a client ALPS, Application-Layer
// Protocol Settings (draft-vvv-tls-alps), which no Go TLS library does on the
// server side: TLS_AES_128_GCM_SHA256, X25519 and ecdsa_secp256r1_sha256 alone,
// which Chrome and tls-forge both offer, and a full handshake every time.
const (
	recordChangeCipher = 20
	recordAlert        = 21
	recordHandshake    = 22
	recordApplication  = 23

	msgClientHello         = 1
	msgServerHello         = 2
	msgEncryptedExtensions = 8
	msgCertificate         = 11
	msgCertificateVerify   = 15
	msgFinished            = 20

	extServerName          = 0
	extSignatureAlgorithms = 13
	extALPN                = 16
	extSupportedVersions   = 43
	extKeyShare            = 51
	// ALPS has the code point Chrome sends now and the one it sent before.
	extALPS    = 17613
	extALPSOld = 17513

	// maxRecord is the most plaintext a record carries, and maxCiphertext
	// the most a record of TLS 1.3 may: its plaintext, the content type, and
	// what an AEAD adds.
	maxRecord     = 16384
	maxCiphertext = maxRecord + 256
)

// errNotTLS13 is a ClientHello the bench's TLS cannot answer: no TLS 1.3, or
// none of TLS_AES_128_GCM_SHA256, X25519 or ecdsa_secp256r1_sha256.
var errNotTLS13 = errors.New("harness: a ClientHello without TLS 1.3, TLS_AES_128_GCM_SHA256, X25519 and ecdsa_secp256r1_sha256")

// clientHello is what the bench reads of a ClientHello: its session ID, what it
// offers of what the bench takes, its share of X25519, the protocols of its
// ALPN, and the code point and protocols of its ALPS.
type clientHello struct {
	sessionID     []byte
	usable        bool
	x25519        []byte
	alpn          []string
	alps          uint16
	alpsProtocols []string
}

// parseClientHello reads the body of a ClientHello.
func parseClientHello(body []byte) (*clientHello, error) {
	s := cryptobyte.String(body)
	var ch clientHello
	var sessionID, suites, compression, extensions cryptobyte.String
	if !s.Skip(2+32) || !s.ReadUint8LengthPrefixed(&sessionID) || !s.ReadUint16LengthPrefixed(&suites) ||
		!s.ReadUint8LengthPrefixed(&compression) || !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, errors.New("harness: a ClientHello that does not read")
	}
	ch.sessionID = sessionID
	offered := map[string]bool{"suite": slices.Contains(uint16s(suites), 0x1301)}
	for !extensions.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&typ) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("harness: a ClientHello whose extensions do not read")
		}
		ok := true
		switch typ {
		case extSupportedVersions:
			var versions cryptobyte.String
			ok = data.ReadUint8LengthPrefixed(&versions)
			offered["version"] = slices.Contains(uint16s(versions), 0x0304)
		case extSignatureAlgorithms:
			var schemes cryptobyte.String
			ok = data.ReadUint16LengthPrefixed(&schemes)
			offered["signature"] = slices.Contains(uint16s(schemes), 0x0403)
		case extKeyShare:
			var shares cryptobyte.String
			ok = data.ReadUint16LengthPrefixed(&shares)
			for ok && !shares.Empty() {
				var group uint16
				var key cryptobyte.String
				ok = shares.ReadUint16(&group) && shares.ReadUint16LengthPrefixed(&key)
				if ok && group == 0x001d {
					ch.x25519 = key
				}
			}
		case extALPN:
			ch.alpn, ok = protocolNames(data)
		case extALPS, extALPSOld:
			ch.alps = typ
			ch.alpsProtocols, ok = protocolNames(data)
		}
		if !ok {
			return nil, fmt.Errorf("harness: a ClientHello whose extension %d does not read", typ)
		}
	}
	ch.usable = offered["suite"] && offered["version"] && offered["signature"] && ch.x25519 != nil
	return &ch, nil
}

// uint16s are the numbers of a list of them, as many as it holds whole.
func uint16s(s cryptobyte.String) []uint16 {
	var out []uint16
	var v uint16
	for s.ReadUint16(&v) {
		out = append(out, v)
	}
	return out
}

// protocolNames reads a list of protocol names as ALPN and ALPS say them.
func protocolNames(data cryptobyte.String) ([]string, bool) {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) {
		return nil, false
	}
	var names []string
	for !list.Empty() {
		var name cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&name) {
			return nil, false
		}
		names = append(names, string(name))
	}
	return names, true
}

// expandLabel is TLS 1.3's HKDF-Expand-Label, with SHA-256.
func expandLabel(secret []byte, label string, context []byte, length int) []byte {
	var b cryptobyte.Builder
	b.AddUint16(uint16(length))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("tls13 " + label)) })
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(context) })
	out, _ := hkdf.Expand(sha256.New, secret, string(b.BytesOrPanic()), length)
	return out
}

// hkdfExtract is HKDF-Extract with SHA-256.
func hkdfExtract(salt, secret []byte) []byte {
	out, _ := hkdf.Extract(sha256.New, secret, salt)
	return out
}

// finished is the verify_data of a Finished made with the traffic secret
// base, over a transcript whose hash is sum.
func finished(base, sum []byte) []byte {
	mac := hmac.New(sha256.New, expandLabel(base, "finished", nil, 32))
	mac.Write(sum)
	return mac.Sum(nil)
}

// recordCipher seals and opens the records of one direction of a
// connection: AES-128-GCM with the key and IV of a traffic secret, and the
// records it took so far.
type recordCipher struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newRecordCipher(secret []byte) *recordCipher {
	block, _ := aes.NewCipher(expandLabel(secret, "key", nil, 16))
	aead, _ := cipher.NewGCM(block)
	return &recordCipher{aead: aead, iv: expandLabel(secret, "iv", nil, 12)}
}

// nonce is the next record's.
func (c *recordCipher) nonce() []byte {
	n := slices.Clone(c.iv)
	for i := range 8 {
		n[4+i] ^= byte(c.seq >> (56 - 8*i))
	}
	c.seq++
	return n
}

// seal is a record of application data carrying data of type typ.
func (c *recordCipher) seal(typ byte, data []byte) []byte {
	inner := append(slices.Clone(data), typ)
	n := len(inner) + c.aead.Overhead()
	header := []byte{recordApplication, 3, 3, byte(n >> 8), byte(n)}
	return c.aead.Seal(slices.Clone(header), c.nonce(), inner, header)
}

// open is what a record of application data whose body is body carries, and
// its type, the padding off.
func (c *recordCipher) open(body []byte) (byte, []byte, error) {
	header := []byte{recordApplication, 3, 3, byte(len(body) >> 8), byte(len(body))}
	inner, err := c.aead.Open(nil, c.nonce(), body, header)
	if err != nil {
		return 0, nil, fmt.Errorf("harness: a record that does not open: %w", err)
	}
	end := len(inner) - 1
	for end >= 0 && inner[end] == 0 {
		end--
	}
	if end < 0 {
		return 0, nil, errors.New("harness: a record with no content type")
	}
	return inner[end], inner[:end], nil
}

// readRecord reads a record: its type and its body.
func readRecord(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	n := int(header[3])<<8 | int(header[4])
	if n > maxCiphertext {
		return 0, nil, fmt.Errorf("harness: a record of %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return header[0], body, nil
}

// handshakeMessage is a handshake message of type typ, its header on.
func handshakeMessage(typ byte, body []byte) []byte {
	n := len(body)
	return append([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// nextMessage is the first whole handshake message of buf, its header on, and
// what follows it; none when buf holds no whole one.
func nextMessage(buf []byte) ([]byte, []byte) {
	if len(buf) < 4 {
		return nil, buf
	}
	n := 4 + (int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3]))
	if len(buf) < n {
		return nil, buf
	}
	return buf[:n], buf[n:]
}

// messageNames say the types of the handshake messages a client's flight
// carried.
var messageNames = map[byte]string{msgEncryptedExtensions: "EE", msgFinished: "F"}

// alpsServer answers TLS as the bench's ALPS server does: with its
// certificate, an ECDSA key on P-256, the first of protos the client offers,
// and for a protocol settings has, ALPS with those settings when the client
// offers ALPS for it.
type alpsServer struct {
	cert     tls.Certificate
	protos   []string
	settings map[string][]byte
}

// ALPSHandshake is what a client's handshake with the bench's ALPS server was
// made of: the code point its ClientHello offered ALPS under and the
// protocols it offered it for, the protocol negotiated, whether ALPS was, and
// the settings the client's EncryptedExtensions gave as hex; Flight, what
// each record of the client's encrypted handshake carried, EE for its
// EncryptedExtensions and F for its Finished, joined by "+"; and over HTTP/2
// the client's first SETTINGS, ID=value each, and the error and debug data
// of a GOAWAY it sent.
type ALPSHandshake struct {
	Conn           int      `json:"-"`
	Codepoint      uint16   `json:"codepoint,omitempty"`
	Protocols      []string `json:"protocols,omitempty"`
	ALPN           string   `json:"alpn"`
	Negotiated     bool     `json:"negotiated,omitempty"`
	ClientSettings string   `json:"client_settings,omitempty"`
	Flight         []string `json:"flight"`
	Settings       []string `json:"settings,omitempty"`
	GoAway         string   `json:"goaway,omitempty"`
}

// handshake shakes hands with the client of raw: the connection its
// application data goes on, and what the handshake was made of.
func (srv *alpsServer) handshake(raw net.Conn) (*alpsConn, *ALPSHandshake, error) {
	// The ClientHello, in as many records as it took.
	var buf, hello []byte
	for hello == nil {
		typ, body, err := readRecord(raw)
		if err != nil {
			return nil, nil, err
		}
		if typ != recordHandshake {
			return nil, nil, fmt.Errorf("harness: a record of type %d for a ClientHello", typ)
		}
		hello, buf = nextMessage(append(buf, body...))
	}
	if hello[0] != msgClientHello || len(buf) != 0 {
		return nil, nil, errors.New("harness: no ClientHello alone")
	}
	ch, err := parseClientHello(hello[4:])
	if err != nil {
		return nil, nil, err
	}
	seen := &ALPSHandshake{Codepoint: ch.alps, Protocols: ch.alpsProtocols}
	peer, err := ecdh.X25519().NewPublicKey(ch.x25519)
	if !ch.usable || err != nil {
		return nil, nil, errNotTLS13
	}
	for _, p := range srv.protos {
		if seen.ALPN == "" && slices.Contains(ch.alpn, p) {
			seen.ALPN = p
		}
	}
	settings, ok := srv.settings[seen.ALPN]
	seen.Negotiated = ok && slices.Contains(ch.alpsProtocols, seen.ALPN)

	// ServerHello, and the handshake's secrets.
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := key.ECDH(peer)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	var sh cryptobyte.Builder
	sh.AddUint16(0x0303)
	sh.AddBytes(random)
	sh.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ch.sessionID) })
	sh.AddUint16(0x1301)
	sh.AddUint8(0)
	sh.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(extSupportedVersions)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x0304) })
		b.AddUint16(extKeyShare)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x001d)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		})
	})
	serverHello := handshakeMessage(msgServerHello, sh.BytesOrPanic())
	transcript := sha256.New()
	transcript.Write(hello)
	transcript.Write(serverHello)
	zeros := make([]byte, 32)
	empty := sha256.Sum256(nil)
	secret := hkdfExtract(expandLabel(hkdfExtract(zeros, zeros), "derived", empty[:], 32), shared)
	clientSecret := expandLabel(secret, "c hs traffic", transcript.Sum(nil), 32)
	serverSecret := expandLabel(secret, "s hs traffic", transcript.Sum(nil), 32)
	master := hkdfExtract(expandLabel(secret, "derived", empty[:], 32), zeros)

	// The server's flight, encrypted in records of at most maxRecord bytes:
	// one, unless ALPS makes it longer.
	var ee cryptobyte.Builder
	ee.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if seen.ALPN != "" {
			b.AddUint16(extALPN)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(seen.ALPN)) })
				})
			})
		}
		if seen.Negotiated {
			b.AddUint16(ch.alps)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(settings) })
		}
	})
	var certificate cryptobyte.Builder
	certificate.AddUint8(0)
	certificate.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(srv.cert.Certificate[0]) })
		b.AddUint16(0)
	})
	flight := handshakeMessage(msgEncryptedExtensions, ee.BytesOrPanic())
	flight = append(flight, handshakeMessage(msgCertificate, certificate.BytesOrPanic())...)
	transcript.Write(flight)
	signed := sha256.Sum256(append([]byte(strings.Repeat(" ", 64)+"TLS 1.3, server CertificateVerify\x00"),
		transcript.Sum(nil)...))
	signature, _ := ecdsa.SignASN1(rand.Reader, srv.cert.PrivateKey.(*ecdsa.PrivateKey), signed[:])
	var verify cryptobyte.Builder
	verify.AddUint16(0x0403)
	verify.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(signature) })
	certificateVerify := handshakeMessage(msgCertificateVerify, verify.BytesOrPanic())
	transcript.Write(certificateVerify)
	serverFinished := handshakeMessage(msgFinished, finished(serverSecret, transcript.Sum(nil)))
	transcript.Write(serverFinished)
	flight = append(append(flight, certificateVerify...), serverFinished...)
	cipher := newRecordCipher(serverSecret)
	var sealed []byte
	for rest := flight; len(rest) > 0; rest = rest[min(len(rest), maxRecord):] {
		sealed = append(sealed, cipher.seal(recordHandshake, rest[:min(len(rest), maxRecord)])...)
	}
	compatible := []byte{}
	if len(ch.sessionID) > 0 {
		compatible = []byte{recordChangeCipher, 3, 3, 0, 1, 1}
	}
	out := append(append([]byte{recordHandshake, 3, 3, byte(len(serverHello) >> 8), byte(len(serverHello))}, serverHello...),
		compatible...)
	if _, err := raw.Write(append(out, sealed...)); err != nil {
		return nil, nil, err
	}
	application := transcript.Sum(nil)

	// The client's flight: what each of its records carried, its settings,
	// and its Finished, over what came before it.
	in := newRecordCipher(clientSecret)
	buf = nil
	for {
		typ, body, err := readRecord(raw)
		if err != nil {
			return nil, nil, err
		}
		if typ == recordChangeCipher {
			continue
		}
		if typ != recordApplication {
			return nil, nil, fmt.Errorf("harness: a record of type %d in the client's flight", typ)
		}
		inner, data, err := in.open(body)
		if err != nil {
			return nil, nil, err
		}
		if inner != recordHandshake {
			return nil, nil, fmt.Errorf("harness: a record carrying type %d in the client's flight", inner)
		}
		var carried []string
		var msg []byte
		buf = append(buf, data...)
		for msg, buf = nextMessage(buf); msg != nil; msg, buf = nextMessage(buf) {
			name, known := messageNames[msg[0]]
			if !known {
				return nil, nil, fmt.Errorf("harness: a handshake message of type %d in the client's flight", msg[0])
			}
			carried = append(carried, name)
			if msg[0] == msgFinished {
				if !hmac.Equal(msg[4:], finished(clientSecret, transcript.Sum(nil))) {
					return nil, nil, errors.New("harness: a client Finished that does not verify")
				}
				seen.Flight = append(seen.Flight, flightOf(carried))
				return newALPSConn(raw, newRecordCipher(expandLabel(master, "c ap traffic", application, 32)),
					newRecordCipher(expandLabel(master, "s ap traffic", application, 32))), seen, nil
			}
			settings, err := clientSettings(msg[4:])
			if err != nil {
				return nil, nil, err
			}
			seen.ClientSettings = settings
			transcript.Write(msg)
		}
		seen.Flight = append(seen.Flight, flightOf(carried))
	}
}

// flightOf says what a record of a client's flight carried: the messages it
// ended, joined by "+", or "part" for a part of one.
func flightOf(carried []string) string {
	if len(carried) == 0 {
		return "part"
	}
	return strings.Join(carried, "+")
}

// clientSettings are the ALPS settings, as hex, a client's
// EncryptedExtensions of body gave.
func clientSettings(body []byte) (string, error) {
	s := cryptobyte.String(body)
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return "", errors.New("harness: a client's EncryptedExtensions that do not read")
	}
	settings := ""
	for !extensions.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&typ) || !extensions.ReadUint16LengthPrefixed(&data) {
			return "", errors.New("harness: a client's EncryptedExtensions that do not read")
		}
		if typ == extALPS || typ == extALPSOld {
			settings = fmt.Sprintf("%x", []byte(data))
		}
	}
	return settings, nil
}

// alpsConn is the application data of a connection the bench's ALPS server
// shook hands on, in records of TLS 1.3 sealed with its traffic keys. What the
// client sends is read as it comes, before anything asks for it: a client
// that ends a connection at once, as Chrome does after a GOAWAY, may reset it
// and lose what was not read yet.
type alpsConn struct {
	net.Conn
	in, out *recordCipher
	wmu     sync.Mutex
	mu      sync.Mutex
	came    *sync.Cond
	pending []byte
	err     error
}

func newALPSConn(raw net.Conn, in, out *recordCipher) *alpsConn {
	c := &alpsConn{Conn: raw, in: in, out: out}
	c.came = sync.NewCond(&c.mu)
	go c.pump()
	return c
}

// pump reads the client's records as they come, until one ends them.
func (c *alpsConn) pump() {
	for {
		data, err := c.next()
		c.mu.Lock()
		c.pending, c.err = append(c.pending, data...), err
		c.came.Broadcast()
		c.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// next is what the client's next record carried: application data, or why
// there is no more.
func (c *alpsConn) next() ([]byte, error) {
	typ, body, err := readRecord(c.Conn)
	if err != nil {
		return nil, err
	}
	inner, data, err := c.in.open(body)
	switch {
	case err != nil:
		return nil, err
	case typ == recordApplication && inner == recordApplication:
		return data, nil
	case typ == recordApplication && inner == recordAlert:
		return nil, io.EOF
	}
	return nil, fmt.Errorf("harness: a record of type %d, %d, after the handshake", typ, inner)
}

func (c *alpsConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.pending) == 0 && c.err == nil {
		c.came.Wait()
	}
	if len(c.pending) == 0 {
		return 0, c.err
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *alpsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var out []byte
	for rest := p; len(rest) > 0; rest = rest[min(len(rest), maxRecord):] {
		out = append(out, c.out.seal(recordApplication, rest[:min(len(rest), maxRecord)])...)
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
