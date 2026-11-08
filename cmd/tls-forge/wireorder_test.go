package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/igor-lemon/utls"
)

// keyLog keeps what a handshake wrote to its key log.
type keyLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *keyLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

// sentTo keeps what a client wrote.
type sentTo struct {
	net.Conn
	mu   sync.Mutex
	sent []byte
}

func (c *sentTo) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, p...)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// acceptedECH is a uTLS client's handshake whose ECH offer a server took:
// what the client sent, and what its key log said, in order.
func acceptedECH(t *testing.T) (sent []byte, log string) {
	t.Helper()
	keys := newECHKeys(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"ech.test", "public.test"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	served := make(chan error, 1)
	go func() {
		server := utls.Server(b, &utls.Config{Certificates: []utls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			EncryptedClientHelloKeys: []utls.EncryptedClientHelloKey{{Config: keys.config, PrivateKey: keys.key.Bytes()}}})
		_ = server.SetDeadline(time.Now().Add(10 * time.Second))
		served <- server.Handshake()
	}()
	conn := &sentTo{Conn: a}
	lines := &keyLog{}
	client := utls.Client(conn, &utls.Config{ServerName: "ech.test", InsecureSkipVerify: true, MinVersion: utls.VersionTLS13,
		EncryptedClientHelloConfigList: keys.list(), KeyLogWriter: lines})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if !client.ConnectionState().ECHAccepted {
		t.Fatal("ECH not accepted")
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	lines.mu.Lock()
	defer lines.mu.Unlock()
	return conn.sent, lines.text.String()
}

// A QUIC client's socket tells the wire of a datagram once it went, by when
// the server may have answered and the handshake written its secrets to the
// key log: the lines of a random no connection has sent yet wait, as an ECH
// offer's do, and are kept once a connection's hello, or the inner hello of
// its offer, says they are its own.
func TestTheWireKeepsSecretsTheKeyLogSaidBeforeTheirHello(t *testing.T) {
	t.Run("a hello's", func(t *testing.T) {
		w := newWire()
		mine := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
		other := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
		lines := "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + mine + " 01\nSERVER_HANDSHAKE_TRAFFIC_SECRET " + mine + " 02\n"
		_, _ = io.WriteString(w, lines+"CLIENT_HANDSHAKE_TRAFFIC_SECRET "+other+" 03\n")
		conn, far := dialedPair(t, w, 1, stringAddr("127.0.0.1:5000"), stringAddr("127.0.0.1:443"))
		go func() { _, _ = io.Copy(io.Discard, far) }()
		if _, err := conn.Write(helloOf(0xab)); err != nil {
			t.Fatal(err)
		}
		if _, secrets := w.capture(1); string(secrets) != lines {
			t.Errorf("secrets\n%s\nwant\n%s", secrets, lines)
		}
		// Another connection's still waits.
		if len(w.early) != 1 || !strings.Contains(w.early[0], other) {
			t.Errorf("waiting %q", w.early)
		}
	})
	t.Run("the inner hello of an accepted ECH offer", func(t *testing.T) {
		sent, log := acceptedECH(t)
		w := newWire()
		_, _ = io.WriteString(w, log)
		conn, far := dialedPair(t, w, 1, stringAddr("127.0.0.1:5000"), stringAddr("127.0.0.1:443"))
		go func() { _, _ = io.Copy(io.Discard, far) }()
		if _, err := conn.Write(sent); err != nil {
			t.Fatal(err)
		}
		c := w.conns[0]
		if c.inner == "" || c.inner == c.random {
			t.Fatalf("no inner hello opened (outer %s, inner %q)", c.random, c.inner)
		}
		_, secrets := w.capture(1)
		var want []string
		for _, line := range strings.SplitAfter(log, "\n") {
			if f := strings.Fields(line); len(f) == 3 && (f[1] == c.random || f[1] == c.inner) {
				want = append(want, line)
			}
		}
		inner := 0
		for _, line := range want {
			if !bytes.Contains(secrets, []byte(line)) {
				t.Errorf("the capture lacks %q", line)
			}
			if strings.Contains(line, c.inner) {
				inner++
			}
		}
		if inner != 4 || len(want) != inner+2 {
			t.Errorf("the key log said %d lines of the inner hello, %d in all:\n%s", inner, len(want), log)
		}
		if len(w.early) != 0 {
			t.Errorf("still waiting %q", w.early)
		}
	})
}
