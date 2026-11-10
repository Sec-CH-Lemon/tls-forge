package main

import (
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/pcapng"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls/http3"
	utls "github.com/igor-lemon/utls"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/dns/dnsmessage"
)

// echKeys are an ECH key of a site's and the config of it a record gives:
// X25519, HKDF-SHA256 and AES-128-GCM, public name public.test.
type echKeys struct {
	key    *ecdh.PrivateKey
	config []byte
}

func newECHKeys(t *testing.T) echKeys {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(0)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.test")) })
		b.AddUint16(0)
	})
	return echKeys{key: key, config: b.BytesOrPanic()}
}

// list is the config as an ECHConfigList.
func (k echKeys) list() []byte {
	return append([]byte{byte(len(k.config) >> 8), byte(len(k.config))}, k.config...)
}

// echNamesAt is a DNS server over UDP that finds every name at 127.0.0.1,
// with an HTTPS record naming alpn and offering ECH of keys.
func echNamesAt(t *testing.T, alpn string, keys echKeys) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		for {
			buf := make([]byte, 1500)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
			switch q.Type {
			case dnsmessage.TypeA:
				_ = b.AResource(rh, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
			case dnsmessage.TypeHTTPS:
				name := q.Name.String()
				if parts := strings.SplitN(name, ".", 3); len(parts) == 3 && parts[1] == "_https" {
					name = parts[2]
				}
				svcb := dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName(name)}
				svcb.SetParam(dnsmessage.SVCParamALPN, []byte(alpn))
				svcb.SetParam(dnsmessage.SVCParamECH, keys.list())
				_ = b.HTTPSResource(rh, dnsmessage.HTTPSResource{SVCBResource: svcb})
			}
			reply, _ := b.Finish()
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return pc.LocalAddr().String()
}

// echSite is a site over TLS and TCP that takes ECH of keys, answering with
// the protocol it is asked over and writing its secrets to log.
func echSite(t *testing.T, keys echKeys, log io.Writer) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	server.EnableHTTP2 = true
	server.TLS = &stdtls.Config{KeyLogWriter: log, EncryptedClientHelloKeys: []stdtls.EncryptedClientHelloKey{
		{Config: keys.config, PrivateKey: keys.key.Bytes()}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	return port
}

// echH3Site is a site over QUIC alone that takes ECH of keys.
func echH3Site(t *testing.T, keys echKeys, log io.Writer) string {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS()
	pair := cert.TLS.Certificates[0]
	cert.Close()
	h3 := &http3.Server{Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}), TLSConfig: &utls.Config{Certificates: []utls.Certificate{{Certificate: pair.Certificate, PrivateKey: pair.PrivateKey}},
		NextProtos: []string{"h3"}, KeyLogWriter: log,
		EncryptedClientHelloKeys: []utls.EncryptedClientHelloKey{{Config: keys.config, PrivateKey: keys.key.Bytes()}}}}
	go func() { _ = h3.Serve(udp) }()
	t.Cleanup(func() { _ = h3.Close(); _ = udp.Close() })
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	return port
}

// openedECH holds a capture of a connection whose ECH a site accepted to
// what opens it: the key log's ECH_SECRET and ECH_CONFIG of the outer hello
// sent, which open its inner hello, and every line the site wrote of that
// inner hello's random.
func openedECH(t *testing.T, capture keptCapture, hello []byte, site *siteKeys, config []byte) {
	t.Helper()
	outer, ok := pcapng.ClientRandom(append([]byte{22, 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...))
	if !ok {
		t.Fatal("no outer random")
	}
	var secret, offered []byte
	for _, line := range linesOf(capture.secrets, outer) {
		f := strings.Fields(line)
		switch f[0] {
		case pcapng.ECHSecretLabel:
			secret = unhexed(t, f[2])
		case pcapng.ECHConfigLabel:
			offered = unhexed(t, f[2])
		}
	}
	if secret == nil || string(offered) != string(config) {
		t.Fatalf("the capture holds no ECH offer of %s: %v", outer, capture.secrets)
	}
	inner, ok := pcapng.ECHInnerRandom(hello, secret, offered)
	if !ok || inner == outer {
		t.Fatalf("the offer opens no inner hello (%s)", inner)
	}
	mine := linesOf(site.lines(), inner)
	if len(mine) != 4 || !containsAll(capture.secrets, mine) {
		t.Errorf("the capture holds\n%s\nthe site's lines of the inner hello\n%s", strings.Join(capture.secrets, "\n"),
			strings.Join(mine, "\n"))
	}
}

// A connection whose ECH the site accepted is kept in a capture with what
// opens it: the key log's ECH lines of the outer hello, by which Wireshark
// opens the inner hello, and the secrets of the inner hello's random, which
// the handshake's are written by. Over TLS and TCP, and over QUIC.
func TestFetchKeepsAConnectionWhoseECHWasAcceptedOpenable(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		clock := fakeClock(t)
		keys := newECHKeys(t)
		var site siteKeys
		port := echSite(t, keys, &site)
		dir := filepath.Join(t.TempDir(), "out")
		code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--dns-server",
			echNamesAt(t, "\x02h2", keys), "-o", dir, "--pcap", "https://ech.test:"+port+"/")
		if code != 0 {
			t.Fatalf("exit code = %d\n%s", code, stderr)
		}
		name := "ech.test-" + stamp(clock.now())
		capture := readCapture(t, filepath.Join(dir, name+"-1.pcapng"))
		if len(capture.conns) != 1 {
			t.Fatalf("%d connections", len(capture.conns))
		}
		hello, ok := pcapng.ClientHello(capture.conns[0].sent)
		if !ok {
			t.Fatal("no ClientHello")
		}
		openedECH(t, capture, hello, &site, keys.config)
	})
	t.Run("quic", func(t *testing.T) {
		clock := fakeClock(t)
		keys := newECHKeys(t)
		var site siteKeys
		port := echH3Site(t, keys, &site)
		dir := filepath.Join(t.TempDir(), "out")
		code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--dns-server",
			echNamesAt(t, "\x02h3", keys), "-o", dir, "--pcap", "https://ech.test:"+port+"/")
		if code != 0 {
			t.Fatalf("exit code = %d\n%s", code, stderr)
		}
		name := "ech.test-" + stamp(clock.now())
		if page, err := os.ReadFile(filepath.Join(dir, name+"-1-response.txt")); err != nil || string(page) != "HTTP/3.0" {
			t.Fatalf("the page came over %q (%v), want HTTP/3", page, err)
		}
		capture := readCapture(t, filepath.Join(dir, name+"-1.pcapng"))
		if len(capture.quic) != 1 {
			t.Fatalf("%d QUIC connections", len(capture.quic))
		}
		hello, ok := pcapng.QUICClientHello(capture.quic[0].sent)
		if !ok {
			t.Fatal("no ClientHello")
		}
		openedECH(t, capture, hello, &site, keys.config)
	})
}

func unhexed(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
