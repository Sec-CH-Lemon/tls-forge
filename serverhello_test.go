package tlsforge

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// helloServer answers each ClientHello with a TLS 1.3 ServerHello of these
// extensions besides supported_versions and an X25519 key share, then keeps
// what the client sends until it hangs up or a second goes by.
type helloServer struct {
	addr  string
	conns sync.WaitGroup // a connection's until what it sent is kept
	mu    sync.Mutex
	got   [][]byte
}

func startHelloServer(t *testing.T, extra [][2]any) *helloServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &helloServer{addr: l.Addr().String()}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			s.conns.Add(1)
			go func() {
				defer wg.Done()
				defer s.conns.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				id, ok := readClientHelloSessionID(c)
				if !ok {
					return
				}
				if _, err := c.Write(serverHelloRecord(id, extra)); err != nil {
					return
				}
				rest, _ := io.ReadAll(c)
				s.mu.Lock()
				s.got = append(s.got, rest)
				s.mu.Unlock()
			}()
		}
	}()
	return s
}

// sent is what each connection sent, once every connection the server took
// is done: a client that has heard its ServerHello was taken.
func (s *helloServer) sent() [][]byte {
	s.conns.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.got...)
}

// readClientHelloSessionID reads the first record, a ClientHello, and gives
// its legacy_session_id, which a ServerHello echoes.
func readClientHelloSessionID(c net.Conn) ([]byte, bool) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 22 {
		return nil, false
	}
	body := make([]byte, binary.BigEndian.Uint16(head[3:]))
	if _, err := io.ReadFull(c, body); err != nil || len(body) < 4+2+32+1 || body[0] != 1 {
		return nil, false
	}
	n := int(body[4+2+32])
	if len(body) < 4+2+32+1+n {
		return nil, false
	}
	return body[4+2+32+1 : 4+2+32+1+n], true
}

// serverHelloRecord is a TLS 1.3 ServerHello in a record: TLS_AES_128_GCM_SHA256,
// supported_versions 1.3, an X25519 key share, then extra (type and body).
func serverHelloRecord(session []byte, extra [][2]any) []byte {
	share := []byte{0x00, 0x1d, 0x00, 0x20}
	share = append(share, bytes.Repeat([]byte{9}, 32)...)
	exts := [][2]any{{uint16(0x002b), []byte{3, 4}}, {uint16(0x0033), share}}
	var list []byte
	for _, e := range append(exts, extra...) {
		data := e[1].([]byte)
		list = binary.BigEndian.AppendUint16(list, e[0].(uint16))
		list = binary.BigEndian.AppendUint16(list, uint16(len(data)))
		list = append(list, data...)
	}
	body := []byte{3, 3}
	body = append(body, bytes.Repeat([]byte{7}, 32)...)
	body = append(body, byte(len(session)))
	body = append(body, session...)
	body = append(body, 0x13, 0x01, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(list)))
	body = append(body, list...)
	msg := append([]byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 3, byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// alerted says whether what a client sent holds a fatal alert of this code in
// the clear, as an alert before any key is: a record of type 21 of two bytes,
// in a record of this version.
func alerted(sent []byte, code byte, version uint16) bool {
	for len(sent) >= 5 {
		n := int(binary.BigEndian.Uint16(sent[3:5]))
		if len(sent) < 5+n {
			return false
		}
		if sent[0] == 21 && binary.BigEndian.Uint16(sent[1:3]) == version && n == 2 && sent[5] == 2 && sent[6] == code {
			return true
		}
		sent = sent[5+n:]
	}
	return false
}

// A ServerHello of TLS 1.3 with an extension BoringSSL takes only in TLS 1.2
// (ec_point_formats, which the hello offered) is refused with the profile's
// unsupported_extension alert (110) before its keys are worked out, as
// tls13_process_server_hello refuses it in Chrome 156, in a record of TLS 1.2
// (0x0303), as BoringSSL writes one once it knows the version; the profile's
// tls.retry_local_alerts tries the handshake once more on a local 110, so two
// connections each alert. Without tls.validate_server_hello_extensions,
// crypto/tls's reading passes over it (it refuses extended_master_secret and
// the others it parses there, not this one).
func TestAServerHelloWithAnExtensionTLS13DoesNotTakeIsRefusedAsChromeRefusesIt(t *testing.T) {
	shipped, err := profile.Get("chrome_156_macos")
	if err != nil {
		t.Fatal(err)
	}
	if !shipped.Behavior.Flag("tls.validate_server_hello_extensions") {
		t.Fatal("the shipped profile does not hold ServerHello to BoringSSL's")
	}
	without := shipped.Clone()
	delete(without.Behavior, "tls.validate_server_hello_extensions")
	for _, tc := range []struct {
		name    string
		p       *profile.Profile
		alerts  bool
		dialled int
	}{{"shipped", shipped, true, 2}, {"without the key", without, false, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			server := startHelloServer(t, [][2]any{{uint16(0x000b), []byte{1, 0}}})
			client, err := New(WithProfileValue(tc.p), WithTimeout(5*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			_, port, _ := net.SplitHostPort(server.addr)
			if _, err := client.Do(&Request{URL: "https://127.0.0.1:" + port + "/"}); err == nil {
				t.Fatal("a handshake with a ServerHello of no keys went on")
			}
			sent := server.sent()
			if len(sent) != tc.dialled {
				t.Fatalf("%d connections, want %d", len(sent), tc.dialled)
			}
			for i, s := range sent {
				if alerted(s, 110, 0x0303) != tc.alerts {
					t.Errorf("connection %d: alerted unsupported_extension %v, want %v (sent % x)", i, !tc.alerts, tc.alerts, s)
				}
			}
		})
	}
}
