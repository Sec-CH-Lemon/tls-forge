package harness

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// This owned TLS peer authenticates records with its negotiated application
// key. It reads the raw EOF after the TLS end before closing its own socket,
// so a close_notify cannot be confused with a FIN, random bytes or an alert
// emitted only by the server. It never receives the expected client policy.
type a12ShutdownWire struct {
	net.Conn
	mu   sync.Mutex
	raw  []byte
	once sync.Once
	end  chan error
}

func (c *a12ShutdownWire) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.raw = append(c.raw, p[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *a12ShutdownWire) Close() error {
	c.once.Do(func() {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := io.Copy(io.Discard, c)
		if err == nil { // io.Copy accepts only the raw stream EOF as success.
			c.end <- nil
		} else {
			c.end <- err
		}
		_ = c.Conn.Close()
	})
	return nil
}

func a12OpenedAlerts(raw []byte, handshakeRecords int, key *recordCipher) ([][]byte, error) {
	cipher := &recordCipher{aead: key.aead, iv: bytes.Clone(key.iv)}
	var alerts [][]byte
	for len(raw) != 0 {
		if len(raw) < 5 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(binary.BigEndian.Uint16(raw[3:5]))
		if len(raw) < 5+n {
			return nil, io.ErrUnexpectedEOF
		}
		typ, body := raw[0], raw[5:5+n]
		raw = raw[5+n:]
		switch typ {
		case recordHandshake, recordChangeCipher:
		case recordApplication:
			if handshakeRecords > 0 {
				handshakeRecords--
				continue
			}
			inner, plain, err := cipher.open(body)
			if err != nil {
				return nil, err
			}
			if inner == recordAlert {
				alerts = append(alerts, bytes.Clone(plain))
			} else if inner != recordApplication {
				return nil, fmt.Errorf("unexpected application-epoch content type%d", inner)
			}
		default:
			return nil, fmt.Errorf("unexpected outer record type%d", typ)
		}
	}
	if handshakeRecords != 0 {
		return nil, errors.New("missing authenticated client handshake records")
	}
	return alerts, nil
}

func a12CheckCloseAlerts(alerts [][]byte, notify bool) error {
	if notify && (len(alerts) != 1 || !bytes.Equal(alerts[0], []byte{1, 0})) || !notify && len(alerts) != 0 {
		return fmt.Errorf("normal close alerts%v, selected notify%v", alerts, notify)
	}
	return nil
}

func TestA12NormalTLSShutdownUsesOnlyTheSelectedJSON(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		for _, notify := range []bool{false, true} {
			for _, trigger := range []string{"request-return", "Client.Close", "idle"} {
				t.Run(fmt.Sprintf("%s/notify%v/%s", protocol, notify, trigger), func(t *testing.T) {
					var raw []byte
					var err error
					if notify {
						raw, err = os.ReadFile("../../example/profiles/chrome_156_macos_close_notify.json")
					} else {
						raw, err = os.ReadFile("../../profile/data/chrome_156/macos.json")
					}
					if err != nil {
						t.Fatal(err)
					}
					p, err := profile.Load(raw)
					if err != nil {
						t.Fatal(err)
					}
					p.Name = "a12_generic_shutdown_choice"
					if trigger != "request-return" {
						p.Behavior["http.instance_scope"] = []byte(`"client"`)
					}
					if trigger == "idle" {
						p.Behavior["h2.idle_connection_timeout_ms"] = []byte("100")
						p.Behavior["h1.idle_connection_timeout_ms"] = []byte("100")
						p.Behavior["h1.idle_reap"] = []byte(`"timer"`)
					}
					// These technical lifecycle inputs pass through actual JSON again.
					raw, err = p.Save()
					if err != nil {
						t.Fatal(err)
					}
					p, err = profile.Load(raw)
					if err != nil {
						t.Fatal(err)
					}
					profileJSON := bytes.Clone(raw)
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = ln.Close() })
					peer := alpsTestServer(t, nil)
					peer.protos = []string{protocol}
					payload := bytes.Repeat([]byte("u"), 4096)
					result := make(chan error, 1)
					go func() {
						raw, err := ln.Accept()
						if err != nil {
							result <- err
							return
						}
						t.Cleanup(func() { _ = raw.Close() })
						_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
						wire := &a12ShutdownWire{Conn: raw, end: make(chan error, 1)}
						conn, seen, err := peer.handshake(wire)
						if err != nil {
							result <- err
							return
						}
						key := &recordCipher{aead: conn.in.aead, iv: bytes.Clone(conn.in.iv)}
						if protocol == "h2" {
							protocols := new(http.Protocols)
							// The independent ALPS peer has already authenticated
							// TLS. Serve the decrypted H2 preface through net/http.
							protocols.SetUnencryptedHTTP2(true)
							srv := &http.Server{Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								body, err := io.ReadAll(r.Body)
								if err != nil || !bytes.Equal(body, payload) {
									t.Errorf("incomplete upload:%d/%v", len(body), err)
								}
								_, _ = io.WriteString(w, "complete-body")
							})}
							_ = srv.Serve(&oneConnListener{conn: conn})
						} else {
							reader := bufio.NewReader(conn)
							req, err := http.ReadRequest(reader)
							if err != nil {
								result <- err
								return
							}
							body, err := io.ReadAll(req.Body)
							if err != nil || !bytes.Equal(body, payload) {
								result <- fmt.Errorf("incomplete upload:%d/%v", len(body), err)
								return
							}
							_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ncomplete-body")
							if _, err := reader.ReadByte(); err != io.EOF {
								result <- fmt.Errorf("application did not end cleanly:%v", err)
								return
							}
							_ = conn.Close()
						}
						if err := <-wire.end; err != nil {
							result <- fmt.Errorf("no raw FIN after TLS end:%w", err)
							return
						}
						wire.mu.Lock()
						captured := bytes.Clone(wire.raw)
						wire.mu.Unlock()
						alerts, err := a12OpenedAlerts(captured, len(seen.Flight), key)
						if err == nil {
							err = a12CheckCloseAlerts(alerts, notify)
						}
						if err == nil && notify && protocol == "h2" && trigger == "Client.Close" {
							corrupt := bytes.Clone(captured)
							corrupt[len(corrupt)-1] ^= 1
							if _, rejected := a12OpenedAlerts(corrupt, len(seen.Flight), key); rejected == nil {
								err = errors.New("corrupted ciphertext accepted by close oracle")
							}
							if _, rejected := a12OpenedAlerts(captured[:len(captured)-1], len(seen.Flight), key); rejected == nil {
								err = errors.New("truncated ciphertext accepted by close oracle")
							}
							wrong := &recordCipher{aead: key.aead, iv: bytes.Clone(key.iv)}
							wrong.iv[0] ^= 1
							if _, rejected := a12OpenedAlerts(captured, len(seen.Flight), wrong); rejected == nil {
								err = errors.New("wrong traffic nonce accepted by close oracle")
							}
							if a12CheckCloseAlerts(nil, true) == nil || a12CheckCloseAlerts(alerts, false) == nil || a12CheckCloseAlerts([][]byte{{2, 40}}, true) == nil {
								err = errors.New("missing/foreign/fatal alert accepted as selected normal close")
							}
						}
						if folder := os.Getenv("TLSFORGE_A12_EVIDENCE"); folder != "" && err == nil {
							data, _ := json.MarshalIndent(struct {
								Case             string
								ProfileJSON      json.RawMessage
								RawClientRecords []byte
								Handshake        *ALPSHandshake
								Alerts           [][]byte
								RawFINObserved   bool
								KeyExport        string
							}{t.Name(), profileJSON, captured, seen, alerts, true, "AEAD validated in-process; maintained unit does not export key material; independent capture bench retains NSS keys separately"}, "", "  ")
							if err = os.MkdirAll(folder, 0700); err == nil {
								name := strings.ReplaceAll(t.Name(), "/", "-") + fmt.Sprint(time.Now().UnixNano()) + ".json"
								err = os.WriteFile(filepath.Join(folder, name), append(data, '\n'), 0600)
							}
						}
						result <- err
					}()
					client, err := tlsforge.New(tlsforge.WithProfileValue(p), tlsforge.WithInsecureSkipVerify())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = client.Close() })
					origin := "https://" + ln.Addr().String()
					response, err := client.Do(&tlsforge.Request{URL: origin, Method: "POST", Body: payload,
						Browser: &tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Initiator: origin + "/page"}})
					if err != nil || string(response.Body) != "complete-body" {
						t.Fatalf("incomplete response:%v/%v", response, err)
					}
					if trigger == "Client.Close" {
						if err := client.Close(); err != nil {
							t.Fatal(err)
						}
					}
					select {
					case err := <-result:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("normal shutdown did not finish")
					}
				})
			}
		}
	}
}
