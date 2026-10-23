package tlsforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
	"github.com/quic-go/qpack"
)

// This peer reads the actual QUIC request stream, before any HTTP parser can
// erase QPACK representation choices. It advertises no dynamic QPACK support.
func qpackWirePeer(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	cert := seed.TLS.Certificates[0]
	seed.Close()
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	observed := make(chan []byte, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("QPACK peer did not stop")
		}
	})
	go func() {
		defer close(done)
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		control, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		// Control stream type; empty SETTINGS frame.
		if _, err = control.Write([]byte{0, 4, 0}); err != nil {
			t.Error(err)
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		reader := quicvarint.NewReader(stream)
		for {
			typ, err := quicvarint.Read(reader)
			if err != nil {
				t.Error(err)
				return
			}
			n, err := quicvarint.Read(reader)
			if err != nil || n > 1<<20 {
				t.Errorf("frame size%d: %v", n, err)
				return
			}
			payload := make([]byte, n)
			if _, err = io.ReadFull(stream, payload); err != nil {
				t.Error(err)
				return
			}
			if typ == 1 {
				observed <- payload
				break
			}
		}
		var block bytes.Buffer
		e := qpack.NewEncoder(&block)
		_ = e.WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
		frame := quicvarint.Append(nil, 1)
		frame = quicvarint.Append(frame, uint64(block.Len()))
		frame = append(frame, block.Bytes()...)
		frame = append(frame, 0, 2, 'o', 'k')
		if _, err = stream.Write(frame); err != nil {
			t.Error(err)
			return
		}
		_ = stream.Close()
		select {
		case <-conn.Context().Done():
		case <-ctx.Done():
		}
	}()
	return "https://" + ln.Addr().String(), observed
}

func TestProfileJSONChangesActualQPACKWithoutRenamingDispatch(t *testing.T) {
	outputs := map[string][]byte{}
	for _, mode := range []string{"shorter", "always", "never"} {
		t.Run(mode, func(t *testing.T) {
			url, wire := qpackWirePeer(t)
			p := policyFile(t, map[string]any{"h3.qpack.huffman_names": mode, "h3.qpack.huffman_values": mode})
			// An identical authority makes literal wire bytes comparable across peers.
			c := newTestClient(t, WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(4*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			r, err := c.Do(&Request{URL: url, Header: NewHeader("X-Literal", "?0"), Browser: &BrowserContext{Kind: KindFetch, Initiator: url}})
			if err != nil || string(r.Body) != "ok" {
				t.Fatalf("response%v: %v", r, err)
			}
			select {
			case b := <-wire:
				outputs[mode] = b
				decode := qpack.NewDecoder().Decode(b)
				found := false
				for {
					f, err := decode()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if f.Name == "x-literal" {
						found = true
						if f.Value != "?0" {
							t.Fatal(f)
						}
					}
				}
				if !found {
					t.Fatal("actual QPACK missed test field")
				}
				// For the unique field value, shorter/never must emit two literal bytes;
				// always emits the expanding Huffman representation ff01 instead.
				want := []byte{2, '?', '0'}
				if mode == "always" {
					want = []byte{0x82, 0xff, 0x01}
				}
				if !bytes.Contains(b, want) {
					t.Fatalf("%s policy did not reach request wire: %x", mode, b)
				}
			case <-time.After(time.Second):
				t.Fatal("no original QUIC HEADERS")
			}
		})
	}
	if bytes.Equal(outputs["shorter"], outputs["always"]) || bytes.Equal(outputs["shorter"], outputs["never"]) {
		t.Fatal("coding policy ignored")
	}
}

func TestQPACKPolicyIsRequiredAndValidatedBeforeNetwork(t *testing.T) {
	for _, bad := range []json.RawMessage{nil, json.RawMessage(`"automatic"`), json.RawMessage(`null`), json.RawMessage(`true`)} {
		p, err := profile.Get("chrome_155_macos")
		if err != nil {
			t.Fatal(err)
		}
		if bad == nil {
			delete(p.Behavior, "h3.qpack.huffman_values")
		} else {
			p.Behavior["h3.qpack.huffman_values"] = bad
		}
		dialed := false
		c, err := New(WithProfileValue(p), WithTransportOption(tc.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, fmt.Errorf("unexpected dial")
		})))
		if err == nil {
			c.Close()
			t.Fatal("invalid QPACK choice accepted")
		}
		if dialed || !strings.Contains(err.Error(), "h3.qpack.huffman_values") {
			t.Fatal(dialed, err)
		}
	}
}

func TestDynamicQPACKJSONGateBeforeNetwork(t *testing.T) {
	for key, bad := range map[string]string{
		"h3.qpack.error_invalid_relative_index_reason": `true`,
		"h3.qpack.error_capacity_exceeded_reason":      `true`,
		"h3.qpack.error_zero_increment_reason":         `true`,
		"h3.qpack.error_decompression_reason":          `true`,
		"h3.qpack.error_encoder_reason":                `true`,
		"h3.qpack.error_decoder_reason":                `true`,
		"h3.qpack.error_stream_unavailable_reason":     `true`,
		"h3.qpack.error_stream_write_reason":           `true`,
		"h3.qpack.error_queue_exhausted_reason":        `true`,
		"h3.qpack.draining_percent":                    `101`,
		"h3.qpack.critical_close_space":                `"either"`,
		"h3.qpack.critical_close_code":                 `-1`,
		"h3.qpack.critical_close_frame_type":           `-1`,
		"h3.qpack.critical_close_reason":               `true`,
		"h3.retry_unprocessed_attempts":                `0`,
		"h3.retry_attempts":                            `17`,
		"h3.retry_methods":                             `true`,
		"h3.retry_application_errors":                  `[-1]`,
		"h3.retry_transport_errors":                    `[4294967296]`,
		"h3.qpack.encoder_table_bytes":                 `1048577`,
		"h3.qpack.encoder_strategy":                    `"browser-magic"`,
		"h3.qpack.decoder_feedback":                    `"maybe"`,
		"h3.qpack.streams":                             `"hidden-default"`,
		"h3.qpack.stream_order":                        `[2,2]`,
		"h3.qpack.encoder_warmup_sections":             `1025`,
		"h3.qpack.reference_base":                      `"auto"`,
		"h3.qpack.never_index":                         `true`,
	} {
		t.Run(key, func(t *testing.T) {
			for _, missing := range []bool{false, true} {
				p, e := profile.Get("chrome_155_macos")
				if e != nil {
					t.Fatal(e)
				}
				p.Name = "neutral-identity"
				if missing {
					delete(p.Behavior, key)
				} else {
					p.Behavior[key] = json.RawMessage(bad)
				}
				dialed := false
				_, e = New(WithProfileValue(p), WithTransportOption(tc.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
					dialed = true
					return nil, fmt.Errorf("unexpected dial")
				})))
				if e == nil || dialed || !strings.Contains(e.Error(), key) {
					t.Fatalf("missing=%v dialed=%v error=%v", missing, dialed, e)
				}
			}
		})
	}
}

func TestQPACKCloseReasonBoundBeforeNetwork(t *testing.T) {
	p, e := profile.Get("chrome_155_macos")
	if e != nil {
		t.Fatal(e)
	}
	p.Behavior["h3.qpack.critical_close_reason"], _ = json.Marshal(strings.Repeat("x", 1025))
	if _, e = New(WithProfileValue(p)); e == nil || !strings.Contains(e.Error(), "critical_close_reason") {
		t.Fatal(e)
	}
}
