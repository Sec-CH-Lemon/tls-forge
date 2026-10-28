package tlsforge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/fhttp/http2/hpack"
)

func TestClientRejectsUnsafeChunkedResponses(t *testing.T) {
	for _, test := range []struct {
		name, wire string
		invalid    bool
	}{
		{"bare LF", "1\nx\r\n0\r\n\r\n", true},
		{"extension overhead", strings.Repeat("1;"+strings.Repeat("a", 3000)+"\r\nx\r\n", 100) + "0\r\n\r\n", true},
		// An empty size line is no last chunk: followed by what ends a
		// trailer, the body was "hello" with no error.
		{"empty chunk size", "5\r\nhello\r\n\r\n\r\n", true},
		{"empty chunk size, more after it", "5\r\nhello\r\n\r\n5\r\nworld\r\n0\r\n\r\n", true},
		{"cut in a chunk's data", "5\r\nhel", true},
		{"cut before a chunk's CRLF", "5\r\nhello", true},
		{"cut before the last chunk", "5\r\nhello\r\n", true},
		{"ordinary extension", "1;name=value\r\nx\r\n0\r\n\r\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newRecorder(t, "h1", func(w http.ResponseWriter, r *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"+test.wire)
			})
			client := newTestClient(t, server.dialing())
			response, err := client.Get("https://www.example.com/")
			if (err != nil) != test.invalid {
				t.Fatalf("response=%v error=%v, invalid=%v", response, err, test.invalid)
			}
			if !test.invalid && string(response.Body) != "x" {
				t.Fatalf("ordinary chunk changed: %q", response.Body)
			}
		})
	}
}

func TestClientClosesAnUnfinishedOversizedHeaderBlock(t *testing.T) {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{recorderCertificate(t)}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			done <- err
			return
		}
		framer := http2.NewFramer(conn, conn)
		if err := framer.WriteSettings(); err != nil {
			done <- err
			return
		}
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				done <- err
				return
			}
			switch frame := frame.(type) {
			case *http2.SettingsFrame:
				if !frame.IsAck() {
					if err := framer.WriteSettingsAck(); err != nil {
						done <- err
						return
					}
				}
			case *http2.HeadersFrame:
				var block bytes.Buffer
				encoder := hpack.NewEncoder(&block)
				_ = encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				_ = encoder.WriteField(hpack.HeaderField{Name: "x-audit", Value: strings.Repeat("a", 40)})
				if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: block.Bytes()}); err != nil {
					done <- err
					return
				}
				if err := framer.WriteContinuation(frame.StreamID, false, []byte{0x88}); err != nil {
					done <- err
					return
				}
				for {
					if _, err := framer.ReadFrame(); err != nil {
						if errors.Is(err, io.EOF) {
							err = nil
						}
						done <- err
						return
					}
				}
			}
		}
	}()
	p := shippedProfile(t, "chrome_155_macos")
	for i := range p.HTTP2.Settings {
		if p.HTTP2.Settings[i].ID == 6 {
			p.HTTP2.Settings[i].Value = 64
		}
	}
	client := newTestClient(t, WithProfileValue(p), WithTimeout(2*time.Second))
	_, err = client.Get("https://" + listener.Addr().String() + "/")
	if err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(fmt.Sprint(err), "deadline exceeded") {
		t.Errorf("did not reject the unfinished block before deadline: %v", err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Errorf("the peer did not observe connection closure: %v", err)
	}
}
