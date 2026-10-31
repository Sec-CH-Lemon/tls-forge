package tlsforge

import (
	"bytes"
	"context"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls "github.com/igor-lemon/utls"
	"github.com/quic-go/qpack"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type a13H3Setting struct {
	ID    uint64 `json:"id"`
	Value uint64 `json:"value"`
}

type a13H3Observed struct {
	Connection  int                 `json:"connection"`
	Stream      int64               `json:"stream"`
	Resumed     bool                `json:"resumed"`
	Settings    []a13H3Setting      `json:"settings"`
	SettingsRaw []byte              `json:"settings_raw"`
	RequestRaw  []byte              `json:"request_raw"`
	Headers     []qpack.HeaderField `json:"headers"`
}

// An independent literal HTTP/3 peer advertises no dynamic QPACK capability.
// It keeps the original SETTINGS payload and request field-section bytes.
func a13CatalogueH3PeerObserved(t *testing.T, onConnection func(*quic.Conn)) (string, <-chan a13H3Observed) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	cert := seed.TLS.Certificates[0]
	seed.Close()
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
	var peersMu sync.Mutex
	var peers []*quic.Conn
	var ended bool
	var workers sync.WaitGroup
	t.Cleanup(func() {
		stop()
		_ = ln.Close()
		peersMu.Lock()
		ended = true
		owned := append([]*quic.Conn(nil), peers...)
		peersMu.Unlock()
		// Closing a listener does not close its accepted connections. Release the
		// fixture's own I/O outside the registry lock, then join its readers.
		for _, peer := range owned {
			_ = peer.CloseWithError(0, "")
		}
		workers.Wait()
	})
	observations := make(chan a13H3Observed, 3)
	workers.Go(func() {
		for ci := 0; ; ci++ {
			conn, e := ln.Accept(ctx)
			if e != nil {
				return
			}
			peersMu.Lock()
			closing := ended
			if !closing {
				peers = append(peers, conn)
			}
			peersMu.Unlock()
			if closing {
				_ = conn.CloseWithError(0, "")
				return
			}
			if onConnection != nil {
				onConnection(conn)
			}
			index := ci
			workers.Go(func() {
				controlReady := make(chan a13H3Observed, 1)
				workers.Go(func() {
					for {
						stream, e := conn.AcceptUniStream(ctx)
						if e != nil {
							return
						}
						workers.Go(func() {
							r := quicvarint.NewReader(stream)
							typ, e := quicvarint.Read(r)
							if e != nil {
								return
							}
							if typ != 0 {
								_, _ = io.Copy(io.Discard, stream)
								return
							}
							typ, e = quicvarint.Read(r)
							if e != nil || typ != 4 {
								return
							}
							size, e := quicvarint.Read(r)
							if e != nil || size > 65536 {
								return
							}
							raw := make([]byte, size)
							if _, e = io.ReadFull(stream, raw); e != nil {
								return
							}
							seen := a13H3Observed{SettingsRaw: raw}
							br := bytes.NewReader(raw)
							for br.Len() > 0 {
								id, e := quicvarint.Read(br)
								if e != nil {
									return
								}
								value, e := quicvarint.Read(br)
								if e != nil {
									return
								}
								seen.Settings = append(seen.Settings, a13H3Setting{ID: id, Value: value})
							}
							select {
							case controlReady <- seen:
							case <-ctx.Done():
							}
							_, _ = io.Copy(io.Discard, stream)
						})
					}
				})
				control, e := conn.OpenUniStreamSync(ctx)
				if e != nil {
					return
				}
				if _, e = control.Write([]byte{0, 4, 0}); e != nil {
					return
				}
				var settings a13H3Observed
				select {
				case settings = <-controlReady:
				case <-ctx.Done():
					return
				}
				for {
					stream, e := conn.AcceptStream(ctx)
					if e != nil {
						return
					}
					raw := bytes.Buffer{}
					r := quicvarint.NewReader(io.TeeReader(stream, &raw))
					var block []byte
					for {
						typ, e := quicvarint.Read(r)
						if e != nil {
							return
						}
						size, e := quicvarint.Read(r)
						if e != nil || size > 65536 {
							return
						}
						payload := make([]byte, size)
						if _, e = io.ReadFull(r, payload); e != nil {
							return
						}
						if typ == 1 {
							block = payload
							break
						}
					}
					seen := settings
					seen.Connection = index
					seen.Stream = int64(stream.StreamID())
					seen.Resumed = conn.ConnectionState().TLS.DidResume
					seen.RequestRaw = bytes.Clone(raw.Bytes())
					decode := qpack.NewDecoder().Decode(block)
					for {
						field, e := decode()
						if e == io.EOF {
							break
						}
						if e != nil {
							return
						}
						seen.Headers = append(seen.Headers, field)
					}
					select {
					case observations <- seen:
					case <-ctx.Done():
						return
					}
					if _, e = stream.Write([]byte{1, 3, 0, 0, 0xd9, 0, 2, 'o', 'k'}); e != nil {
						return
					}
					if e = stream.Close(); e != nil {
						return
					}
				}
			})
		}
	})
	return "https://" + ln.Addr().String() + "/a13", observations
}
