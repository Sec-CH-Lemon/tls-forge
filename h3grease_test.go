package tlsforge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls "github.com/igor-lemon/utls"
)

type greasePeerSetting struct {
	conn  *quic.Conn
	pairs [][2]uint64
	err   error
}

// Inspect actual peer control-stream bytes, independently of the transport's
// SETTINGS serializer. No application observer substitutes for the wire path.
func greasePeer(t *testing.T) (string, <-chan greasePeerSetting) {
	t.Helper()
	udp, tcp := udpAndTCP(t)
	_, port, _ := net.SplitHostPort(tcp.Addr().String())
	fallback := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) { _, _ = io.WriteString(w, "TCP fallback") }))
	fallback.Listener = &slowFirstWord{Listener: tcp, lag: time.Second}
	fallback.EnableHTTP2 = true
	fallback.StartTLS()
	t.Cleanup(fallback.Close)
	cert := fallback.TLS.Certificates[0]
	listener, err := quic.Listen(udp, &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}, ApplicationSettings: map[string][]byte{"h3": qpackTable}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = udp.Close() })
	observed := make(chan greasePeerSetting, 128)
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				control, err := conn.OpenUniStreamSync(context.Background())
				if err != nil {
					return
				}
				_, _ = control.Write(append([]byte{0}, qpackTable...))
				go func() {
					for {
						stream, err := conn.AcceptUniStream(context.Background())
						if err != nil {
							return
						}
						go func() {
							_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
							reader := quicvarint.NewReader(stream)
							kind, err := quicvarint.Read(reader)
							if err != nil {
								return
							}
							if kind != 0 {
								_, _ = io.Copy(io.Discard, stream)
								return
							}
							seen := greasePeerSetting{conn: conn}
							frame, err := quicvarint.Read(reader)
							if err != nil || frame != 4 {
								seen.err = fmt.Errorf("SETTINGS first: type=%d error=%v", frame, err)
							} else {
								size, err := quicvarint.Read(reader)
								if err != nil || size > 4096 {
									seen.err = fmt.Errorf("SETTINGS length=%d error=%v", size, err)
								} else {
									body := make([]byte, size)
									_, seen.err = io.ReadFull(stream, body)
									payload := bytes.NewReader(body)
									for payload.Len() > 0 && seen.err == nil {
										id, e := quicvarint.Read(payload)
										if e != nil {
											seen.err = e
											break
										}
										v, e := quicvarint.Read(payload)
										if e != nil {
											seen.err = e
											break
										}
										seen.pairs = append(seen.pairs, [2]uint64{id, v})
									}
								}
							}
							observed <- seen
							_, _ = io.Copy(io.Discard, stream)
						}()
					}
				}()
				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						_, _ = io.Copy(io.Discard, stream)
						_, _ = stream.Write([]byte{1, 3, 0, 0, 0xd9, 0, 2, 'o', 'k'})
						_ = stream.Close()
					}()
				}
			}()
		}
	}()
	return port, observed
}

func greaseObservation(t *testing.T, ch <-chan greasePeerSetting) greasePeerSetting {
	t.Helper()
	select {
	case seen := <-ch:
		if seen.err != nil {
			t.Fatal(seen.err)
		}
		return seen
	case <-time.After(5 * time.Second):
		t.Fatal("no control SETTINGS")
		return greasePeerSetting{}
	}
}

func greaseN(t *testing.T, seen greasePeerSetting) (uint64, uint64) {
	t.Helper()
	var found [][2]uint64
	for _, pair := range seen.pairs {
		if pair[0] >= 33 && (pair[0]-33)%31 == 0 {
			found = append(found, pair)
		}
	}
	if len(found) != 1 {
		t.Fatalf("GREASE fields %v", found)
	}
	return (found[0][0] - 33) / 31, found[0][1]
}

func TestProfileJSONH3GREASEConnectionLifetime(t *testing.T) {
	// Boundary/fixed-range rules are real JSON edits. Repeats are expected.
	for _, n := range []uint64{0, 4294967295} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			port, observed := greasePeer(t)
			p := policyFile(t, map[string]any{"quic.tcp_waits_with_connection": true, "h3.grease_setting_n_min": n, "h3.grease_setting_n_max": n, "h3.grease_setting_nonzero": false})
			client := echClient(t, alpsNames(t), WithProfileValue(p), WithoutSessionResumption())
			for range 3 {
				if body := came(t, client, "https://h3.h3.test:"+port+"/"); body != "ok" {
					t.Fatalf("not H3: %s", body)
				}
				seen := greaseObservation(t, observed)
				got, value := greaseN(t, seen)
				if got != n || value > 4294967295 {
					t.Fatalf("N/value %d/%d", got, value)
				}
				if body := came(t, client, "https://h3.h3.test:"+port+"/"); body != "ok" {
					t.Fatal(body)
				}
				select {
				case extra := <-observed:
					t.Fatalf("new connection for reused request: %+v", extra.pairs)
				default:
				}
				if err := seen.conn.CloseWithError(0, "fresh connection control"); err != nil {
					t.Fatal(err)
				}
				client.CloseIdleConnections()
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestProfileH3GREASEFreshConnectionCohort(t *testing.T) {
	// Declared before collection:64 connections,16 equal uint32 bins, Pearson
	// statistic<=60 (very conservative alert threshold, not an RNG certificate).
	// Repeated draws are allowed. A transport-frozen draw fails with statistic960.
	port, observed := greasePeer(t)
	p := policyFile(t, map[string]any{"quic.tcp_waits_with_connection": true, "h3.grease_setting_n_min": 0, "h3.grease_setting_n_max": uint64(4294967295), "h3.grease_setting_nonzero": false})
	client := echClient(t, alpsNames(t), WithProfileValue(p), WithoutSessionResumption())
	bins := make([]int, 16)
	var order []uint64
	for range 64 {
		if body := came(t, client, "https://h3.h3.test:"+port+"/"); body != "ok" {
			t.Fatalf("not H3: %s", body)
		}
		seen := greaseObservation(t, observed)
		n, v := greaseN(t, seen)
		t.Logf("peer SETTINGS %v", seen.pairs)
		if n > 4294967295 || v > 4294967295 {
			t.Fatalf("outside uint32: %d %d", n, v)
		}
		bins[n>>28]++
		current := make([]uint64, 0, len(seen.pairs))
		for _, pair := range seen.pairs {
			if pair[0] < 33 || (pair[0]-33)%31 != 0 {
				current = append(current, pair[0])
			}
		}
		if order == nil {
			order = current
		} else if !slices.Equal(order, current) {
			t.Fatalf("stable SETTINGS order changed: %v %v", order, current)
		}
		if err := seen.conn.CloseWithError(0, "cohort"); err != nil {
			t.Fatal(err)
		}
		client.CloseIdleConnections()
		time.Sleep(10 * time.Millisecond)
	}
	statistic := 0.0
	for _, count := range bins {
		d := float64(count) - 4
		statistic += d * d / 4
	}
	t.Logf("connections64 bins%v statistic%.3f", bins, statistic)
	if statistic > 60 {
		t.Fatalf("connection draw distribution inconsistent: %.3f", statistic)
	}
}
