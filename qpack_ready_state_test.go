package tlsforge

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	tls "github.com/igor-lemon/utls"
)

func TestQPACKJSONFirstSectionUsesActualPeerSettingsState(t *testing.T) {
	for _, known := range []bool{false, true} {
		for _, warmup := range []int{0, 1} {
			t.Run(fmt.Sprintf("known=%t/warmup=%d", known, warmup), func(t *testing.T) {
				p := policyFile(t, map[string]any{"h3.qpack.encoder_warmup_sections": warmup})
				// Profile validation precedes the direct generic mechanism control. Public
				// Client.Do/native cohort checks cover the product adapter independently.
				if err := p.Validate(); err != nil {
					t.Fatal(err)
				}
				var release chan struct{}
				if !known {
					release = make(chan struct{})
				}
				url, wire := qpackWirePeerSettings(t, [][2]uint64{{1, 65536}, {7, 100}}, release)
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				conn, err := quic.DialAddr(ctx, url[len("https://"):], &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.CloseWithError(0x100, "state control complete")
				tr := &http3.Transport{Behavior: p.RuntimeBehavior()}
				client := tr.NewClientConn(conn)
				if known {
					select {
					case <-client.ReceivedSettings():
					case <-ctx.Done():
						t.Fatal("peer SETTINGS not read")
					}
				}
				done := make(chan error, 1)
				go func() {
					request, e := http.NewRequestWithContext(ctx, "GET", url, nil)
					if e == nil {
						var response *http.Response
						response, e = client.RoundTrip(request)
						if e == nil {
							var body []byte
							body, e = io.ReadAll(response.Body)
							_ = response.Body.Close()
							if e == nil && string(body) != "ok" {
								e = fmt.Errorf("body %q", body)
							}
						}
					}
					done <- e
				}()
				var block []byte
				select {
				case block = <-wire:
				case <-ctx.Done():
					t.Fatal("first section waited for peer SETTINGS")
				}
				if release != nil {
					close(release)
				}
				if len(block) < 2 {
					t.Fatal("no field-section prefix")
				}
				dynamic := block[0] != 0
				want := known && warmup == 0
				if dynamic != want {
					t.Fatalf("first section dynamic=%v, want%v, prefix%x", dynamic, want, block[:2])
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
