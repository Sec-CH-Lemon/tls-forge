package tlsforge

import (
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	tc "github.com/igor-lemon/tls-client"
	"testing"
	"time"
)

func TestA13NativeQUICActuallyResumesPSK(t *testing.T) {
	for _, alias := range []string{"firefox_146_PSK", "firefox_147_PSK"} {
		for cohort := range 2 {
			t.Run(fmt.Sprintf("%s/%d", alias, cohort), func(t *testing.T) {
				p, err := profile.Get(alias)
				if err != nil {
					t.Fatal(err)
				}
				target, seen := a13CatalogueH3Peer(t)
				client := newTestClient(t, WithProfileValue(p), WithTimeout(6*time.Second), WithTransportOption(tc.WithProtocolRacing()))
				for i := range 3 {
					if i == 2 {
						client.CloseIdleConnections()
					}
					res, err := client.Get(target)
					if err != nil || string(res.Body) != "ok" {
						t.Fatalf("request%d %+v %v", i, res, err)
					}
					select {
					case got := <-seen:
						if got.Connection != i/2 || got.Stream != int64(i%2)*4 || got.Resumed != (i == 2) {
							t.Fatalf("request%d conn%d stream%d resumed%v", i, got.Connection, got.Stream, got.Resumed)
						}
					case <-time.After(time.Second):
						t.Fatal("missing peer")
					}
				}
			})
		}
	}
}
