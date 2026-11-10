package tlsforge

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	tc "github.com/igor-lemon/tls-client"
)

func TestA13ExplicitEmptyH3SettingsReachEveryRoute(t *testing.T) {
	for _, racing := range []bool{false, true} {
		t.Run(fmt.Sprint("racing=", racing), func(t *testing.T) {
			p, err := profile.Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			p = p.Clone()
			p.Behavior["h3.settings"] = json.RawMessage(`[]`)
			p.Behavior["h3.grease_settings"] = json.RawMessage(`false`)
			p.Behavior["quic.datagrams"] = json.RawMessage(`false`)
			raw, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			p, err = profile.Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			target, wire := a13CatalogueH3Peer(t)
			dns := echNames(t, nil, 0, 0)
			opts := []Option{WithProfileValue(p), WithTimeout(4 * time.Second), WithDNSServer(dns.addr)}
			if racing {
				opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
			}
			c := newTestClient(t, opts...)
			if racing {
				response, err := c.Get(target)
				if err != nil || string(response.Body) != "ok" {
					t.Fatalf("racing response %+v %v", response, err)
				}
			} else {
				u, err := url.Parse(target)
				if err != nil {
					t.Fatal(err)
				}
				_, port, err := net.SplitHostPort(u.Host)
				if err != nil {
					t.Fatal(err)
				}
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/seed" {
						w.Header().Set("Alt-Svc", `h3=":`+port+`"`)
					}
					_, _ = w.Write([]byte("tcp"))
				}))
				origin.EnableHTTP2 = true
				origin.StartTLS()
				defer origin.Close()
				originURL, err := url.Parse(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
				_, originPort, err := net.SplitHostPort(originURL.Host)
				if err != nil {
					t.Fatal(err)
				}
				originURL.Host = net.JoinHostPort("alt.h3.test", originPort)
				if _, err = c.Get(originURL.String() + "/seed"); err != nil {
					t.Fatal(err)
				}
				if !soon(3*time.Second, func() bool {
					response, err := c.Get(originURL.String() + "/probe")
					return err == nil && string(response.Body) == "ok"
				}) {
					t.Fatal("Alt-Svc did not reach owned H3 peer")
				}
			}
			select {
			case seen := <-wire:
				if len(seen.Settings) != 0 {
					t.Fatalf("explicit empty SETTINGS inherited data: %+v", seen.Settings)
				}
			case <-time.After(time.Second):
				t.Fatal("missing raw H3 SETTINGS")
			}
		})
	}
}
