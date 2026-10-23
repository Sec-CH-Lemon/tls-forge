package tlsforge

import (
	"context"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
	tc "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngineGateBeforeProxyOrOriginConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			calls.Add(1)
			c.Close()
		}
	}()
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	for _, major := range []*int{nil, profile.Major(-1), profile.Major(0), profile.Major(1), profile.Major(2), profile.Major(3), profile.Major(4), profile.Major(5), profile.Major(6), profile.Major(8)} {
		q := p.Clone()
		q.Name = "renamed"
		q.EngineMajor = major
		for _, proxy := range []string{"", "http://" + listener.Addr().String(), "https://" + listener.Addr().String(), "socks5://" + listener.Addr().String()} {
			c, err := New(WithProfileValue(q), WithProxy(proxy))
			if err == nil {
				c.CloseIdleConnections()
				t.Fatal("New accepted mismatch")
			}
			if !strings.Contains(err.Error(), "engine_major") {
				t.Fatal(err)
			}
		}
	}
	c, err := New(WithProfileValue(p))
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	// Caller-owned profile and returned clones cannot mutate a constructed client.
	*p.EngineMajor = 0
	view := c.Profile()
	*view.EngineMajor = 2
	if _, err := c.Fresh(); err != nil {
		t.Fatal(err)
	}
	// Internal corruption also fails before either a pooled clone or origin I/O.
	c.profile.EngineMajor = profile.Major(0)
	if _, err := c.Fresh(); err == nil {
		t.Fatal("Fresh bypass")
	}
	if _, err := c.Do(&Request{URL: "https://" + listener.Addr().String()}); err == nil {
		t.Fatal("Do bypass")
	}
	time.Sleep(20 * time.Millisecond)
	listener.Close()
	<-done
	if calls.Load() != 0 {
		t.Fatalf("%d network side effects", calls.Load())
	}
}

// This is engine/wire migration validation against an owned peer, not a new
// Chrome151-154 or Linux/Windows browser-equivalence measurement.
func TestMigratedProfilesOnRealTLSAndHTTP2(t *testing.T) {
	server := startEcho(t)
	for _, major := range []string{"151", "152", "153", "154", "155"} {
		for _, platform := range []string{"linux", "macos", "windows"} {
			name := "chrome_" + major + "_" + platform
			t.Run(name, func(t *testing.T) {
				p, err := profile.Get(name)
				if err != nil {
					t.Fatal(err)
				}
				measured := measure(t, newTestClient(t, WithProfileValue(p)), server)
				if measured.TLS.Resumed || measured.UserAgent() != p.UserAgent || !reflect.DeepEqual(measured.HTTP2.HeaderOrder, p.HeaderOrder()) {
					t.Fatalf("migration wire mismatch: %+v", measured.HTTP2)
				}
				if len(measured.HTTP2.Settings) != len(p.HTTP2.Settings) {
					t.Fatal("SETTINGS count")
				}
				for i, setting := range p.HTTP2.Settings {
					if measured.HTTP2.Settings[i].ID != setting.ID || measured.HTTP2.Settings[i].Value != setting.Value {
						t.Fatal("SETTINGS order/value")
					}
				}
			})
		}
	}
}

func TestRawPresetCannotReplaceValidatedEngineProfile(t *testing.T) {
	called := false
	dial := tc.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, fmt.Errorf("unexpected dial")
	})
	for _, raw := range []tc.HttpClientOption{tc.WithClientProfile(profiles.Firefox_148), tc.WithLockedClientProfile(profiles.Chrome_133, "another")} {
		c, err := New(WithProfile("chrome_155_macos"), WithTransportOption(dial, raw))
		if err == nil {
			c.CloseIdleConnections()
			t.Fatal("raw profile bypass")
		}
		if !strings.Contains(err.Error(), "chrome_155_macos") || !strings.Contains(err.Error(), "engine_major 7") || !strings.Contains(err.Error(), "raw client profile override") {
			t.Fatal(err)
		}
	}
	if called {
		t.Fatal("profile override caused network I/O")
	}
}
