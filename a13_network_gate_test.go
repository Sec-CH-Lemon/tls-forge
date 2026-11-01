package tlsforge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	tc "github.com/igor-lemon/tls-client"
)

func TestA13NetworkCapabilityRejectsBeforeTransportAndRequestIO(t *testing.T) {
	var dials atomic.Int32
	dial := tc.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("unexpected I/O")
	})
	original := a13EstimatedProfile(t)
	for _, mutation := range []func(*profile.Profile){
		func(p *profile.Profile) { delete(p.Behavior, "headers.network_hints") },
		func(p *profile.Profile) { p.NetworkHints = nil },
		func(p *profile.Profile) { p.Behavior["headers.network_hints"] = json.RawMessage(`"literal"`) },
	} {
		for _, proxy := range []string{"", "http://must-not-resolve.invalid:80", "https://must-not-resolve.invalid:443", "socks5://must-not-resolve.invalid:1080"} {
			p := original.Clone()
			p.Name = "unrelated-name"
			mutation(p)
			for _, file := range []bool{false, true} {
				option := WithProfileValue(p)
				if file {
					raw, e := p.Save()
					if e != nil {
						t.Fatal(e)
					}
					path := filepath.Join(t.TempDir(), "renamed.json")
					if e = os.WriteFile(path, raw, 0600); e != nil {
						t.Fatal(e)
					}
					option = WithProfile(path)
				}
				c, e := New(option, WithProxy(proxy), WithTransportOption(dial))
				if e == nil {
					c.Close()
					t.Fatal("incomplete network capability constructed transport")
				}
				if !strings.Contains(e.Error(), "network_hints") {
					t.Fatal(e)
				}
			}
		}
	}
	c, e := New(WithProfileValue(original), WithTransportOption(dial))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	delete(c.profile.Behavior, "headers.network_hints")
	if _, e = c.Fresh(); e == nil {
		t.Fatal("Fresh bypassed required capability")
	}
	if _, e = c.Do(&Request{URL: "https://must-not-resolve.invalid/"}); e == nil {
		t.Fatal("Do bypassed required capability")
	}
	if dials.Load() != 0 {
		t.Fatal("rejected capability caused I/O", dials.Load())
	}
}

func TestA13ObservedConnectionDoesNotInventASocketHandle(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := networkConn{Conn: a}
	if raw, e := c.SyscallConn(); e == nil || raw != nil {
		t.Fatal("non-socket connection invented a kernel descriptor", raw, e)
	}
}
