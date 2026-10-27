package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestA6CLIAndPooledConstructorsRejectBeforeDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			calls.Add(1)
			_ = c.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "a6-invalid-profile"
	p.HTTP2.Settings = []profile.Setting{{ID: 5, Value: 1}}
	raw, _ := json.Marshal(p)
	file := filepath.Join(t.TempDir(), "renamed.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	address := "https://" + listener.Addr().String() + "/"
	for _, args := range [][]string{
		{"fetch", "--profile", file, address},
		{"fetch", "--profile", file, "--proxy", "http://" + listener.Addr().String(), address},
		{"daemon", "--profile", file},
	} {
		code, _, stderr := exec(t, args...)
		if code == 0 || !strings.Contains(stderr, "http2.settings[0].value") {
			t.Fatal(args, code, stderr)
		}
	}
	flags := startedFlags(t)
	flags.run.profile = p
	pool := newPool(flags, "")
	defer pool.close()
	for _, proxy := range []string{"", "http://" + listener.Addr().String(), "https://" + listener.Addr().String(), "socks5://" + listener.Addr().String()} {
		if _, err = pool.get(proxy); err == nil || !strings.Contains(err.Error(), "http2.settings[0].value") {
			t.Fatal(proxy, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected profile dialed", calls.Load())
	}
}
