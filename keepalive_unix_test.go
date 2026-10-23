//go:build darwin || linux

package tlsforge

import (
	"net"
	"syscall"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// probing is how the system probes conn while idle: whether it does, after
// how many seconds, how often and how many times.
type probing struct{ on, idle, interval, count int }

func probingOf(t *testing.T, conn net.Conn) probing {
	t.Helper()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("a %T is no TCP connection", conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var p probing
	var errs []error
	if err := raw.Control(func(fd uintptr) {
		get := func(level, opt int) int {
			v, err := syscall.GetsockoptInt(int(fd), level, opt)
			errs = append(errs, err)
			return v
		}
		p.on = get(syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		p.idle = get(syscall.IPPROTO_TCP, tcpKeepIdle)
		p.interval = get(syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL)
		p.count = get(syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT)
	}); err != nil {
		t.Fatal(err)
	}
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// TestEveryConnectionIsProbedAsTheProfilesBrowserProbesIt reads the socket
// options of the connection a request was dialed on, through the client's
// own dialer: Chrome's profiles keep it alive after 45 s idle, the interval
// 45 s on Linux and Windows and the system's on macOS, the count the
// system's; a profile that turns it off sets none; one that says nothing gets
// Go's 15 s.
func TestEveryConnectionIsProbedAsTheProfilesBrowserProbesIt(t *testing.T) {
	interval, count, err := systemKeepAlive()
	if err != nil {
		t.Fatal(err)
	}
	legacy := func(t *testing.T) *profile.Profile {
		p := policyFile(t, nil)
		for _, k := range []string{"tcp.keepalive", "tcp.keepalive_idle_seconds", "tcp.keepalive_interval_seconds", "tcp.keepalive_count"} {
			delete(p.Behavior, k)
		}
		return p
	}
	named := func(name string) func(*testing.T) *profile.Profile {
		return func(t *testing.T) *profile.Profile {
			p, err := profile.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	for _, tc := range []struct {
		name    string
		profile func(*testing.T) *profile.Profile
		want    probing
	}{
		{"chrome_155_macos", named("chrome_155_macos"), probing{1, 45, interval, count}},
		{"chrome_155_linux", named("chrome_155_linux"), probing{1, 45, 45, count}},
		{"chrome_155_windows", named("chrome_155_windows"), probing{1, 45, 45, count}},
		{"off", func(t *testing.T) *profile.Profile {
			return policyFile(t, map[string]any{"tcp.keepalive": false, "tcp.keepalive_idle_seconds": 0, "tcp.keepalive_interval_seconds": 0})
		}, probing{on: 0}},
		{"explicit", func(t *testing.T) *profile.Profile {
			return policyFile(t, map[string]any{"tcp.keepalive_idle_seconds": 61, "tcp.keepalive_interval_seconds": 7, "tcp.keepalive_count": 3})
		}, probing{1, 61, 7, 3}},
		{"unsaid", legacy, probing{1, 15, 15, 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := newLifecycleServer(t, true, nil)
			c := newTestClient(t, WithProfileValue(tc.profile(t)))
			tap := &seeingTap{}
			get(t, c, site.URL, tap)
			dialed, _ := tap.seen()
			if len(dialed) != 1 {
				t.Fatalf("%d connections dialed", len(dialed))
			}
			got := probingOf(t, dialed[0].Conn)
			if tc.want.on == 0 {
				if got.on != 0 {
					t.Fatalf("probing %+v, want none", got)
				}
				return
			}
			if got.on == 0 || got.idle != tc.want.idle || got.interval != tc.want.interval || got.count != tc.want.count {
				t.Fatalf("probing %+v, want %+v", got, tc.want)
			}
		})
	}
}
