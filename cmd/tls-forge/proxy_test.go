package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// A proxy that records what it was asked to reach.
//
// The rest of the batch tests prove per-URL proxying by pointing entries at
// ports nothing is listening on and reading the refusals: that shows each URL
// tried its own proxy, and stops there. This one carries the traffic, so what
// it shows is that the request went through, and through which.

type recordingProxy struct {
	addr     string
	mu       sync.Mutex
	targets  []string
	listener net.Listener
}

// startProxy runs a CONNECT proxy on a loopback port.
//
// CONNECT only, which is all that is needed: the servers behind it speak TLS,
// and a proxied request to an https URL is a tunnel. A plain http one would
// arrive as an absolute-form GET instead, and handling both would be more
// proxy than this is here to be.
func startProxy(t *testing.T) *recordingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	p := &recordingProxy{addr: listener.Addr().String(), listener: listener}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	return p
}

func (p *recordingProxy) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return
	}
	target := fields[1]

	// Drain the headers, so the tunnel starts where the client expects it to.
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(header) == "" {
			break
		}
	}

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = upstream.Close() }()

	// Recorded only once the tunnel is real, so the list holds what went
	// through rather than what was merely asked for.
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.mu.Unlock()

	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstream, reader) }()
	_, _ = io.Copy(conn, upstream)
}

func (p *recordingProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func TestBatchRoutesEachURLThroughItsOwnProxy(t *testing.T) {
	// Two servers and two proxies, so the evidence is which proxy carried
	// which host rather than which port refused a connection. Nothing here
	// would pass if the run shared one client, or if the proxy column were
	// read and then ignored.
	first, second := tlsBatchServer(t), tlsBatchServer(t)
	proxyA, proxyB := startProxy(t), startProxy(t)

	path := writeList(t, "routed.csv", fmt.Sprintf("url,proxy\n%s/a,http://%s\n%s/b,http://%s\n",
		first.URL, proxyA.addr, second.URL, proxyB.addr))

	code, stdout, stderr := exec(t, "batch", "--input", path, "--insecure", "--timeout", "20s")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}

	got := lines(t, stdout)
	for _, url := range []string{first.URL + "/a", second.URL + "/b"} {
		if r := got[url]; r.Status != 200 {
			t.Errorf("%s did not come back: %+v", url, r)
		}
	}

	// Each proxy carried exactly its own server, and neither carried the other's.
	for _, tc := range []struct {
		name  string
		proxy *recordingProxy
		want  string
		other string
	}{
		{"the first", proxyA, hostOf(first.URL), hostOf(second.URL)},
		{"the second", proxyB, hostOf(second.URL), hostOf(first.URL)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := tc.proxy.seen()
			if len(seen) != 1 {
				t.Fatalf("carried %d connections, want 1: %v", len(seen), seen)
			}
			if seen[0] != tc.want {
				t.Errorf("carried %q, want %q", seen[0], tc.want)
			}
			if seen[0] == tc.other {
				t.Errorf("carried the other server's traffic")
			}
		})
	}
}

func hostOf(rawURL string) string {
	return strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
}
