package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// trusting is a pool of roots that holds the proxy's authority alone.
func trusting(t *testing.T, ca *CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("the authority is not usable as a trust root")
	}
	return pool
}

// eagerConn sends a CONNECT with the first thing written on it rather than
// waiting for the answer to it, as a client in a hurry does, and reads that
// answer before anything else is read.
type eagerConn struct {
	net.Conn
	connect  string
	reader   *bufio.Reader
	answered bool
}

func (c *eagerConn) Write(p []byte) (int, error) {
	if c.connect != "" {
		written := append([]byte(c.connect), p...)
		c.connect = ""
		if _, err := c.Conn.Write(written); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *eagerConn) Read(p []byte) (int, error) {
	if !c.answered {
		c.answered = true
		res, err := http.ReadResponse(c.reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			return 0, err
		}
		if res.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("CONNECT answered %s", res.Status)
		}
	}
	return c.reader.Read(p)
}

func TestBytesSentWithTheConnectGoIntoTheTunnel(t *testing.T) {
	// The handshake's first flight in the same write as the CONNECT: it is in
	// the reader the CONNECT was read through, and the tunnel begins with it.
	client := &answering{}
	ca := newCAForTest(t)
	server, problems := startProxy(t, client, ca)
	raw, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	eager := &eagerConn{Conn: raw, connect: "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
		reader: bufio.NewReader(raw)}
	tunnel := tls.Client(eager, &tls.Config{RootCAs: trusting(t, ca), ServerName: "example.test"})
	if err := tunnel.Handshake(); err != nil {
		t.Fatalf("the handshake sent with the CONNECT: %v", err)
	}
	if _, err := io.WriteString(tunnel, "GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	res, err := http.ReadResponse(bufio.NewReader(tunnel), nil)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("answered %v, %v", res, err)
	}
	if got := problems.list(); len(got) != 0 {
		t.Errorf("reported %v", got)
	}
}

// openedTunnel opens a tunnel through the proxy to authority, and is the TLS
// connection through it to the proxy's stand-in for what it names.
func openedTunnel(t *testing.T, server *Server, ca *CA, authority string, chunk int) *tls.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn := raw
	if chunk > 0 {
		conn = &choppedConn{Conn: raw, chunk: chunk}
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatalf("writing the CONNECT: %v", err)
	}
	reader := bufio.NewReader(raw)
	res, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s answered %v, %v", authority, res, err)
	}
	name, _, _ := net.SplitHostPort(authority)
	tunnel := tls.Client(&bufferedConn{Conn: conn, reader: reader},
		&tls.Config{RootCAs: trusting(t, ca), ServerName: name})
	if err := tunnel.Handshake(); err != nil {
		t.Fatalf("the handshake in the tunnel to %s: %v", authority, err)
	}
	return tunnel
}

// choppedConn writes what it is given a few bytes at a time, as a network
// that fragments a handshake does.
type choppedConn struct {
	net.Conn
	chunk int
}

func (c *choppedConn) Write(p []byte) (int, error) {
	for sent := 0; sent < len(p); sent += c.chunk {
		if _, err := c.Conn.Write(p[sent:min(sent+c.chunk, len(p))]); err != nil {
			return sent, err
		}
		time.Sleep(time.Millisecond)
	}
	return len(p), nil
}

func TestARequestInATunnelGoesWhereTheTunnelWasOpened(t *testing.T) {
	// To the host and port the CONNECT names. A request that names no port is
	// the tunnel's; one that names another host or port is answered 421, and
	// goes nowhere.
	for _, tc := range []struct {
		name, connect, target, inner, want string
		status                             int
	}{
		{"the default port", "example.test:443", "/x", "example.test", "https://example.test/x", 200},
		{"the default port, named", "example.test:443", "/x", "EXAMPLE.test:443", "https://example.test/x", 200},
		{"another port", "example.test:8443", "/x", "example.test:8443", "https://example.test:8443/x", 200},
		{"another port, not named inside", "example.test:8443", "/x", "example.test", "https://example.test:8443/x", 200},
		{"an IPv6 address", "[::1]:8443", "/x", "[::1]:8443", "https://[::1]:8443/x", 200},
		{"an IPv6 address, its port not named", "[::1]:8443", "/x", "[::1]", "https://[::1]:8443/x", 200},
		{"another host", "example.test:443", "/x", "other.test", "", http.StatusMisdirectedRequest},
		{"another port named inside", "example.test:8443", "/x", "example.test:9000", "", http.StatusMisdirectedRequest},
		{"another host, as the request's own URL", "example.test:443", "https://other.test/x", "example.test", "",
			http.StatusMisdirectedRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &answering{}
			ca := newCAForTest(t)
			server, _ := startProxy(t, client, ca)
			tunnel := openedTunnel(t, server, ca, tc.connect, 0)
			if _, err := fmt.Fprintf(tunnel, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", tc.target, tc.inner); err != nil {
				t.Fatalf("writing: %v", err)
			}
			res, err := http.ReadResponse(bufio.NewReader(tunnel), nil)
			if err != nil || res.StatusCode != tc.status {
				t.Fatalf("answered %v, %v; want %d", res, err, tc.status)
			}
			asked := client.requests()
			switch {
			case tc.want == "" && len(asked) != 0:
				t.Errorf("%s went on", asked[0].URL)
			case tc.want != "" && (len(asked) != 1 || asked[0].URL != tc.want):
				t.Errorf("went on as %v, want %s", asked, tc.want)
			}
		})
	}
}

func TestAHandshakeInPiecesStillOpensTheTunnel(t *testing.T) {
	client := &answering{}
	ca := newCAForTest(t)
	server, _ := startProxy(t, client, ca)
	tunnel := openedTunnel(t, server, ca, "example.test:443", 7)
	if _, err := io.WriteString(tunnel, "GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if res, err := http.ReadResponse(bufio.NewReader(tunnel), nil); err != nil || res.StatusCode != http.StatusOK {
		t.Errorf("answered %v, %v", res, err)
	}
}

func TestMisdirected(t *testing.T) {
	for _, tc := range []struct {
		inner, host, port string
		want              bool
	}{
		{"", "a.test", "443", false},
		{"a.test", "a.test", "443", false},
		{"A.TEST:443", "a.test", "443", false},
		{"a.test:8443", "a.test", "443", true},
		{"b.test", "a.test", "443", true},
		{"[::1]", "::1", "8443", false},
		{"[::1]:8443", "::1", "8443", false},
		{"[::2]", "::1", "8443", true},
		// An empty port is no port.
		{"a.test:", "a.test", "443", false},
	} {
		if got := misdirected(tc.inner, tc.host, tc.port); got != tc.want {
			t.Errorf("misdirected(%q, %q, %q) = %v", tc.inner, tc.host, tc.port, got)
		}
	}
}
