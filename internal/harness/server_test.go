package harness

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// started is a server answering scenarios, closed with the test.
func started(t *testing.T, scenarios map[string]scenario) *Server {
	t.Helper()
	s, err := startServer(scenarios)
	if err != nil {
		t.Fatalf("startServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// client is how a test asks the server for something: every name it serves is
// the loopback address, its certificate is taken on trust, and HTTP/2 is used
// where it is offered.
func client() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return dialer.DialContext(ctx, network, "127.0.0.1:"+port)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the bench's own certificate
		ForceAttemptHTTP2: true,
	}}
}

// get asks for url, and is the answer read whole.
func get(t *testing.T, method, url string, body io.Reader, header ...string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for i := 0; i < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	res, err := client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = res.Body.Close() }()
	data, _ := io.ReadAll(res.Body)
	return res, string(data)
}

// requests are what the server kept, failing the test on trouble.
func requests(t *testing.T, s *Server) []Entry {
	t.Helper()
	entries, err := s.Requests()
	if err != nil {
		t.Fatalf("Requests: %v", err)
	}
	return entries
}

// headerNames are the names of an entry's fields, in order.
func headerNames(e Entry) []string {
	var out []string
	for _, h := range e.Headers {
		out = append(out, h[0])
	}
	return out
}

func TestTheServerKeepsEachRequestAsItWasSentOverEachProtocol(t *testing.T) {
	s := started(t, catalogue)
	for _, tc := range []struct {
		name, url, proto string
	}{
		{"HTTP/2", "https://www.example.com:" + strconv.Itoa(s.H2) + "/p/a?b=1", "h2"},
		{"HTTP/1.1 over TLS", "https://www.example.net:" + strconv.Itoa(s.H1) + "/p/a?b=1", "http/1.1"},
		{"plain HTTP", "http://localhost:" + strconv.Itoa(s.Plain) + "/p/a?b=1", "http/1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.Reset()
			res, _ := get(t, http.MethodPost, tc.url, strings.NewReader("a=1&b=x"), "X-Foo", "bar")
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status %d", res.StatusCode)
			}
			entries := requests(t, s)
			if len(entries) != 1 {
				t.Fatalf("kept %d requests", len(entries))
			}
			e := entries[0]
			if e.Proto != tc.proto || e.Method != http.MethodPost || e.Target != tc.url || e.Body != "a=1&b=x" || e.Conn < 1 {
				t.Errorf("kept %+v", e)
			}
			if !slices.Contains(headerNames(e), map[string]string{"h2": "x-foo", "http/1.1": "X-Foo"}[tc.proto]) {
				t.Errorf("headers %v", headerNames(e))
			}
			// HTTP/2's header block is kept as the client wrote it, and is
			// what was read of it.
			if tc.proto == "h2" {
				fields, err := hpack.NewDecoder(4096, nil).DecodeFull(e.Block)
				if err != nil || len(fields) != len(e.Headers) || fields[0].Name != e.Headers[0][0] {
					t.Errorf("the block %x reads %v, %v", e.Block, fields, err)
				}
			} else if e.Block != nil {
				t.Errorf("an HTTP/1.1 request with a block %x", e.Block)
			}
			// The pseudo-headers lead, in the order the client wrote them.
			if tc.proto == "h2" && (e.Stream%2 != 1 || !slices.Equal(headerNames(e)[:4], []string{":authority", ":method", ":path", ":scheme"})) {
				t.Errorf("stream %d, headers %v", e.Stream, headerNames(e))
			}
		})
	}
}

func TestPlainHTTPIsServedAtTheIPv6LoopbackAddressTooOnItsPort(t *testing.T) {
	// A URL naming [::1] is kept as one naming 127.0.0.1 is: its port left
	// out, as the server's.
	s := started(t, catalogue)
	url := "http://[::1]:" + strconv.Itoa(s.Plain) + "/p/a"
	res, err := (&http.Client{Timeout: 10 * time.Second}).Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_ = res.Body.Close()
	entries := requests(t, s)
	if len(entries) != 1 || entries[0].Target != url || entries[0].Proto != "http/1.1" {
		t.Fatalf("kept %+v", entries)
	}
	if got := s.kept(entries, false); len(got) != 1 || got[0].URL != "http://[::1]/p/a" ||
		!slices.Contains(got[0].Headers, [2]string{"Host", "[::1]"}) {
		t.Errorf("kept as %+v", got)
	}
}

func TestEachRequestSaysWhetherItsConnectionResumedATLSSession(t *testing.T) {
	s := started(t, catalogue)
	for _, tc := range []struct {
		name, proto string
		port        int
	}{{"HTTP/2", "h2", s.H2}, {"HTTP/1.1", "http/1.1", s.H1}} {
		t.Run(tc.name, func(t *testing.T) {
			s.Reset()
			// A client that keeps its sessions: its second connection resumes
			// what the first was given, though another clone of the server's
			// TLS answers it.
			c := client()
			c.Transport.(*http.Transport).TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(4)
			for range 2 {
				res, err := c.Get("https://www.example.com:" + strconv.Itoa(tc.port) + "/p/x")
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				c.CloseIdleConnections()
			}
			entries := requests(t, s)
			if len(entries) != 2 || entries[0].Proto != tc.proto || entries[0].Resumed || !entries[1].Resumed ||
				entries[0].Conn == entries[1].Conn {
				t.Errorf("kept %+v", entries)
			}
		})
	}
	// Plain HTTP resumes nothing.
	s.Reset()
	get(t, http.MethodGet, "http://www.example.com:"+strconv.Itoa(s.Plain)+"/p/x", nil)
	if e := requests(t, s)[0]; e.Resumed || e.Conn == 0 {
		t.Errorf("kept %+v", e)
	}
}

func TestTheServerSaysItsKeyAsChromeIsToldToTakeOne(t *testing.T) {
	s := started(t, catalogue)
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.H1), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the bench's own
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	sum := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	if want := base64.StdEncoding.EncodeToString(sum[:]); s.spki != want {
		t.Errorf("spki %q, the certificate's %q", s.spki, want)
	}
}

func TestAnAnswerThatSaysCloseEndsItsConnection(t *testing.T) {
	s := started(t, catalogue)
	// Over HTTP/2 the server says GOAWAY, and the next request goes on
	// another connection.
	c := client()
	h2 := "https://www.example.com:" + strconv.Itoa(s.H2)
	for _, path := range []string{"/p/x?close=1", "/p/y", "/p/z"} {
		res, err := c.Get(h2 + path)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.ProtoMajor != 2 {
			t.Fatalf("over %s", res.Proto)
		}
	}
	if e := requests(t, s); len(e) != 3 || e[0].Conn == e[1].Conn || e[1].Conn != e[2].Conn {
		t.Errorf("kept %+v", e)
	}
	// Over HTTP/1.1 it closes the connection once it has answered.
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.H1), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the bench's own
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "GET /p/x?close=1 HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if answer, err := io.ReadAll(conn); err != nil || !strings.Contains(string(answer), "Connection: close") {
		t.Errorf("read %q, %v", answer, err)
	}
}

func TestARequestForANameItsConnectionWasNotMadeForIsMisdirected(t *testing.T) {
	s := started(t, map[string]scenario{"t": {table: 1024}})
	h1 := strconv.Itoa(s.H1)
	// Over HTTP/1.1, each request on a connection of its own whose TLS asked
	// for the name given.
	for _, tc := range []struct {
		name, host string
		status     string
	}{
		{"www.example.com", "api.example.com:" + h1, "421"},
		{"www.example.com", "www.example.com:" + h1, "200"},
		{"www.example.com", "WWW.Example.COM:" + h1, "200"},
		{"www.example.com", "www.example.com", "200"},
		{"www.example.com", "api.example.com", "421"},
	} {
		conn, err := tls.Dial("tcp", "127.0.0.1:"+h1, &tls.Config{ServerName: tc.name, InsecureSkipVerify: true}) //nolint:gosec // the bench's own
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		_, _ = io.WriteString(conn, "GET /misdirected/x HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if !strings.HasPrefix(line, "HTTP/1.1 "+tc.status) {
			t.Errorf("%s over a connection to %s: %q", tc.host, tc.name, line)
		}
	}
	// Over HTTP/2, on the port that offers it and on one with a table of its
	// own, a connection whose TLS asked for www.example.com carrying a request
	// for another name.
	for _, port := range []int{s.H2, s.Tables[1024]} {
		h2 := strconv.Itoa(port)
		tr := &http.Transport{ForceAttemptHTTP2: true, DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{ServerName: "www.example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true}} //nolint:gosec // the bench's own
			return d.DialContext(ctx, network, "127.0.0.1:"+h2)
		}}
		for host, want := range map[string]int{"www.example.com": http.StatusOK, "api.example.com": http.StatusMisdirectedRequest} {
			req, _ := http.NewRequest(http.MethodGet, "https://"+host+":"+h2+"/misdirected/x", nil)
			res, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != want || res.ProtoMajor != 2 {
				t.Errorf("%s over a connection to www.example.com on %s: %d over %s, want %d", host, h2, res.StatusCode,
					res.Proto, want)
			}
		}
		tr.CloseIdleConnections()
	}
	// In the clear, never.
	if res, _ := get(t, http.MethodGet, "http://api.example.com:"+strconv.Itoa(s.Plain)+"/misdirected/x", nil); res.StatusCode != http.StatusOK {
		t.Errorf("in the clear: %d", res.StatusCode)
	}
}

func TestStartServerAnswersTheCatalogue(t *testing.T) {
	s, err := StartServer()
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer func() { _ = s.Close() }()
	res, body := get(t, http.MethodGet, "https://www.example.com:"+strconv.Itoa(s.H2)+"/run/nav-direct", nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "const done=()=>fetch('/done/nav-direct');") {
		t.Errorf("status %d, body %q", res.StatusCode, body)
	}
}

func TestRequestsAreCopiesAndResetForgetsThem(t *testing.T) {
	s := started(t, catalogue)
	get(t, http.MethodGet, "https://www.example.com:"+strconv.Itoa(s.H2)+"/p/x", nil)
	first := requests(t, s)
	first[0].Headers[0][1] = "changed"
	first[0].Block[0] = 0
	if again := requests(t, s)[0]; again.Headers[0][1] == "changed" || again.Block[0] == 0 {
		t.Error("a copy shared the server's headers or block")
	}
	s.Reset()
	if got := requests(t, s); len(got) != 0 {
		t.Errorf("kept %d requests after Reset", len(got))
	}
}

// rawHTTP1 writes request over a connection to addr, TLS ones offering
// HTTP/1.1 alone, and is the answer's status line.
func rawHTTP1(t *testing.T, addr string, useTLS bool, chunks ...string) string {
	t.Helper()
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // the bench's own
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	for _, chunk := range chunks {
		if _, err := io.WriteString(conn, chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return line
}

func TestHTTP11IsKeptAsTheBytesSaidItHeaderLineByHeaderLine(t *testing.T) {
	s := started(t, catalogue)
	// HTTP/1.1 on the port that offers HTTP/2 too, the body in pieces, and a
	// second request on the same connection.
	status := rawHTTP1(t, "127.0.0.1:"+strconv.Itoa(s.H2), true,
		"POST /p/one HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 6\r\nX-B:  1\r\nx-a:\t2\r\n\r\nab",
		"cd", "ef")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("status %q", status)
	}
	entries := requests(t, s)
	if len(entries) != 1 {
		t.Fatalf("kept %d", len(entries))
	}
	e := entries[0]
	want := [][2]string{{"Host", "www.example.com"}, {"Content-Length", "6"}, {"X-B", "1"}, {"x-a", "2"}}
	if e.Target != "https://www.example.com/p/one" || e.Body != "abcdef" || !slices.Equal(e.Headers, want) || e.Proto != "http/1.1" {
		t.Errorf("kept %+v", e)
	}
}

func TestABadConnectionIsLetGoAndKeepsNothing(t *testing.T) {
	s := started(t, catalogue)
	// A TLS port given no TLS: its handshake fails, and the server goes on.
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.H1))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.ReadAll(conn)
	_ = conn.Close()
	if got := requests(t, s); len(got) != 0 {
		t.Errorf("kept %v", got)
	}
	get(t, http.MethodGet, "https://www.example.com:"+strconv.Itoa(s.H1)+"/p/after", nil)
	if got := requests(t, s); len(got) != 1 {
		t.Errorf("after a bad connection, kept %d", len(got))
	}
}

func TestCloseEndsWhatIsOpenAndTakesNoMore(t *testing.T) {
	s, err := startServer(catalogue)
	if err != nil {
		t.Fatalf("startServer: %v", err)
	}
	// A connection that is open, and says nothing.
	idle, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.H2))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = idle.Close() }()
	// Once the server holds it: closed before, it would be none of Close's.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		s.mu.Lock()
		held := len(s.open)
		s.mu.Unlock()
		if held == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the server never took the connection")
		}
	}
	done := make(chan struct{})
	go func() {
		_ = s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited on an idle connection")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(s.Plain), time.Second); err == nil {
		t.Error("a closed server took a connection")
	}
}

// oneConnListener hands out one connection, then says it is closed.
type oneConnListener struct {
	conn net.Conn
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, net.ErrClosed
	}
	l.used = true
	return l.conn, nil
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAConnectionThatArrivesAsTheServerClosesIsClosedToo(t *testing.T) {
	s := started(t, catalogue)
	ours, theirs := net.Pipe()
	defer func() { _ = theirs.Close() }()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.done.Add(1)
	s.accept(&oneConnListener{conn: ours}, nil, nil)
	if _, err := ours.Write([]byte("x")); err == nil {
		t.Error("the connection was left open")
	}
	s.mu.Lock()
	s.closed = false
	s.mu.Unlock()
}

func TestAConnectionHandedOnAfterCloseIsClosed(t *testing.T) {
	l := &chanListener{conns: make(chan net.Conn), done: make(chan struct{})}
	l.close()
	l.close()
	ours, theirs := net.Pipe()
	defer func() { _ = theirs.Close() }()
	l.hand(ours)
	if _, err := ours.Write([]byte("x")); err == nil {
		t.Error("the connection was left open")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after close: %v", err)
	}
	if l.Close() != nil || l.Addr().String() != "127.0.0.1:0" {
		t.Errorf("Close %v, Addr %v", l.Close(), l.Addr())
	}
}

func TestAServerThatCannotStartSaysWhy(t *testing.T) {
	failing := errors.New("no")
	for _, tc := range []struct {
		name   string
		break_ func()
		// says is how the error begins, when it is not failing.
		says string
	}{
		{"no key", func() { newKey = func() (*ecdsa.PrivateKey, error) { return nil, failing } }, ""},
		{"no certificate", func() {
			createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
				return nil, failing
			}
		}, ""},
		{"a certificate that cannot be read", func() {
			createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
				return []byte("no certificate"), nil
			}
		}, "harness: x509: "},
		{"no port", func() {
			calls := 0
			listen = func(network, addr string) (net.Listener, error) {
				// The first two are had, and the third is not.
				if calls++; calls < 3 {
					return net.Listen(network, addr)
				}
				return nil, failing
			}
		}, ""},
		{"no plain port at the IPv6 loopback address", func() {
			listen = func(network, addr string) (net.Listener, error) {
				if strings.HasPrefix(addr, "[::1]:") {
					return nil, failing
				}
				return net.Listen(network, addr)
			}
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldKey, oldCreate, oldListen := newKey, createCertificate, listen
			t.Cleanup(func() { newKey, createCertificate, listen = oldKey, oldCreate, oldListen })
			tc.break_()
			_, err := startServer(catalogue)
			if tc.says == "" && !errors.Is(err, failing) || tc.says != "" && (err == nil || !strings.HasPrefix(err.Error(), tc.says)) {
				t.Errorf("startServer: %v", err)
			}
		})
	}
}

// frame is an HTTP/2 frame's bytes.
func frame(typ http2.FrameType, flags http2.Flags, stream uint32, payload []byte) []byte {
	out := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), byte(typ), byte(flags),
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(out, payload...)
}

// block is a header block of fields, as an HPACK encoder writes it.
func block(fields ...string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for i := 0; i < len(fields); i += 2 {
		_ = enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	return buf.Bytes()
}

func parser(s *Server) *h2parser {
	return &h2parser{s: s, conn: 7, dec: hpack.NewDecoder(4096, nil), open: map[uint32]*Entry{}}
}

func TestHTTP2IsReadFrameByFrame(t *testing.T) {
	s := started(t, catalogue)
	p := parser(s)
	head := block(":method", "POST", ":scheme", "https", ":authority", "www.example.com", ":path", "/p/x", "x-a", "1")
	// HEADERS padded, with a priority, split across a CONTINUATION; a padded
	// DATA frame; DATA on a stream nobody opened; and the preface in pieces.
	priority := []byte{0x80, 0, 0, 3, 219}
	headers := append([]byte{2}, priority...)
	headers = append(headers, head[:5]...)
	headers = append(headers, 0, 0)
	all := []byte(http2.ClientPreface)
	all = append(all, frame(http2.FrameSettings, 0, 0, nil)...)
	all = append(all, frame(http2.FrameHeaders, http2.FlagHeadersPadded|http2.FlagHeadersPriority, 5, headers)...)
	all = append(all, frame(http2.FrameContinuation, http2.FlagContinuationEndHeaders, 5, head[5:])...)
	all = append(all, frame(http2.FrameData, http2.FlagDataPadded, 5, []byte{1, 'a', 'b', 0})...)
	all = append(all, frame(http2.FrameData, 0, 9, []byte("lost"))...)
	all = append(all, frame(http2.FrameData, http2.FlagDataEndStream, 5, []byte("cd"))...)
	for _, b := range all {
		p.write([]byte{b})
	}
	entries := requests(t, s)
	if len(entries) != 1 {
		t.Fatalf("kept %d", len(entries))
	}
	e := entries[0]
	if e.Target != "https://www.example.com/p/x" || e.Method != "POST" || e.Stream != 5 || e.Conn != 7 ||
		e.Body != "abcd" || e.Priority == nil || *e.Priority != [3]uint32{1, 3, 219} || len(e.Headers) != 5 {
		t.Errorf("kept %+v", e)
	}
	// A request that ends with its headers has no body to wait for, and one
	// without a priority says none.
	s.Reset()
	p.write(frame(http2.FrameHeaders, http2.FlagHeadersEndHeaders|http2.FlagHeadersEndStream, 7,
		block(":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/")))
	if e := requests(t, s)[0]; e.Priority != nil || p.open[7] != nil {
		t.Errorf("kept %+v, open %v", e, p.open)
	}
}

func TestHTTP2ThatCannotBeReadIsTrouble(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		says  string
	}{
		{"padding past the end", frame(http2.FrameHeaders, http2.FlagHeadersPadded|http2.FlagHeadersEndHeaders, 1, []byte{9, 1}),
			"padded past its end on stream 1"},
		{"no padding length", frame(http2.FrameHeaders, http2.FlagHeadersPadded|http2.FlagHeadersEndHeaders, 1, nil),
			"padded past its end"},
		{"no room for a priority", frame(http2.FrameHeaders, http2.FlagHeadersPriority|http2.FlagHeadersEndHeaders, 3, []byte{1, 2}),
			"too short for its priority on stream 3"},
		{"a block that does not decode", frame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 5, []byte{0xff, 0xff, 0xff, 0xff}),
			"the header block of stream 5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := started(t, catalogue)
			p := parser(s)
			p.write([]byte(http2.ClientPreface))
			p.write(tc.frame)
			entries, err := s.Requests()
			if len(entries) != 0 || err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("kept %v, trouble %v", entries, err)
			}
		})
	}
	// Padding a DATA frame says too much of is dropped, not added.
	s := started(t, catalogue)
	p := parser(s)
	p.write([]byte(http2.ClientPreface))
	p.write(frame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 1,
		block(":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/")))
	p.write(frame(http2.FrameData, http2.FlagDataPadded, 1, []byte{5, 'x'}))
	if e := requests(t, s)[0]; e.Body != "" {
		t.Errorf("body %q", e.Body)
	}
}

func TestHTTP11ThatCannotBeReadIsTrouble(t *testing.T) {
	s := started(t, catalogue)
	p := &h1parser{s: s, conn: 1, scheme: "http"}
	// A line that is no request line, then one that is, with a length that is
	// no number and a field that has no colon.
	p.write([]byte("BREW\r\n\r\nGET /x HTTP/1.1\r\nHost: h\r\nContent-Length: many\r\nOdd\r\n\r\n"))
	entries, err := s.Requests()
	if err == nil || !strings.Contains(err.Error(), `a request line that is not one: "BREW"`) {
		t.Errorf("trouble %v", err)
	}
	if len(entries) != 1 || entries[0].Target != "http://h/x" || entries[0].Body != "" ||
		!slices.Equal(entries[0].Headers, [][2]string{{"Host", "h"}, {"Content-Length", "many"}, {"Odd", ""}}) {
		t.Errorf("kept %+v", entries)
	}
}

func TestUnpadded(t *testing.T) {
	for _, tc := range []struct {
		flags   http2.Flags
		payload []byte
		want    []byte
		ok      bool
	}{
		{0, []byte("ab"), []byte("ab"), true},
		{http2.FlagDataPadded, []byte{1, 'a', 'b', 0}, []byte("ab"), true},
		{http2.FlagDataPadded, []byte{0, 'a'}, []byte("a"), true},
		{http2.FlagDataPadded, []byte{3, 'a'}, nil, false},
		{http2.FlagDataPadded, nil, nil, false},
	} {
		got, ok := unpadded(tc.flags, tc.payload)
		if ok != tc.ok || !bytes.Equal(got, tc.want) {
			t.Errorf("unpadded(%v, %v) = %q, %v", tc.flags, tc.payload, got, ok)
		}
	}
}
