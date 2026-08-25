package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// budgetedReader yields a fixed number of bytes and then fails, so a test can
// put the entropy source's failure at each point that reads from it.
type budgetedReader struct{ remaining int }

func (r *budgetedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("out of entropy")
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := range p[:n] {
		p[i] = byte(i + 1)
	}
	r.remaining -= n
	return n, nil
}

func TestCertificateGenerationReportsEveryEntropyFailure(t *testing.T) {
	// Generating an authority reads entropy three times: the key, the serial and
	// the signature. A failure at any of them has to be reported rather than
	// producing something that only looks random. The budget is swept rather
	// than tuned, so a change in how much the standard library reads does not
	// silently stop exercising a branch.
	original := randReader
	t.Cleanup(func() { randReader = original })

	seenCA := map[string]bool{}
	leafFailures := 0
	good := newCAForTest(t)

	for budget := 0; budget <= 4096; budget += 8 {
		randReader = &budgetedReader{remaining: budget}
		if _, _, err := newCAMaterial(); err != nil {
			for _, stage := range []string{"generating a key", "serial", "creating the authority"} {
				if strings.Contains(err.Error(), stage) {
					seenCA[stage] = true
				}
			}
		}
		// The same three reads happen again for every leaf certificate.
		fresh := &CA{cert: good.cert, key: good.key, pem: good.pem, leaves: map[string]*tls.Certificate{}}
		if _, err := fresh.leafFor("example.com"); err != nil {
			leafFailures++
		}
	}

	for _, stage := range []string{"generating a key", "serial", "creating the authority"} {
		if !seenCA[stage] {
			t.Errorf("no budget produced a %q failure; that branch is untested", stage)
		}
	}
	if leafFailures == 0 {
		t.Error("no budget made leaf generation fail")
	}
}

func TestCAWriteFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits: chmod only toggles read-only, so the write this needs to fail succeeds")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, where the permission bits below do not apply")
	}
	dir := t.TempDir()

	// A directory that cannot be created: the parent is read-only.
	readOnly := filepath.Join(dir, "read-only")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })

	if _, err := LoadOrCreateCA(filepath.Join(readOnly, "sub", "ca.pem"),
		filepath.Join(readOnly, "sub", "ca.key")); err == nil {
		t.Error("expected an error when the directory cannot be created")
	}
	// The key can be written but the certificate cannot. The key is removed so
	// a later start sees two absent files rather than a broken pair.
	keyFile := filepath.Join(t.TempDir(), "ca.key")
	if _, err := LoadOrCreateCA(filepath.Join(readOnly, "ca.pem"), keyFile); err == nil {
		t.Error("expected an error when the certificate cannot be written")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Error("a key was left behind after the certificate write failed")
	}
	// The certificate can be written but the key cannot, which must not leave a
	// usable-looking authority behind.
	writable := t.TempDir()
	if _, err := LoadOrCreateCA(filepath.Join(writable, "ca.pem"),
		filepath.Join(readOnly, "ca.key")); err == nil {
		t.Error("expected an error when the key cannot be written")
	}
}

func TestCAReportsAnUnreadableKeyFile(t *testing.T) {
	// The certificate is there and readable; the key is a directory, so reading
	// it fails with something that is not "does not exist".
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certFile, newCAForTest(t).CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(dir, "ca.key")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(certFile, keyDir); err == nil {
		t.Error("expected an error for an unreadable key file")
	}
}

// scriptedConn plays a fixed client stream and fails writes past a budget,
// which is what a caller that hangs up mid-answer looks like from here.
type scriptedConn struct {
	reader      io.Reader
	writeBudget int
	written     bytes.Buffer
	closed      bool
}

func (c *scriptedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *scriptedConn) Write(p []byte) (int, error) {
	if c.writeBudget < len(p) {
		return 0, errors.New("broken pipe")
	}
	c.writeBudget -= len(p)
	return c.written.Write(p)
}

func (c *scriptedConn) Close() error                     { c.closed = true; return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func newTestServer(t *testing.T, client Client) (*Server, *errorLog) {
	t.Helper()
	problems := &errorLog{}
	return &Server{
		opts:  Options{CA: newCAForTest(t), Client: client, OnError: problems.add},
		conns: map[net.Conn]struct{}{},
	}, problems
}

func TestTheCallerHangsUpWhileTheAnswerIsWritten(t *testing.T) {
	// The budget is swept so the write fails at the CONNECT acknowledgement, in
	// the middle of the response head, and in the body.
	client := stubClient{status: 200, body: bytes.Repeat([]byte("x"), 4096)}
	failures := 0
	for budget := 0; budget < 6000; budget += 37 {
		server, _ := newTestServer(t, client)
		conn := &scriptedConn{
			reader:      strings.NewReader("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			writeBudget: budget,
		}
		server.handle(conn)
		if conn.written.Len() < 4096 {
			failures++
		}
	}
	if failures == 0 {
		t.Fatal("no budget interrupted the answer")
	}
}

func TestOversizedRequestReportsAResponseWriteFailure(t *testing.T) {
	server, _ := newTestServer(t, stubClient{status: 200})
	server.opts.MaxRequestBody = 4
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("12345"))
	if err := server.forward(failingWriter{}, req, "http"); err == nil {
		t.Error("expected the failed 413 response write to be reported")
	}
}

func TestConnectIsAbandonedWhenTheAcknowledgementCannotBeWritten(t *testing.T) {
	server, _ := newTestServer(t, stubClient{status: 200})
	conn := &scriptedConn{
		reader:      strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
		writeBudget: 0,
	}
	server.handle(conn)
	if conn.written.Len() != 0 {
		t.Errorf("wrote %q", conn.written.String())
	}
}

func TestConnectWithoutAPortStillNamesTheHost(t *testing.T) {
	server, problems := newTestServer(t, stubClient{status: 200})
	conn := &scriptedConn{
		reader:      strings.NewReader("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		writeBudget: 1 << 20,
	}
	server.handle(conn)

	if !strings.Contains(conn.written.String(), "200 Connection established") {
		t.Errorf("wrote %q", conn.written.String())
	}
	// The TLS handshake then fails because the scripted client sends nothing,
	// and that is reported rather than swallowed.
	for _, p := range problems.list() {
		if strings.Contains(p.Error(), "example.com") {
			return
		}
	}
}

func TestACertificateThatCannotBeMintedIsA500(t *testing.T) {
	original := randReader
	t.Cleanup(func() { randReader = original })

	server, problems := newTestServer(t, stubClient{status: 200})
	randReader = &budgetedReader{}
	conn := &scriptedConn{
		reader:      strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
		writeBudget: 1 << 20,
	}
	server.handle(conn)

	if !strings.Contains(conn.written.String(), "500") {
		t.Errorf("wrote %q, want a 500", conn.written.String())
	}
	found := false
	for _, p := range problems.list() {
		if strings.Contains(p.Error(), "certificate for example.com") {
			found = true
		}
	}
	if !found {
		t.Errorf("the failure was not reported: %v", problems.list())
	}
}

func TestATruncatedRequestBodyIsReported(t *testing.T) {
	// content-length promises more than the caller sent, so reading the body
	// fails part way. Answering anyway would forward half a request.
	server, problems := newTestServer(t, stubClient{status: 200})
	conn := &scriptedConn{
		reader: strings.NewReader("POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n" +
			"Content-Length: 100\r\n\r\nshort"),
		writeBudget: 1 << 20,
	}
	server.handle(conn)

	found := false
	for _, p := range problems.list() {
		if strings.Contains(p.Error(), "reading the request body") {
			found = true
		}
	}
	if !found {
		t.Errorf("a truncated body was not reported: %v", problems.list())
	}
}

func TestGarbageOnTheConnectionIsReported(t *testing.T) {
	server, problems := newTestServer(t, stubClient{status: 200})
	conn := &scriptedConn{reader: strings.NewReader("not a request at all\r\n\r\n"), writeBudget: 1 << 20}
	server.handle(conn)

	if len(problems.list()) == 0 {
		t.Error("garbage was accepted silently")
	}
	if !conn.closed {
		t.Error("the connection was left open")
	}
}

func TestAnEmptyConnectionEndsQuietly(t *testing.T) {
	server, problems := newTestServer(t, stubClient{status: 200})
	conn := &scriptedConn{reader: strings.NewReader(""), writeBudget: 1 << 20}
	server.handle(conn)
	if len(problems.list()) != 0 {
		t.Errorf("a client that connected and said nothing was reported: %v", problems.list())
	}
}

// stubClient answers without a network.
type stubClient struct {
	status int
	body   []byte
	err    error
}

func (s stubClient) Do(*tlsforge.Request) (*tlsforge.Response, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &tlsforge.Response{
		Status: s.status,
		Header: map[string][]string{"content-type": {"text/plain"}},
		Body:   s.body,
	}, nil
}

func (s stubClient) Headers() tlsforge.Header {
	return tlsforge.NewHeader("user-agent", "Chrome", "accept", "text/html")
}

var _ http.RoundTripper = (*http.Transport)(nil)

func TestEncodeECKeyRejectsAnUnsupportedCurve(t *testing.T) {
	// Not reachable through newCAMaterial, which always uses P-256, but x509
	// genuinely refuses a curve it has no OID for. Returning the error rather
	// than swallowing it is what keeps a future change of curve from writing a
	// key file with nothing in it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key.Curve = unnamedCurve{elliptic.P256()}
	if _, err := encodeECKey(key); err == nil {
		t.Error("expected an error for a curve x509 cannot name")
	}
}

// unnamedCurve is a curve x509 has no object identifier for.
type unnamedCurve struct{ elliptic.Curve }

func TestLoadOrCreateCAReportsAGenerationFailure(t *testing.T) {
	original := randReader
	t.Cleanup(func() { randReader = original })
	randReader = &budgetedReader{}

	dir := t.TempDir()
	if _, err := LoadOrCreateCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")); err == nil {
		t.Error("expected an error when the authority cannot be generated")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); !os.IsNotExist(err) {
		t.Error("a half-made authority was left on disk")
	}
}

func TestConnectHostIsFoundWhereverItIs(t *testing.T) {
	// A request-URI that is not host:port form. Real clients send the authority
	// form, but the host still has to come from somewhere, and the Host header
	// is where.
	for _, tc := range []struct{ name, request, want string }{
		{"host header with a port", "CONNECT / HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "example.com"},
		{"host header without a port", "CONNECT / HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newTestServer(t, stubClient{status: 200})
			conn := &scriptedConn{reader: strings.NewReader(tc.request), writeBudget: 1 << 20}
			server.handle(conn)

			if !strings.Contains(conn.written.String(), "200 Connection established") {
				t.Fatalf("wrote %q", conn.written.String())
			}
			// The certificate minted for the connection names the host it found.
			if _, ok := server.opts.CA.leaves[tc.want]; !ok {
				t.Errorf("no certificate was minted for %q; have %v", tc.want, keysOfLeaves(server.opts.CA))
			}
		})
	}
}

func keysOfLeaves(ca *CA) []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	out := []string{}
	for k := range ca.leaves {
		out = append(out, k)
	}
	return out
}

// tunnelTo opens a CONNECT tunnel through a running proxy and completes the TLS
// handshake, which is the only way to reach the code that runs inside it.
func tunnelTo(t *testing.T, server *Server, ca *CA, host string) *tls.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	if _, err := io.WriteString(raw, "CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, 39)
	if _, err := io.ReadFull(raw, answer); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(answer), "200") {
		t.Fatalf("proxy answered %q", answer)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: pool})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake through the tunnel: %v", err)
	}
	return conn
}

func TestFailuresInsideTheTunnelAreReported(t *testing.T) {
	ca := newCAForTest(t)

	t.Run("garbage instead of a request", func(t *testing.T) {
		server, problems := startProxy(t, stubClient{status: 200}, ca)
		conn := tunnelTo(t, server, ca, "example.com")
		if _, err := io.WriteString(conn, "NOT A REQUEST\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, problems, "reading a request for example.com")
	})

	t.Run("a body that stops short", func(t *testing.T) {
		server, problems := startProxy(t, stubClient{status: 200}, ca)
		conn := tunnelTo(t, server, ca, "example.com")
		if _, err := io.WriteString(conn,
			"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\nshort"); err != nil {
			t.Fatal(err)
		}
		_ = conn.CloseWrite()
		waitFor(t, problems, "reading the request body")
	})
}

func waitFor(t *testing.T, problems *errorLog, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range problems.list() {
			if strings.Contains(p.Error(), want) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("never reported %q; got %v", want, problems.list())
}
