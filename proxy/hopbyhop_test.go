package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v6"
)

// answering is a client that keeps what each request said, and answers each
// path as the test tells it to.
type answering struct {
	mu      sync.Mutex
	asked   []*tlsforge.Request
	answers map[string]*tlsforge.Response
}

func (a *answering) Do(req *tlsforge.Request) (*tlsforge.Response, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, req)
	path := req.URL[strings.Index(req.URL[len("http://"):], "/")+len("http://"):]
	if answer, ok := a.answers[path]; ok {
		return answer, nil
	}
	return &tlsforge.Response{Status: 200, Header: map[string][]string{}, Body: []byte("page")}, nil
}

func (a *answering) Headers() tlsforge.Header { return tlsforge.NewHeader("user-agent", "Chrome") }

func (a *answering) requests() []*tlsforge.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.asked)
}

// through sends what is written to the proxy on one connection, and is how to
// read what comes back.
func through(t *testing.T, server *Server, written string) (*bufio.Reader, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, written); err != nil {
		t.Fatalf("writing: %v", err)
	}
	return bufio.NewReader(conn), conn
}

// headLines are the header lines of the next answer on a connection, as they
// were written, and its status line.
func headLines(t *testing.T, r *bufio.Reader) (string, []string) {
	t.Helper()
	status, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the status line: %v", err)
	}
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the header: %v", err)
		}
		if line == "\r\n" {
			return strings.TrimSpace(status), lines
		}
		lines = append(lines, strings.TrimSpace(line))
	}
}

func TestTheFieldsAConnectionNamesGoNoFurther(t *testing.T) {
	// On however many lines, in any case and with any spaces; and the
	// standard ones, an Upgrade that is not asked for included.
	client := &answering{}
	server, problems := startProxy(t, client, newCAForTest(t))
	r, _ := through(t, server, "GET http://example.test/ HTTP/1.1\r\n"+
		"Host: example.test\r\n"+
		"Connection: X-Hop, keep-alive\r\n"+
		"connection:  x-OTHER ,  \r\n"+
		"X-Hop: 1\r\nX-Other: 2\r\nX-Keep: 3\r\n"+
		"TE: trailers\r\nTrailer: X-T\r\nUpgrade: something\r\nKeep-Alive: timeout=5\r\n"+
		"Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic eDp5\r\n\r\n")
	if status, _ := headLines(t, r); status != "HTTP/1.1 200 OK" {
		t.Fatalf("answered %q", status)
	}
	asked := client.requests()
	if len(asked) != 1 {
		t.Fatalf("%d requests went on", len(asked))
	}
	var names []string
	for _, field := range asked[0].Header {
		names = append(names, field.Name)
	}
	if !slices.Equal(names, []string{"user-agent", "x-keep"}) {
		t.Errorf("the request went on with %v", names)
	}
	if got := problems.list(); len(got) != 0 {
		t.Errorf("reported %v", got)
	}
}

func TestTheFieldsAnAnswerSaysAreItsConnectionsGoNoFurther(t *testing.T) {
	// In the order of their names, so that two answers alike are written
	// alike, and with the length of what is sent.
	client := &answering{answers: map[string]*tlsforge.Response{"/": {Status: 200, Body: []byte("hello"),
		Header: map[string][]string{
			"Connection": {"X-Internal, close"}, "x-internal": {"secret"}, "Keep-Alive": {"timeout=5"},
			"Trailer": {"X-T"}, "Transfer-Encoding": {"chunked"}, "Upgrade": {"h2c"}, "TE": {"trailers"},
			"Proxy-Connection": {"keep-alive"}, "X-Keep": {"1"}, "Content-Length": {"999"}, "a-first": {"0"},
			"b-second": {"2"}, "c-third": {"3"}, "d-fourth": {"4"}, "z-last": {"9"},
		}}}}
	server, _ := startProxy(t, client, newCAForTest(t))
	r, _ := through(t, server, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"+
		"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
	for range 2 {
		status, lines := headLines(t, r)
		if status != "HTTP/1.1 200 OK" || !slices.Equal(lines, []string{"X-Keep: 1", "a-first: 0", "b-second: 2",
			"c-third: 3", "d-fourth: 4", "z-last: 9", "content-length: 5"}) {
			t.Errorf("answered %q with %q", status, lines)
		}
		if body := make([]byte, 5); func() bool { _, err := io.ReadFull(r, body); return err != nil || string(body) != "hello" }() {
			t.Error("the body is not what was answered")
		}
	}
}

func TestAnAnswerIsFramedAsItsRequestAndStatusCall(t *testing.T) {
	// A HEAD keeps the length a GET would have had and sends no body; a 204
	// and a 304 send neither. What follows on the connection is read as the
	// next answer, which a stray body or length would have spoiled.
	client := &answering{answers: map[string]*tlsforge.Response{
		"/head":         {Status: 200, Header: map[string][]string{"Content-Length": {"1234"}}},
		"/head-no-size": {Status: 200, Header: map[string][]string{}},
		"/none":         {Status: 204, Header: map[string][]string{"Content-Length": {"0"}}, Body: []byte("stray")},
		"/same":         {Status: 304, Header: map[string][]string{"Content-Length": {"77"}, "Etag": {`"v1"`}}},
	}}
	server, _ := startProxy(t, client, newCAForTest(t))
	r, _ := through(t, server, strings.Join([]string{
		"HEAD http://example.test/head HTTP/1.1\r\nHost: example.test\r\n\r\n",
		"HEAD http://example.test/head-no-size HTTP/1.1\r\nHost: example.test\r\n\r\n",
		"GET http://example.test/none HTTP/1.1\r\nHost: example.test\r\n\r\n",
		"GET http://example.test/same HTTP/1.1\r\nHost: example.test\r\n\r\n",
		"GET http://example.test/last HTTP/1.1\r\nHost: example.test\r\n\r\n",
	}, ""))
	for _, want := range []struct {
		status string
		lines  []string
	}{
		{"HTTP/1.1 200 OK", []string{"content-length: 1234"}},
		{"HTTP/1.1 200 OK", nil},
		{"HTTP/1.1 204 No Content", nil},
		{"HTTP/1.1 304 Not Modified", []string{`Etag: "v1"`}},
		{"HTTP/1.1 200 OK", []string{"content-length: 4"}},
	} {
		status, lines := headLines(t, r)
		if status != want.status || !slices.Equal(lines, want.lines) {
			t.Errorf("answered %q with %q, want %q with %q", status, lines, want.status, want.lines)
		}
	}
	if body, _ := r.Peek(4); string(body) != "page" {
		t.Errorf("the last answer's body is %q", body)
	}
}

func TestAnUpgradeIsRefusedNotSentOnAsARequest(t *testing.T) {
	// Asked for with Connection: upgrade, a WebSocket among them: a protocol
	// this proxy does not speak, refused and the connection ended, and nobody
	// asked anything or told of a problem.
	client := &answering{}
	server, problems := startProxy(t, client, newCAForTest(t))
	r, _ := through(t, server, "GET http://example.test/socket HTTP/1.1\r\nHost: example.test\r\n"+
		"Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n")
	res, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusNotImplemented || string(body) != "this proxy does not pass on an upgrade to another protocol\n" {
		t.Errorf("answered %d: %q", res.StatusCode, body)
	}
	if rest, err := io.ReadAll(r); err != nil || len(rest) != 0 {
		t.Errorf("the connection went on: %q, %v", rest, err)
	}
	if got := client.requests(); len(got) != 0 {
		t.Errorf("%d requests went on", len(got))
	}
	if got := problems.list(); len(got) != 0 {
		t.Errorf("reported %v", got)
	}
}

func TestConnectionOptions(t *testing.T) {
	got := connectionOptions(map[string][]string{
		"Connection": {"X-A, ,keep-alive", " x-B "}, "connection": {"X-C"}, "X-A": {"1"},
	})
	for _, name := range append(slices.Clone(hopByHop), "x-a", "x-b", "x-c") {
		if !got[name] {
			t.Errorf("%s is not taken for the connection's", name)
		}
	}
	if got[""] || got["x-d"] {
		t.Errorf("connectionOptions = %v", got)
	}
}

func TestAnUpgradeRefusalThatCannotBeWrittenIsSaid(t *testing.T) {
	server, _ := newTestServer(t, &answering{})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/socket", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if err := server.forward(failingWriter{}, req, "http"); err == nil || errors.Is(err, errUpgradeRefused) {
		t.Errorf("forward() = %v, want the failed write", err)
	}
}
