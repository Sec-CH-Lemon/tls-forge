package echo

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHTTP1SendsContinueToAClientThatWaitsForIt(t *testing.T) {
	// Sent before the body is read, and only then does the client send it:
	// curl waits a second for it, a stricter client for ever.
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	body := `{"user_agent":"waited"}`
	if _, err := io.WriteString(conn, "POST /collect HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n"+
		"Content-Length: 23\r\n\r\n"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	reader := bufio.NewReader(conn)
	interim := make([]byte, len("HTTP/1.1 100 Continue\r\n\r\n"))
	if _, err := io.ReadFull(reader, interim); err != nil || string(interim) != "HTTP/1.1 100 Continue\r\n\r\n" {
		t.Fatalf("before the body, read %q, %v", interim, err)
	}
	if _, err := io.WriteString(conn, body); err != nil {
		t.Fatalf("writing the body: %v", err)
	}
	if status, err := reader.ReadString('\n'); err != nil || status != "HTTP/1.1 200 OK\r\n" {
		t.Errorf("then read %q, %v", status, err)
	}
}

func TestHTTP1SendsContinueOnlyForABodyItWillRead(t *testing.T) {
	server := startServer(t)
	for _, tc := range []struct {
		name, request string
		continued     bool
		status        string
	}{
		{"a body", "POST /collect HTTP/1.1\r\nExpect: 100-Continue\r\nContent-Length: 2\r\n\r\n{}", true, "200"},
		{"a list with empty members", "POST /collect HTTP/1.1\r\nExpect: , 100-continue ,\r\nContent-Length: 2\r\n\r\n{}",
			true, "200"},
		{"no body", "POST /collect HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n", false, "400"},
		{"a body too large to read", "POST /collect HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 70000\r\n\r\n",
			false, "413"},
		{"HTTP/1.0, which knows no expectations",
			"POST /collect HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}", false, "200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedConn{reader: strings.NewReader(tc.request), writeBudget: 1 << 20}
			_ = server.serveHTTP1(conn, &Session{})
			written := conn.written.String()
			continued := strings.HasPrefix(written, "HTTP/1.1 100 Continue\r\n\r\n")
			final := strings.TrimPrefix(written, "HTTP/1.1 100 Continue\r\n\r\n")
			if continued != tc.continued || !strings.HasPrefix(final, "HTTP/1.1 "+tc.status+" ") {
				t.Errorf("answered %q", written)
			}
		})
	}
}

func TestHTTP1ContinueThatCannotBeWrittenEndsTheConnection(t *testing.T) {
	// The client has gone, which is an ordinary end; its request is neither
	// recorded nor answered, its body never having been read.
	server := startServer(t)
	conn := &scriptedConn{reader: strings.NewReader("POST /collect HTTP/1.1\r\nExpect: 100-continue\r\n" +
		"Content-Length: 2\r\n\r\n{}"), writeBudget: 0}
	session := &Session{}
	if err := server.serveHTTP1(conn, session); err != nil {
		t.Errorf("serveHTTP1 = %v", err)
	}
	if session.http1 != nil || conn.written.Len() != 0 {
		t.Errorf("recorded %+v, answered %q", session.http1, conn.written.String())
	}
}

func TestHTTP1EndsTheConnectionWhenAsked(t *testing.T) {
	// Connection: close, in any case and among other options, on any line;
	// and HTTP/1.0 unless it asks to keep the connection. The request after
	// it is not read.
	server := startServer(t)
	for _, tc := range []struct {
		name, header string
		closes       bool
	}{
		{"close", "GET /api/all HTTP/1.1\r\nConnection: close\r\n", true},
		{"close among other options", "GET /api/all HTTP/1.1\r\nConnection: keep-alive, Close\r\n", true},
		{"close on a line of its own", "GET /api/all HTTP/1.1\r\nConnection: x-other\r\nConnection: close\r\n", true},
		{"HTTP/1.0", "GET /api/all HTTP/1.0\r\n", true},
		{"HTTP/1.0 keeping the connection", "GET /api/all HTTP/1.0\r\nConnection: Keep-Alive\r\n", false},
		{"HTTP/1.1", "GET /api/all HTTP/1.1\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedConn{reader: strings.NewReader(tc.header + "\r\nGET /api/all HTTP/1.1\r\n\r\n"),
				writeBudget: 1 << 20}
			if err := server.serveHTTP1(conn, &Session{}); err != nil {
				t.Fatalf("serveHTTP1 = %v", err)
			}
			written := conn.written.String()
			answers := strings.Count(written, "HTTP/1.1 200 OK\r\n")
			saidClose := strings.Contains(written, "Connection: close\r\n")
			if tc.closes && (answers != 1 || !saidClose) || !tc.closes && (answers != 2 || saidClose) {
				t.Errorf("%d answers, closing %v:\n%s", answers, saidClose, written)
			}
		})
	}
}

func TestUnread(t *testing.T) {
	other := errors.New("no route to host")
	for _, tc := range []struct {
		err     error
		want    error
		written string
	}{
		{refuse("400", "malformed header %q", "x"), refuse("400", "malformed header %q", "x"),
			refused("400", `malformed header "x"`)},
		{io.EOF, nil, ""},
		{net.ErrClosed, nil, ""},
		{other, other, ""},
	} {
		conn := &scriptedConn{writeBudget: 1 << 20}
		got := unread(conn, tc.err)
		if tc.want == nil && got != nil || tc.want != nil && (got == nil || got.Error() != tc.want.Error()) {
			t.Errorf("unread(%v) = %v", tc.err, got)
		}
		if conn.written.String() != tc.written {
			t.Errorf("unread(%v) wrote %q", tc.err, conn.written.String())
		}
	}
}

func TestHTTP1KeepsAValueAsSentButForItsSpaces(t *testing.T) {
	// Spaces and tabs around a value are not part of it (RFC 9112, section
	// 5.1); anything else is, a no-break space at its end among it.
	server := startServer(t)
	session := &Session{}
	conn := &scriptedConn{reader: strings.NewReader("GET / HTTP/1.1\r\nX-A: \t x  \t\r\n\r\n"), writeBudget: 1 << 20}
	if err := server.serveHTTP1(conn, session); err != nil {
		t.Fatalf("serveHTTP1 = %v", err)
	}
	if got := session.http1.Headers[0].Value; got != "x " {
		t.Errorf("recorded %q", got)
	}
}

func TestHTTP1RecordsHowARequestWasWrittenWhereAServerReadsItAlike(t *testing.T) {
	// A browser writes "Name: value" and CRLF, its target a path: its layout
	// is the target's form alone. What a server reads alike and a browser
	// never writes is recorded, so that a comparison can see it.
	for _, tc := range []struct {
		name, request string
		want          []string
	}{
		{"as a browser writes it", "GET /x HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nX-E: \r\n\r\n",
			[]string{"target in origin-form"}},
		{"lines ending in LF alone", "GET / HTTP/1.1\nHost: h\r\nX-A: 1\n\n", []string{"target in origin-form",
			"the request line ends in LF alone", "X-A ends in LF alone", "the blank line ends in LF alone"}},
		{"no space after a colon, two, a tab", "GET / HTTP/1.1\r\nX-A:1\r\nX-B:  2\r\nX-C:\t3\r\n\r\n",
			[]string{"target in origin-form", `X-A: "" after the colon`, `X-B: "  " after the colon`,
				`X-C: "\t" after the colon`}},
		{"spaces after a value", "GET / HTTP/1.1\r\nX-A: 1 \r\nX-B: 2\t\r\n\r\n",
			[]string{"target in origin-form", `X-A: " " after the value`, `X-B: "\t" after the value`}},
		// An empty value's spaces are after its colon, and said once.
		{"an empty value of spaces", "GET / HTTP/1.1\r\nX-A:   \r\nX-B:\r\n\r\n",
			[]string{"target in origin-form", `X-A: "   " after the colon`, `X-B: "" after the colon`}},
		{"a whole URL", "GET http://h/x HTTP/1.1\r\n\r\n", []string{"target in absolute-form"}},
		{"an authority", "CONNECT h:443 HTTP/1.1\r\n\r\n", []string{"target in authority-form"}},
		{"an asterisk", "OPTIONS * HTTP/1.1\r\n\r\n", []string{"target in asterisk-form"}},
		{"after empty lines", "\r\n\nGET / HTTP/1.1\r\n\r\n", []string{"target in origin-form"}},
	} {
		req, err := readHTTP1Request(bufio.NewReader(strings.NewReader(tc.request)), io.Discard)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !slices.Equal(req.Layout, tc.want) {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, req.Layout, tc.want)
		}
	}
}
