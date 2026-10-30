package proxy

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type a11ReadFailure struct{ err error }

func (r a11ReadFailure) Read([]byte) (int, error) { return 0, r.err }

type a11FinalRead struct{ input string }

func (r *a11FinalRead) Read(p []byte) (int, error) {
	n := copy(p, r.input)
	r.input = r.input[n:]
	return n, os.ErrDeadlineExceeded
}

func TestA11HeaderReadKeepsItsActualTimeout(t *testing.T) {
	for _, input := range []string{
		"GET http://example.test/ HTTP/1.1\r\nxxxxxxxxxxxxxx",
		"GET http://example.test/ HTTP/1.1\r\nX-Test: unfinished",
		"GET http://example.test/ HTTP/1.1",
	} {
		t.Run(input, func(t *testing.T) {
			server, problems := newTestServer(t, &counting{})
			// Read deadlines can be observed before a separately sampled clock says
			// that the time passed. The I/O error, not that sample, owns this cause.
			server.budget.header = time.Hour
			conn := &scriptedConn{reader: io.MultiReader(strings.NewReader(input), a11ReadFailure{os.ErrDeadlineExceeded})}
			_, err := server.requestsOn(conn).next()
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("actual read timeout lost: %v", err)
			}
			server.unread(conn, err, "")
			if got := problems.list(); len(got) != 0 {
				t.Fatalf("timeout reported as parse failure: %v", got)
			}
		})
	}
}

func TestA11HeaderReadStillReportsMalformedInput(t *testing.T) {
	for _, tail := range []error{io.EOF, errors.New("independent read failure")} {
		t.Run(tail.Error(), func(t *testing.T) {
			server, problems := newTestServer(t, &counting{})
			conn := &scriptedConn{reader: io.MultiReader(strings.NewReader("GET http://example.test/ HTTP/1.1\r\nmissing-colon"), a11ReadFailure{tail})}
			_, err := server.requestsOn(conn).next()
			if err == nil || isClosed(err) || !strings.Contains(err.Error(), "missing colon") {
				t.Fatalf("malformed input lost its diagnosis: %v", err)
			}
			server.unread(conn, err, "")
			if got := problems.list(); len(got) != 1 {
				t.Fatalf("malformed input was not reported once: %v", got)
			}
		})
	}
}

func TestA11HeaderReadDoesNotReuseAnEarlierTimeout(t *testing.T) {
	server, _ := newTestServer(t, &counting{})
	// A buffered complete request remains valid even if the underlying read
	// returned a timeout with those bytes. A later parse failure is its own.
	input := "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n" +
		"GET http://example.test/ HTTP/1.1\r\nmissing-colon\r\n\r\n"
	conn := &scriptedConn{reader: &a11FinalRead{input: input}}
	requests := server.requestsOn(conn)
	if req, err := requests.next(); req == nil || err != nil {
		t.Fatalf("complete header refused: %v, %v", req, err)
	}
	if _, err := requests.next(); err == nil || isClosed(err) || !strings.Contains(err.Error(), "missing colon") {
		t.Fatalf("earlier timeout hid this malformed input: %v", err)
	}
}
