package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v6"
	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
)

// fakeClient records what it was asked for and answers with whatever it was
// told to. The daemon's job is protocol handling, so the transport underneath
// it is exactly the part these tests should not involve.
type fakeClient struct {
	got      *tlsforge.Request
	response *tlsforge.Response
	err      error
	headers  tlsforge.Header
}

func (f *fakeClient) Do(req *tlsforge.Request) (*tlsforge.Response, error) {
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	if f.response != nil {
		return f.response, nil
	}
	return &tlsforge.Response{Status: 200, URL: req.URL, Body: []byte("hello")}, nil
}

func (f *fakeClient) Headers() tlsforge.Header { return f.headers }

func TestAnAnswerWithoutCookiesSaysSoWithAnEmptyList(t *testing.T) {
	// Null is a failure's way of having nothing to report. An answer from a
	// session whose jar holds nothing says [], as the protocol document shows.
	for _, tc := range []struct {
		name   string
		client *fakeClient
		want   string
	}{
		{"an answer", &fakeClient{}, `"cookies":[]`},
		{"a failure", &fakeClient{err: errors.New("refused")}, `"cookies":null`},
	} {
		var out strings.Builder
		if err := Serve(strings.NewReader(`{"engine_major":6,"id":1,"url":"https://example.com/"}`+"\n"), &out, tc.client); err != nil {
			t.Fatalf("%s: Serve: %v", tc.name, err)
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("%s: wrote %s, want %s", tc.name, out.String(), tc.want)
		}
	}
}

func serve(t *testing.T, client Client, lines ...string) []Response {
	t.Helper()
	var out strings.Builder
	if err := Serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, client); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var responses []Response
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var response Response
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatalf("response %q: %v", line, err)
		}
		responses = append(responses, response)
	}
	return responses
}

func TestServeAnswersARequest(t *testing.T) {
	client := &fakeClient{response: &tlsforge.Response{
		Status:  200,
		URL:     "https://example.com/after-redirect",
		Body:    []byte("<html>"),
		Header:  map[string][]string{"set-cookie": {"a=1", "b=2"}},
		Cookies: []string{"a=1"},
	}}

	responses := serve(t, client, `{"engine_major":6,"id":7,"url":"https://example.com"}`)
	if len(responses) != 1 {
		t.Fatalf("got %d responses, want 1", len(responses))
	}
	got := responses[0]

	if got.ID != 7 {
		t.Errorf("id = %d, want 7", got.ID)
	}
	if got.Status != 200 || got.Body != "<html>" {
		t.Errorf("response = %+v", got)
	}
	if got.URL != "https://example.com/after-redirect" {
		t.Errorf("url = %q, want the post-redirect one", got.URL)
	}
	// Values stay separate: commas and semicolons are data in several headers,
	// and Set-Cookie specifically must never be folded into one field value.
	if want := []string{"a=1", "b=2"}; !reflect.DeepEqual(got.Headers["set-cookie"], want) {
		t.Errorf("set-cookie = %q, want %q", got.Headers["set-cookie"], want)
	}
}

func TestEveryResponseCarriesItsID(t *testing.T) {
	// The whole reason the protocol has ids: an answer that cannot be attributed
	// can be mistaken for the next request's, and the result is one page filed
	// under another page's request — well-formed, plausible and wrong. That has
	// to hold on the error paths too, which is where it is easiest to lose.
	client := &fakeClient{err: errors.New("connection refused")}

	for _, line := range []string{
		`{"engine_major":6,"id":11,"url":"https://example.com"}`,
		`{"engine_major":6,"id":12,"url":""}`,
		`{"engine_major":6,"id":13,"url":5}`,
	} {
		responses := serve(t, client, line)
		if len(responses) != 1 {
			t.Fatalf("%s: got %d responses", line, len(responses))
		}
		if responses[0].ID == 0 {
			t.Errorf("%s: response lost its id: %+v", line, responses[0])
		}
		if responses[0].Error == "" {
			t.Errorf("%s: expected an error", line)
		}
	}
}

func TestSyntacticallyBrokenJSONIsReported(t *testing.T) {
	// A genuine syntax error leaves the id at 0, and the caller lets that request
	// time out — the safe way to lose one.
	responses := serve(t, &fakeClient{}, `{"engine_major":6,"id":9,`)
	if len(responses) != 1 || responses[0].Error == "" {
		t.Fatalf("responses = %+v", responses)
	}
	if !strings.Contains(responses[0].Error, "bad request") {
		t.Errorf("error = %q", responses[0].Error)
	}
}

func TestBlankLinesAreIgnored(t *testing.T) {
	responses := serve(t, &fakeClient{}, "", "   ", `{"engine_major":6,"id":1,"url":"https://example.com"}`, "")
	if len(responses) != 1 {
		t.Fatalf("got %d responses, want 1", len(responses))
	}
}

func TestRequestFieldsReachTheClient(t *testing.T) {
	client := &fakeClient{}
	serve(t, client, `{"engine_major":6,"id":1,"method":"POST","url":"https://example.com","body":"a=1",`+
		`"headers":{"Referer":"https://x"},"order":["referer"],"setCookie":["s=1"]}`)

	if client.got.Method != "POST" {
		t.Errorf("method = %q", client.got.Method)
	}
	if string(client.got.Body) != "a=1" {
		t.Errorf("body = %q", client.got.Body)
	}
	if got, want := client.got.Header.Get("referer"), "https://x"; got != want {
		t.Errorf("referer = %q, want %q", got, want)
	}
	if want := []tlsforge.Cookie{{Name: "s", Value: "1"}}; !reflect.DeepEqual(client.got.Cookies, want) {
		t.Errorf("cookies = %+v, want %+v", client.got.Cookies, want)
	}
}

func TestMalformedCookiesFailOnlyTheirRequest(t *testing.T) {
	client := &fakeClient{}
	responses := serve(t, client,
		`{"engine_major":6,"id":1,"url":"https://example.com","setCookie":["malformed"]}`,
		`{"engine_major":6,"id":2,"url":"https://example.com","setCookie":["=empty-name"]}`,
		`{"engine_major":6,"id":3,"url":"https://example.com","setCookie":["valid=1"]}`,
	)
	if len(responses) != 3 {
		t.Fatalf("responses = %+v", responses)
	}
	for i := range 2 {
		if responses[i].Error == "" || responses[i].ID != uint64(i+1) {
			t.Errorf("response %d = %+v", i, responses[i])
		}
	}
	if responses[2].Error != "" || responses[2].Status != 200 {
		t.Errorf("valid request after errors = %+v", responses[2])
	}
}

func TestAnAnswerSaysNoPasswordOfAnyURL(t *testing.T) {
	// The answer goes to another process, which may log it: neither what the
	// client said of a proxy nor a request's own URL that would not parse
	// carries a password across.
	client := &fakeClient{err: errors.New(`tlsforge: parse "http://alice:s3cr3t@[bad": missing ']' in host`)}
	responses := serve(t, client, `{"engine_major":6,"id":1,"url":"https://example.com"}`)
	if len(responses) != 1 || responses[0].Error != `tlsforge: parse "http://alice@[bad": missing ']' in host` {
		t.Errorf("responses = %+v", responses)
	}
	// A bad request is said with what was wrong with it, quoted.
	responses = serve(t, &fakeClient{}, `{"engine_major":6,"id":2,"url":"https://example.com","setCookie":["http://bob:s3cr3t@x"]}`)
	if len(responses) != 1 ||
		responses[0].Error != `bad request: cookie: expected name=value, got "http://bob@x"` {
		t.Errorf("responses = %+v", responses)
	}
}

func TestHeadersWithDuplicateCasingAreRejectedDeterministically(t *testing.T) {
	client := &fakeClient{}
	responses := serve(t, client,
		`{"engine_major":6,"id":7,"url":"https://example.com","headers":{"User-Agent":"one","user-agent":"two"}}`)
	if len(responses) != 1 || responses[0].ID != 7 ||
		!strings.Contains(responses[0].Error, "repeated with different casing") {
		t.Fatalf("responses = %+v", responses)
	}
	if client.got != nil {
		t.Errorf("ambiguous headers reached the client: %+v", client.got.Header)
	}
}

func TestExplicitOrderWins(t *testing.T) {
	client := &fakeClient{headers: tlsforge.NewHeader("accept", "*/*", "user-agent", "profile")}
	serve(t, client, `{"engine_major":6,"id":1,"url":"https://example.com",`+
		`"headers":{"user-agent":"mine","accept":"text/html"},"order":["user-agent","accept"]}`)

	if got, want := client.got.Header.Names(), []string{"user-agent", "accept"}; !reflect.DeepEqual(got, want) {
		t.Errorf("header order = %v, want %v", got, want)
	}
}

func TestWithoutAnOrderTheProfilesOrderIsUsed(t *testing.T) {
	// JSON objects have no order, so a caller who says nothing should still get
	// the browser's ordering rather than Go's map iteration order.
	client := &fakeClient{headers: tlsforge.NewHeader(
		"sec-ch-ua", "", "user-agent", "", "accept", "", "accept-language", "")}
	serve(t, client, `{"engine_major":6,"id":1,"url":"https://example.com","headers":`+
		`{"accept":"text/html","user-agent":"mine","sec-ch-ua":"x"}}`)

	if got, want := client.got.Header.Names(), []string{"sec-ch-ua", "user-agent", "accept"}; !reflect.DeepEqual(got, want) {
		t.Errorf("header order = %v, want %v", got, want)
	}
}

func TestHeadersOutsideTheOrderGoLastAndAreStable(t *testing.T) {
	// Stable because Go iterates a map randomly, and a header set that reordered
	// itself between two otherwise identical requests would be a fingerprint of
	// its own.
	client := &fakeClient{headers: tlsforge.NewHeader("accept", "")}
	line := `{"engine_major":6,"id":1,"url":"https://example.com","headers":` +
		`{"accept":"text/html","zeta":"1","alpha":"2","mu":"3"},"order":["accept"]}`

	var first []string
	for i := 0; i < 8; i++ {
		serve(t, client, line)
		names := client.got.Header.Names()
		if first == nil {
			first = names
			continue
		}
		if !reflect.DeepEqual(names, first) {
			t.Fatalf("header order varied between runs: %v then %v", first, names)
		}
	}
	if want := []string{"accept", "alpha", "mu", "zeta"}; !reflect.DeepEqual(first, want) {
		t.Errorf("header order = %v, want %v", first, want)
	}
}

func TestNoHeadersMeansTheProfilesOwn(t *testing.T) {
	client := &fakeClient{headers: tlsforge.NewHeader("accept", "*/*")}
	serve(t, client, `{"engine_major":6,"id":1,"url":"https://example.com"}`)
	if client.got.Header != nil {
		t.Errorf("header = %v, want nil so the client applies the profile's", client.got.Header)
	}
}

func TestServeReportsAWriteFailure(t *testing.T) {
	// A broken stdout is the one failure the daemon cannot answer with a
	// response, so it has to stop rather than spin.
	err := Serve(strings.NewReader(`{"engine_major":6,"id":1,"url":"https://example.com"}`+"\n"),
		failingWriter{}, &fakeClient{})
	if err == nil || !strings.Contains(err.Error(), "writing response") {
		t.Fatalf("error = %v, want a write failure", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestServeReportsAnUnreadableLine(t *testing.T) {
	// Longer than the scanner's buffer: the input is not a protocol this daemon
	// can resynchronise with, so it stops.
	huge := strings.Repeat("x", maxLineBuffer+1)
	var out strings.Builder
	err := Serve(strings.NewReader(huge), &out, &fakeClient{})
	if err == nil {
		t.Fatal("expected an error for an oversized line")
	}
}

func TestALineIsReadUpToItsLimitItsNewlineIncluded(t *testing.T) {
	// The Node.js and Python packages refuse a request longer than this before
	// they send it, so the two have to agree to the byte.
	line := func(size int) string {
		head, tail := `{"engine_major":6,"id":1,"url":"https://example.com","body":"`, `"}`+"\n"
		return head + strings.Repeat("x", size-len(head)-len(tail)) + tail
	}
	for _, tc := range []struct {
		size int
		read bool
	}{{maxLineBuffer - 1, true}, {maxLineBuffer, true}, {maxLineBuffer + 1, false}} {
		var out strings.Builder
		err := Serve(strings.NewReader(line(tc.size)), &out, &fakeClient{})
		switch {
		case tc.read && (err != nil || !strings.Contains(out.String(), `"status":200`)):
			t.Errorf("a line of %d bytes: %v, %q", tc.size, err, out.String())
		case !tc.read && (err == nil || !errors.Is(err, bufio.ErrTooLong) || out.Len() != 0 ||
			!strings.Contains(err.Error(), "longer than 16777216 bytes, its newline included")):
			t.Errorf("a line of %d bytes: %v, %q", tc.size, err, out.String())
		}
	}
}

func TestServeSaysWhyItCouldNotReadItsInput(t *testing.T) {
	// The pipe the requests come down, failing: said as what it is, and
	// underneath for errors.Is.
	broken := errors.New("input/output error")
	var out strings.Builder
	err := Serve(iotest.ErrReader(broken), &out, &fakeClient{})
	if !errors.Is(err, broken) || err.Error() != "daemon: reading requests: input/output error" {
		t.Errorf("Serve() = %v", err)
	}
}

func TestServeRejectsMissingDependencies(t *testing.T) {
	for _, test := range []struct {
		name   string
		in     io.Reader
		out    io.Writer
		client Client
		want   string
	}{
		{name: "input", out: io.Discard, client: &fakeClient{}, want: "nil input"},
		{name: "output", in: strings.NewReader(""), client: &fakeClient{}, want: "nil output"},
		{name: "client", in: strings.NewReader(""), out: io.Discard, want: "nil client"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := Serve(test.in, test.out, test.client)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSortedKeys(t *testing.T) {
	got := sortedKeys(map[string]string{"b": "", "a": "", "c": ""})
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sortedKeys = %v, want %v", got, want)
	}
}

func TestParseCookies(t *testing.T) {
	got, err := parseCookies([]string{"a=1", "b=2=3"})
	if err != nil {
		t.Fatalf("parseCookies: %v", err)
	}
	want := []tlsforge.Cookie{{Name: "a", Value: "1"}, {Name: "b", Value: "2=3"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCookies = %+v, want %+v", got, want)
	}
}

func TestResponseAlwaysEncodesItsID(t *testing.T) {
	// Never omitempty: a caller has to be able to tell "id 0" from "no id at
	// all", and read the latter as a binary older than the code driving it.
	encoded, err := json.Marshal(Response{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"id":0`) {
		t.Errorf("encoded response omits a zero id: %s", encoded)
	}
}

// The daemon interface must stay satisfiable by the real client, or the two
// drift apart without anything failing to build.
var _ Client = (*tlsforge.Client)(nil)

func TestProfileFieldsAreUsable(t *testing.T) {
	// A guard against the header type changing shape underneath the daemon.
	h := tlsforge.Header{profile.Field{Name: "accept", Value: "*/*"}}
	if got := fmt.Sprint(h.Names()); got != "[accept]" {
		t.Errorf("Names = %s", got)
	}
}

// TestABinaryBodySurvivesTheProtocol is the reason bodyEncoding exists.
//
// A JSON string cannot hold arbitrary bytes: encoding/json replaces every byte
// that is not valid UTF-8 with U+FFFD, silently, and the response still says
// status 200 with no error. A caller asking for an image got back something no
// decoder would open, with nothing anywhere reporting a problem.
func TestABinaryBodySurvivesTheProtocol(t *testing.T) {
	// PNG magic followed by bytes that are not valid UTF-8.
	want := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xd8, 0xff}

	var out strings.Builder
	err := Serve(
		strings.NewReader(`{"engine_major":6,"id":1,"url":"https://example.com/logo.png"}`+"\n"),
		&out,
		&fakeClient{response: &tlsforge.Response{Status: 200, Body: want}},
	)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}

	var got Response
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("decoding the response: %v (%s)", err, out.String())
	}
	if got.Error != "" {
		t.Fatalf("unexpected error: %s", got.Error)
	}
	if got.BodyEncoding != BodyBase64 {
		t.Fatalf("bodyEncoding = %q, want %q", got.BodyEncoding, BodyBase64)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.Body)
	if err != nil {
		t.Fatalf("the body is not base64: %v", err)
	}
	if !bytes.Equal(decoded, want) {
		t.Errorf("body round-tripped as % x, want % x", decoded, want)
	}
}

// TestATextBodyCarriesNoEncoding keeps the common case on the wire it has
// always had, so a reader that predates bodyEncoding is unaffected by it.
func TestATextBodyCarriesNoEncoding(t *testing.T) {
	var out strings.Builder
	err := Serve(
		strings.NewReader(`{"engine_major":6,"id":1,"url":"https://example.com/"}`+"\n"),
		&out,
		&fakeClient{response: &tlsforge.Response{Status: 200, Body: []byte("héllo — ok")}},
	)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var got Response
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.BodyEncoding != "" {
		t.Errorf("bodyEncoding = %q, want it absent for text", got.BodyEncoding)
	}
	if got.Body != "héllo — ok" {
		t.Errorf("body = %q", got.Body)
	}
}

func TestAnInvalidUTF8ResponseHeaderFailsExplicitly(t *testing.T) {
	responses := serve(t, &fakeClient{response: &tlsforge.Response{
		Status: 200,
		Header: map[string][]string{"content-disposition": {"name=\xff.txt"}},
	}}, `{"engine_major":6,"id":9,"url":"https://example.com/"}`)
	if len(responses) != 1 || responses[0].ID != 9 {
		t.Fatalf("responses = %+v", responses)
	}
	if !strings.Contains(responses[0].Error, "not valid UTF-8") {
		t.Fatalf("response silently accepted an invalid header: %+v", responses[0])
	}
}

func TestAnInvalidUTF8ResponseHeaderNameFailsExplicitly(t *testing.T) {
	responses := serve(t, &fakeClient{response: &tlsforge.Response{
		Status: 200,
		Header: map[string][]string{"x-\xff": {"value"}},
	}}, `{"engine_major":6,"id":10,"url":"https://example.com/"}`)
	if len(responses) != 1 || responses[0].ID != 10 {
		t.Fatalf("responses = %+v", responses)
	}
	if !strings.Contains(responses[0].Error, "name is not valid UTF-8") {
		t.Fatalf("response silently accepted an invalid header name: %+v", responses[0])
	}
}

// TestABinaryRequestBodyIsSentIntact covers the other direction.
func TestABinaryRequestBodyIsSentIntact(t *testing.T) {
	want := []byte{0x00, 0xff, 0xfe, 0x80}
	seen := &recordingClient{}

	line, err := json.Marshal(Request{EngineMajor: majorForTest(),
		ID:           1,
		Method:       "POST",
		URL:          "https://example.com/upload",
		Body:         base64.StdEncoding.EncodeToString(want),
		BodyEncoding: BodyBase64,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var out strings.Builder
	if err := Serve(strings.NewReader(string(line)+"\n"), &out, seen); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !bytes.Equal(seen.body, want) {
		t.Errorf("the client was handed % x, want % x", seen.body, want)
	}
}

func TestABadBodyEncodingIsRejected(t *testing.T) {
	for _, line := range []string{
		`{"engine_major":6,"id":1,"url":"https://x/","body":"!!not base64!!","bodyEncoding":"base64"}`,
		`{"engine_major":6,"id":1,"url":"https://x/","body":"x","bodyEncoding":"rot13"}`,
	} {
		var out strings.Builder
		if err := Serve(strings.NewReader(line+"\n"), &out, &fakeClient{
			response: &tlsforge.Response{Status: 200},
		}); err != nil {
			t.Fatalf("Serve: %v", err)
		}
		var got Response
		if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		if got.Error == "" {
			t.Errorf("%s was accepted", line)
		}
	}
}

// recordingClient keeps the body it was handed, which is the thing under test.
type recordingClient struct {
	body []byte
}

func (c *recordingClient) Do(req *tlsforge.Request) (*tlsforge.Response, error) {
	c.body = append([]byte(nil), req.Body...)
	return &tlsforge.Response{Status: 200}, nil
}

func (c *recordingClient) Headers() tlsforge.Header { return nil }

// The old way of serving, as callers outside this package write it.
var _ func(io.Reader, io.Writer, Client) error = Serve

// goroutinesBackTo fails the test unless the goroutines are as many as before,
// soon: whatever ServeContext started has ended.
func goroutinesBackTo(t *testing.T, before int) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); runtime.NumGoroutine() > before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			stacks := make([]byte, 1<<20)
			t.Fatalf("%d goroutines, %d before:\n%s", runtime.NumGoroutine(), before, stacks[:runtime.Stack(stacks, true)])
		}
	}
}

// served runs ServeContext on a goroutine, and is what it returned.
func served(ctx context.Context, in io.Reader, out io.Writer, client Client) <-chan error {
	done := make(chan error, 1)
	go func() { done <- ServeContext(ctx, in, out, client) }()
	return done
}

// returned is what ServeContext returned, within a bound.
func returned(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("ServeContext did not return")
		return nil
	}
}

func TestServeContextStopsWhileAReadWaits(t *testing.T) {
	// Nothing comes on the input, and nothing will until its owner closes it:
	// ServeContext returns when it is told to, and the read it leaves waiting
	// ends with the input.
	before := runtime.NumGoroutine()
	ours, theirs := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeClient{}
	done := served(ctx, ours, io.Discard, client)
	cancel()
	if err := returned(t, done); !errors.Is(err, context.Canceled) {
		t.Errorf("ServeContext() = %v", err)
	}
	// A request that comes after it was told to stop is read, and dropped.
	if _, err := io.WriteString(theirs, `{"engine_major":6,"id":1,"url":"https://example.com/late"}`+"\n"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_ = theirs.Close()
	_ = ours.Close()
	goroutinesBackTo(t, before)
	if client.got != nil {
		t.Errorf("a request after the stop was made: %+v", client.got)
	}
}

// writing is an output that says when it is first written to, and then waits
// as a pipe nobody reads does.
type writing struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (w *writing) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	return w.Conn.Write(p)
}

func TestServeContextStopsWhileAWriteWaits(t *testing.T) {
	// The answer cannot be written, since nobody reads the output: once told,
	// it is given up after answerGrace, and not before.
	before := runtime.NumGoroutine()
	ours, theirs := net.Pipe()
	out := &writing{Conn: ours, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := served(ctx, strings.NewReader(`{"engine_major":6,"id":1,"url":"https://example.com"}`+"\n"), out, &fakeClient{})
	<-out.started
	told := time.Now()
	cancel()
	if err := returned(t, done); !errors.Is(err, context.Canceled) {
		t.Errorf("ServeContext() = %v", err)
	}
	if waited := time.Since(told); waited < answerGrace {
		t.Errorf("the answer was given up after %v, before its %v", waited, answerGrace)
	}
	_ = theirs.Close()
	_ = ours.Close()
	goroutinesBackTo(t, before)
}

// waitingClient asks nobody, and answers when the request's context is done.
type waitingClient struct{ asked chan struct{} }

func (c *waitingClient) Do(req *tlsforge.Request) (*tlsforge.Response, error) {
	close(c.asked)
	<-req.Context.Done()
	return nil, fmt.Errorf("tlsforge: Get %q: %w", req.URL, context.Cause(req.Context))
}

func (c *waitingClient) Headers() tlsforge.Header { return nil }

func TestServeContextCancelsTheRequestInFlightAndAnswersIt(t *testing.T) {
	before := runtime.NumGoroutine()
	client := &waitingClient{asked: make(chan struct{})}
	ours, theirs := net.Pipe()
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := served(ctx, ours, &out, client)
	go func() {
		_, _ = io.WriteString(theirs, `{"engine_major":6,"id":1,"url":"https://example.com/slow"}`+"\n")
	}()
	<-client.asked
	cancel()
	if err := returned(t, done); !errors.Is(err, context.Canceled) {
		t.Errorf("ServeContext() = %v", err)
	}
	want := `{"id":1,"status":0,"url":"","body":"","headers":null,"cookies":null,` +
		`"error":"tlsforge: Get \"https://example.com/slow\": context canceled"}` + "\n"
	if out.String() != want {
		t.Errorf("answered %q, want %q", out.String(), want)
	}
	_ = theirs.Close()
	_ = ours.Close()
	goroutinesBackTo(t, before)
}

func TestHelloSaysWhatTheDaemonIsWithoutAConnection(t *testing.T) {
	client := &fakeClient{}
	got := handle(context.Background(), `{"engine_major":6,"id":3,"control":"hello"}`, client)
	if got.ID != 3 || got.Error != "" || got.Protocol != Protocol || !slices.Equal(got.Capabilities, []string{"browser_context", "engine_major"}) ||
		client.got != nil {
		t.Errorf("hello: %+v, a request %v", got, client.got)
	}
	// What it can do is a copy: an answer cannot change what the next says.
	original := capabilities
	capabilities = []string{"something"}
	defer func() { capabilities = original }()
	got = handle(context.Background(), `{"engine_major":6,"id":4,"control":"hello"}`, client)
	got.Capabilities[0] = "changed"
	if capabilities[0] != "something" {
		t.Error("an answer shares the daemon's capabilities")
	}
	for line, want := range map[string]string{
		`{"engine_major":6,"id":5,"control":"hello","url":"https://example.com/"}`: "a control line is not a request, and has no url",
		`{"engine_major":6,"id":6,"control":"goodbye"}`:                            `unknown control "goodbye"`,
	} {
		got := handle(context.Background(), line, client)
		if got.Protocol != 0 || !strings.Contains(got.Error, want) || client.got != nil {
			t.Errorf("%s: %+v, a request %v", line, got, client.got)
		}
	}
}

func TestAFieldTheProtocolDoesNotHaveIsPassedOver(t *testing.T) {
	// The Node.js package of 0.2 and before put a caller's whole request on
	// the line, so a field it does not name has always been sent, and passed
	// over: refusing it now would fail a request that worked. Where it falls
	// in the line does not cost the id.
	client := &fakeClient{}
	for _, line := range []string{
		`{"engine_major":6,"timeout":5000,"frame":{"top":true},"id":11,"url":"https://example.com/"}`,
		`{"engine_major":6,"id":11,"url":"https://example.com/","Browser ":{"kind":7},"json":[1,2]}`,
	} {
		client.got = nil
		got := handle(context.Background(), line, client)
		if got.ID != 11 || got.Error != "" || client.got == nil || client.got.URL != "https://example.com/" ||
			client.got.Browser != nil {
			t.Errorf("%s: %+v, sent %+v", line, got, client.got)
		}
	}
}

func TestABrowserContextIsApplied(t *testing.T) {
	client := &fakeClient{}
	got := handle(context.Background(), `{"engine_major":6,"id":7,"url":"https://example.com/","browser":{"kind":"fetch",`+
		`"initiator":"https://example.com/page","referrerPolicy":"origin","mode":"no-cors","credentials":"omit"}}`, client)
	want := &tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Initiator: "https://example.com/page",
		ReferrerPolicy: "origin", Mode: "no-cors", Credentials: "omit"}
	if got.Error != "" || client.got == nil || client.got.Browser == nil || *client.got.Browser != *want {
		t.Errorf("a browser context: %+v, sent %+v", got, client.got)
	}
	// None given, or null, is none.
	for _, line := range []string{`{"engine_major":6,"id":8,"url":"https://example.com/"}`,
		`{"engine_major":6,"id":8,"url":"https://example.com/","browser":null}`} {
		client.got = nil
		if got := handle(context.Background(), line, client); got.Error != "" || client.got == nil ||
			client.got.Browser != nil {
			t.Errorf("%s: %+v", line, got)
		}
	}
	// What the protocol does not have is a bad request, and nothing is sent.
	for line, says := range map[string]string{
		`{"engine_major":6,"id":9,"url":"https://example.com/","browser":{"kind":"fetch","frame":"top"}}`: `bad request: browser: json: unknown field "frame"`,
		`{"engine_major":6,"id":9,"url":"https://example.com/","browser":{"kind":7}}`:                     "bad request: browser: json: cannot unmarshal number",
		`{"engine_major":6,"id":9,"url":"https://example.com/","browser":"fetch"}`:                        "bad request: browser: json: cannot unmarshal string",
	} {
		client.got = nil
		got := handle(context.Background(), line, client)
		if got.ID != 9 || !strings.HasPrefix(got.Error, says) || client.got != nil {
			t.Errorf("%s: %+v, sent %+v", line, got, client.got)
		}
	}
}

func TestReadInit(t *testing.T) {
	// The proxy, the id, and the input after it, blank lines before it aside;
	// the last line need not end in a newline.
	for _, input := range []string{
		`{"engine_major":6,"id":3,"control":"init","proxy":"http://u:p@h:1"}` + "\n" + `{"engine_major":6,"id":4,"url":"x"}` + "\n",
		"\n  \n" + `{"engine_major":6,"id":3,"control":"init","proxy":"http://u:p@h:1"}` + "\n" + `{"engine_major":6,"id":4,"url":"x"}` + "\n",
		`{"engine_major":6,"id":3,"control":"init","proxy":"http://u:p@h:1"}`,
	} {
		init, rest, err := ReadInit(strings.NewReader(input))
		if err != nil || init.ID != 3 || init.Proxy != "http://u:p@h:1" {
			t.Fatalf("%q: %+v, %v", input, init, err)
		}
		after, _ := io.ReadAll(rest)
		if want := strings.TrimPrefix(strings.SplitAfterN(input, "}", 2)[1], "\n"); string(after) != want {
			t.Errorf("%q: the input after it is %q, want %q", input, after, want)
		}
	}
	// A line longer than the reader's buffer, not than a request line may be.
	long := `{"engine_major":6,"id":9,"control":"init","proxy":"http://h:1/` + strings.Repeat("a", 3*initialLineBuffer) + `"}` + "\n"
	if init, _, err := ReadInit(strings.NewReader(long)); err != nil || init.ID != 9 {
		t.Errorf("a long init line: %+v, %v", init, err)
	}
	for _, tc := range []struct {
		name  string
		input io.Reader
		id    uint64
		says  string
	}{
		{"a request", strings.NewReader(`{"engine_major":6,"id":5,"url":"https://example.com/"}`), 5, "is its init line"},
		{"hello", strings.NewReader(`{"engine_major":6,"id":5,"control":"hello"}`), 5, "is its init line"},
		{"a url", strings.NewReader(`{"engine_major":6,"id":5,"control":"init","proxy":"http://h:1","url":"x"}`), 5, "is its init line"},
		{"no proxy", strings.NewReader(`{"engine_major":6,"id":5,"control":"init"}`), 5, "the init line names no proxy"},
		{"no JSON", strings.NewReader(`{"engine_major":6,"id":5,` + "\n"), 0, "bad request: unexpected end of JSON input"},
		{"the wrong shape", strings.NewReader(`{"engine_major":6,"id":5,"proxy":7}` + "\n"), 5, "bad request: json: cannot unmarshal"},
		{"nothing", strings.NewReader(""), 0, "the input ended before the init line"},
		{"a broken input", iotest.ErrReader(errors.New("gone")), 0, "reading the init line: gone"},
		{"a line too long", io.MultiReader(strings.NewReader(`{"engine_major":6,"id":5,"proxy":"`),
			strings.NewReader(strings.Repeat("a", maxLineBuffer))), 0, "longer than 16777216 bytes"},
	} {
		init, _, err := ReadInit(tc.input)
		if err == nil || init.ID != tc.id || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %+v, %v, want %q", tc.name, init, err, tc.says)
		}
	}
}

func TestAnInitLineIsReadUpToItsLimitItsNewlineIncluded(t *testing.T) {
	// As Serve reads a request line, to the byte: a last line without a
	// newline is counted as one with it. size is that count.
	line := func(head string, size int, newline string) string {
		return head + strings.Repeat("x", size-len(head)-len(`"}`)-1) + `"}` + newline
	}
	for _, tc := range []struct {
		size    int
		newline string
		read    bool
	}{
		{maxLineBuffer - 1, "\n", true}, {maxLineBuffer, "\n", true}, {maxLineBuffer + 1, "\n", false},
		{maxLineBuffer, "", true}, {maxLineBuffer + 1, "", false},
	} {
		init := line(`{"engine_major":6,"id":1,"control":"init","proxy":"http://h:1/`, tc.size, tc.newline)
		_, _, err := ReadInit(strings.NewReader(init))
		if read := err == nil; read != tc.read ||
			(!read && (!errors.Is(err, bufio.ErrTooLong) || !strings.Contains(err.Error(), "its newline included"))) {
			t.Errorf("an init line of %d bytes (newline %q): %v", tc.size, tc.newline, err)
		}
		var out strings.Builder
		err = Serve(strings.NewReader(line(`{"engine_major":6,"id":1,"url":"https://example.com","body":"`, tc.size, tc.newline)),
			&out, &fakeClient{})
		if read := strings.Contains(out.String(), `"status":200`); read != tc.read {
			t.Errorf("a request line of %d bytes (newline %q): %v, %q", tc.size, tc.newline, err, out.String())
		}
	}
}

func TestAnInitLineIsAnswered(t *testing.T) {
	var out bytes.Buffer
	if err := AnswerInit(&out, 3, nil); err != nil {
		t.Fatalf("AnswerInit: %v", err)
	}
	if got := out.String(); got != `{"id":3,"status":0,"url":"","body":"","headers":null,"cookies":null}`+"\n" {
		t.Errorf("ready: %s", got)
	}
	out.Reset()
	_ = AnswerInit(&out, 4, errors.New(`the proxy "http://alice:secret@h:1" refused`))
	if got := out.String(); !strings.Contains(got, `"id":4`) || !strings.Contains(got, "alice") ||
		strings.Contains(got, "secret") {
		t.Errorf("failed: %s", got)
	}
	// An init line among requests is no init line.
	client := &fakeClient{}
	got := handle(context.Background(), `{"engine_major":6,"id":5,"control":"init","proxy":"http://h:1"}`, client)
	if got.ID != 5 || !strings.Contains(got.Error, "init is the first line of a daemon started with --proxy-stdin") ||
		client.got != nil {
		t.Errorf("%+v", got)
	}
}
