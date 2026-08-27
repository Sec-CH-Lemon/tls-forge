package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
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

	responses := serve(t, client, `{"id":7,"url":"https://example.com"}`)
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
		`{"id":11,"url":"https://example.com"}`,
		`{"id":12,"url":""}`,
		`{"id":13,"url":5}`,
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
	responses := serve(t, &fakeClient{}, `{"id":9,`)
	if len(responses) != 1 || responses[0].Error == "" {
		t.Fatalf("responses = %+v", responses)
	}
	if !strings.Contains(responses[0].Error, "bad request") {
		t.Errorf("error = %q", responses[0].Error)
	}
}

func TestBlankLinesAreIgnored(t *testing.T) {
	responses := serve(t, &fakeClient{}, "", "   ", `{"id":1,"url":"https://example.com"}`, "")
	if len(responses) != 1 {
		t.Fatalf("got %d responses, want 1", len(responses))
	}
}

func TestRequestFieldsReachTheClient(t *testing.T) {
	client := &fakeClient{}
	serve(t, client, `{"id":1,"method":"POST","url":"https://example.com","body":"a=1",`+
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
		`{"id":1,"url":"https://example.com","setCookie":["malformed"]}`,
		`{"id":2,"url":"https://example.com","setCookie":["=empty-name"]}`,
		`{"id":3,"url":"https://example.com","setCookie":["valid=1"]}`,
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

func TestHeadersWithDuplicateCasingAreRejectedDeterministically(t *testing.T) {
	client := &fakeClient{}
	responses := serve(t, client,
		`{"id":7,"url":"https://example.com","headers":{"User-Agent":"one","user-agent":"two"}}`)
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
	serve(t, client, `{"id":1,"url":"https://example.com",`+
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
	serve(t, client, `{"id":1,"url":"https://example.com","headers":`+
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
	line := `{"id":1,"url":"https://example.com","headers":` +
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
	serve(t, client, `{"id":1,"url":"https://example.com"}`)
	if client.got.Header != nil {
		t.Errorf("header = %v, want nil so the client applies the profile's", client.got.Header)
	}
}

func TestServeReportsAWriteFailure(t *testing.T) {
	// A broken stdout is the one failure the daemon cannot answer with a
	// response, so it has to stop rather than spin.
	err := Serve(strings.NewReader(`{"id":1,"url":"https://example.com"}`+"\n"),
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
		strings.NewReader(`{"id":1,"url":"https://example.com/logo.png"}`+"\n"),
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
		strings.NewReader(`{"id":1,"url":"https://example.com/"}`+"\n"),
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

// TestABinaryRequestBodyIsSentIntact covers the other direction.
func TestABinaryRequestBodyIsSentIntact(t *testing.T) {
	want := []byte{0x00, 0xff, 0xfe, 0x80}
	seen := &recordingClient{}

	line, err := json.Marshal(Request{
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
		`{"id":1,"url":"https://x/","body":"!!not base64!!","bodyEncoding":"base64"}`,
		`{"id":1,"url":"https://x/","body":"x","bodyEncoding":"rot13"}`,
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
