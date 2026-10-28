package tlsforge

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/andybalholm/brotli"
	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/klauspost/compress/zstd"
)

// page is a body worth compressing: what a server sends, before it does.
var page = []byte(strings.Repeat("the page as it was written, before anybody compressed it. ", 40))

// coded is one answer of a codedServer: the Content-Encoding fields it says,
// in order, and the body as it goes over the wire.
type coded struct {
	status   int
	encoding []string
	body     []byte
}

// codedServer answers each path with its coded answer, over HTTP/2 when h2 is
// set and over HTTP/1.1 otherwise, and is told every request's
// Accept-Encoding, by path.
type codedServer struct {
	url      string
	mu       sync.Mutex
	accepted map[string][]string
}

func startCoded(t *testing.T, h2 bool, answers map[string]coded) *codedServer {
	t.Helper()
	s := &codedServer{accepted: map[string][]string{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.accepted[r.URL.Path] = r.Header.Values("Accept-Encoding")
		s.mu.Unlock()
		answer, ok := answers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		for _, field := range answer.encoding {
			w.Header().Add("Content-Encoding", field)
		}
		status := answer.status
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusNoContent && status != http.StatusNotModified {
			w.Header().Set("Content-Length", strconv.Itoa(len(answer.body)))
		}
		w.WriteHeader(status)
		_, _ = w.Write(answer.body)
	}))
	if h2 {
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	s.url = server.URL
	return s
}

func (s *codedServer) acceptEncoding(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted[path]
}

// protocols are both, so that every case runs over each: the transport decoded
// differently over each, and broke differently.
var protocols = []struct {
	name string
	h2   bool
}{{"HTTP/1.1", false}, {"HTTP/2", true}}

func encoded(t *testing.T, write func(*bytes.Buffer) (interface {
	Write([]byte) (int, error)
	Close() error
}, error), body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := write(&buf)
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing the encoder: %v", err)
	}
	return buf.Bytes()
}

type encoder = interface {
	Write([]byte) (int, error)
	Close() error
}

func gzipped(t *testing.T, body []byte) []byte {
	return encoded(t, func(b *bytes.Buffer) (encoder, error) { return gzip.NewWriter(b), nil }, body)
}

func zlibbed(t *testing.T, body []byte) []byte {
	return encoded(t, func(b *bytes.Buffer) (encoder, error) { return zlib.NewWriter(b), nil }, body)
}

func rawDeflated(t *testing.T, body []byte) []byte {
	return encoded(t, func(b *bytes.Buffer) (encoder, error) { return flate.NewWriter(b, flate.DefaultCompression) }, body)
}

func brotlied(t *testing.T, body []byte) []byte {
	return encoded(t, func(b *bytes.Buffer) (encoder, error) { return brotli.NewWriter(b), nil }, body)
}

func zstded(t *testing.T, body []byte, opts ...zstd.EOption) []byte {
	return encoded(t, func(b *bytes.Buffer) (encoder, error) { return zstd.NewWriter(b, opts...) }, body)
}

func TestABodyIsDecodedFromEveryCodingChromeAccepts(t *testing.T) {
	stacked := brotlied(t, gzipped(t, page))
	twoFields := zstded(t, zlibbed(t, page))
	answers := map[string]coded{
		"/gzip":              {encoding: []string{"gzip"}, body: gzipped(t, page)},
		"/x-gzip":            {encoding: []string{"x-gzip"}, body: gzipped(t, page)},
		"/capitals":          {encoding: []string{"GZIP"}, body: gzipped(t, page)},
		"/zlib":              {encoding: []string{"deflate"}, body: zlibbed(t, page)},
		"/raw-deflate":       {encoding: []string{"deflate"}, body: rawDeflated(t, page)},
		"/br":                {encoding: []string{"br"}, body: brotlied(t, page)},
		"/zstd":              {encoding: []string{"zstd"}, body: zstded(t, page)},
		"/stacked":           {encoding: []string{"gzip, br"}, body: stacked},
		"/two-fields":        {encoding: []string{"deflate", "zstd"}, body: twoFields},
		"/beside-identity":   {encoding: []string{"identity, gzip"}, body: gzipped(t, page)},
		"/spaced-and-commas": {encoding: []string{" , gzip ,, "}, body: gzipped(t, page)},
	}
	// A body beside identity is decoded as it always was by a profile whose
	// JSON passes identity over, as the frozen generic data does; Chrome
	// leaves such a chain raw, which TestABodyComesAsItCameWhenThereIsNothingToDecode
	// holds a Chromium profile to.
	passingOver := policyFile(t, map[string]any{"http.ignored_content_codings": []string{"identity"}})
	for _, protocol := range protocols {
		server := startCoded(t, protocol.h2, answers)
		client := newTestClient(t)
		ignoring := newTestClient(t, WithProfileValue(passingOver))
		for _, tc := range []struct{ path, want string }{
			{"/gzip", "gzip"}, {"/x-gzip", "x-gzip"}, {"/capitals", "gzip"},
			{"/zlib", "deflate"}, {"/raw-deflate", "deflate"}, {"/br", "br"}, {"/zstd", "zstd"},
			{"/stacked", "gzip, br"}, {"/two-fields", "deflate, zstd"},
			{"/beside-identity", "gzip"}, {"/spaced-and-commas", "gzip"},
		} {
			t.Run(protocol.name+tc.path, func(t *testing.T) {
				client := client
				if tc.path == "/beside-identity" {
					client = ignoring
				}
				res, err := client.Get(server.url + tc.path)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				if !bytes.Equal(res.Body, page) {
					t.Errorf("body = %q…, want the page", res.Body[:min(len(res.Body), 40)])
				}
				if res.Encoding != tc.want {
					t.Errorf("Encoding = %q, want %q", res.Encoding, tc.want)
				}
				// The fields said what came over the wire, and the body is not that.
				for _, name := range []string{"content-encoding", "content-length"} {
					if got, ok := res.Header[name]; ok {
						t.Errorf("%s = %q is left on a decoded body", name, got)
					}
				}
			})
		}
	}
}

func TestABodyComesAsItCameWhenThereIsNothingToDecode(t *testing.T) {
	compressedGarbage := []byte("\x1f\x8b not something anybody can decode")
	besideIdentity := gzipped(t, page)
	answers := map[string]coded{
		"/plain":           {body: page},
		"/identity":        {encoding: []string{"identity"}, body: page},
		"/beside-identity": {encoding: []string{"identity, gzip"}, body: besideIdentity},
		"/unknown":         {encoding: []string{"compress"}, body: compressedGarbage},
		"/unknown-stacked": {encoding: []string{"gzip, dcb"}, body: compressedGarbage},
		"/empty":           {encoding: []string{"gzip"}, body: nil},
		"/no-content":      {status: http.StatusNoContent, encoding: []string{"gzip"}},
		"/not-modified":    {status: http.StatusNotModified, encoding: []string{"br"}},
		"/br-head":         {encoding: []string{"br"}, body: brotlied(t, page)},
	}
	for _, protocol := range protocols {
		server := startCoded(t, protocol.h2, answers)
		client := newTestClient(t)
		for _, tc := range []struct {
			path         string
			body         []byte
			contentCoded []string // what Content-Encoding still says
		}{
			{"/plain", page, nil},
			{"/identity", page, []string{"identity"}},
			// Chrome 156's measured identity handling leaves the whole chain
			// raw, just like an unknown coding; no partial decoding is safe.
			{"/beside-identity", besideIdentity, []string{"identity, gzip"}},
			// Chrome passes a body in a coding it does not know through undecoded,
			// and so does this; its fields stay true of it.
			{"/unknown", compressedGarbage, []string{"compress"}},
			{"/unknown-stacked", compressedGarbage, []string{"gzip, dcb"}},
			{"/empty", nil, []string{"gzip"}},
			{"/no-content", nil, []string{"gzip"}},
			{"/not-modified", nil, []string{"br"}},
		} {
			t.Run(protocol.name+tc.path, func(t *testing.T) {
				res, err := client.Get(server.url + tc.path)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				if !bytes.Equal(res.Body, tc.body) {
					t.Errorf("body = %q, want it as it came, %q", res.Body, tc.body)
				}
				if res.Encoding != "" {
					t.Errorf("Encoding = %q for a body that was not decoded", res.Encoding)
				}
				if got := res.Header["content-encoding"]; strings.Join(got, ",") != strings.Join(tc.contentCoded, ",") {
					t.Errorf("content-encoding = %q, want %q", got, tc.contentCoded)
				}
			})
		}

		t.Run(protocol.name+"/HEAD", func(t *testing.T) {
			// A HEAD without a context goes as given, as a profile that says
			// so sends it.
			client := newTestClient(t, WithProfileValue(asGivenProfile(t, DefaultProfile)))
			res, err := client.Do(&Request{Method: http.MethodHead, URL: server.url + "/br-head"})
			if err != nil {
				t.Fatalf("HEAD: %v", err)
			}
			if len(res.Body) != 0 || res.Encoding != "" {
				t.Errorf("HEAD came back with %q decoded from %q", res.Body, res.Encoding)
			}
			// The fields of a HEAD describe the representation a GET would get.
			if got := res.Header["content-encoding"]; len(got) != 1 || got[0] != "br" {
				t.Errorf("HEAD content-encoding = %q, want br kept", got)
			}
		})
	}
}

func TestABodyThatDoesNotDecodeIsAnError(t *testing.T) {
	flipped := zlibbed(t, page)
	flipped[len(flipped)-1] ^= 0xff
	// A zlib header that asks for a preset dictionary, by an id that is not the
	// empty dictionary's (whose checksum is 1).
	needsDictionary := []byte{0x78, 0xbb, 0, 0, 0, 2, 0x03, 0x00}
	answers := map[string]coded{
		"/gzip-corrupt":    {encoding: []string{"gzip"}, body: []byte("this is not gzip at all")},
		"/br-corrupt":      {encoding: []string{"br"}, body: []byte{0xff, 0xff, 0xff, 0xff}},
		"/zstd-corrupt":    {encoding: []string{"zstd"}, body: []byte("not a zstd frame")},
		"/deflate-corrupt": {encoding: []string{"deflate"}, body: []byte{0xff, 0xff, 0xff}},
		"/zlib-checksum":   {encoding: []string{"deflate"}, body: flipped},
		"/zlib-dictionary": {encoding: []string{"deflate"}, body: needsDictionary},
		// More than 8 MiB, or the encoder shrinks the window to fit the input.
		"/zstd-wide-window": {encoding: []string{"zstd"},
			body: zstded(t, make([]byte, 9<<20), zstd.WithWindowSize(16<<20), zstd.WithSingleSegment(false))},
		"/stacked-corrupt": {encoding: []string{"gzip", "br"}, body: brotlied(t, []byte("not gzip"))},
	}
	for _, protocol := range protocols {
		server := startCoded(t, protocol.h2, answers)
		client := newTestClient(t)
		for _, tc := range []struct{ path, want string }{
			{"/gzip-corrupt", "decoding a gzip body"},
			{"/br-corrupt", "decoding a br body"},
			{"/zstd-corrupt", "decoding a zstd body"},
			{"/deflate-corrupt", "decoding a deflate body"},
			{"/zlib-checksum", "decoding a deflate body: zlib: invalid checksum"},
			{"/zlib-dictionary", "decoding a deflate body: zlib: invalid dictionary"},
			// Chrome refuses a zstd body that wants more than an 8 MiB window,
			// rather than find it the memory.
			{"/zstd-wide-window", "decoding a zstd body"},
			{"/stacked-corrupt", "decoding a gzip, br body"},
		} {
			t.Run(protocol.name+tc.path, func(t *testing.T) {
				_, err := client.Get(server.url + tc.path)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Get = %v, want %q", err, tc.want)
				}
			})
		}
	}
}

func TestTheLimitIsCountedOnWhatABodyDecodesTo(t *testing.T) {
	// A small body that decodes to an enormous one: what is kept stops at the
	// limit, however little came over the wire.
	const limit = 1 << 20
	bomb := gzipped(t, make([]byte, 32<<20))
	exact := gzipped(t, bytes.Repeat([]byte("a"), limit))
	over := gzipped(t, bytes.Repeat([]byte("a"), limit+1))
	server := startCoded(t, true, map[string]coded{
		"/bomb":  {encoding: []string{"gzip"}, body: bomb},
		"/exact": {encoding: []string{"gzip"}, body: exact},
		"/over":  {encoding: []string{"gzip"}, body: over},
	})
	if len(bomb) > 64<<10 {
		t.Fatalf("the bomb is %d bytes on the wire; it is meant to be small", len(bomb))
	}
	client := newTestClient(t, WithMaxResponseBody(limit))
	for _, path := range []string{"/bomb", "/over"} {
		if _, err := client.Get(server.url + path); !errors.Is(err, ErrResponseTooLarge) {
			t.Errorf("%s: error = %v, want ErrResponseTooLarge", path, err)
		}
	}
	if res, err := client.Get(server.url + "/exact"); err != nil {
		t.Errorf("a body that decodes to exactly the limit: %v", err)
	} else if len(res.Body) != limit {
		t.Errorf("a body that decodes to exactly the limit: %d bytes", len(res.Body))
	}

	// Not decoded, the limit is counted on what came.
	raw := startCoded(t, false, map[string]coded{"/raw": {encoding: []string{"compress"}, body: make([]byte, limit+1)}})
	if _, err := client.Get(raw.url + "/raw"); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("an undecoded body over the limit: error = %v, want ErrResponseTooLarge", err)
	}
}

func TestABodyCutShortBeforeItsFirstByteIsAReadingError(t *testing.T) {
	// The fields promise a gzip body and the connection ends before any of it:
	// there is nothing to decode, and the failure is the read.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 10\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	_, err = newTestClient(t).Get("http://" + listener.Addr().String() + "/")
	if err == nil || !strings.Contains(err.Error(), "tlsforge: reading body") {
		t.Fatalf("Get = %v, want a reading error", err)
	}
}

func TestADecoderThatCannotBeMadeIsADecodingError(t *testing.T) {
	saved := zstdOptions
	t.Cleanup(func() { zstdOptions = saved })
	zstdOptions = []zstd.DOption{zstd.WithDecoderMaxWindow(1)} // below any window zstd allows
	server := startCoded(t, false, map[string]coded{"/zstd": {encoding: []string{"zstd"}, body: zstded(t, page)}})
	if _, err := newTestClient(t).Get(server.url + "/zstd"); err == nil ||
		!strings.Contains(err.Error(), "decoding a zstd body") {
		t.Fatalf("Get = %v, want a decoding error", err)
	}
	// Without a policy the frozen legacy data decodes, by zstd's decoder of its
	// own, which the same options refuse.
	res := &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Content-Encoding": {"zstd"}},
		Body: io.NopCloser(bytes.NewReader(zstded(t, page)))}
	if _, _, err := readBody(res, http.MethodGet, 1<<20); err == nil || !strings.Contains(err.Error(), "decoding a zstd body") {
		t.Errorf("readBody without a policy = %v, want a decoding error", err)
	}
}

func TestTheAcceptEncodingThatGoesOutIsTheProfiles(t *testing.T) {
	// The transport no longer decodes, and so no longer adds an Accept-Encoding
	// of its own: the profile's goes out as it is, and a profile without one
	// sends none.
	for _, protocol := range protocols {
		server := startCoded(t, protocol.h2, map[string]coded{"/": {body: page}})
		if _, err := newTestClient(t).Get(server.url + "/"); err != nil {
			t.Fatalf("%s: Get: %v", protocol.name, err)
		}
		if got := server.acceptEncoding("/"); len(got) != 1 || got[0] != "gzip, deflate, br, zstd" {
			t.Errorf("%s: the default profile sent accept-encoding %q, want Chrome's", protocol.name, got)
		}
		if _, err := newTestClient(t, WithProfile("chrome_133")).Get(server.url + "/"); err != nil {
			t.Fatalf("%s: Get with a catalogue profile: %v", protocol.name, err)
		}
		if got := server.acceptEncoding("/"); len(got) != 0 {
			t.Errorf("%s: a profile without headers sent accept-encoding %q", protocol.name, got)
		}
	}
}

func TestATransportLetDecodeByTheCallerIsNotDecodedTwice(t *testing.T) {
	// WithTransportOption replacing the transport options turns the transport's
	// own decoding back on. Over HTTP/2 it decodes one coding spelled exactly
	// as it knows it and leaves the fields on, which are taken off here; a
	// stack of codings it passes through, and it is decoded here. Over
	// HTTP/1.1 it takes the fields off itself. What it does with a stack over
	// HTTP/1.1, passing the body through with the fields taken off, is the
	// transport's own and is said in WithTransportOption.
	answers := map[string]coded{
		"/gzip":    {encoding: []string{"gzip"}, body: gzipped(t, page)},
		"/stacked": {encoding: []string{"gzip, br"}, body: brotlied(t, gzipped(t, page))},
	}
	for _, tc := range []struct {
		h2   bool
		path string
		want string
	}{
		{true, "/gzip", "gzip"},
		{true, "/stacked", "gzip, br"},
		{false, "/gzip", ""},
	} {
		server := startCoded(t, tc.h2, answers)
		client := newTestClient(t, WithTransportOption(tls_client.WithTransportOptions(&tls_client.TransportOptions{})))
		res, err := client.Get(server.url + tc.path)
		if err != nil {
			t.Fatalf("h2=%v %s: Get: %v", tc.h2, tc.path, err)
		}
		if !bytes.Equal(res.Body, page) {
			t.Errorf("h2=%v %s: body = %q…, want the page decoded once", tc.h2, tc.path, res.Body[:min(len(res.Body), 40)])
		}
		if got, ok := res.Header["content-encoding"]; ok {
			t.Errorf("h2=%v %s: content-encoding = %q left on a decoded body", tc.h2, tc.path, got)
		}
		if res.Encoding != tc.want {
			t.Errorf("h2=%v %s: Encoding = %q, want %q", tc.h2, tc.path, res.Encoding, tc.want)
		}
	}

	// What the transport decoded is held to the limit like anything else.
	server := startCoded(t, true, answers)
	small := newTestClient(t, WithMaxResponseBody(10),
		WithTransportOption(tls_client.WithTransportOptions(&tls_client.TransportOptions{})))
	if _, err := small.Get(server.url + "/gzip"); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("a body the transport decoded, over the limit: error = %v, want ErrResponseTooLarge", err)
	}
}

func TestTheLogSaysWhatABodyWasDecodedFrom(t *testing.T) {
	var buf bytes.Buffer
	server := startCoded(t, true, map[string]coded{"/br": {encoding: []string{"br"}, body: brotlied(t, page)}})
	client := newTestClient(t, WithLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))))
	if _, err := client.Get(server.url + "/br"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("a record that is not JSON: %q", line)
		}
		if record["msg"] == "response" {
			if record["decoded_from"] != "br" || record["bytes"] != float64(len(page)) {
				t.Errorf("response record = %v, want the decoded size and decoded_from br", record)
			}
			return
		}
	}
	t.Fatalf("no response record:\n%s", buf.String())
}

func TestZlibHeader(t *testing.T) {
	for _, tc := range []struct {
		cmf, flg byte
		want     bool
	}{
		{0x78, 0x9c, true},  // default compression
		{0x78, 0x01, true},  // fastest
		{0x78, 0xda, true},  // best
		{0x08, 0x1d, true},  // the smallest window
		{0x78, 0x9d, false}, // check bits wrong
		{0x79, 0x9c, false}, // not deflate
		{0x88, 0x1c, false}, // window over 32 KiB
	} {
		if got := zlibHeader(tc.cmf, tc.flg); got != tc.want {
			t.Errorf("zlibHeader(%#02x, %#02x) = %v, want %v", tc.cmf, tc.flg, got, tc.want)
		}
	}
}

// askedSizes is a body that keeps how much each read of it asked for.
type askedSizes struct {
	io.Reader
	asked []int
}

func (a *askedSizes) Read(p []byte) (int, error) {
	a.asked = append(a.asked, len(p))
	return a.Reader.Read(p)
}

func TestABodyIsReadAtMostEightKiBAtATime(t *testing.T) {
	// As Chrome's network service takes a body from its HTTP/2 stream: what a
	// read frees of a window past half of it, which the transport tells the
	// server of, is at most 8 KiB more (testdata/chrome155-flow.json). Plain
	// and compressed alike.
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(bytes.Repeat(page, 100))
	_ = w.Close()
	for _, c := range []struct {
		name string
		body []byte
		head fhttp.Header
	}{
		{"plain", make([]byte, 1<<20), fhttp.Header{}},
		{"gzip", gz.Bytes(), fhttp.Header{"Content-Encoding": {"gzip"}}},
	} {
		body := &askedSizes{Reader: bytes.NewReader(c.body)}
		res := &fhttp.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body), Header: c.head}
		if _, _, err := readBody(res, http.MethodGet, 2<<20); err != nil {
			t.Fatalf("%s: readBody: %v", c.name, err)
		}
		if len(body.asked) == 0 || slices.Max(body.asked) > 8192 {
			t.Errorf("%s: reads asked for %v", c.name, body.asked)
		}
	}
}

// failsAfter is a body whose bytes end in an error, not an EOF: a connection
// that broke after them.
type failsAfter struct {
	*bytes.Reader
	err error
}

func (f *failsAfter) Read(p []byte) (int, error) {
	n, err := f.Reader.Read(p)
	if err == io.EOF {
		err = f.err
	}
	return n, err
}

func TestAGzipHeadersOptionalFieldsAreReadAsChromeReadsThem(t *testing.T) {
	valid := gzipped(t, page)
	// with is the member with flag set and the field after its fixed header.
	with := func(flag byte, field ...byte) []byte {
		out := append(bytes.Clone(valid[:10]), field...)
		out[3] |= flag
		return append(out, valid[10:]...)
	}
	broke := errors.New("connection reset")
	for _, tc := range []struct {
		name   string
		body   []byte
		broken bool // the bytes end in an error, not in the body's end
		want   []byte
		err    error
	}{
		{"extra", with(4, 3, 0, 'a', 'b', 'c'), false, page, nil},
		{"header crc", with(2, 0x12, 0x34), false, page, nil},
		{"extra and crc", with(4|2, 1, 0, 'x', 0x12, 0x34), false, page, nil},
		// A complete body that ends inside the header is Chrome's empty page.
		{"no extra length", with(4)[:10], false, nil, nil},
		{"half an extra length", with(4, 9)[:11], false, nil, nil},
		{"extra cut", with(4, 9, 0, 'a')[:13], false, nil, nil},
		{"crc cut", with(2, 0x12)[:11], false, nil, nil},
		// One that broke there is the connection's error.
		{"broken before the extra length", with(4)[:10], true, nil, broke},
		{"broken in the extra length", with(4, 9)[:11], true, nil, broke},
		{"broken in the extra", with(4, 9, 0, 'a')[:13], true, nil, broke},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r io.Reader = bytes.NewReader(tc.body)
			if tc.broken {
				r = &failsAfter{bytes.NewReader(tc.body), broke}
			}
			d, err := gzipDecoder(r)
			if err == nil {
				var got []byte
				got, err = io.ReadAll(d)
				if err == nil && !bytes.Equal(got, tc.want) {
					t.Errorf("decoded %d bytes, want %d", len(got), len(tc.want))
				}
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("error %v, want %v", err, tc.err)
			}
		})
	}
	// After the member, what follows is drained for the connection's sake, and
	// a connection that breaks then is the body's error.
	d, err := gzipDecoder(&failsAfter{bytes.NewReader(append(bytes.Clone(valid), "trailing"...)), broke})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(d); !errors.Is(err, broke) {
		t.Errorf("draining after the member: %v", err)
	}
}

func TestABodyIsDecodedByThePolicysDecoders(t *testing.T) {
	answer := func(coding string, body []byte) *fhttp.Response {
		return &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Content-Encoding": {coding}}, Body: io.NopCloser(bytes.NewReader(body))}
	}
	chrome := shippedProfile(t, "chrome_155_macos").RuntimeBehavior()
	// Without a policy the frozen legacy data decodes, zstd by its own decoder.
	if got, coding, err := readBody(answer("zstd", zstded(t, page)), http.MethodGet, 1<<20); err != nil || coding != "zstd" || !bytes.Equal(got, page) {
		t.Errorf("zstd without a policy: %d bytes, %q, %v", len(got), coding, err)
	}
	// RFC 1952's decoder, when a profile says so, is Go's: a trailer is checked.
	rfc := chrome.Clone()
	rfc["http.gzip_decoder"] = json.RawMessage(`"rfc1952"`)
	if got, _, err := readBody(answer("gzip", gzipped(t, page)), http.MethodGet, 1<<20, rfc); err != nil || !bytes.Equal(got, page) {
		t.Errorf("rfc1952: %d bytes, %v", len(got), err)
	}
	cut := gzipped(t, page)
	if _, _, err := readBody(answer("gzip", cut[:len(cut)-4]), http.MethodGet, 1<<20, rfc); err == nil {
		t.Error("rfc1952 took a member without its trailer")
	}
	// A policy that says no read size reads nothing.
	none := chrome.Clone()
	delete(none, "http.body_read_bytes")
	if _, _, err := readBody(answer("gzip", gzipped(t, page)), http.MethodGet, 1<<20, none); err == nil || !strings.Contains(err.Error(), "no body read policy") {
		t.Errorf("no read size: %v", err)
	}
}
