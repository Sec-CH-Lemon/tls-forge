package tlsforge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/utls/behavior"
)

func codingLimitPolicy(limit string, action string) behavior.Policy {
	p := legacyPolicy().Clone()
	p["http.max_content_codings"] = json.RawMessage(limit)
	p["http.content_coding_overflow"] = json.RawMessage(`"` + action + `"`)
	p["http.ignored_content_codings"] = json.RawMessage(`[]`)
	return p
}

func TestContentCodingDepthAllocationsBounded(t *testing.T) {
	if os.Getenv("TLSFORGE_CODING_LIMIT_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, executable, "-test.run=^TestContentCodingDepthAllocationsBounded$", "-test.timeout=12s", "-test.v")
		command.Env = append(os.Environ(), "TLSFORGE_CODING_LIMIT_CHILD=1", "GOMEMLIMIT=64MiB")
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("bounded decoder failed: %v (deadline %v)\n%s", err, ctx.Err(), out)
		}
		t.Logf("%s", out)
		return
	}
	for _, layers := range []int{10000, 100000} {
		response := &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Content-Encoding": {strings.TrimSuffix(strings.Repeat("br,", layers), ",")}}, Body: io.NopCloser(strings.NewReader("x"))}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, _, err := readBody(response, "GET", 1<<20, codingLimitPolicy("10", "error"))
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("%d layers allocated %d bytes, error %v", layers, allocated, err != nil)
		if err == nil || !strings.Contains(err.Error(), "content coding limit") || allocated > 16<<20 {
			t.Fatalf("unbounded coding stack: allocated=%d error=%v", allocated, err)
		}
	}
}

type codingFailure struct{}

func (codingFailure) Read([]byte) (int, error) { return 0, errors.New("synthetic decoding failure") }

func TestUnusedInnerDecodersAreNotCreated(t *testing.T) {
	old := decoders["br"]
	t.Cleanup(func() { decoders["br"] = old })
	created := 0
	decoders["br"] = func(io.Reader) (io.ReadCloser, error) {
		created++
		return io.NopCloser(codingFailure{}), nil
	}
	response := &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Content-Encoding": {"br, br, br"}}, Body: io.NopCloser(strings.NewReader("x"))}
	_, _, err := readBody(response, "GET", 1<<20, codingLimitPolicy("10", "error"))
	if err == nil || created != 1 {
		t.Fatalf("created %d decoders before the outer decoder failed; error %v", created, err)
	}
}

func TestContentCodingBoundaryMatchesMeasuredChrome(t *testing.T) {
	for _, n := range []int{0, 1, 9, 10, 11} {
		body := []byte("a2-decoded-payload")
		for i := 0; i < n; i++ {
			body = gzipped(t, body)
		}
		encoding := strings.TrimSuffix(strings.Repeat("gzip,", n), ",")
		for _, empty := range []bool{false, true} {
			if empty {
				body = nil
			}
			response := &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Content-Encoding": {encoding}}, Body: io.NopCloser(bytes.NewReader(body))}
			got, _, err := readBody(response, "GET", 1<<20, codingLimitPolicy("10", "error"))
			if (err != nil) != (n > 10) {
				t.Errorf("layers=%d empty=%v: %v", n, empty, err)
			}
			if err == nil && !empty && string(got) != "a2-decoded-payload" {
				t.Errorf("layers=%d body changed", n)
			}
		}
	}
	for _, encoding := range []string{"identity", "gzip, identity", "gzip, unknown", "unknown, gzip"} {
		body := gzipped(t, []byte("raw"))
		response := &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Content-Encoding": {encoding}}, Body: io.NopCloser(bytes.NewReader(body))}
		got, decoded, err := readBody(response, "GET", 1<<20, codingLimitPolicy("0", "error"))
		if err != nil || decoded != "" || !bytes.Equal(got, body) {
			t.Errorf("unknown/identity coding was partly decoded: %s, %s, %v", encoding, decoded, err)
		}
	}
}

// The limit holds at its edges: the engine's bound of 64 layers decodes and
// one more is over it, and a limit of 0 lets no coding through, while a body
// with none still comes as it came.
func TestContentCodingLimitsHoldAtTheirEdges(t *testing.T) {
	coded := func(n int) (*fhttp.Response, []byte) {
		body := []byte("a2-decoded-payload")
		for i := 0; i < n; i++ {
			body = gzipped(t, body)
		}
		header := fhttp.Header{}
		if n > 0 {
			header.Set("Content-Encoding", strings.TrimSuffix(strings.Repeat("gzip, ", n), ", "))
		}
		return &fhttp.Response{StatusCode: 200, Header: header, Body: io.NopCloser(bytes.NewReader(body))}, body
	}
	for _, tc := range []struct {
		limit, action string
		layers        int
		decoded, raw  bool
	}{
		{"64", "error", 64, true, false},
		{"64", "error", 65, false, false},
		{"64", "raw", 65, false, true},
		{"0", "error", 0, false, true},
		{"0", "error", 1, false, false},
		{"0", "raw", 1, false, true},
	} {
		response, body := coded(tc.layers)
		got, decodedFrom, err := readBody(response, "GET", 1<<20, codingLimitPolicy(tc.limit, tc.action))
		switch {
		case tc.decoded:
			if err != nil || string(got) != "a2-decoded-payload" || strings.Count(decodedFrom, "gzip") != tc.layers {
				t.Errorf("limit %s, %d layers: %q from %q, %v; want it decoded", tc.limit, tc.layers, got, decodedFrom, err)
			}
		case tc.raw:
			if err != nil || !bytes.Equal(got, body) || decodedFrom != "" {
				t.Errorf("limit %s %s, %d layers: %q from %q, %v; want it as it came", tc.limit, tc.action, tc.layers, got, decodedFrom, err)
			}
		default:
			want := "content coding limit exceeded (" + strconv.Itoa(tc.layers) + " > " + tc.limit + ")"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("limit %s, %d layers: %v; want %q", tc.limit, tc.layers, err, want)
			}
		}
	}
}

// Chrome sets a response's decoders up whether it has a body or not, and
// refuses a chain deeper than its limit on a HEAD, a 204 and a 304 as on a
// 200 (measured on Chrome 156.0.8078.74: three cohorts, H1 and H2; 10 layers
// came, 11 and 16 failed).
func TestAChainTooDeepIsRefusedOnAnAnswerWithoutABody(t *testing.T) {
	chain := func(n int) fhttp.Header {
		return fhttp.Header{"Content-Encoding": {strings.TrimSuffix(strings.Repeat("gzip, ", n), ", ")}}
	}
	for _, tc := range []struct {
		method string
		status int
	}{{"HEAD", 200}, {"GET", 204}, {"GET", 304}, {"HEAD", 204}, {"HEAD", 304}} {
		for _, n := range []int{1, 10, 11, 16} {
			response := &fhttp.Response{StatusCode: tc.status, Header: chain(n), Body: io.NopCloser(strings.NewReader(""))}
			got, decoded, err := readBody(response, tc.method, 1<<20, codingLimitPolicy("10", "error"))
			if (err != nil) != (n > 10) {
				t.Errorf("%s %d, %d layers: %v", tc.method, tc.status, n, err)
			}
			if err == nil && (len(got) != 0 || decoded != "") {
				t.Errorf("%s %d, %d layers: %q decoded from %q", tc.method, tc.status, n, got, decoded)
			}
		}
		response := &fhttp.Response{StatusCode: tc.status, Header: chain(11), Body: io.NopCloser(strings.NewReader(""))}
		if got, decoded, err := readBody(response, tc.method, 1<<20, codingLimitPolicy("10", "raw")); err != nil || len(got) != 0 || decoded != "" {
			t.Errorf("%s %d, 11 layers left raw: %q decoded from %q, %v", tc.method, tc.status, got, decoded, err)
		}
	}
}

type codingCloser struct {
	io.Reader
	closed *int
	err    error
}

func (r codingCloser) Close() error { *r.closed++; return r.err }

func TestLazyCodingLifecycleAndHardBound(t *testing.T) {
	old := decoders["br"]
	t.Cleanup(func() { decoders["br"] = old })
	created, closed := 0, 0
	decodeErr := errors.New("decoder initialization failed")
	closeErr := errors.New("decoder close failed")
	decoders["br"] = func(io.Reader) (io.ReadCloser, error) {
		created++
		return nil, decodeErr
	}
	layer := &lazyCoding{coding: "br", source: strings.NewReader("x"), policy: codingLimitPolicy("10", "error")}
	if n, err := layer.Read(nil); n != 0 || err != nil || created != 0 {
		t.Fatal("empty read initialized decoder")
	}
	for i := 0; i < 2; i++ {
		if _, err := layer.Read(make([]byte, 1)); !errors.Is(err, decodeErr) {
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatal("failed initialization was repeated")
	}
	if err := layer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := layer.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("read after close", err)
	}
	if err := layer.Close(); err != nil {
		t.Fatal(err)
	}
	decoders["br"] = func(io.Reader) (io.ReadCloser, error) {
		created++
		return codingCloser{Reader: strings.NewReader("x"), closed: &closed, err: closeErr}, nil
	}
	layer = &lazyCoding{coding: "br", source: strings.NewReader("x"), policy: codingLimitPolicy("10", "error")}
	if _, err := layer.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := layer.Close(); !errors.Is(err, closeErr) {
		t.Fatal(err)
	}
	if err := layer.Close(); err != nil || closed != 1 {
		t.Fatal("duplicate close", err, closed)
	}
	for _, test := range []struct{ limit, action string }{{"65", "error"}, {"0", "missing"}} {
		response := &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Content-Encoding": {"br"}}, Body: io.NopCloser(strings.NewReader("x"))}
		before := created
		if _, _, err := readBody(response, "GET", 1<<20, codingLimitPolicy(test.limit, test.action)); err == nil || created != before {
			t.Fatal("invalid policy reached decoder", err)
		}
	}
	// The explicit legacy normalization is selectable data, not the name.
	p := codingLimitPolicy("10", "error")
	p["http.ignored_content_codings"] = json.RawMessage(`["identity"]`)
	if got := codingsOf(fhttp.Header{"Content-Encoding": {"gzip, identity"}}, p); len(got) != 1 || got[0] != "gzip" {
		t.Fatal(got)
	}
}
