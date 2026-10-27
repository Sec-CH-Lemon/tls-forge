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
