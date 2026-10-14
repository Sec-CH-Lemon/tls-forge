package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// pathServer answers every path with a body naming it, so a test can tell one
// result from another.
func pathServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "page %s", r.URL.Path)
	}))
	t.Cleanup(server.Close)
	return server
}

// tlsPathServer is the same stand-in over TLS, so a proxied request to it is a
// CONNECT tunnel rather than an absolute-form GET.
func tlsPathServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "page %s", r.URL.Path)
	}))
	t.Cleanup(server.Close)
	return server
}

// lines decodes the JSON-lines output, keyed by URL so a test does not depend
// on the order several workers happen to finish in.
func lines(t *testing.T, stdout string) map[string]result {
	t.Helper()
	got := map[string]result{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decoding %q: %v", line, err)
		}
		got[r.URL] = r
	}
	return got
}

func TestListFetchesEveryURL(t *testing.T) {
	server := pathServer(t)
	code, stdout, stderr := exec(t, "fetch",
		server.URL+"/one", server.URL+"/two", server.URL+"/three")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}

	got := lines(t, stdout)
	if len(got) != 3 {
		t.Fatalf("got %d results:\n%s", len(got), stdout)
	}
	for _, path := range []string{"/one", "/two", "/three"} {
		r := got[server.URL+path]
		if r.Status != 200 {
			t.Errorf("%s: status = %d, error %q", path, r.Status, r.Error)
		}
		if r.Body != "page "+path {
			t.Errorf("%s: body = %q", path, r.Body)
		}
	}
}

func TestListJSONLPreservesABinaryBody(t *testing.T) {
	want := []byte{0x89, 'P', 'N', 'G', 0xff, 0xd8, 0xff}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(want)
	}))
	defer server.Close()

	code, stdout, stderr := exec(t, "fetch", "--json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	got := lines(t, stdout)[server.URL]
	if got.BodyEncoding != "base64" {
		t.Fatalf("body_encoding = %q, want base64", got.BodyEncoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.Body)
	if err != nil {
		t.Fatalf("body is not base64: %v", err)
	}
	if string(decoded) != string(want) || got.Bytes != len(want) {
		t.Errorf("decoded body = % x (%d bytes reported), want % x", decoded, got.Bytes, want)
	}
}

func TestListReadsEveryFormat(t *testing.T) {
	server := pathServer(t)
	for _, tc := range []struct{ name, file, body string }{
		{"json", "list.json", `[{"url":"%[1]s/one"},"%[1]s/two"]`},
		{"csv", "list.csv", "url,proxy\n%[1]s/one,\n%[1]s/two,\n"},
		{"lines", "list.txt", "%[1]s/one\n%[1]s/two\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeList(t, tc.file, fmt.Sprintf(tc.body, server.URL))
			code, stdout, stderr := exec(t, "fetch", "--input", path)
			if code != 0 {
				t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
			}
			got := lines(t, stdout)
			if len(got) != 2 {
				t.Fatalf("got %d results:\n%s", len(got), stdout)
			}
		})
	}
}

func TestListTakesACommaSeparatedList(t *testing.T) {
	server := pathServer(t)
	code, stdout, _ := exec(t, "fetch", "--urls", server.URL+"/one,"+server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	if got := lines(t, stdout); len(got) != 2 {
		t.Fatalf("got %d results:\n%s", len(got), stdout)
	}
}

func TestListReadsStandardInput(t *testing.T) {
	server := pathServer(t)
	original := listInput
	t.Cleanup(func() { listInput = original })
	listInput = strings.NewReader(server.URL + "/one\n")

	code, stdout, _ := exec(t, "fetch")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	if got := lines(t, stdout); len(got) != 1 {
		t.Fatalf("got %d results:\n%s", len(got), stdout)
	}
}

func TestListUsesEachURLsOwnProxy(t *testing.T) {
	// The point of the feature. Two URLs are given proxies that nothing is
	// listening on, and a third none at all: the first two have to fail against
	// their own port, and the third has to succeed. A run that shared one client
	// could not produce that.
	server := pathServer(t)
	path := writeList(t, "mixed.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/one,http://127.0.0.1:9001\n%[1]s/two,http://127.0.0.1:9002\n%[1]s/three,\n",
		server.URL))

	code, stdout, _ := exec(t, "fetch", "--input", path, "--timeout", "5s")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
	}

	got := lines(t, stdout)
	for port, path := range map[string]string{"9001": "/one", "9002": "/two"} {
		r := got[server.URL+path]
		if r.Error == "" {
			t.Errorf("%s went through: status %d", path, r.Status)
			continue
		}
		if !strings.Contains(r.Error, port) {
			t.Errorf("%s failed against the wrong proxy: %q", path, r.Error)
		}
		if r.Proxy != "http://127.0.0.1:"+port {
			t.Errorf("%s: the result does not record its proxy: %q", path, r.Proxy)
		}
	}
	if r := got[server.URL+"/three"]; r.Status != 200 {
		t.Errorf("the URL with no proxy did not go direct: %+v", r)
	}
}

func TestListFallsBackToTheProxyFlag(t *testing.T) {
	// --proxy is the default for entries that name none, so the two ways of
	// saying it compose instead of one overriding the other.
	server := pathServer(t)
	path := writeList(t, "one.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/named,http://127.0.0.1:9001\n%[1]s/unnamed,\n", server.URL))

	_, stdout, _ := exec(t, "fetch", "--input", path,
		"--proxy", "http://127.0.0.1:9003", "--timeout", "5s")

	got := lines(t, stdout)
	if r := got[server.URL+"/named"]; !strings.Contains(r.Error, "9001") {
		t.Errorf("the entry's own proxy was not used: %q", r.Error)
	}
	if r := got[server.URL+"/unnamed"]; !strings.Contains(r.Error, "9003") {
		t.Errorf("the flag was not used as the default: %q", r.Error)
	} else if r.Proxy != "http://127.0.0.1:9003" {
		t.Errorf("the result records proxy %q, want the fallback proxy", r.Proxy)
	}
}

func TestListKeepsEveryRequestInADirectory(t *testing.T) {
	server := pathServer(t)
	dir := filepath.Join(t.TempDir(), "out")

	code, stdout, stderr := exec(t, "fetch", "--output", dir, server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// What the run came to is commentary, so it goes to stderr with the rest of
	// it, and names where the requests were kept.
	want := "\n  Requests      2\n  Retries       0\n  Success rate  100.0%\n  Avg time      0ms\n" +
		"  Saved to      " + dir + "\n"
	if !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end with what the run came to (%q):\n%s", want, stderr)
	}

	// The lines still go where standard output goes, and name the files rather
	// than carry the pages a second time.
	got := lines(t, stdout)
	if len(got) != 2 {
		t.Fatalf("got %d results", len(got))
	}
	for url, r := range got {
		if r.Body != "" {
			t.Errorf("%s: the body was inlined as well as written out", url)
		}
		body, err := os.ReadFile(r.File)
		if err != nil || !strings.HasPrefix(string(body), "page ") {
			t.Errorf("%s: the page file %q holds %q (%v)", url, r.File, body, err)
		}
		if _, err := os.Stat(r.Log); err != nil {
			t.Errorf("%s: no log at %q: %v", url, r.Log, err)
		}
		if _, err := os.Stat(r.Trace); err != nil {
			t.Errorf("%s: no trace at %q: %v", url, r.Trace, err)
		}
	}
}

func TestListKeepsRepeatedURLBodiesSeparate(t *testing.T) {
	var replies atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "response-%d", replies.Add(1))
	}))
	t.Cleanup(server.Close)

	dir := filepath.Join(t.TempDir(), "out")
	code, stdout, stderr := exec(t, "fetch", "--progress", "never", "--concurrency", "2",
		"--output", dir, server.URL, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\nstderr: %s", code, stderr)
	}

	var results []result
	decoder := json.NewDecoder(strings.NewReader(stdout))
	for decoder.More() {
		var r result
		if err := decoder.Decode(&r); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		results = append(results, r)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results: %s", len(results), stdout)
	}
	if results[0].File == results[1].File {
		t.Fatalf("repeated URL results share %q", results[0].File)
	}
	bodies := map[string]bool{}
	for _, r := range results {
		body, err := os.ReadFile(r.File)
		if err != nil {
			t.Fatalf("read %s: %v", r.File, err)
		}
		bodies[string(body)] = true
	}
	if !bodies["response-1"] || !bodies["response-2"] {
		t.Errorf("body files = %v", bodies)
	}
}

func TestListRetries(t *testing.T) {
	var mu sync.Mutex
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 3 {
			// Hang up without answering, which is a transport error rather than
			// an answer of any kind.
			hijacked, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = hijacked.Close()
			}
			return
		}
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)

	code, stdout, _ := exec(t, "fetch", "--json", "--retry", "2", "--timeout", "10s", server.URL+"/flaky")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	// One try, then the two it was allowed on top.
	r := lines(t, stdout)[server.URL+"/flaky"]
	if r.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", r.Attempts)
	}
}

func TestListTriesOnceWhenToldNotToRetry(t *testing.T) {
	server := pathServer(t)
	_, stdout, _ := exec(t, "fetch", "--json", "--retry", "0", server.URL+"/one")
	if r := lines(t, stdout)[server.URL+"/one"]; r.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", r.Attempts)
	}
}

func TestListTriesOnceUnlessToldOtherwise(t *testing.T) {
	// A list is asked for the way one URL is: once each. Trying again is for
	// whoever says how many times.
	_, stdout, _ := exec(t, "fetch", "--json", "--timeout", "3s", "https://127.0.0.1:1/gone")
	if r := lines(t, stdout)["https://127.0.0.1:1/gone"]; r.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", r.Attempts)
	}
}

func TestRetryBackoff(t *testing.T) {
	// A retry with no pause is not another try: it is the same failure in the
	// same microsecond, against a host whose situation has not had time to
	// change.
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{
		{1, 250 * time.Millisecond},
		{2, 500 * time.Millisecond},
		{3, time.Second},
		{4, 2 * time.Second},
		// Capped: a run has better things to do than wait out an outage.
		{9, 2 * time.Second},
	} {
		if got := backoff(tc.attempt); got != tc.want {
			t.Errorf("backoff(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestRetryActuallyPauses(t *testing.T) {
	// The suite runs without the waits; this is the one test that puts them
	// back, so "there is a pause" is measured rather than assumed.
	original := retryWait
	t.Cleanup(func() { retryWait = original })
	retryWait = backoff

	started := time.Now()
	_, stdout, _ := exec(t, "fetch", "--json", "--retry", "1", "--timeout", "3s",
		"https://127.0.0.1:1/gone")
	elapsed := time.Since(started)

	if r := lines(t, stdout)["https://127.0.0.1:1/gone"]; r.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", r.Attempts)
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("the two tries took %v, so nothing waited between them", elapsed)
	}
}

func TestRetryDoesNotWaitOutAnInterruptedRun(t *testing.T) {
	// Ctrl-C during a backoff should end the run, not finish the nap first.
	original := retryWait
	t.Cleanup(func() { retryWait = original })
	retryWait = func(int) time.Duration { return 30 * time.Second }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"fetch", "--retry", "5", "--timeout", "3s",
			"--progress", "never", "https://127.0.0.1:1/gone"},
			&strings.Builder{}, &strings.Builder{})
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		if code == 0 {
			t.Error("an interrupted run reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run waited out its backoff after being interrupted")
	}
}

func TestListArgumentErrors(t *testing.T) {
	server := pathServer(t)
	// A count that cannot be honoured is a usage error, so it exits 2 and not
	// the 1 that means "some URLs failed".
	for _, args := range [][]string{
		{"fetch", "--concurrency", "0", server.URL},
		{"fetch", "--retry", "-1", server.URL},
		{"fetch", "--retry", fmt.Sprint(math.MaxInt), server.URL},
		{"fetch", "--repeat", "0", server.URL},
		// More passes than there are requests to count them in.
		{"fetch", "--repeat", fmt.Sprint(math.MaxInt), server.URL, server.URL},
		{"fetch", "--nonsense"},
	} {
		if code, _, _ := exec(t, args...); code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, code)
		}
	}

	original := listInput
	t.Cleanup(func() { listInput = original })
	listInput = strings.NewReader("")

	for _, args := range [][]string{
		{"fetch"},              // an empty list
		{"fetch", "not-a-url"}, // rejected before anything is fetched
		{"fetch", "--input", "no-such-file.json"}, // an unreadable list
		{"fetch", "--format", "yaml", server.URL}, // a format that does not exist
	} {
		if code, _, _ := exec(t, args...); code != 1 && code != 2 {
			t.Errorf("%v: exit code = %d", args, code)
		}
	}
}

func TestListStopsWhenItCannotKeepWhatItFetched(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits: chmod only toggles read-only, so the write this needs to fail succeeds")
	}
	// The directory is there when the run starts and cannot be written to by the
	// time the first page is in. Nowhere to keep that one is nowhere to keep the
	// next, so the run ends rather than fetch pages to throw away.
	server, asked := replying(t, 200)
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	code, _, stderr := exec(t, "fetch", "--output", dir, "--concurrency", "1",
		server.URL+"/one", server.URL+"/two", server.URL+"/three")
	if code != 1 || !strings.Contains(stderr, "tlsforge: fetch: ") {
		t.Errorf("exit code = %d, want 1\n%s", code, stderr)
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("the server was asked %d times after the first page could not be kept", got)
	}
}

func TestPoolKeepsOneClientPerProxy(t *testing.T) {
	// One per proxy, not one per worker: the proxy is the identity, and two
	// pages through one exit IP should share a jar.
	fs := newFlagSet("fetch", newPrinter(os.Stdout))
	flags := addClientFlags(fs)
	if err := parse(fs, nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	p := newPool(flags, "")
	defer p.close()

	first, err := p.get("http://127.0.0.1:9001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	again, err := p.get("http://127.0.0.1:9001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if first != again {
		t.Error("the same proxy produced two clients")
	}

	other, err := p.get("http://127.0.0.1:9002")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if other == first {
		t.Error("two proxies shared one client")
	}

	// An entry naming no proxy falls back to the flag, so it must not become a
	// third identity of its own.
	fallback := newPool(flags, "http://127.0.0.1:9001")
	defer fallback.close()
	viaEmpty, err := fallback.get("")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	viaNamed, err := fallback.get("http://127.0.0.1:9001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if viaEmpty != viaNamed {
		t.Error("the fallback proxy produced a second client")
	}
}

func TestListStopsHandingOutWorkWhenInterrupted(t *testing.T) {
	// What is in flight finishes; what has not started does not begin. Without
	// it, Ctrl-C on a list of ten thousand keeps fetching.
	released := make(chan struct{})
	started := make(chan struct{}, 50)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-released
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(func() { close(released); server.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	urls := make([]string, 0, 50)
	for i := range 50 {
		urls = append(urls, fmt.Sprintf("%s/%d", server.URL, i))
	}

	var stdout strings.Builder
	done := make(chan int, 1)
	go func() {
		args := append([]string{"fetch", "--concurrency", "2", "--timeout", "2s"}, urls...)
		done <- run(ctx, args, &stdout, &strings.Builder{})
	}()

	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("two workers did not start requests")
		}
	}
	cancel()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not stop after the context was cancelled")
	}
	if got := len(lines(t, stdout.String())); got != 2 {
		t.Fatalf("got %d results after interrupt, want only the two in flight\n%s", got, stdout.String())
	}
}

func TestListReportsAProxyItCannotUse(t *testing.T) {
	// A typo in the proxy column. It is the entry's failure, not the run's:
	// the other URLs still go out, and the line says which one was wrong.
	server := pathServer(t)
	path := writeList(t, "typo.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/bad,::not a proxy::\n%[1]s/good,\n", server.URL))

	code, stdout, _ := exec(t, "fetch", "--input", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
	}
	got := lines(t, stdout)
	if r := got[server.URL+"/bad"]; r.Error == "" {
		t.Errorf("the unusable proxy was accepted: %+v", r)
	}
	if r := got[server.URL+"/good"]; r.Status != 200 {
		t.Errorf("one bad proxy stopped the rest of the run: %+v", r)
	}
}

func TestListWarnsAboveTheCoreCount(t *testing.T) {
	original := numCPU
	t.Cleanup(func() { numCPU = original })
	numCPU = func() int { return 4 }

	server := pathServer(t)

	for _, tc := range []struct {
		name    string
		workers string
		want    bool
	}{
		{"below the core count", "2", false},
		{"exactly the core count", "4", false},
		{"above it", "16", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := exec(t, "fetch", "--json", "-c", tc.workers, server.URL+"/one")
			if code != 0 {
				t.Fatalf("exit code = %d\n%s", code, stderr)
			}
			warned := strings.Contains(stderr, "WARN")
			if warned != tc.want {
				t.Errorf("warned = %v, want %v; stderr = %q", warned, tc.want, stderr)
			}
			if tc.want {
				// It has to say both numbers, or the reader cannot tell what it
				// asked for from what the machine has.
				for _, part := range []string{tc.workers, "4", "cores"} {
					if !strings.Contains(stderr, part) {
						t.Errorf("stderr does not mention %q: %q", part, stderr)
					}
				}
			}
			// Whatever it says, it must not say it on stdout: that stream is
			// JSON lines, and a reader of them would choke.
			if strings.Contains(stdout, "WARN") {
				t.Errorf("the warning landed on stdout:\n%s", stdout)
			}
			for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
				var r result
				if err := json.Unmarshal([]byte(line), &r); err != nil {
					t.Errorf("stdout is not JSON lines: %q", line)
				}
			}
		})
	}
}

func TestListDoesNotWarnBeforeItFailsOnTheFlags(t *testing.T) {
	// A warning about a number that was rejected anyway is noise.
	original := numCPU
	t.Cleanup(func() { numCPU = original })
	numCPU = func() int { return 1 }

	code, _, stderr := exec(t, "fetch", "-c", "0", "https://example.com/")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if strings.Contains(stderr, "WARN") {
		t.Errorf("warned about a rejected value: %q", stderr)
	}
}

func TestListDrawsAStatusLine(t *testing.T) {
	// --progress always, so the assertion does not depend on what the test's
	// stderr happens to be attached to.
	server := pathServer(t)
	code, stdout, stderr := exec(t, "fetch", "--progress", "always",
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	// The bar, full, with the run's own total, and under it how long it took
	// and how much came back.
	for _, want := range []string{"████████████████████████████████████████  2/2  100%", " elapsed · ", " B"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%q", want, stderr)
		}
	}
	// And none of it on the stream carrying the results.
	if strings.Contains(stdout, "\x1b") || strings.Contains(stdout, "elapsed") {
		t.Errorf("the status line landed on stdout:\n%q", stdout)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Errorf("stdout is not JSON lines: %q", line)
		}
	}
}

func TestListWithoutAStatusLine(t *testing.T) {
	// The default is auto, and a test's stderr is not a terminal.
	server := pathServer(t)
	for _, args := range [][]string{
		{"fetch", server.URL + "/one"},
		{"fetch", "--progress", "never", server.URL + "/one"},
	} {
		_, _, stderr := exec(t, args...)
		if strings.Contains(stderr, "elapsed") {
			t.Errorf("%v drew a status line into something that is not a terminal: %q",
				args, stderr)
		}
	}
}

func TestListRejectsAnUnknownProgressMode(t *testing.T) {
	// Rejected before the list is read, so a typo does not cost a run that then
	// has nowhere to report itself.
	code, _, stderr := exec(t, "fetch", "--progress", "sometimes", "https://example.com/")
	if code != 1 {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(stderr, "--progress") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestListKeepsNoBodiesInMemory(t *testing.T) {
	// The summary and the report show counts, not pages, so a run holds only
	// what they need. Kept whole, 200 MB of pages measured 353 MB of resident
	// memory against 117 MB once the bodies went.
	server := pathServer(t)
	fs := newFlagSet("fetch", newPrinter(io.Discard))
	flags := addClientFlags(fs)
	if err := parse(fs, nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	clients := newPool(flags, "")
	defer clients.close()

	var sink strings.Builder
	var records []result
	jobs := []job{{URL: server.URL + "/one"}, {URL: server.URL + "/two"}}
	failed, err := runJobs(context.Background(), jobs, runner{
		clients: clients, workers: 2, retry: 1, repeat: 1,
		out:    &linesOutput{encoder: json.NewEncoder(&sink), say: (&stderrLog{}).say},
		counts: newProgress(len(jobs)),
	}, &records)
	if err != nil {
		t.Fatalf("runJobs: %v", err)
	}
	if failed != 0 {
		t.Fatalf("%d of the jobs failed", failed)
	}

	if len(records) != 2 {
		t.Fatalf("kept %d records", len(records))
	}
	for _, r := range records {
		if r.Body != "" {
			t.Errorf("%s: the page was kept in memory (%d bytes)", r.URL, len(r.Body))
		}
		// The rest is what the report is made of, and has to survive.
		if r.Status != 200 || r.Bytes == 0 || r.Started.IsZero() || r.Ended.IsZero() {
			t.Errorf("%s: the record lost something the report needs: %+v", r.URL, r)
		}
	}
	// And the page still reaches whoever asked for the output.
	if !strings.Contains(sink.String(), "page /one") {
		t.Errorf("the body did not reach the output: %q", sink.String())
	}
}

func TestRunJobsReportsAnOutputWriteFailure(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)
	fs := newFlagSet("fetch", newPrinter(io.Discard))
	flags := addClientFlags(fs)
	if err := parse(fs, nil); err != nil {
		t.Fatal(err)
	}
	clients := newPool(flags, "")
	defer clients.close()

	jobs := make([]job, 100)
	for i := range jobs {
		jobs[i] = job{URL: fmt.Sprintf("%s/%d", server.URL, i)}
	}
	var records []result
	_, err := runJobs(context.Background(), jobs, runner{
		clients: clients, workers: 1, repeat: 1,
		out:    &linesOutput{encoder: json.NewEncoder(failingWriter{}), say: (&stderrLog{}).say},
		counts: newProgress(len(jobs)),
	}, &records)
	if err == nil || !strings.Contains(err.Error(), "writing result") {
		t.Fatalf("error = %v, want output write failure", err)
	}
	if got := requests.Load(); got >= int64(len(jobs)) {
		t.Fatalf("fetched all %d jobs after output failed", got)
	}
}

func TestVerboseLine(t *testing.T) {
	// Fixed-width columns, so a run scrolling past stays a column of statuses
	// rather than a paragraph.
	for _, tc := range []struct {
		name string
		r    result
		want []string
	}{
		{
			"a page",
			result{URL: "https://a/", Status: 200, Bytes: 559, Millis: 74, Attempts: 1},
			[]string{"200", "559 B", "74ms", "https://a/"},
		},
		{
			"an answer that is not the page",
			result{URL: "https://b/", Status: 503, Millis: 797, Attempts: 1},
			[]string{"503", "0 B", "797ms"},
		},
		{
			"nothing came back, after retries",
			result{URL: "https://c/", Millis: 423, Attempts: 4, Error: "connection refused"},
			// No status to print, and the attempt count earns a column.
			[]string{"---", "x4", "connection refused"},
		},
		{
			"through a proxy",
			result{URL: "https://d/", Status: 200, Proxy: "http://p:8080", Attempts: 1},
			[]string{"via http://p:8080"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := verboseLine(tc.r)
			for _, want := range tc.want {
				if !strings.Contains(line, want) {
					t.Errorf("the line has no %q: %q", want, line)
				}
			}
			if strings.Contains(line, "\n") {
				t.Errorf("one request took more than one line: %q", line)
			}
		})
	}
	// An attempt count of one is not worth a number; the column stays for width.
	if strings.Contains(verboseLine(result{URL: "https://a/", Status: 200, Attempts: 1}), "x1") {
		t.Error("a single attempt was labelled")
	}
}

func TestListVerbose(t *testing.T) {
	server := pathServer(t)
	code, stdout, stderr := exec(t, "fetch", "-v", "--progress", "never",
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	for _, want := range []string{server.URL + "/one", server.URL + "/two", "200"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
	// On stderr, with everything else that is commentary, so the JSON lines
	// stay readable by whatever is consuming them.
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Errorf("stdout is not JSON lines: %q", line)
		}
	}
}

func TestListQuietByDefault(t *testing.T) {
	server := pathServer(t)
	_, _, stderr := exec(t, "fetch", "--progress", "never", server.URL+"/one")
	if strings.Contains(stderr, server.URL+"/one") {
		t.Errorf("a request was reported without being asked for:\n%s", stderr)
	}
}

func TestVerboseAndTheStatusLineShareTheStream(t *testing.T) {
	// Both draw on stderr. Without the status line stepping aside they land on
	// each other and the reader gets neither.
	server := pathServer(t)
	_, _, stderr := exec(t, "fetch", "-v", "--progress", "always",
		server.URL+"/one", server.URL+"/two")

	// Asked of the terminal rather than of the bytes: the status line redraws
	// in place and carries no newline, so a raw chunk holding a frame and a
	// request's line is what correct output looks like. What matters is what
	// ends up on screen.
	screen := replay(stderr)
	var reported int
	for _, line := range screen {
		if !strings.Contains(line, server.URL) {
			continue
		}
		reported++
		if strings.ContainsAny(line, "█▓▒░") || strings.Contains(line, "elapsed") || strings.Contains(line, "\x1b") {
			t.Errorf("a request's line shares a row with the status: %q", line)
		}
	}
	if reported != 2 {
		t.Errorf("%d of the 2 requests reached the screen:\n%q", reported, screen)
	}
	// And the status line survived to the end, under them.
	if last := screen[len(screen)-1]; !strings.Contains(strings.Join(screen, "\n"), "2/2") {
		t.Errorf("the status line was lost; last row %q", last)
	}
}

// replay works out what a terminal ends up showing, given a stream that moves
// the cursor about. \r returns to the start of the row, ESC[A goes up a row,
// ESC[K erases from the cursor to the end of the row, and a colour changes
// nothing about where anything is.
func replay(stream string) []string {
	rows := [][]rune{nil}
	row, col := 0, 0
	for i := 0; i < len(stream); {
		rest := stream[i:]
		if strings.HasPrefix(rest, eraseToEnd) {
			rows[row] = rows[row][:min(col, len(rows[row]))]
			i += len(eraseToEnd)
			continue
		}
		if strings.HasPrefix(rest, cursorUp) {
			row = max(row-1, 0)
			i += len(cursorUp)
			continue
		}
		if end := strings.IndexByte(rest, 'm'); strings.HasPrefix(rest, "\x1b[") && end >= 0 {
			i += end + 1
			continue
		}

		r, width := utf8.DecodeRuneInString(rest)
		i += width
		switch r {
		case '\r':
			col = 0
		case '\n':
			row, col = row+1, 0
			if row == len(rows) {
				rows = append(rows, nil)
			}
		default:
			for len(rows[row]) < col {
				rows[row] = append(rows[row], ' ')
			}
			if col < len(rows[row]) {
				rows[row][col] = r
			} else {
				rows[row] = append(rows[row], r)
			}
			col++
		}
	}

	screen := make([]string, 0, len(rows))
	for _, runes := range rows {
		screen = append(screen, string(runes))
	}
	// The row the cursor was left on, when nothing was ever written to it.
	if last := len(screen) - 1; screen[last] == "" {
		screen = screen[:last]
	}
	return screen
}

func TestStderrLogWithoutAStatusLine(t *testing.T) {
	// Several workers write here, so it takes a lock of its own when there is
	// no status line to work around.
	var out strings.Builder
	log := &stderrLog{out: newPrinter(&out), on: true}

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.say(fmt.Sprintf("line %02d", i))
		}()
	}
	wg.Wait()

	if got := len(strings.Split(strings.TrimSpace(out.String()), "\n")); got != 50 {
		t.Errorf("%d lines, want 50", got)
	}
	// Nothing is half-written into anything else.
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if len(line) != len("line 00") {
			t.Errorf("a line came out mangled: %q", line)
		}
	}
}

func TestFetchSaysWhatItNeedsWhenNothingNamesAURL(t *testing.T) {
	// Nothing named a URL and standard input is a terminal, so there is no list
	// coming either. Waiting to be typed at looks like having hung, which is how
	// that was once reported, so it is said at once and nothing is waited for.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("opening %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })

	original := listInput
	t.Cleanup(func() { listInput = original })
	// A character device, which is what a terminal is to this question.
	listInput = devNull

	code, stdout, stderr := exec(t, "fetch")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	for _, want := range []string{"needs a URL", "--input", "--urls", "standard input"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
	if !strings.Contains(stdout, "usage: tls-forge fetch") {
		t.Errorf("the usage was not printed: %q", stdout)
	}
}

func TestListPipedInIsReadWithoutBeingAskedFor(t *testing.T) {
	// A list on standard input is a list, and its lines come out as a list's do
	// however many of them there are.
	server := pathServer(t)
	original := listInput
	t.Cleanup(func() { listInput = original })
	listInput = strings.NewReader(server.URL + "/one\n")

	code, stdout, stderr := exec(t, "fetch")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if r := lines(t, stdout)[server.URL+"/one"]; r.Status != 200 || r.Body != "page /one" {
		t.Errorf("stdout is not the line for the one URL in the list: %q", stdout)
	}
}

// One command for one URL and for a list of them.

func TestFetchAnswersInTheShapeItWasAskedIn(t *testing.T) {
	// The page when the command names the one URL it is after. A line of JSON
	// for each request when it names several, or a list, or asks for lines: by
	// how it was asked rather than by how many URLs turned up, so that a list
	// which happens to hold one is not answered in another shape.
	server := pathServer(t)
	one := server.URL + "/one"
	list := writeList(t, "one.txt", one+"\n")
	kept := filepath.Join(t.TempDir(), "out")

	for _, tc := range []struct {
		name    string
		args    []string
		asLines bool
	}{
		{"one URL", []string{one}, false},
		{"one URL, asked for as a line", []string{"--json", one}, true},
		// Kept in a directory, one URL is still answered with its page.
		{"one URL, kept in a directory", []string{"--output", kept, "--print-body", one}, false},
		{"a list of one, in a file", []string{"--input", list}, true},
		{"a list of one, on the command line", []string{"--urls", one}, true},
		{"two URLs", []string{one, server.URL + "/two"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := exec(t, append([]string{"fetch"}, tc.args...)...)
			if code != 0 {
				t.Fatalf("exit code = %d\n%s", code, stderr)
			}
			if !tc.asLines {
				if stdout != "page /one" {
					t.Errorf("stdout = %q, want the page and nothing else", stdout)
				}
				return
			}
			r, found := lines(t, stdout)[one]
			if !found || r.Status != 200 || r.Bytes != len("page /one") {
				t.Errorf("stdout is not a line for the URL: %q", stdout)
			}
		})
	}

	// Kept in a directory, a line names the file the page is in and does not
	// carry the page as well.
	_, stdout, _ := exec(t, "fetch", "--output", kept, "--json", one)
	r := lines(t, stdout)[one]
	if page, err := os.ReadFile(r.File); err != nil || string(page) != "page /one" || r.Body != "" {
		t.Errorf("the line names %q, which holds %q (%v), and carries %q itself", r.File, page, err, r.Body)
	}
}

func TestListLinesCarryTheHeadersWhenAsked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "the stand-in")
		_, _ = fmt.Fprintf(w, "page %s", r.URL.Path)
	}))
	t.Cleanup(server.Close)
	urls := []string{server.URL + "/one", server.URL + "/two"}

	// What -i prints in front of a page, a line has room for inside it.
	_, stdout, _ := exec(t, append([]string{"fetch", "-i"}, urls...)...)
	got := lines(t, stdout)
	for _, url := range urls {
		// Under the name the client hands it over by, which is lower case.
		if served := got[url].Header["x-served-by"]; len(served) != 1 || served[0] != "the stand-in" {
			t.Errorf("%s: headers = %v", url, got[url].Header)
		}
	}
	// And not otherwise: a line is what it has always been.
	if _, stdout, _ = exec(t, append([]string{"fetch"}, urls...)...); strings.Contains(stdout, `"headers"`) {
		t.Errorf("the lines carry headers nobody asked for: %s", stdout)
	}
}

func TestListIsAskedForTheWayOneURLIs(t *testing.T) {
	// The method, the header fields and the body are the request, and a list is
	// that request made of every URL in it.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s %s %s %s", r.Method, r.URL.Path, r.Header.Get("X-Asked-By"), sent)
	}))
	t.Cleanup(server.Close)

	code, stdout, stderr := exec(t, "fetch", "-X", "POST", "-H", "X-Asked-By: a test", "-d", "payload",
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	got := lines(t, stdout)
	for _, path := range []string{"/one", "/two"} {
		if want := "POST " + path + " a test payload"; got[server.URL+path].Body != want {
			t.Errorf("%s was asked for with %q, want %q", path, got[server.URL+path].Body, want)
		}
	}
}

func TestFetchRepeatsOneAtATimeUnlessToldHowMany(t *testing.T) {
	server, _ := replying(t, 200)
	dir := t.TempDir()
	rowsOf := func(path string) (rows map[int]string, onCommandRow int, concurrency any) {
		events := traceFile(t, path)
		checkShape(t, events)
		rows = map[int]string{}
		for _, lane := range named(events, phaseMetadata, "thread_name") {
			rows[lane.TID] = fmt.Sprint(lane.Args["name"])
		}
		for _, event := range events {
			if event.Phase == phaseBegin && event.Cat == "request" && event.TID == mainLane {
				onCommandRow++
			}
		}
		return rows, onCommandRow, one(t, events, phaseBegin, "fetch").Args["concurrency"]
	}

	// One URL is asked for the way a page is reloaded: again, when the last
	// answer is in. Its requests are drawn on the command's own row.
	alone := filepath.Join(dir, "alone.json")
	if code, _, stderr := exec(t, "fetch", "--repeat", "4", "--trace", alone, server.URL); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	rows, onCommandRow, concurrency := rowsOf(alone)
	if len(rows) != 1 || rows[mainLane] != "fetch" || onCommandRow != 4 || concurrency != 1.0 {
		t.Errorf("one at a time: rows %v, %d requests on the command's row, concurrency %v", rows, onCommandRow, concurrency)
	}

	// Told how many at once, it is that many workers, each with a row, and every
	// run still keeps its page under its own number.
	together, kept := filepath.Join(dir, "together.json"), filepath.Join(dir, "out")
	code, _, stderr := exec(t, "fetch", "--repeat", "4", "-c", "2", "--trace", together, "-o", kept, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	rows, onCommandRow, concurrency = rowsOf(together)
	if want := map[int]string{1: "fetch", 2: "worker 1", 3: "worker 2"}; fmt.Sprint(rows) != fmt.Sprint(want) ||
		onCommandRow != 0 || concurrency != 2.0 {
		t.Errorf("two at a time: rows %v, %d requests on the command's row, concurrency %v", rows, onCommandRow, concurrency)
	}
	for run := 1; run <= 4; run++ {
		if pages, _ := filepath.Glob(filepath.Join(kept, fmt.Sprintf("*-%d.html", run))); len(pages) != 1 {
			t.Errorf("run %d kept no page among %v", run, keptIn(t, kept))
		}
	}
	if want := "\n  Saved to      " + kept + "\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end by naming the directory (%q):\n%s", want, stderr)
	}
}

func TestListThroughAProxyThatCannotBeUsedFailsBeforeItStarts(t *testing.T) {
	// One way for every URL is one client, made before anything is fetched: a
	// proxy that cannot be used is the command's failure, said once, rather
	// than the same failure on every line.
	server, asked := replying(t, 200)

	code, stdout, stderr := exec(t, "fetch", "--proxy", "::not a proxy::", server.URL+"/one", server.URL+"/two")
	if code != 1 || stdout != "" {
		t.Errorf("exit code = %d and stdout = %q, want 1 and nothing\n%s", code, stdout, stderr)
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("%d requests were made through a proxy that cannot be used", got)
	}
	// What the run was wearing is still closed off, with no address under it.
	if strings.Count(stderr, identityRule) != 2 || strings.Contains(stderr, "exit-ip") {
		t.Errorf("the report of what the run was wearing was left open, or names an address:\n%s", stderr)
	}
}

func TestSameWay(t *testing.T) {
	for _, tc := range []struct {
		name     string
		jobs     []job
		fallback string
		proxy    string
		same     bool
	}{
		{"one URL, direct", []job{{URL: "a"}}, "", "", true},
		{"every URL through the flag's proxy", []job{{URL: "a"}, {URL: "b"}}, "http://p", "http://p", true},
		// Naming the proxy the flag names is going the same way as not naming one.
		{"a URL that names the flag's proxy", []job{{URL: "a", Proxy: "http://p"}, {URL: "b"}}, "http://p", "http://p", true},
		{"two proxies", []job{{URL: "a", Proxy: "http://p1"}, {URL: "b", Proxy: "http://p2"}}, "", "", false},
		{"a proxy and none", []job{{URL: "a"}, {URL: "b", Proxy: "http://p1"}}, "", "", false},
	} {
		if proxy, same := sameWay(tc.jobs, tc.fallback); proxy != tc.proxy || same != tc.same {
			t.Errorf("%s: %q, %v, want %q, %v", tc.name, proxy, same, tc.proxy, tc.same)
		}
	}
}

func TestEndingSaysWhereEverythingWent(t *testing.T) {
	everything := ending{saved: "out/", unprinted: true, reports: []string{"run.html", "run.json"}}
	// As rows of the figures a run of several requests ends with.
	wantRows := [][2]string{
		{"Saved to", "out/"},
		{"JSON lines", "not printed on a terminal; > FILE keeps them, --print-body shows them"},
		{"Report", "run.html"},
		{"Report", "run.json"},
	}
	if got := everything.rows(); !slices.Equal(got, wantRows) {
		t.Errorf("rows = %q", got)
	}
	// And as one request says them, under the line it has said the rest on.
	wantLines := []string{
		"saved to out/",
		"JSON lines not printed on a terminal; > FILE keeps them, --print-body shows them",
		"report written to run.html",
		"report written to run.json",
	}
	if got := everything.lines(); !slices.Equal(got, wantLines) {
		t.Errorf("lines = %q", got)
	}
	// A run that left nothing anywhere has nothing to add.
	if nothing := (ending{}); nothing.rows() != nil || nothing.lines() != nil {
		t.Errorf("a run that left nothing says %q and %q", nothing.rows(), nothing.lines())
	}
}
