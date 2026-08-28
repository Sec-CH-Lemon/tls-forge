package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// batchServer answers every path with a body naming it, so a test can tell one
// result from another.
func batchServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "page %s", r.URL.Path)
	}))
	t.Cleanup(server.Close)
	return server
}

// tlsBatchServer is the same stand-in over TLS, so a proxied request to it is a
// CONNECT tunnel rather than an absolute-form GET.
func tlsBatchServer(t *testing.T) *httptest.Server {
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

func TestBatchFetchesEveryURL(t *testing.T) {
	server := batchServer(t)
	code, stdout, stderr := exec(t, "batch",
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

func TestBatchJSONLPreservesABinaryBody(t *testing.T) {
	want := []byte{0x89, 'P', 'N', 'G', 0xff, 0xd8, 0xff}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(want)
	}))
	defer server.Close()

	code, stdout, stderr := exec(t, "batch", server.URL)
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

func TestBatchReadsEveryFormat(t *testing.T) {
	server := batchServer(t)
	for _, tc := range []struct{ name, file, body string }{
		{"json", "list.json", `[{"url":"%[1]s/one"},"%[1]s/two"]`},
		{"csv", "list.csv", "url,proxy\n%[1]s/one,\n%[1]s/two,\n"},
		{"lines", "list.txt", "%[1]s/one\n%[1]s/two\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeList(t, tc.file, fmt.Sprintf(tc.body, server.URL))
			code, stdout, stderr := exec(t, "batch", "--input", path)
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

func TestBatchTakesACommaSeparatedList(t *testing.T) {
	server := batchServer(t)
	code, stdout, _ := exec(t, "batch", "--urls", server.URL+"/one,"+server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	if got := lines(t, stdout); len(got) != 2 {
		t.Fatalf("got %d results:\n%s", len(got), stdout)
	}
}

func TestBatchReadsStandardInput(t *testing.T) {
	server := batchServer(t)
	original := batchInput
	t.Cleanup(func() { batchInput = original })
	batchInput = strings.NewReader(server.URL + "/one\n")

	code, stdout, _ := exec(t, "batch")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	if got := lines(t, stdout); len(got) != 1 {
		t.Fatalf("got %d results:\n%s", len(got), stdout)
	}
}

func TestBatchUsesEachURLsOwnProxy(t *testing.T) {
	// The point of the feature. Two URLs are given proxies that nothing is
	// listening on, and a third none at all: the first two have to fail against
	// their own port, and the third has to succeed. A run that shared one client
	// could not produce that.
	server := batchServer(t)
	path := writeList(t, "mixed.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/one,http://127.0.0.1:9001\n%[1]s/two,http://127.0.0.1:9002\n%[1]s/three,\n",
		server.URL))

	code, stdout, _ := exec(t, "batch", "--input", path, "--timeout", "5s")
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

func TestBatchFallsBackToTheProxyFlag(t *testing.T) {
	// --proxy is the default for entries that name none, so the two ways of
	// saying it compose instead of one overriding the other.
	server := batchServer(t)
	path := writeList(t, "one.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/named,http://127.0.0.1:9001\n%[1]s/unnamed,\n", server.URL))

	_, stdout, _ := exec(t, "batch", "--input", path,
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

func TestBatchWritesToAFileAndADirectory(t *testing.T) {
	server := batchServer(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "results.jsonl")
	bodyDir := filepath.Join(dir, "bodies")

	code, stdout, stderr := exec(t, "batch", "--output", outPath, "--body-dir", bodyDir,
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// The summary is commentary, so it goes to stderr with the rest of it, and
	// names where the results went.
	for _, want := range []string{"Scraped      2", outPath} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stdout, "Scraped") {
		t.Errorf("the summary landed on stdout: %q", stdout)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading the results: %v", err)
	}
	got := lines(t, string(data))
	if len(got) != 2 {
		t.Fatalf("got %d results", len(got))
	}
	for url, r := range got {
		if r.Body != "" {
			t.Errorf("%s: the body was inlined as well as written out", url)
		}
		body, err := os.ReadFile(r.File)
		if err != nil {
			t.Fatalf("reading %s: %v", r.File, err)
		}
		if !strings.HasPrefix(string(body), "page ") {
			t.Errorf("%s: body file holds %q", url, body)
		}
	}
}

func TestBatchRetries(t *testing.T) {
	var mu sync.Mutex
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 3 {
			// Hang up without answering, which is a transport error rather than
			// a status a retry would not help with.
			hijacked, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = hijacked.Close()
			}
			return
		}
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)

	code, stdout, _ := exec(t, "batch", "--repeat", "2", "--timeout", "10s", server.URL+"/flaky")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	// One try, then the two it was told to repeat.
	r := lines(t, stdout)[server.URL+"/flaky"]
	if r.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", r.Attempts)
	}
}

func TestBatchTriesOnceWhenToldNotToRepeat(t *testing.T) {
	server := batchServer(t)
	_, stdout, _ := exec(t, "batch", "--repeat", "0", server.URL+"/one")
	if r := lines(t, stdout)[server.URL+"/one"]; r.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", r.Attempts)
	}
}

func TestBatchRepeatsThreeTimesByDefault(t *testing.T) {
	// A URL that never comes back is tried once and then three times more.
	_, stdout, _ := exec(t, "batch", "--timeout", "3s", "https://127.0.0.1:1/gone")
	if r := lines(t, stdout)["https://127.0.0.1:1/gone"]; r.Attempts != 4 {
		t.Errorf("attempts = %d, want 4", r.Attempts)
	}
}

func TestRepeatBackoff(t *testing.T) {
	// A repeat with no pause is not another try: it is the same failure in the
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
		// Capped: a batch has better things to do than wait out an outage.
		{9, 2 * time.Second},
	} {
		if got := backoff(tc.attempt); got != tc.want {
			t.Errorf("backoff(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestRepeatActuallyPauses(t *testing.T) {
	// The suite runs without the waits; this is the one test that puts them
	// back, so "there is a pause" is measured rather than assumed.
	original := repeatWait
	t.Cleanup(func() { repeatWait = original })
	repeatWait = backoff

	started := time.Now()
	_, stdout, _ := exec(t, "batch", "--repeat", "1", "--timeout", "3s",
		"https://127.0.0.1:1/gone")
	elapsed := time.Since(started)

	if r := lines(t, stdout)["https://127.0.0.1:1/gone"]; r.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", r.Attempts)
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("the two tries took %v, so nothing waited between them", elapsed)
	}
}

func TestRepeatDoesNotWaitOutAnInterruptedRun(t *testing.T) {
	// Ctrl-C during a backoff should end the run, not finish the nap first.
	original := repeatWait
	t.Cleanup(func() { repeatWait = original })
	repeatWait = func(int) time.Duration { return 30 * time.Second }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"batch", "--repeat", "5", "--timeout", "3s",
			"--progress", "never", "https://127.0.0.1:1/gone"},
			&strings.Builder{}, &strings.Builder{})
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		if code == 0 {
			t.Error("an interrupted batch reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run waited out its backoff after being interrupted")
	}
}

func TestBatchArgumentErrors(t *testing.T) {
	server := batchServer(t)
	// A count that cannot be honoured is a usage error, so it exits 2 and not
	// the 1 that means "some URLs failed".
	for _, args := range [][]string{
		{"batch", "--concurrency", "0", server.URL},
		{"batch", "--repeat", "-1", server.URL},
		{"batch", "--nonsense"},
	} {
		if code, _, _ := exec(t, args...); code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, code)
		}
	}

	original := batchInput
	t.Cleanup(func() { batchInput = original })
	batchInput = strings.NewReader("")

	for _, args := range [][]string{
		{"batch"},              // an empty list
		{"batch", "not-a-url"}, // rejected before anything is fetched
		{"batch", "--input", "no-such-file.json"}, // an unreadable list
		{"batch", "--format", "yaml", server.URL}, // a format that does not exist
	} {
		if code, _, _ := exec(t, args...); code != 1 && code != 2 {
			t.Errorf("%v: exit code = %d", args, code)
		}
	}
}

func TestBatchCannotWriteWhereItWasTold(t *testing.T) {
	server := batchServer(t)
	missing := filepath.Join(t.TempDir(), "no-such-directory")

	if code, _, _ := exec(t, "batch", "--output",
		filepath.Join(missing, "out.jsonl"), server.URL); code == 0 {
		t.Error("an unwritable output file should fail")
	}

	// A body directory that cannot be made, because a file is in its way.
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if code, _, _ := exec(t, "batch", "--body-dir", blocked, server.URL); code == 0 {
		t.Error("an unmakeable body directory should fail")
	}
}

func TestBatchReportsAnOutputCloseFailure(t *testing.T) {
	original := closeBatchOutput
	closeBatchOutput = func(file *os.File) error {
		_ = original(file)
		return errors.New("close failed")
	}
	t.Cleanup(func() { closeBatchOutput = original })

	server := batchServer(t)
	code, _, stderr := exec(t, "batch", "--output", filepath.Join(t.TempDir(), "out.jsonl"), server.URL)
	if code == 0 || !strings.Contains(stderr, "closing output") {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
}

func TestBatchReportsABodyItCannotWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits: chmod only toggles read-only, so the write this needs to fail succeeds")
	}
	// The directory exists at start-up and is gone by the time a body is
	// written. Reported on the entry's own line rather than ending the run: the
	// page was fetched, and the next one may still be writable.
	server := batchServer(t)
	dir := filepath.Join(t.TempDir(), "bodies")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	code, stdout, _ := exec(t, "batch", "--body-dir", dir, server.URL+"/one")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
	}
	if r := lines(t, stdout)[server.URL+"/one"]; r.Error == "" {
		t.Errorf("no error recorded: %+v", r)
	}
}

func TestPoolKeepsOneClientPerProxy(t *testing.T) {
	// One per proxy, not one per worker: the proxy is the identity, and two
	// pages through one exit IP should share a jar.
	fs := newFlagSet("batch", newPrinter(os.Stdout))
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

func TestBatchStopsHandingOutWorkWhenInterrupted(t *testing.T) {
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
		args := append([]string{"batch", "--concurrency", "2", "--timeout", "2s"}, urls...)
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

func TestBatchReportsAProxyItCannotUse(t *testing.T) {
	// A typo in the proxy column. It is the entry's failure, not the run's:
	// the other URLs still go out, and the line says which one was wrong.
	server := batchServer(t)
	path := writeList(t, "typo.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/bad,::not a proxy::\n%[1]s/good,\n", server.URL))

	code, stdout, _ := exec(t, "batch", "--input", path)
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

func TestBatchWarnsAboveTheCoreCount(t *testing.T) {
	original := numCPU
	t.Cleanup(func() { numCPU = original })
	numCPU = func() int { return 4 }

	server := batchServer(t)

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
			code, stdout, stderr := exec(t, "batch", "-c", tc.workers, server.URL+"/one")
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

func TestBatchDoesNotWarnBeforeItFailsOnTheFlags(t *testing.T) {
	// A warning about a number that was rejected anyway is noise.
	original := numCPU
	t.Cleanup(func() { numCPU = original })
	numCPU = func() int { return 1 }

	code, _, stderr := exec(t, "batch", "-c", "0", "https://example.com/")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if strings.Contains(stderr, "WARN") {
		t.Errorf("warned about a rejected value: %q", stderr)
	}
}

func TestBatchDrawsAStatusLine(t *testing.T) {
	// --progress always, so the assertion does not depend on what the test's
	// stderr happens to be attached to.
	server := batchServer(t)
	code, stdout, stderr := exec(t, "batch", "--progress", "always",
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	// Every number the line is for, and the run's own total.
	for _, want := range []string{"2/2", "running", "B", "elapsed"} {
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

func TestBatchWithoutAStatusLine(t *testing.T) {
	// The default is auto, and a test's stderr is not a terminal.
	server := batchServer(t)
	for _, args := range [][]string{
		{"batch", server.URL + "/one"},
		{"batch", "--progress", "never", server.URL + "/one"},
	} {
		_, _, stderr := exec(t, args...)
		if strings.Contains(stderr, "elapsed") {
			t.Errorf("%v drew a status line into something that is not a terminal: %q",
				args, stderr)
		}
	}
}

func TestBatchRejectsAnUnknownProgressMode(t *testing.T) {
	// Rejected before the list is read, so a typo does not cost a run that then
	// has nowhere to report itself.
	code, _, stderr := exec(t, "batch", "--progress", "sometimes", "https://example.com/")
	if code != 1 {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(stderr, "--progress") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestBatchKeepsNoBodiesInMemory(t *testing.T) {
	// The summary and the report show counts, not pages, so a run holds only
	// what they need. Kept whole, 200 MB of pages measured 353 MB of resident
	// memory against 117 MB once the bodies went.
	server := batchServer(t)
	fs := newFlagSet("batch", newPrinter(io.Discard))
	flags := addClientFlags(fs)
	if err := parse(fs, nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	clients := newPool(flags, "")
	defer clients.close()

	var sink strings.Builder
	var records []result
	jobs := []job{{URL: server.URL + "/one"}, {URL: server.URL + "/two"}}
	failed, err := runJobs(context.Background(), jobs, clients, 2, &sink, 1, "",
		newProgress(len(jobs)), &records, &stderrLog{})
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
	fs := newFlagSet("batch", newPrinter(io.Discard))
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
	_, err := runJobs(context.Background(), jobs, clients, 1,
		failingWriter{}, 0, "", newProgress(len(jobs)), &records, &stderrLog{})
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
			"nothing came back, after repeats",
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

func TestBatchVerbose(t *testing.T) {
	server := batchServer(t)
	code, stdout, stderr := exec(t, "batch", "-v", "--progress", "never",
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

func TestBatchQuietByDefault(t *testing.T) {
	server := batchServer(t)
	_, _, stderr := exec(t, "batch", "--progress", "never", server.URL+"/one")
	if strings.Contains(stderr, server.URL+"/one") {
		t.Errorf("a request was reported without being asked for:\n%s", stderr)
	}
}

func TestVerboseAndTheStatusLineShareTheStream(t *testing.T) {
	// Both draw on stderr. Without the status line stepping aside they land on
	// each other and the reader gets neither.
	server := batchServer(t)
	_, _, stderr := exec(t, "batch", "-v", "--progress", "always",
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
		if strings.Contains(line, "running") || strings.Contains(line, "\x1b") {
			t.Errorf("a request's line shares a row with the status line: %q", line)
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
// the cursor about. \r returns to the start of the row and ESC[K erases from
// the cursor to its end.
func replay(stream string) []string {
	var screen []string
	var row []rune
	col := 0
	for i := 0; i < len(stream); {
		if strings.HasPrefix(stream[i:], "\x1b[K") {
			row = row[:col]
			i += 3
			continue
		}
		r, width := utf8.DecodeRuneInString(stream[i:])
		i += width
		switch r {
		case '\r':
			col = 0
		case '\n':
			screen = append(screen, string(row))
			row, col = nil, 0
		default:
			if col < len(row) {
				row[col] = r
			} else {
				row = append(row, r)
			}
			col++
		}
	}
	if len(row) > 0 {
		screen = append(screen, string(row))
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

func TestBatchSaysItIsWaitingForInput(t *testing.T) {
	// Nothing named a list and standard input is a terminal, so the next thing
	// that happens is a wait for someone to type. A command that goes quiet
	// there looks like one that has hung, which is how this was reported.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("opening %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })

	original := batchInput
	t.Cleanup(func() { batchInput = original })
	batchInput = devNull

	// A character device that is already at end of file, so the wait it
	// announces is over as soon as it begins.
	_, _, stderr := exec(t, "batch")
	for _, want := range []string{"standard input", "Ctrl-D", "--input", "--urls"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
}

func TestBatchSaysNothingWhenItWasGivenAList(t *testing.T) {
	server := batchServer(t)
	_, _, stderr := exec(t, "batch", "--progress", "never", server.URL+"/one")
	if strings.Contains(stderr, "Ctrl-D") {
		t.Errorf("a run that was given URLs announced a wait for them:\n%s", stderr)
	}
}
