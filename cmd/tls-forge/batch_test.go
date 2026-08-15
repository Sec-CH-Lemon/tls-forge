package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
	}
}

func TestBatchWritesToAFileAndADirectory(t *testing.T) {
	server := batchServer(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "results.jsonl")
	bodyDir := filepath.Join(dir, "bodies")

	code, stdout, _ := exec(t, "batch", "--output", outPath, "--body-dir", bodyDir,
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	// The summary goes to the terminal only when the results went elsewhere.
	if !strings.Contains(stdout, "2 of 2 succeeded") {
		t.Errorf("stdout = %q", stdout)
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

	code, stdout, _ := exec(t, "batch", "--retry", "3", "--timeout", "10s", server.URL+"/flaky")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	r := lines(t, stdout)[server.URL+"/flaky"]
	if r.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", r.Attempts)
	}
}

func TestBatchArgumentErrors(t *testing.T) {
	server := batchServer(t)
	// A count that cannot be honoured is a usage error, so it exits 2 and not
	// the 1 that means "some URLs failed".
	for _, args := range [][]string{
		{"batch", "--concurrency", "0", server.URL},
		{"batch", "--retry", "0", server.URL},
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

func TestBatchReportsABodyItCannotWrite(t *testing.T) {
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-released
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(func() { close(released); server.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	urls := make([]string, 0, 50)
	for i := range 50 {
		urls = append(urls, fmt.Sprintf("%s/%d", server.URL, i))
	}

	done := make(chan int, 1)
	go func() {
		args := append([]string{"batch", "--concurrency", "2", "--timeout", "2s"}, urls...)
		done <- run(ctx, args, &strings.Builder{}, &strings.Builder{})
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not stop after the context was cancelled")
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
