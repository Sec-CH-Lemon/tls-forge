package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// replying answers each request with the next status given, and with the last
// of them from then on. The body says which request it was, so a test can
// tell one answer from another.
//
// A status of zero answers with something that is not HTTP and hangs up, which
// is a transport error rather than a response. Not a bare hang-up: the
// transport quietly asks again on a new connection when a kept-alive one closes
// under it, and a test that wants a request to fail would then watch it work.
func replying(t *testing.T, statuses ...int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(asked.Add(1))
		status := statuses[min(n, len(statuses))-1]
		if status == 0 {
			if hijacked, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_, _ = hijacked.Write([]byte("this is not HTTP\r\n\r\n"))
				_ = hijacked.Close()
			}
			return
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "answer-%d", n)
	}))
	t.Cleanup(server.Close)
	return server, &asked
}

func TestFetchAsksAgainWhenTheAnswerIsNotThePage(t *testing.T) {
	server, asked := replying(t, 503, 503, 200)

	code, stdout, stderr := exec(t, "fetch", "--retry", "3", "-v", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != 3 {
		t.Errorf("the server was asked %d times, want 3", got)
	}
	// The page is what comes out, and the answers before it are not.
	if stdout != "answer-3" {
		t.Errorf("stdout = %q, want the third answer alone", stdout)
	}
	// Each try that was made again is said, with why and how long it waits.
	for _, want := range []string{"try 1 of 4: HTTP 503", "try 2 of 4: HTTP 503", "trying again in"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "try 3 of 4") {
		t.Errorf("the try that worked was announced as one to be repeated:\n%s", stderr)
	}
	// What is reported is how the request ended, which was with the page, and
	// what that took.
	if !strings.Contains(stderr, "\n  ✓ 200 OK · 8 B · ") || strings.Contains(stderr, "✗") {
		t.Errorf("what is reported is something other than the last answer:\n%s", stderr)
	}
	if !strings.HasSuffix(stderr, " · 2 retries\n") {
		t.Errorf("the last line does not say the request was made again twice:\n%s", stderr)
	}
}

func TestFetchKeepsItsRetriesToItselfUnlessAsked(t *testing.T) {
	// A run being watched is watched for how it is going. Which try it took is
	// for somebody who asked to hear about every request.
	server, asked := replying(t, 503, 200)

	code, _, stderr := exec(t, "fetch", "--retry", "1", server.URL)
	if code != 0 || asked.Load() != 2 {
		t.Fatalf("exit code = %d after %d requests\n%s", code, asked.Load(), stderr)
	}
	if strings.Contains(stderr, "try 1 of 2") {
		t.Errorf("a retry was announced without being asked for:\n%s", stderr)
	}
	// That there was one is a figure, and that is said at the end to everybody.
	if !strings.HasSuffix(stderr, " · 1 retry\n") {
		t.Errorf("the last line does not count the retry:\n%s", stderr)
	}
}

func TestFetchAsksOnceUnlessToldOtherwise(t *testing.T) {
	// One request is what fetch was asked for. An answer that is not a 2xx is
	// still the answer, printed as it always was.
	server, asked := replying(t, 503)

	code, stdout, _ := exec(t, "fetch", server.URL)
	if code != 0 {
		t.Errorf("exit code = %d, want 0: something did come back", code)
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("the server was asked %d times, want once", got)
	}
	if stdout != "answer-1" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestFetchHandsBackTheLastAnswerWhenTheTriesRunOut(t *testing.T) {
	server, asked := replying(t, 500)

	code, stdout, _ := exec(t, "fetch", "--retry", "2", server.URL)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if got := asked.Load(); got != 3 {
		t.Errorf("the server was asked %d times, want one try and two more", got)
	}
	if stdout != "answer-3" {
		t.Errorf("stdout = %q, want what the last try got", stdout)
	}
}

func TestFetchAsksAgainWhenNothingComesBack(t *testing.T) {
	server, asked := replying(t, 0, 200)

	code, stdout, stderr := exec(t, "fetch", "--retry", "1", "-v", "--timeout", "10s", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != 2 {
		t.Errorf("the server was asked %d times, want 2", got)
	}
	if stdout != "answer-2" {
		t.Errorf("stdout = %q", stdout)
	}
	// Why, in the transport's own words, since there is no status to give.
	if !strings.Contains(stderr, "try 1 of 2: tlsforge:") {
		t.Errorf("the failed try was not explained:\n%s", stderr)
	}
}

func TestFetchFailsWhenNoTryGetsAnAnswer(t *testing.T) {
	code, _, stderr := exec(t, "fetch", "--retry", "1", "-v", "--timeout", "3s", "https://127.0.0.1:1/")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "try 1 of 2") {
		t.Errorf("the retry was not made:\n%s", stderr)
	}
	// One request, and nothing came back from it.
	if !strings.Contains(stderr, "\n  ✗ no response · 0 B · ") {
		t.Errorf("stderr does not say that nothing came back:\n%s", stderr)
	}
}

func TestRunFlagErrorsAreUsageErrors(t *testing.T) {
	// A count that cannot be honoured is a mistake in the command, and nothing
	// is fetched to find that out.
	server, asked := replying(t, 200)
	for _, args := range [][]string{
		{"fetch", "--retry", "-1", server.URL},
		{"fetch", "--retry", fmt.Sprint(math.MaxInt), server.URL},
		{"fetch", "--repeat", "0", server.URL},
		{"fetch", "--repeat", "-3", server.URL},
	} {
		if code, _, _ := exec(t, args...); code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, code)
		}
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("%d requests were made by commands that were refused", got)
	}
}

func TestListAsksAgainWhenTheAnswerIsNotThePage(t *testing.T) {
	server, asked := replying(t, 503, 200)

	code, stdout, stderr := exec(t, "fetch", "--json", "--retry", "3", server.URL+"/flaky")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	r := lines(t, stdout)[server.URL+"/flaky"]
	if r.Status != 200 || r.Attempts != 2 || r.Body != "answer-2" {
		t.Errorf("result = %+v, want the page on the second try", r)
	}
	if got := asked.Load(); got != 2 {
		t.Errorf("the server was asked %d times, want 2", got)
	}
	// One try beyond the first, counted where one request says what it took.
	if !strings.HasSuffix(stderr, " · 1 retry\n") {
		t.Errorf("the last line does not count the retry:\n%s", stderr)
	}
}

func TestListKeepsTheAnswerItGotWhenToldNotToRetry(t *testing.T) {
	server, asked := replying(t, 503, 200)

	code, stdout, _ := exec(t, "fetch", "--json", "--retry", "0", server.URL+"/flaky")
	// Not a failure of the run: something came back, as it did before retries
	// looked at the status.
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if r := lines(t, stdout)[server.URL+"/flaky"]; r.Status != 503 || r.Attempts != 1 {
		t.Errorf("result = %+v, want the 503 after one try", r)
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("the server was asked %d times, want once", got)
	}
}

func TestFetchRepeatKeepsEveryRunInTheDirectory(t *testing.T) {
	server, _ := replying(t, 200)
	dir := filepath.Join(t.TempDir(), "out")

	code, stdout, stderr := exec(t, "fetch", "--repeat", "3", "-o", dir, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Each run under its own number, with the page it got.
	for run := 1; run <= 3; run++ {
		pages, _ := filepath.Glob(filepath.Join(dir, fmt.Sprintf("127.0.0.1-*-%d.txt", run)))
		if len(pages) != 1 {
			t.Fatalf("run %d kept no page among %v", run, keptIn(t, dir))
		}
		if body, _ := os.ReadFile(pages[0]); string(body) != fmt.Sprintf("answer-%d", run) {
			t.Errorf("%s holds %q", pages[0], body)
		}
	}
	// The directory is where the pages went, so nothing went to stdout, and
	// where they went is said once, as the last of what the run came to.
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	if want := "\n  Saved to      " + dir + "\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end by saying where the runs went (%q):\n%s", want, stderr)
	}
	// Three runs counted, and not a line each.
	if !strings.Contains(stderr, "  3/3  100%\n") || !strings.Contains(stderr, "\n  ✓ 200 OK   3  100%\n") {
		t.Errorf("stderr does not count the runs:\n%s", stderr)
	}
	if strings.Contains(stderr, "1/3") {
		t.Errorf("a run was reported on its own without being asked for:\n%s", stderr)
	}
}

func TestFetchRepeatWritesEveryBodyToStandardOutput(t *testing.T) {
	server, asked := replying(t, 200)

	code, stdout, stderr := exec(t, "fetch", "--repeat", "2", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if stdout != "answer-1answer-2" {
		t.Errorf("stdout = %q, want both bodies in order", stdout)
	}
	if got := asked.Load(); got != 2 {
		t.Errorf("the server was asked %d times, want 2", got)
	}
}

func TestFetchRepeatGoesOnPastARunThatGotNoAnswer(t *testing.T) {
	// Nine runs out of ten is a finding, not a reason to stop at the second.
	server, _ := replying(t, 200, 0, 200)
	dir := filepath.Join(t.TempDir(), "out")

	code, _, stderr := exec(t, "fetch", "--repeat", "3", "--timeout", "10s", "-o", dir, server.URL)
	if code != 1 {
		t.Errorf("exit code = %d, want 1: one run got nothing", code)
	}
	if !strings.Contains(stderr, "fetch: 1 of 3 requests got no response") {
		t.Errorf("the failed run was not counted:\n%s", stderr)
	}
	// Counted with the others, under what it came back as: nothing.
	for _, want := range []string{"  3/3  100%\n", "\n  ✓ 200 OK        2   67%\n", "\n  ✗ no response   1   33%\n"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
	// A page for each run that got one, and a log and a trace for every run,
	// the one that got nothing most of all.
	for run, answered := range map[int]bool{1: true, 2: false, 3: true} {
		pages, _ := filepath.Glob(filepath.Join(dir, fmt.Sprintf("*-%d.txt", run)))
		logs, _ := filepath.Glob(filepath.Join(dir, fmt.Sprintf("*-%d.log", run)))
		traces, _ := filepath.Glob(filepath.Join(dir, fmt.Sprintf("trace-*-%d.json", run)))
		if (len(pages) == 1) != answered || len(logs) != 1 || len(traces) != 1 {
			t.Errorf("run %d kept %v, %v and %v", run, pages, logs, traces)
		}
	}
}

func TestFetchRepeatStopsWhenInterrupted(t *testing.T) {
	// The first run answers; the second never does. Interrupted there, the run
	// ends rather than making the three that were left.
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if asked.Add(1) == 1 {
			_, _ = w.Write([]byte("page"))
			return
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"fetch", "--repeat", "5", server.URL}, &strings.Builder{}, &strings.Builder{})
	}()

	for deadline := time.Now().Add(10 * time.Second); asked.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("the second run was never made")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code == 0 {
			t.Error("an interrupted fetch reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run went on after being interrupted")
	}
	if got := asked.Load(); got != 2 {
		t.Errorf("the server was asked %d times, want the run to stop at 2", got)
	}
}

func TestListRepeatGoesThroughTheListAgain(t *testing.T) {
	server := pathServer(t)
	dir := filepath.Join(t.TempDir(), "out")

	code, stdout, stderr := exec(t, "fetch", "--repeat", "3", "--concurrency", "2",
		"--output", dir, server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	// A line per pass per URL, each saying which pass it was and each with a
	// page of its own.
	seen := map[string]bool{}
	files := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decoding %q: %v", line, err)
		}
		seen[fmt.Sprintf("%s#%d", strings.TrimPrefix(r.URL, server.URL), r.Run)] = true
		if _, err := os.Stat(r.File); err != nil {
			t.Errorf("%s run %d: no body file: %v", r.URL, r.Run, err)
		}
		files[r.File] = true
	}
	for _, want := range []string{"/one#1", "/one#2", "/one#3", "/two#1", "/two#2", "/two#3"} {
		if !seen[want] {
			t.Errorf("no result for %s among %v", want, seen)
		}
	}
	if len(seen) != 6 || len(files) != 6 {
		t.Errorf("%d results in %d files, want 6 in 6", len(seen), len(files))
	}
	// Six requests, and what turns that number back into a list of two.
	if want := "\n  Requests      6  (3 passes over 2 URLs)\n"; !strings.Contains(stderr, want) {
		t.Errorf("the figures do not say what was run (%q):\n%s", want, stderr)
	}
}

func TestListWithoutRepeatKeepsItsOldShape(t *testing.T) {
	// A list gone through once says nothing about passes: its lines are what
	// they have always been, for whatever is already reading them.
	server := pathServer(t)
	code, stdout, stderr := exec(t, "fetch", server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if strings.Contains(stdout, `"run"`) {
		t.Errorf("a single pass was numbered: %s", stdout)
	}
	if want := "\n  Requests      2\n"; !strings.Contains(stderr, want) || strings.Contains(stderr, "passes") {
		t.Errorf("the figures say something about passes (%q):\n%s", want, stderr)
	}
}

func TestListRepeatCountsRequestsWhenItFails(t *testing.T) {
	code, _, stderr := exec(t, "fetch", "--repeat", "2", "--retry", "0", "--timeout", "3s",
		"https://127.0.0.1:1/gone")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	// Two requests failed and there is one URL, so requests is the word.
	if !strings.Contains(stderr, "fetch: 2 of 2 requests got no response") {
		t.Errorf("stderr = %q", stderr)
	}
}
