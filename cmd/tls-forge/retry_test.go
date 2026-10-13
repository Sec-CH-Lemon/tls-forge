package main

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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

	code, stdout, stderr := exec(t, "fetch", "--retry", "3", server.URL)
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

	code, stdout, stderr := exec(t, "fetch", "--retry", "1", "--timeout", "10s", server.URL)
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
	code, _, stderr := exec(t, "fetch", "--retry", "1", "--timeout", "3s", "https://127.0.0.1:1/")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "try 1 of 2") {
		t.Errorf("the retry was not made:\n%s", stderr)
	}
}

func TestRunFlagErrorsAreUsageErrors(t *testing.T) {
	// A count that cannot be honoured is a mistake in the command, and nothing
	// is fetched to find that out.
	server, asked := replying(t, 200)
	for _, args := range [][]string{
		{"fetch", "--retry", "-1", server.URL},
		{"fetch", "--retry", fmt.Sprint(math.MaxInt), server.URL},
	} {
		if code, _, _ := exec(t, args...); code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, code)
		}
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("%d requests were made by commands that were refused", got)
	}
}

func TestBatchAsksAgainWhenTheAnswerIsNotThePage(t *testing.T) {
	server, asked := replying(t, 503, 200)

	code, stdout, stderr := exec(t, "batch", server.URL+"/flaky")
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
	// One try beyond the first, counted where retries always were.
	if !strings.Contains(stderr, "Retries      1") {
		t.Errorf("the summary does not count the retry:\n%s", stderr)
	}
}

func TestBatchKeepsTheAnswerItGotWhenToldNotToRetry(t *testing.T) {
	server, asked := replying(t, 503, 200)

	code, stdout, _ := exec(t, "batch", "--retry", "0", server.URL+"/flaky")
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
