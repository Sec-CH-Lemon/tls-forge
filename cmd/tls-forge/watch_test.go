package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// What a run shows while it runs, and what it keeps to itself.

// asIfOnScreen makes standard output a terminal for one test. A test's own
// streams are buffers, so this is the only way to see what a run does for
// somebody watching it.
func asIfOnScreen(t *testing.T) {
	t.Helper()
	original := onScreen
	t.Cleanup(func() { onScreen = original })
	onScreen = func(io.Writer) bool { return true }
}

// after is what a command said once it had said which profile it was wearing:
// everything under the rule that closes that report.
func after(stderr string) string {
	closing := strings.LastIndex(stderr, identityRule)
	if closing < 0 {
		return stderr
	}
	return stderr[closing+len(identityRule):]
}

func TestProgressFrame(t *testing.T) {
	clock := fakeClock(t)
	p := newProgress(100)

	// Nothing has come back, so there is nothing to count under the first line.
	if got := p.frame(clock.now(), palette{}); !slices.Equal(got, []string{p.line(clock.now())}) {
		t.Errorf("at the start: %q", got)
	}

	for _, r := range []result{
		{Status: 503}, {Status: 200}, {Error: "connection refused"}, {Status: 301},
		{Status: 200}, {Status: 404}, {Status: 200},
	} {
		p.begin()
		p.finish(r)
	}
	// Lowest code first, so a row stays where it is as others arrive, and what
	// got no answer last. The counts line up whatever the label beside them.
	want := []string{
		"7/100  0 running  0 B  0s elapsed  ~0s left  1 failed",
		"  200           3",
		"  301           1",
		"  404           1",
		"  503           1",
		"  no response   1",
	}
	if got := p.frame(clock.now(), palette{}); !slices.Equal(got, want) {
		t.Errorf("frame =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestProgressFrameIsColouredByOutcome(t *testing.T) {
	clock := fakeClock(t)
	p := newProgress(10)
	for _, r := range []result{
		{Status: 200}, {Status: 204}, {Status: 304}, {Status: 403}, {Status: 500},
		{Error: "connection refused"},
	} {
		p.begin()
		p.finish(r)
	}

	frame := p.frame(clock.now(), inColour)
	// The first line is a count of everything, so it is no colour in particular.
	if strings.Contains(frame[0], "\x1b") {
		t.Errorf("the count itself was coloured: %q", frame[0])
	}
	// Green for the page, yellow for a redirect, red for the rest, and each row
	// puts the colour back when it is done.
	want := []string{
		ansiGreen + "  200          1" + ansiReset,
		ansiGreen + "  204          1" + ansiReset,
		ansiYellow + "  304          1" + ansiReset,
		ansiRed + "  403          1" + ansiReset,
		ansiRed + "  500          1" + ansiReset,
		ansiRed + "  no response  1" + ansiReset,
	}
	if got := frame[1:]; !slices.Equal(got, want) {
		t.Errorf("rows = %q, want %q", got, want)
	}
}

func TestColourForAStatus(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{
		{200, ansiGreen}, {201, ansiGreen}, {299, ansiGreen},
		{300, ansiYellow}, {304, ansiYellow}, {399, ansiYellow},
		{400, ansiRed}, {403, ansiRed}, {429, ansiRed}, {500, ansiRed}, {503, ansiRed},
		// Never the last word from a server, and not a page if it ever is.
		{101, ansiRed},
	} {
		if got := inColour.forStatus(tc.code); got != tc.want {
			t.Errorf("forStatus(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
	// With colour off there is nothing to put in front of a row.
	if got := (palette{}).forStatus(200); got != "" {
		t.Errorf("a palette with no colours coloured a row: %q", got)
	}
}

func TestProgressLineOfOneRequestAtATime(t *testing.T) {
	// How many are running is never news when it is always one or none.
	clock := fakeClock(t)
	p := newProgress(3)
	p.solo = true
	p.begin()
	if got := p.line(clock.now()); got != "0/3  0 B  0s elapsed" {
		t.Errorf("line = %q", got)
	}
}

func TestStatusIsRedrawnOverItselfAsItGrows(t *testing.T) {
	// The ticker draws a frame over the one before it, with nothing erased in
	// between, and each frame can be a row taller than the last.
	clock := fakeClock(t)
	status := &captured{}
	p := newProgress(3)
	line := newStatusLine(newPrinter(status), io.Discard, p, palette{})

	line.draw()
	for _, r := range []result{{Status: 200}, {Status: 503}, {Error: "connection refused"}} {
		p.begin()
		p.finish(r)
		clock.advance(time.Second)
		line.draw()
	}

	want := []string{
		"3/3  0 running  0 B  3s elapsed  1 failed",
		"  200         1",
		"  503         1",
		"  no response 1",
	}
	if got := replay(status.String()); !slices.Equal(got, want) {
		t.Errorf("the screen shows %q, want %q", got, want)
	}

	// Something said about a request goes above the status, which moves down a
	// row to make room and loses none of its own.
	line.Log("a line about a request")
	line.Close()
	if got := replay(status.String()); !slices.Equal(got, append([]string{"a line about a request"}, want...)) {
		t.Errorf("after a line was logged the screen shows %q", got)
	}
}

func TestFetchOnAScreenShowsTheCountAndNotThePage(t *testing.T) {
	asIfOnScreen(t)
	server, asked := replying(t, 200)

	code, stdout, stderr := exec(t, "fetch", server.URL)
	if code != 0 || asked.Load() != 1 {
		t.Fatalf("exit code = %d after %d requests\n%s", code, asked.Load(), stderr)
	}
	// A page is thousands of lines nobody reads as they go past.
	if stdout != "" {
		t.Errorf("the page was printed on a screen without being asked for: %q", stdout)
	}
	// What a person watching wants to know: how far, and how it went.
	if got, want := after(stderr), "\n1/1  8 B  0s elapsed\n  200         1\n"; got != want {
		t.Errorf("under the report stderr says %q, want %q", got, want)
	}
}

func TestFetchPrintsThePageOnAScreenWhenAsked(t *testing.T) {
	asIfOnScreen(t)
	for _, tc := range []struct {
		name, page, under string
	}{
		// A page rarely ends its last line, and the count would start on the end
		// of it.
		{"a page that stops mid-line", "<html>page</html>", "\n\n1/1  17 B  0s elapsed\n  200         1\n"},
		{"a page that ends its last line", "page\n", "\n1/1  5 B  0s elapsed\n  200         1\n"},
		{"a page with nothing in it", "", "\n1/1  0 B  0s elapsed\n  200         1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tc.page)
			}))
			t.Cleanup(server.Close)

			// --progress always as well: with pages going past on the same
			// screen there is nothing to redraw a count between, so it is said
			// once, when they have stopped.
			code, stdout, stderr := exec(t, "fetch", "--body", "--progress", "always", server.URL)
			if code != 0 {
				t.Fatalf("exit code = %d\n%s", code, stderr)
			}
			if stdout != tc.page {
				t.Errorf("stdout = %q, want the page", stdout)
			}
			if got := after(stderr); got != tc.under {
				t.Errorf("under the report stderr says %q, want %q", got, tc.under)
			}
		})
	}
}

func TestFetchKeepsThePageOutOfAPipeWhenItHasAFile(t *testing.T) {
	// Standard output here is a buffer, which is to say a pipe. A page with a
	// file to go to goes there; asked for on standard output too, it gets both.
	server, _ := replying(t, 200)
	path := filepath.Join(t.TempDir(), "page.html")

	if _, stdout, _ := exec(t, "fetch", "-o", path, server.URL); stdout != "" {
		t.Errorf("the page went down the pipe as well as into the file: %q", stdout)
	}
	code, stdout, stderr := exec(t, "fetch", "-o", path, "--body", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if stdout != "answer-2" {
		t.Errorf("stdout = %q, want the page that was asked for there", stdout)
	}
	if kept, err := os.ReadFile(path); err != nil || string(kept) != "answer-2" {
		t.Errorf("the file holds %q (%v)", kept, err)
	}
}

func TestFetchPrintsTheHeadersAloneWhenThatIsAllThatWasAskedFor(t *testing.T) {
	asIfOnScreen(t)
	server, _ := replying(t, 200)

	code, stdout, stderr := exec(t, "fetch", "-i", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "200 "+server.URL+"\ncontent-type: text/plain") ||
		!strings.HasSuffix(stdout, "\n\n") {
		t.Errorf("stdout is not the status and the headers, ended with a blank line: %q", stdout)
	}
	if strings.Contains(stdout, "answer-1") {
		t.Errorf("the page was printed with the headers without being asked for: %q", stdout)
	}
	// The headers end their own last line, so the count starts on a fresh one.
	if got := after(stderr); !strings.HasPrefix(got, "\n1/1  ") {
		t.Errorf("under the report stderr says %q", got)
	}
}

func TestFetchCountsWhatCameBackByStatus(t *testing.T) {
	server, _ := replying(t, 200, 503, 0, 200, 304)

	code, _, stderr := exec(t, "fetch", "--repeat", "5", "--timeout", "10s", server.URL)
	if code != 1 {
		t.Errorf("exit code = %d, want 1: one run got no answer", code)
	}
	// Under the count of runs, a row for each status the answers had, lowest
	// first, and the run that got none last.
	want := []string{
		"  200         2",
		"  304         1",
		"  503         1",
		"  no response 1",
	}
	rows := strings.Split(strings.TrimSpace(after(stderr)), "\n")
	if len(rows) < 5 || !strings.HasPrefix(rows[0], "5/5  ") || !strings.HasSuffix(rows[0], "1 failed") {
		t.Fatalf("stderr does not count the runs:\n%s", stderr)
	}
	if got := rows[1:5]; !slices.Equal(got, want) {
		t.Errorf("rows = %q, want %q", got, want)
	}
	// A buffer is not a terminal, so nothing is coloured and nothing is redrawn.
	if strings.Contains(stderr, "\x1b") {
		t.Errorf("an escape sequence was written to something that is not a terminal: %q", stderr)
	}
}

func TestFetchColoursTheCountByOutcome(t *testing.T) {
	server, _ := replying(t, 200, 304, 403, 0)

	_, _, stderr := exec(t, "fetch", "--repeat", "4", "--timeout", "10s", "--color", "always", server.URL)
	for _, want := range []string{
		ansiGreen + "  200         1" + ansiReset,
		ansiYellow + "  304         1" + ansiReset,
		ansiRed + "  403         1" + ansiReset,
		ansiRed + "  no response 1" + ansiReset,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%q", want, after(stderr))
		}
	}

	// And none at all when told not to, whatever it is being written to.
	_, _, plain := exec(t, "fetch", "--color", "never", server.URL)
	if strings.Contains(plain, "\x1b") {
		t.Errorf("--color never wrote an escape sequence: %q", plain)
	}
}

func TestFetchRedrawsTheCountWhileItRuns(t *testing.T) {
	// --progress always, so the assertion does not depend on what the test's
	// stderr happens to be attached to.
	server, _ := replying(t, 200, 404, 200)

	code, stdout, stderr := exec(t, "fetch", "--repeat", "3", "--progress", "always", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// The pages went down the pipe untouched by what was being drawn beside it.
	if stdout != "answer-1answer-2answer-3" {
		t.Errorf("stdout = %q", stdout)
	}
	// Drawn over itself as it went: more than once, and going up to do it.
	if !strings.Contains(stderr, cursorUp) || strings.Count(stderr, "/3  ") < 3 {
		t.Errorf("the count was not redrawn in place: %q", after(stderr))
	}
	// What is left on screen at the end is the last frame and nothing of the
	// ones before it.
	screen := replay(after(stderr))
	want := []string{"", "3/3  24 B  0s elapsed", "  200         2", "  404         1"}
	if !slices.Equal(screen, want) {
		t.Errorf("the screen ends as %q, want %q", screen, want)
	}
}

func TestFetchVerboseSaysEveryRunAndWhereItWent(t *testing.T) {
	server, _ := replying(t, 503, 200, 200)
	dir := t.TempDir()
	path := filepath.Join(dir, "page.html")

	code, _, stderr := exec(t, "fetch", "-v", "--repeat", "2", "--retry", "1", "-o", path, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	first, second := filepath.Join(dir, "page-1.html"), filepath.Join(dir, "page-2.html")
	for _, want := range []string{
		"try 1 of 2: HTTP 503",
		// The columns batch prints for a URL, with the file where it has the URL.
		"  1/2  200",
		" x2    " + first,
		"  2/2  200",
		"       " + second,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, after(stderr))
		}
	}
	// In the order things happened: the retry, the run it belonged to, the next.
	if a, b, c := strings.Index(stderr, "try 1 of 2"), strings.Index(stderr, "  1/2  "), strings.Index(stderr, "  2/2  "); a > b || b > c {
		t.Errorf("the lines are out of order:\n%s", after(stderr))
	}
}

func TestFetchRejectsWordsItDoesNotKnow(t *testing.T) {
	// Before anything is fetched: a typo should not cost a request to find out.
	server, asked := replying(t, 200)
	for _, tc := range []struct{ flag, value string }{
		{"--progress", "sometimes"},
		{"--color", "sometimes"},
	} {
		code, _, stderr := exec(t, "fetch", tc.flag, tc.value, server.URL)
		if code != 1 || !strings.Contains(stderr, tc.flag) || !strings.Contains(stderr, tc.value) {
			t.Errorf("%s %s: exit code = %d, stderr = %q", tc.flag, tc.value, code, stderr)
		}
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("%d requests were made by commands that were refused", got)
	}
}

func TestBatchOnAScreenKeepsItsLinesToItself(t *testing.T) {
	asIfOnScreen(t)
	server := batchServer(t)

	// Each line holds a whole page. On a screen the run is watched through its
	// count and its summary, which are still there.
	code, stdout, stderr := exec(t, "batch", server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("the JSON lines were printed on a screen without being asked for: %q", stdout)
	}
	if !strings.Contains(stderr, "Scraped      2") {
		t.Errorf("the summary went with them:\n%s", stderr)
	}
	// And the summary says that they went nowhere, and the two ways to have them.
	const unprinted = "  JSON lines   not printed on a terminal; -o FILE keeps them, --body shows them\n"
	if !strings.Contains(stderr, unprinted) {
		t.Errorf("the summary does not say the lines were not printed:\n%s", stderr)
	}

	// Asked for, they are printed as they always were.
	_, stdout, stderr = exec(t, "batch", "--body", server.URL+"/one", server.URL+"/two")
	if got := lines(t, stdout); len(got) != 2 || got[server.URL+"/one"].Body != "page /one" {
		t.Errorf("--body printed %q", stdout)
	}
	if strings.Contains(stderr, "JSON lines") {
		t.Errorf("lines that were printed were reported as not printed:\n%s", stderr)
	}

	// And a file gets them whatever standard output is.
	path := filepath.Join(t.TempDir(), "results.jsonl")
	if _, stdout, stderr = exec(t, "batch", "--output", path, server.URL+"/one"); stdout != "" ||
		strings.Contains(stderr, "JSON lines") {
		t.Errorf("with --output: stdout = %q, stderr = %q", stdout, after(stderr))
	}
	if kept, err := os.ReadFile(path); err != nil || len(lines(t, string(kept))) != 1 {
		t.Errorf("the file holds %q (%v)", kept, err)
	}
}

func TestBatchCountsStatusesUnderItsProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = fmt.Fprintf(w, "page %s", r.URL.Path)
	}))
	t.Cleanup(server.Close)

	code, stdout, stderr := exec(t, "batch", "--progress", "always", "--color", "always",
		"--retry", "0", "--concurrency", "1", server.URL+"/one", server.URL+"/missing")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// The same rows fetch draws, under the line batch always had.
	for _, want := range []string{
		ansiGreen + "  200         1" + ansiReset,
		ansiRed + "  404         1" + ansiReset,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%q", want, after(stderr))
		}
	}
	screen := strings.Join(replay(after(stderr)), "\n")
	if !strings.Contains(screen, "2/2  0 running") ||
		!strings.Contains(screen, "elapsed\n  200         1\n  404         1\n") {
		t.Errorf("the screen does not end with the count and its rows:\n%s", screen)
	}
	// And none of it on the stream carrying the results.
	if strings.Contains(stdout, "\x1b") || len(lines(t, stdout)) != 2 {
		t.Errorf("the status reached stdout: %q", stdout)
	}
}

func TestFetchStopsWhenItCannotPrintWhatWasAskedFor(t *testing.T) {
	// Three runs, and nowhere to print the headers of the first. The other two
	// would have nowhere either, so they are not made.
	server, asked := replying(t, 200)
	var stderr strings.Builder
	code := run(context.Background(), []string{"fetch", "-i", "--repeat", "3", server.URL},
		&countingWriter{fail: errors.New("no space left on device")}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "no space left on device") {
		t.Errorf("exit code = %d, stderr = %q", code, after(stderr.String()))
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("the server was asked %d times after the first answer could not be printed", got)
	}
}
