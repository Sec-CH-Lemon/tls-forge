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
	"regexp"
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

// oneLine is what a single request is reported as, under the report of what
// the run is wearing: how it ended, how much came back and how long it took, on
// a line of its own and with nothing after it.
var oneLine = regexp.MustCompile(`^\n  [✓→✗] [^\n]+ · \d[^\n]* B · \d[^\n]*s\n$`)

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

	// Nothing has come back: a bar with nothing in it yet, and no rows under it.
	want := []string{
		"  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0/100  0%",
		"  0s elapsed · 0 B",
	}
	if got := p.frame(clock.now(), palette{}); !slices.Equal(got, want) {
		t.Errorf("at the start:\n%s", strings.Join(got, "\n"))
	}

	for _, r := range []result{
		{Status: 503}, {Status: 200, Bytes: 1000}, {Error: "connection refused"}, {Status: 301},
		{Status: 200, Bytes: 1000}, {Status: 404}, {Status: 200, Bytes: 1000}, {Status: 599},
	} {
		p.begin()
		p.finish(r)
	}
	clock.advance(16 * time.Second)

	// The bar is cut where the running totals fall, so one redirect in a
	// hundred is too narrow to draw and takes nothing from its neighbours. Under
	// it, a row per status: lowest code first, so a row stays where it is as
	// others arrive, what got no answer last, and a code nobody has named
	// without a name. The numbers line up whatever is written beside them.
	want = []string{
		"  █▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  8/100  8%",
		"  16s elapsed · ~3m04s left · 3.0 kB",
		"",
		"  ✓ 200 OK                      3   38%",
		"  → 301 Moved Permanently       1   13%",
		"  ✗ 404 Not Found               1   13%",
		"  ✗ 503 Service Unavailable     1   13%",
		"  ✗ 599                         1   13%",
		"  ✗ no response                 1   13%",
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

	// Green for the page, yellow for a redirect, red for the rest, in the bar
	// and in the rows alike, and each puts the colour back when it is done. What
	// is still to come is dimmed rather than coloured: it has not gone any way
	// yet.
	want := []string{
		"  " + ansiGreen + "████████" + ansiReset + ansiYellow + "▓▓▓▓" + ansiReset +
			ansiRed + "▒▒▒▒▒▒▒▒▒▒▒▒" + ansiReset + ansiDim + "░░░░░░░░░░░░░░░░" + ansiReset + "  6/10  60%",
		"  0s elapsed · ~0s left · 0 B",
		"",
		ansiGreen + "  ✓ 200 OK                       1   17%" + ansiReset,
		ansiGreen + "  ✓ 204 No Content               1   17%" + ansiReset,
		ansiYellow + "  → 304 Not Modified             1   17%" + ansiReset,
		ansiRed + "  ✗ 403 Forbidden                1   17%" + ansiReset,
		ansiRed + "  ✗ 500 Internal Server Error    1   17%" + ansiReset,
		ansiRed + "  ✗ no response                  1   17%" + ansiReset,
	}
	if got := p.frame(clock.now(), inColour); !slices.Equal(got, want) {
		t.Errorf("frame = %q\nwant    %q", got, want)
	}
}

func TestVerdictOfAStatus(t *testing.T) {
	for _, tc := range []struct {
		code int
		want verdict
	}{
		{200, answered}, {201, answered}, {299, answered},
		{300, redirected}, {304, redirected}, {399, redirected},
		{400, refused}, {403, refused}, {429, refused}, {500, refused}, {503, refused},
		// Never the last word from a server, and not a page if it ever is.
		{101, refused},
		// What a request that got no answer is counted under.
		{noResponse, refused},
	} {
		if got := verdictOf(tc.code); got != tc.want {
			t.Errorf("verdictOf(%d) = %d, want %d", tc.code, got, tc.want)
		}
	}

	// Each has a colour of its own, and with colour off there is nothing to put
	// in front of a row.
	if got := []string{inColour.of(answered), inColour.of(redirected), inColour.of(refused)}; !slices.Equal(got, []string{ansiGreen, ansiYellow, ansiRed}) {
		t.Errorf("colours = %q", got)
	}
	if got := (palette{}).of(answered); got != "" {
		t.Errorf("a palette with no colours coloured a row: %q", got)
	}
}

func TestProgressOfOneRequest(t *testing.T) {
	// A bar that is either empty or full says nothing a word does not. One
	// request gets one line: how it ended, how much came back, how long it took.
	clock := fakeClock(t)
	p := newProgress(1)
	p.begin()
	clock.advance(3 * time.Second)
	if got := p.frame(clock.now(), palette{}); !slices.Equal(got, []string{"  waiting for the response · 3s"}) {
		t.Errorf("while it is out: %q", got)
	}

	p.finish(result{Status: 200, Bytes: 577})
	if got := p.frame(clock.now(), inColour); !slices.Equal(got, []string{ansiGreen + "  ✓ 200 OK · 577 B · 3.0s" + ansiReset}) {
		t.Errorf("when it is back: %q", got)
	}

	lost := newProgress(1)
	lost.begin()
	lost.finish(result{Error: "connection refused"})
	clock.advance(57 * time.Millisecond)
	if got := lost.frame(clock.now(), palette{}); !slices.Equal(got, []string{"  ✗ no response · 0 B · 57ms"}) {
		t.Errorf("when nothing came back: %q", got)
	}
}

func TestProgressOfOneRequestAtATime(t *testing.T) {
	// How many are running is never news when it is always one or none.
	clock := fakeClock(t)
	p := newProgress(3)
	p.solo = true
	p.begin()
	if got := p.frame(clock.now(), palette{})[1]; got != "  0s elapsed · 0 B" {
		t.Errorf("pace = %q", got)
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
		"  █████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  3/3  100%",
		"  3s elapsed · 0 B",
		"",
		"  ✓ 200 OK                    1   33%",
		"  ✗ 503 Service Unavailable   1   33%",
		"  ✗ no response               1   33%",
	}
	if got := replay(status.String()); !slices.Equal(got, want) {
		t.Errorf("the screen shows\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Something said about a request goes above the status, which moves down a
	// row to make room and loses none of its own.
	line.Log("a line about a request")
	line.Close()
	if got := replay(status.String()); !slices.Equal(got, append([]string{"a line about a request"}, want...)) {
		t.Errorf("after a line was logged the screen shows\n%s", strings.Join(got, "\n"))
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
	// What a person watching wants to know: how it went.
	if got := after(stderr); !oneLine.MatchString(got) || !strings.HasPrefix(got, "\n  ✓ 200 OK · 8 B · ") {
		t.Errorf("under the report stderr says %q", got)
	}
}

func TestFetchPrintsThePageOnAScreenWhenAsked(t *testing.T) {
	asIfOnScreen(t)
	for _, tc := range []struct {
		name, page, under string
	}{
		// A page rarely ends its last line, and the count would start on the end
		// of it.
		{"a page that stops mid-line", "<html>page</html>", "\n\n  ✓ 200 OK · 17 B · "},
		{"a page that ends its last line", "page\n", "\n  ✓ 200 OK · 5 B · "},
		{"a page with nothing in it", "", "\n  ✓ 200 OK · 0 B · "},
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
			// Whole lines and no escape sequences: nothing was redrawn.
			if got := after(stderr); !strings.HasPrefix(got, tc.under) || strings.Contains(got, "\x1b") ||
				strings.Count(got, "\n") != strings.Count(tc.under, "\n")+1 {
				t.Errorf("under the report stderr says %q, want it to start %q", got, tc.under)
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
	// The headers end their own last line, so what follows starts on a fresh one.
	if got := after(stderr); !oneLine.MatchString(got) {
		t.Errorf("under the report stderr says %q", got)
	}
}

func TestFetchCountsWhatCameBackByStatus(t *testing.T) {
	server, _ := replying(t, 200, 503, 0, 200, 304)

	code, _, stderr := exec(t, "fetch", "--repeat", "5", "--timeout", "10s", server.URL)
	if code != 1 {
		t.Errorf("exit code = %d, want 1: one run got no answer", code)
	}
	// A bar cut into what worked, what was redirected and what did not, then a
	// row for each status the answers had, lowest first, and the run that got
	// none last.
	rows := strings.Split(strings.Trim(after(stderr), "\n"), "\n")
	if len(rows) < 7 {
		t.Fatalf("stderr does not count the runs:\n%s", stderr)
	}
	if want := "  ████████████████▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  5/5  100%"; rows[0] != want {
		t.Errorf("bar = %q, want %q", rows[0], want)
	}
	// Three answers of eight bytes each: a 304 has no body, and nor has silence.
	if !strings.HasSuffix(rows[1], " elapsed · 24 B") {
		t.Errorf("pace = %q", rows[1])
	}
	want := []string{
		"",
		"  ✓ 200 OK                    2   40%",
		"  → 304 Not Modified          1   20%",
		"  ✗ 503 Service Unavailable   1   20%",
		"  ✗ no response               1   20%",
	}
	if got := rows[2:7]; !slices.Equal(got, want) {
		t.Errorf("rows =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
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
		ansiGreen + "██████████" + ansiReset + ansiYellow + "▓▓▓▓▓▓▓▓▓▓" + ansiReset +
			ansiRed + "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" + ansiReset + "  4/4  100%",
		ansiGreen + "  ✓ 200 OK             1   25%" + ansiReset,
		ansiYellow + "  → 304 Not Modified   1   25%" + ansiReset,
		ansiRed + "  ✗ 403 Forbidden      1   25%" + ansiReset,
		ansiRed + "  ✗ no response        1   25%" + ansiReset,
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
	want := []string{
		"",
		"  ██████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒  3/3  100%",
		"  0s elapsed · 24 B",
		"",
		"  ✓ 200 OK          2   67%",
		"  ✗ 404 Not Found   1   33%",
	}
	if !slices.Equal(screen, want) {
		t.Errorf("the screen ends as\n%s\nwant\n%s", strings.Join(screen, "\n"), strings.Join(want, "\n"))
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
		ansiGreen + "  ✓ 200 OK          1   50%" + ansiReset,
		ansiRed + "  ✗ 404 Not Found   1   50%" + ansiReset,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%q", want, after(stderr))
		}
	}
	screen := strings.Join(replay(after(stderr)), "\n")
	if !strings.Contains(screen, "  ████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  2/2  100%\n") ||
		!strings.Contains(screen, "\n\n  ✓ 200 OK          1   50%\n  ✗ 404 Not Found   1   50%\n") {
		t.Errorf("the screen does not end with the bar and its rows:\n%s", screen)
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
