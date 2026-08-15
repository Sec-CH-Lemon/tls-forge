package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// atClock is a clock a test moves by hand, so elapsed times and estimates can
// be asserted rather than approximated.
type atClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *atClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *atClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func fakeClock(t *testing.T) *atClock {
	t.Helper()
	clock := &atClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	original := now
	t.Cleanup(func() { now = original })
	now = clock.now
	return clock
}

func TestProgressLine(t *testing.T) {
	clock := fakeClock(t)
	p := newProgress(100)

	// Nothing done yet: no estimate, because there is nothing to estimate from.
	if got := p.line(clock.now()); got != "0/100  0 running  0 B  0s elapsed" {
		t.Errorf("at the start: %q", got)
	}

	for range 4 {
		p.begin()
	}
	clock.advance(30 * time.Second)
	if got := p.line(clock.now()); got != "0/100  4 running  0 B  30s elapsed" {
		t.Errorf("with four in flight: %q", got)
	}

	// Ten done in a minute is six seconds each, so ninety left is nine minutes.
	for range 4 {
		p.finish(result{Bytes: 250_000})
	}
	for range 6 {
		p.begin()
		p.finish(result{Bytes: 250_000})
	}
	clock.advance(30 * time.Second)
	if got := p.line(clock.now()); got != "10/100  0 running  2.5 MB  1m00s elapsed  ~9m00s left" {
		t.Errorf("part way: %q", got)
	}

	// A failure is counted and named, and still counts as done.
	p.begin()
	p.finish(result{Error: "no route to host"})
	if got := p.line(clock.now()); !strings.Contains(got, "11/100") ||
		!strings.Contains(got, "1 failed") {
		t.Errorf("after a failure: %q", got)
	}
}

func TestProgressLineAtTheEnd(t *testing.T) {
	// No estimate once there is nothing left to estimate.
	clock := fakeClock(t)
	p := newProgress(2)
	for range 2 {
		p.begin()
		p.finish(result{Bytes: 10})
	}
	clock.advance(5 * time.Second)
	if got := p.line(clock.now()); strings.Contains(got, "left") {
		t.Errorf("a finished run still guessed at a remainder: %q", got)
	}
}

func TestHumanBytes(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1_000, "1.0 kB"},
		{999_999, "1000.0 kB"},
		{1_000_000, "1.0 MB"},
		{41_200_000, "41.2 MB"},
		{2_500_000_000, "2.50 GB"},
	} {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestCompactDuration(t *testing.T) {
	// time.Duration.String renders a minute and three seconds as
	// "1m3.000481922s", which is not a thing to put in a status line.
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0s"},
		{0, "0s"},
		{950 * time.Millisecond, "1s"},
		{59 * time.Second, "59s"},
		{time.Minute + 3*time.Second, "1m03s"},
		{59*time.Minute + 59*time.Second, "59m59s"},
		{time.Hour + 3*time.Minute, "1h03m"},
		{25 * time.Hour, "25h00m"},
	} {
		if got := compactDuration(tc.d); got != tc.want {
			t.Errorf("compactDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestProgressWanted(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"always", true},
		{"never", false},
		// Not a terminal, so auto stays quiet: a line redrawn five times a
		// second into a log file is thousands of escape sequences nobody asked
		// for.
		{"auto", false},
	} {
		got, err := progressWanted(tc.mode, &strings.Builder{})
		if err != nil || got != tc.want {
			t.Errorf("progressWanted(%q) = %v, %v; want %v", tc.mode, got, err, tc.want)
		}
	}

	_, err := progressWanted("sometimes", &strings.Builder{})
	if err == nil {
		t.Fatal("no error for an unknown mode")
	}
	for _, want := range []string{"--progress", "sometimes", "always"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// captured is a writer a test can read back, safely from either goroutine.
type captured struct {
	mu sync.Mutex
	b  strings.Builder
}

func (c *captured) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}

func (c *captured) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}

func TestStatusLineErasesItselfAroundAResult(t *testing.T) {
	// The two streams can be the same terminal. Without the erase they
	// overwrite one another and the reader gets neither.
	clock := fakeClock(t)
	status, results := &captured{}, &captured{}
	p := newProgress(2)
	line := newStatusLine(newPrinter(status), results, p)

	for _, body := range []string{"{\"url\":\"a\"}\n", "{\"url\":\"b\"}\n"} {
		p.begin()
		p.finish(result{Bytes: 100})
		if _, err := line.Write([]byte(body)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		clock.advance(500 * time.Millisecond)
	}
	line.Close()

	// The results went to the sink untouched: no escape sequence reached the
	// stream something is parsing.
	if got := results.String(); got != "{\"url\":\"a\"}\n{\"url\":\"b\"}\n" {
		t.Errorf("the results were altered: %q", got)
	}
	if strings.Contains(results.String(), "\x1b") {
		t.Error("an escape sequence reached the results")
	}

	drawn := status.String()
	// Nothing was on screen before the first result, so nothing was erased for
	// it. The second one had a frame to clear, and so did Close.
	if strings.HasPrefix(drawn, eraseLine) {
		t.Errorf("the first frame erased a line that was not there: %q", drawn)
	}
	if erases := strings.Count(drawn, eraseLine); erases != 2 {
		t.Errorf("%d erases, want one before the second result and one at the end: %q",
			erases, drawn)
	}
	// Close leaves the final counts as a line of their own.
	if !strings.HasSuffix(drawn, "2/2  0 running  200 B  1s elapsed\n") {
		t.Errorf("the run did not end with its own counts: %q", drawn)
	}
}

func TestStatusLineReportsASinkThatFails(t *testing.T) {
	// A full disk under --output. The error has to reach the caller rather than
	// be swallowed by the thing drawing over it.
	fakeClock(t)
	line := newStatusLine(newPrinter(&captured{}), failingWriter{}, newProgress(1))
	defer line.Close()

	if _, err := line.Write([]byte("{}\n")); err == nil {
		t.Error("no error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

func TestStatusLineTicksOnItsOwn(t *testing.T) {
	// The elapsed time has to keep moving while a slow page is in flight and
	// nothing is completing, which is exactly when someone looks at it.
	clock := fakeClock(t)
	status := &captured{}
	p := newProgress(1)
	p.begin()
	line := newStatusLine(newPrinter(status), &captured{}, p)

	clock.advance(90 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(status.String(), "1m30s elapsed") {
			line.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	line.Close()
	t.Fatalf("the line never redrew on its own: %q", status.String())
}
