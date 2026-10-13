package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
)

// A live status for a run that takes a while: how far it has got, and under
// that what the answers have been.
//
// It goes to standard error, and that is not a detail: standard output is
// carrying one JSON object per URL, and a status redrawn into the middle of
// that stream would break whatever is reading it.
//
// Both can still be the same terminal, so the status is erased before every
// result is written and drawn again after. Without that the two would overwrite
// each other and the reader would get neither.

// watchFlags are how a run shows itself while it goes. Fetch and batch share
// them, so the same word turns the same thing on in each.
type watchFlags struct {
	body     *bool
	verbose  *bool
	progress *string
	color    *string
}

// addWatchFlags registers them. What --body prints is the command's to say: a
// page for fetch, a line of JSON for batch.
func addWatchFlags(fs *pflag.FlagSet, body string) watchFlags {
	return watchFlags{
		body:    fs.Bool("body", false, body),
		verbose: fs.BoolP("verbose", "v", false, "print a line for every request as it finishes"),
		progress: fs.String("progress", "auto",
			"live status on stderr: auto, always or never"),
		color: fs.String("color", "auto",
			"colour the status by outcome: auto, always or never"),
	}
}

// settle reads the two that are words rather than switches: whether to redraw
// the status as the run goes, and in what colours.
//
// Both before anything is fetched, so a misspelling costs a message rather
// than a run that turns out to have nowhere to report itself.
func (f watchFlags) settle(errOut *printer) (live bool, paint palette, err error) {
	if live, err = progressWanted(*f.progress, errOut); err != nil {
		return false, palette{}, err
	}
	if paint, err = paletteFor(*f.color, errOut); err != nil {
		return false, palette{}, err
	}
	return live, paint, nil
}

// onScreen reports whether a stream is one a person is reading as it is
// written. A variable so a test can say that one is.
var onScreen = isTerminal

// wanted reports whether what a run fetched belongs on standard output.
//
// When it leads somewhere other than a screen, yes: a pipe or a redirect was
// pointed at this command to receive exactly that. Unless the run was given a
// file to keep it in, which is then where it goes instead. On a screen only
// when asked: a page is thousands of lines nobody reads as they go past, and
// what a person watching a run wants to know is whether it is working.
func (f watchFlags) wanted(out io.Writer, kept bool) bool {
	return *f.body || (!kept && !onScreen(out))
}

// noResponse is the status a request is counted under when it got none.
const noResponse = 0

// progress is the count behind the status. Every worker touches it, so every
// field goes through the mutex.
type progress struct {
	mu       sync.Mutex
	total    int
	done     int
	failed   int
	inFlight int
	bytes    int64
	started  time.Time
	// statuses is how many answers came back with each status code, and under
	// noResponse how many requests got no answer at all.
	statuses map[int]int
	// solo says the requests are made one at a time, so that how many are
	// running is never news.
	solo bool
}

func newProgress(total int) *progress {
	return &progress{total: total, started: now(), statuses: map[int]int{}}
}

// begin records a request going out.
func (p *progress) begin() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight++
}

// finish records one coming back, whatever it came back as.
func (p *progress) finish(r result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight--
	p.done++
	p.bytes += int64(r.Bytes)
	if r.Failed() {
		p.failed++
		p.statuses[noResponse]++
		return
	}
	p.statuses[r.Status]++
}

// line is the first line of the status: how far the run has got.
//
// A pure function of the counts and the clock, so what it says can be checked
// without a terminal, a ticker or a network.
func (p *progress) line(at time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lineLocked(at)
}

func (p *progress) lineLocked(at time.Time) string {
	elapsed := at.Sub(p.started)
	parts := []string{fmt.Sprintf("%d/%d", p.done, p.total)}
	if !p.solo {
		parts = append(parts, fmt.Sprintf("%d running", p.inFlight))
	}
	parts = append(parts, humanBytes(p.bytes), compactDuration(elapsed)+" elapsed")

	// An estimate needs something to estimate from, and the first few answers
	// are a poor sample of the rest. Nothing is printed rather than a number
	// that will be wrong by a factor of ten a second later.
	if p.done > 0 && p.done < p.total {
		perItem := elapsed / time.Duration(p.done)
		parts = append(parts, "~"+compactDuration(perItem*time.Duration(p.total-p.done))+" left")
	}
	if p.failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", p.failed))
	}
	return strings.Join(parts, "  ")
}

// frame is the whole status: the line that says how far the run has got, and
// under it a line for every status the answers have had, with how many.
//
// By status rather than as two totals, because "seven failed" does not say
// whether the site is refusing the run or is simply down, and 403 against 503
// does. Lowest code first, so the rows stay where they are as others arrive,
// and the requests that got no answer last: they have no code to sort by.
func (p *progress) frame(at time.Time, paint palette) []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	codes := make([]int, 0, len(p.statuses))
	for code := range p.statuses {
		if code != noResponse {
			codes = append(codes, code)
		}
	}
	sort.Ints(codes)

	// As wide as the largest count there can be, so a row does not shift when
	// its number gains a digit.
	width := len(strconv.Itoa(p.total))
	lines := []string{p.lineLocked(at)}
	for _, code := range codes {
		lines = append(lines, fmt.Sprintf("%s  %-11d %*d%s",
			paint.forStatus(code), code, width, p.statuses[code], paint.reset))
	}
	if lost := p.statuses[noResponse]; lost > 0 {
		lines = append(lines, fmt.Sprintf("%s  %-11s %*d%s",
			paint.differ, "no response", width, lost, paint.reset))
	}
	return lines
}

// humanBytes is the body volume, decompressed.
//
// Decompressed, because that is what was measured: the client hands back a
// decoded body and the bytes that crossed the wire were fewer. Calling it
// traffic would overstate it.
func humanBytes(n int64) string {
	switch {
	case n < 1_000:
		return fmt.Sprintf("%d B", n)
	case n < 1_000_000:
		return fmt.Sprintf("%.1f kB", float64(n)/1_000)
	case n < 1_000_000_000:
		return fmt.Sprintf("%.1f MB", float64(n)/1_000_000)
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/1_000_000_000)
	}
}

// compactDuration is a duration a person can read at a glance, which
// time.Duration.String is not: it renders a minute and three seconds as
// "1m3.000481922s".
func compactDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	seconds := int(d.Round(time.Second).Seconds())
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm%02ds", seconds/60, seconds%60)
	default:
		return fmt.Sprintf("%dh%02dm", seconds/3600, (seconds%3600)/60)
	}
}

// preciseDuration is one page's time, where a fifth of a second is a real
// difference and "0s" is not an answer. compactDuration is for the status line,
// where a stable width matters more than the milliseconds.
func preciseDuration(d time.Duration) string {
	switch {
	case d < 0:
		return "0ms"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return compactDuration(d)
	}
}

// statusLine draws the status and keeps it moving.
//
// A ticker as well as a redraw per result, because the elapsed time has to
// advance while a slow page is in flight and nothing is completing.
type statusLine struct {
	out   *printer
	sink  io.Writer
	prog  *progress
	paint palette

	mu sync.Mutex
	// shown is how many lines of status are on screen, which is how far up the
	// next frame has to go to draw over them.
	shown int

	stop chan struct{}
	done chan struct{}
}

// What redrawing in place is made of: return to the start of the line, go up
// to the line above, and erase from the cursor to the end of the line.
//
// A frame is written as text + eraseToEnd on every line rather than erased and
// then painted. Both leave the same thing on screen, but this way the erase
// clears only what the previous, longer frame left behind, instead of blanking
// the status and painting it again.
const (
	lineStart  = "\r"
	cursorUp   = "\x1b[A"
	eraseToEnd = "\x1b[K"
	eraseLine  = lineStart + eraseToEnd
)

// statusInterval is how often the status is redrawn on its own. Fast enough
// that the seconds look like they are counting, slow enough not to be the
// reason a terminal is busy.
const statusInterval = 200 * time.Millisecond

// newStatusLine starts drawing. Results written through the returned value go
// to sink with the status erased around them.
func newStatusLine(out *printer, sink io.Writer, prog *progress, paint palette) *statusLine {
	s := &statusLine{
		out:   out,
		sink:  sink,
		prog:  prog,
		paint: paint,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *statusLine) run() {
	defer close(s.done)
	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.draw()
		}
	}
}

func (s *statusLine) draw() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drawLocked()
}

// drawLocked writes a frame over the one on screen.
//
// In one write, so that a terminal never shows half of the old status and half
// of the new. The cursor is left at the end of the last line, which is where
// the next frame, and the next erase, start from.
func (s *statusLine) drawLocked() {
	frame := s.prog.frame(now(), s.paint)

	var b strings.Builder
	b.WriteString(lineStart)
	for range max(s.shown-1, 0) {
		b.WriteString(cursorUp)
	}
	for i, line := range frame {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(line + eraseToEnd)
	}
	s.out.printf("%s", b.String())
	s.shown = len(frame)
}

// clearLocked takes the status off the screen and leaves the cursor where its
// first line began, so whatever is printed next takes its place.
func (s *statusLine) clearLocked() {
	if s.shown == 0 {
		return
	}
	var b strings.Builder
	b.WriteString(eraseLine)
	for range s.shown - 1 {
		b.WriteString(cursorUp + eraseToEnd)
	}
	s.out.printf("%s", b.String())
	s.shown = 0
}

// Close stops the ticker and leaves the final status on screen as lines of
// their own, which is the answer to "how did that go".
func (s *statusLine) Close() {
	close(s.stop)
	<-s.done

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
	for _, line := range s.prog.frame(now(), s.paint) {
		s.out.println(line)
	}
}

// Log prints a line above the status, which then redraws below it.
func (s *statusLine) Log(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
	s.out.println(text)
	s.drawLocked()
}

// Write puts a result out without the status landing on top of it.
//
// The two streams can be the same terminal, and this is what keeps them from
// interleaving: erase, write the result, draw again underneath it.
func (s *statusLine) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
	n, err := s.sink.Write(p)
	if err != nil {
		return n, err
	}
	s.drawLocked()
	return n, nil
}
