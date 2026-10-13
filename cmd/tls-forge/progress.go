package main

import (
	"fmt"
	"io"
	"net/http"
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

// verdict is how an answer went, which is what the count is drawn by.
type verdict int

// In the order they are drawn: what came back as the page, what was sent
// somewhere else, and what did not work.
const (
	answered verdict = iota
	redirected
	refused
)

// verdictOf sorts a status code into the three. A request that got no answer
// has no code, and is refused with everything else that is not a 2xx or a 3xx.
func verdictOf(code int) verdict {
	switch {
	case code >= 200 && code <= 299:
		return answered
	case code >= 300 && code <= 399:
		return redirected
	}
	return refused
}

// What each verdict is drawn with: a mark in front of its rows, and a cell in
// the bar.
//
// A different shape for each as well as a different colour. Colour is not
// drawn everywhere, and is not told apart by everybody, so it is never the only
// thing saying which is which.
var (
	verdictMark = [...]string{answered: "✓", redirected: "→", refused: "✗"}
	verdictCell = [...]string{answered: "█", redirected: "▓", refused: "▒"}
)

// The bar: how many cells wide, and what the part of the run still to come is
// drawn with. Forty leaves room on the same line for how far the run has got,
// inside the width the report above it is ruled to.
const (
	barWidth    = 40
	pendingCell = "░"
)

// progress is the count behind the status. Every worker touches it, so every
// field goes through the mutex.
type progress struct {
	mu       sync.Mutex
	total    int
	done     int
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
		p.statuses[noResponse]++
		return
	}
	p.statuses[r.Status]++
}

// tally is one row of the count: a status, by number and by name, and how many
// answers had it.
type tally struct {
	how   verdict
	label string
	count int
}

// tallies are the rows of the count.
//
// By status rather than as two totals, because "seven failed" does not say
// whether the site is refusing the run or is simply down, and 403 against 503
// does. Lowest code first, so the rows stay where they are as others arrive,
// and the requests that got no answer last: they have no code to sort by.
func (p *progress) tallies() []tally {
	codes := make([]int, 0, len(p.statuses))
	for code := range p.statuses {
		if code != noResponse {
			codes = append(codes, code)
		}
	}
	sort.Ints(codes)

	rows := make([]tally, 0, len(p.statuses))
	for _, code := range codes {
		// The name beside the number, for whoever does not keep the table of
		// them in their head. A code nobody has named goes without.
		label := strconv.Itoa(code)
		if name := http.StatusText(code); name != "" {
			label += " " + name
		}
		rows = append(rows, tally{verdictOf(code), label, p.statuses[code]})
	}
	if lost := p.statuses[noResponse]; lost > 0 {
		rows = append(rows, tally{refused, "no response", lost})
	}
	return rows
}

// frame is the whole status, as the lines it is drawn in: a bar for how far the
// run has got and how it is going, a line for how long it has taken, and a row
// for every status the answers have had.
//
// A pure function of the counts and the clock, so what it says can be checked
// without a terminal, a ticker or a network.
func (p *progress) frame(at time.Time, paint palette) []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	rows := p.tallies()
	if p.total == 1 {
		return []string{p.single(at, rows, paint)}
	}

	lines := []string{
		fmt.Sprintf("  %s  %d/%d  %d%%", p.bar(rows, paint), p.done, p.total,
			p.done*100/max(p.total, 1)),
		"  " + p.pace(at),
	}
	if len(rows) == 0 {
		return lines
	}

	// The names as wide as the longest of them, and the counts as wide as the
	// largest there can be, so a row does not shift when its number gains a
	// digit.
	widest := 0
	for _, row := range rows {
		widest = max(widest, len(row.label))
	}
	digits := len(strconv.Itoa(p.total))
	lines = append(lines, "")
	for _, row := range rows {
		// A share of what has come back so far, to the nearest whole percent.
		share := (row.count*100 + p.done/2) / p.done
		lines = append(lines, fmt.Sprintf("%s  %s %-*s   %*d  %3d%%%s", paint.of(row.how),
			verdictMark[row.how], widest, row.label, digits, row.count, share, paint.reset))
	}
	return lines
}

// bar is the run as one strip: what came back as the page, what was redirected
// and what failed, each as wide as its share of the run, and then what is
// still to come.
func (p *progress) bar(rows []tally, paint palette) string {
	var by [len(verdictCell)]int
	for _, row := range rows {
		by[row.how] += row.count
	}

	// Cut at running totals rather than by adding widths up, so that rounding
	// never makes the strip longer or shorter than it is.
	var strip strings.Builder
	drawn, counted := 0, 0
	for how, count := range by {
		counted += count
		if end := counted * barWidth / max(p.total, 1); end > drawn {
			strip.WriteString(paint.of(verdict(how)) +
				strings.Repeat(verdictCell[how], end-drawn) + paint.reset)
			drawn = end
		}
	}
	if drawn < barWidth {
		strip.WriteString(paint.dim + strings.Repeat(pendingCell, barWidth-drawn) + paint.reset)
	}
	return strip.String()
}

// pace is the line under the bar: how long the run has taken, how long it has
// left, how many requests are out, and how much has come back.
func (p *progress) pace(at time.Time) string {
	elapsed := at.Sub(p.started)
	parts := []string{compactDuration(elapsed) + " elapsed"}

	// An estimate needs something to estimate from, and the first few answers
	// are a poor sample of the rest. Nothing is printed rather than a number
	// that will be wrong by a factor of ten a second later.
	if p.done > 0 && p.done < p.total {
		perItem := elapsed / time.Duration(p.done)
		parts = append(parts, "~"+compactDuration(perItem*time.Duration(p.total-p.done))+" left")
	}
	if !p.solo && p.inFlight > 0 {
		parts = append(parts, fmt.Sprintf("%d running", p.inFlight))
	}
	return strings.Join(append(parts, humanBytes(p.bytes)), " · ")
}

// single is the status of a run that is one request, on one line.
//
// A bar that is either empty or full says nothing a word does not, and a count
// of one out of one says less. What is worth saying about one request is how it
// ended, how much came back and how long that took.
func (p *progress) single(at time.Time, rows []tally, paint palette) string {
	took := at.Sub(p.started)
	if len(rows) == 0 {
		return "  waiting for the response · " + compactDuration(took)
	}
	row := rows[0]
	return fmt.Sprintf("%s  %s %s · %s · %s%s", paint.of(row.how), verdictMark[row.how],
		row.label, humanBytes(p.bytes), preciseDuration(took), paint.reset)
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
