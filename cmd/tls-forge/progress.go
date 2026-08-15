package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// A live status line for a run that takes a while.
//
// It goes to standard error, and that is not a detail: standard output is
// carrying one JSON object per URL, and a status line redrawn into the middle
// of that stream would break whatever is reading it.
//
// Both can still be the same terminal, so the line is erased before every
// result is written and drawn again after. Without that the two would overwrite
// each other and the reader would get neither.

// progress is the count behind the line. Every worker touches it, so every
// field goes through the mutex.
type progress struct {
	mu       sync.Mutex
	total    int
	done     int
	failed   int
	inFlight int
	bytes    int64
	started  time.Time
}

func newProgress(total int) *progress {
	return &progress{total: total, started: now()}
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
	if r.Error != "" {
		p.failed++
	}
}

// line is the status as one line of text.
//
// A pure function of the counts and the clock, so what it says can be checked
// without a terminal, a ticker or a network.
func (p *progress) line(at time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := at.Sub(p.started)
	parts := []string{
		fmt.Sprintf("%d/%d", p.done, p.total),
		fmt.Sprintf("%d running", p.inFlight),
		humanBytes(p.bytes),
		compactDuration(elapsed) + " elapsed",
	}

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

// statusLine draws the counts and keeps them moving.
//
// A ticker as well as a redraw per result, because the elapsed time has to
// advance while a slow page is in flight and nothing is completing.
type statusLine struct {
	out  *printer
	sink io.Writer
	prog *progress

	mu    sync.Mutex
	shown bool

	stop chan struct{}
	done chan struct{}
}

// The two halves of redrawing one line in place: return to its start, and erase
// from the cursor to the end of it.
//
// A frame is written as start + text + eraseToEnd rather than start + eraseToEnd
// + text. Both leave the same thing on screen, but this way the erase clears
// only what the previous, longer frame left behind, instead of blanking the
// line and painting it again.
const (
	lineStart  = "\r"
	eraseToEnd = "\x1b[K"
	eraseLine  = lineStart + eraseToEnd
)

// statusInterval is how often the line is redrawn on its own. Fast enough that
// the seconds look like they are counting, slow enough not to be the reason a
// terminal is busy.
const statusInterval = 200 * time.Millisecond

// newStatusLine starts drawing. Results written through the returned value go
// to sink with the line erased around them.
func newStatusLine(out *printer, sink io.Writer, prog *progress) *statusLine {
	s := &statusLine{
		out:  out,
		sink: sink,
		prog: prog,
		stop: make(chan struct{}),
		done: make(chan struct{}),
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

func (s *statusLine) drawLocked() {
	s.out.printf("%s%s%s", lineStart, s.prog.line(now()), eraseToEnd)
	s.shown = true
}

func (s *statusLine) clearLocked() {
	if !s.shown {
		return
	}
	s.out.printf("%s", eraseLine)
	s.shown = false
}

// Close stops the ticker and leaves the final counts on screen as a line of
// their own, which is the answer to "how long did that take".
func (s *statusLine) Close() {
	close(s.stop)
	<-s.done

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
	s.out.println(s.prog.line(now()))
}

// Write puts a result out without the status line landing on top of it.
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
