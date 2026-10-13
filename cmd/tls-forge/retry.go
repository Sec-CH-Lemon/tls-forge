package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// How hard a run tries, and where it writes down what trying looked like.
//
// Two different things. Asking again because the answer was wrong is a retry;
// asking again because once was never the plan is a repeat.

// runFlags are how a run is made beyond what its client is: how hard it tries,
// how many times it is made, and whether it is traced.
type runFlags struct {
	retry  *int
	repeat *int
	trace  *string
}

// addRunFlags registers them. Nothing is asked for again unless somebody says
// how many times: what was asked for is one request for each URL, and a list
// is asked for the way one URL is.
func addRunFlags(fs *pflag.FlagSet) runFlags {
	return runFlags{
		retry: fs.Int("retry", 0,
			"times to ask again when the answer is not a 2xx, or does not come"),
		repeat: fs.Int("repeat", 1, "times to make each request"),
		trace: fs.String("trace", "",
			"write every step of the run here as Trace Event JSON, for ui.perfetto.dev"),
	}
}

// check rejects counts that cannot be honoured, as usage errors: nothing has
// been fetched yet, and exit code 1 means something was.
func (f runFlags) check() error {
	// The largest int is refused with the negative ones because the loop that
	// counts tries stops when the count passes this, and nothing passes that.
	if *f.retry < 0 || *f.retry == math.MaxInt {
		return fmt.Errorf("%w: --retry must be non-negative and bounded", errUsage)
	}
	if *f.repeat < 1 {
		return fmt.Errorf("%w: --repeat must be at least 1", errUsage)
	}
	return nil
}

// retrier makes a request until it comes back as a page or the tries run out.
type retrier struct {
	retries int
	// note is told about a try that is about to be made again. Nil keeps quiet,
	// which is what several requests at once want: the tries of two URLs said
	// in turn have nothing to tell them apart.
	note func(text string)
	// keep asks for every try to be written down as it is made, with what it
	// waited on, for a report to show.
	keep bool
}

// do makes the request, and makes it again while the answer is not a 2xx.
//
// A status counts as much as a dead connection. A 503 is not the page, and the
// reason to ask again is the same: whatever was wrong may have passed. The last
// try's answer is the answer, whatever it was, so a run that never got its page
// still hands back what it did get.
//
// The tries come back as well when they are being kept, and nil when not.
func (p retrier) do(ctx context.Context, client *tlsforge.Client, req tlsforge.Request,
	lane *traceLane, run int, proxy string,
) (res *tlsforge.Response, attempts int, tries []try, err error) {
	// One try, then as many again as asked for. The stopping comparison avoids
	// forming retries+1, which overflows for the largest accepted int.
	for attempt := 1; ; attempt++ {
		attempts = attempt
		var log *try
		if p.keep {
			log = &try{}
		}
		shot := lane.attempt(req.Method, req.URL, run, attempt, proxy, log)
		req.Context, req.Trace = ctx, shot.hooks()
		res, err = client.Do(&req)
		shot.end(res, err)
		if log != nil {
			// Copied once the try is over, when nothing is still writing to it.
			tries = append(tries, *log)
		}

		if err == nil && res.OK() {
			return res, attempts, tries, nil
		}
		if ctx.Err() != nil || attempt > p.retries {
			return res, attempts, tries, err
		}
		wait := retryWait(attempt)
		if log != nil {
			tries[len(tries)-1].Wait = wait
		}
		why := whyAgain(res, err, proxy)
		lane.instant("retry", "retry", traceArgs{
			"attempt": attempt, "reason": why, "wait_ms": wait.Milliseconds(),
		})
		if p.note != nil {
			p.note(fmt.Sprintf("  try %d of %d: %s, trying again in %s",
				attempt, p.retries+1, why, preciseDuration(wait)))
		}
		if !pause(ctx, wait) {
			return res, attempts, tries, err
		}
	}
}

// whyAgain is the reason a try was not the last one, as a person reads it.
func whyAgain(res *tlsforge.Response, err error, proxy string) string {
	if err != nil {
		return redactError(err, proxy)
	}
	return "HTTP " + strconv.Itoa(res.Status)
}

// retryWait is how long to wait before trying a URL again. A variable so the
// tests can take the waiting out of the runs where it is not the point; what it
// returns is checked on its own.
var retryWait = backoff

// backoff doubles from a quarter of a second, capped at two.
//
// A retry with no pause is not another try. Measured on an earlier run, a URL
// through a dead proxy recorded two attempts inside one millisecond: the same
// failure twice, in the same microsecond, against a host whose situation had
// not had time to change. Capped, because a run has better things to do than
// sleep, and the point of a pause is to let a transient thing pass rather than
// to wait out an outage.
func backoff(attempt int) time.Duration {
	const first, longest = 250 * time.Millisecond, 2 * time.Second
	if attempt >= 4 {
		return longest
	}
	return first << (attempt - 1)
}

// pause waits, and reports whether it got to finish. A run being wound up does
// not wait out its backoffs first.
func pause(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// numbered is the file one run of several writes its page to: the name given,
// with the run's number in front of the extension.
//
// In front of it rather than after, so that `page-2.html` still opens as what
// it is. Every run is numbered, the first included: a directory holding
// `page.html` beside `page-2.html` reads as a page and a stray copy.
//
// A name that is already something other than a file is left alone. Writing
// to /dev/null is how a body is thrown away, and /dev/null-1 is neither that
// nor anywhere a file can be made.
func numbered(path string, run int) string {
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		return path
	}
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + "-" + strconv.Itoa(run) + ext
}
