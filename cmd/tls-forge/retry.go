package main

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/spf13/pflag"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// How hard a run tries.
//
// Asking again because the answer was wrong is a retry, and that is the word
// for it in fetch and in batch alike. Batch used to call it a repeat, which is
// the word for asking again when once was never the plan.

// runFlags are the flags fetch and batch share beyond the client's own.
type runFlags struct {
	retry *int
}

// addRunFlags registers them. The number of retries a command makes when
// nobody says is the command's to choose: none for the one request fetch was
// asked for, a few for a list batch is left alone with.
func addRunFlags(fs *pflag.FlagSet, retries int) runFlags {
	return runFlags{
		retry: fs.Int("retry", retries,
			"times to ask again when the answer is not a 2xx, or does not come"),
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
	return nil
}

// retrier makes a request until it comes back as a page or the tries run out.
type retrier struct {
	retries int
	// note is told about a try that is about to be made again. Nil keeps quiet,
	// which is what batch wants: it has a line per URL already.
	note func(text string)
}

// do makes the request, and makes it again while the answer is not a 2xx.
//
// A status counts as much as a dead connection. A 503 is not the page, and the
// reason to ask again is the same: whatever was wrong may have passed. The last
// try's answer is the answer, whatever it was, so a run that never got its page
// still hands back what it did get.
func (p retrier) do(ctx context.Context, client *tlsforge.Client, req tlsforge.Request,
	proxy string,
) (res *tlsforge.Response, attempts int, err error) {
	// One try, then as many again as asked for. The stopping comparison avoids
	// forming retries+1, which overflows for the largest accepted int.
	for attempt := 1; ; attempt++ {
		attempts = attempt
		req.Context = ctx
		res, err = client.Do(&req)

		if err == nil && res.OK() {
			return res, attempts, nil
		}
		if ctx.Err() != nil || attempt > p.retries {
			return res, attempts, err
		}
		wait := retryWait(attempt)
		if p.note != nil {
			p.note(fmt.Sprintf("  try %d of %d: %s, trying again in %s",
				attempt, p.retries+1, whyAgain(res, err, proxy), preciseDuration(wait)))
		}
		if !pause(ctx, wait) {
			return res, attempts, err
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
