package main

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"sync"
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
	// reuse keeps a URL's connection for its repeats and its tries.
	reuse *bool
	trace *string
}

// addRunFlags registers them. Nothing is asked for again unless somebody says
// how many times: what was asked for is one request for each URL, and a list
// is asked for the way one URL is.
func addRunFlags(fs *pflag.FlagSet) runFlags {
	return runFlags{
		retry: fs.Int("retry", 0,
			"times to ask again when the answer is not a 2xx, or does not come"),
		repeat: fs.Int("repeat", 1, "times to make each request"),
		reuse: fs.Bool("reuse-connection", false,
			"repeat a URL, and try it again, on the connection its first request opened, rather than on a new one"),
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
	// check is what an answer has to have to be the page; nil asks nothing.
	check *pageCheck
}

// do makes the request, and makes it again while the answer is not the page:
// not a 2xx, or, when --wait-for-element names what the page has, without it,
// whatever its status.
//
// A status counts as much as a dead connection. A 503 is not the page, and the
// reason to ask again is the same: whatever was wrong may have passed. So is a
// 200 that is somebody's challenge rather than the page. The last try's answer
// is the answer, whatever it was, so a run that never got its page still hands
// back what it did get, and found says what its body had of what the page has.
//
// The tries come back as well when they are being kept, and nil when not.
func (p retrier) do(ctx context.Context, conns *connections, req tlsforge.Request,
	lane *traceLane, run int, proxy string,
) (res *tlsforge.Response, attempts int, tries []try, found finding, err error) {
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
		res, err = conns.do(&req)
		shot.end(res, err)
		found = finding{}
		if err == nil {
			found = p.check.look(res)
		}
		if found.MissingElement != "" {
			lane.instant("no element", "check", traceArgs{"selector": found.MissingElement})
		}
		if log != nil {
			log.finding = found
			if found.looked {
				// How an answer that is not the page began, its body and not its
				// status saying so: it is usually where a site says what it is.
				log.Body = ""
				if found.misses() {
					log.Body = preview(res.Body)
				}
			}
			// Copied once the try is over, when nothing is still writing to it.
			tries = append(tries, *log)
		}

		// What the run names the page by says whether it came, when it names
		// anything, and the status when it does not.
		page := err == nil && res.OK()
		if p.check != nil {
			page = err == nil && !found.misses()
		}
		if page {
			return res, attempts, tries, found, nil
		}
		if ctx.Err() != nil || attempt > p.retries {
			return res, attempts, tries, found, err
		}
		wait := retryWait(attempt)
		if log != nil {
			tries[len(tries)-1].Wait = wait
		}
		why := whyAgain(res, err, proxy)
		if found.misses() {
			why = found.said()
		}
		lane.instant("retry", "retry", traceArgs{
			"attempt": attempt, "reason": why, "wait_ms": wait.Milliseconds(),
		})
		if p.note != nil {
			p.note(fmt.Sprintf("  try %d of %d: %s, trying again in %s",
				attempt, p.retries+1, why, preciseDuration(wait)))
		}
		if !pause(ctx, wait) {
			return res, attempts, tries, found, err
		}
	}
}

// connections hands every try of a request the client it goes out through.
//
// Without --reuse-connection that is the worker's client for the request's
// proxy, a client of the session made Fresh once for each worker, which lets go
// of its connection after every try: every URL, every repeat of it and every
// try goes out on a connection of its own. Its TLS sessions it keeps, so that
// once the worker has been to a site a new connection there resumes the
// session the site handed out, as a browser's new connection does, rather than
// being a first contact every time. Under --reuse-connection a URL keeps its
// connection instead, for its repeats and its tries, in a client the first of
// them makes and the last lets go of. What a try's site is asked over the same
// connection goes through the client the try went through.
type connections struct {
	session *tlsforge.Client
	// own holds the worker's clients, one for each proxy, and proxy is this
	// request's; held, under --reuse-connection, keeps each URL's, and entry is
	// which URL this is.
	own   *workerClients
	proxy string
	held  *heldClients
	entry int
	// last is the client the latest try went through.
	last *tlsforge.Client
}

// do makes a try through the client it is to go out through.
func (c *connections) do(req *tlsforge.Request) (*tlsforge.Response, error) {
	client, err := c.next()
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// next is the client for the next try: the URL's own when it keeps one, and
// otherwise the worker's, with the connection of the try before let go of.
func (c *connections) next() (*tlsforge.Client, error) {
	var client *tlsforge.Client
	var err error
	if c.held != nil {
		client, err = c.held.of(c.entry, c.session)
	} else {
		c.release()
		client, err = c.own.of(c.proxy, c.session)
	}
	c.last = client
	return client, err
}

// current is the client the latest try went through, over whose connection
// its site is asked where it came from.
func (c *connections) current() *tlsforge.Client {
	if c.last != nil {
		return c.last
	}
	return c.session
}

// close lets go of what the request held: the connection of its latest try,
// or its share of the URL's, which is closed once the URL's last repeat is
// over.
func (c *connections) close() {
	if c.held != nil {
		c.held.done(c.entry)
		return
	}
	c.release()
}

// release closes the connection the latest try went out on, keeping the client
// it went through and the TLS sessions that holds.
func (c *connections) release() {
	if c.last != nil {
		c.last.CloseIdleConnections()
	}
}

// workerClients are one worker's clients, one for each proxy it has gone
// through, each made Fresh from that proxy's session the first time it is
// needed: connections of their own, and the TLS sessions of the sites they
// have been to. A worker makes one request at a time, so nothing here is
// shared with another.
type workerClients struct {
	clients map[string]*tlsforge.Client
}

func newWorkerClients() *workerClients {
	return &workerClients{clients: map[string]*tlsforge.Client{}}
}

// of is the worker's client for a proxy.
func (w *workerClients) of(proxy string, session *tlsforge.Client) (*tlsforge.Client, error) {
	if client, ok := w.clients[proxy]; ok {
		return client, nil
	}
	client, err := session.Fresh()
	if err != nil {
		return nil, err
	}
	w.clients[proxy] = client
	return client, nil
}

// close closes them all, when the worker is done.
func (w *workerClients) close() {
	for _, client := range w.clients {
		_ = client.Close()
	}
}

// heldClients are the clients the URLs of a run keep their connections in
// under --reuse-connection: made by the first request to a URL, and closed
// when the last of its repeats is over, so that a long list does not hold a
// connection open for every URL it has been through.
type heldClients struct {
	mu      sync.Mutex
	repeats int
	clients map[int]*heldClient
}

// heldClient is one URL's client, and how many of its repeats are not over.
type heldClient struct {
	client *tlsforge.Client
	left   int
}

func newHeldClients(repeats int) *heldClients {
	return &heldClients{repeats: repeats, clients: map[int]*heldClient{}}
}

// of is the URL's client, made from the session the first time it is asked
// for.
func (h *heldClients) of(entry int, session *tlsforge.Client) (*tlsforge.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if held, ok := h.clients[entry]; ok {
		return held.client, nil
	}
	client, err := session.Fresh()
	if err != nil {
		return nil, err
	}
	h.clients[entry] = &heldClient{client: client, left: h.repeats}
	return client, nil
}

// done says one repeat of the URL is over. After the last, its client is
// closed.
func (h *heldClients) done(entry int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	held, ok := h.clients[entry]
	if !ok {
		return
	}
	if held.left--; held.left > 0 {
		return
	}
	_ = held.client.Close()
	delete(h.clients, entry)
}

// closeAll closes what a run that ended before its last repeats left held.
// Nil holds nothing.
func (h *heldClients) closeAll() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for entry, held := range h.clients {
		_ = held.client.Close()
		delete(h.clients, entry)
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
