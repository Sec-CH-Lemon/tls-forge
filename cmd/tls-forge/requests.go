package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// Making a list of requests: the record of each, the clients they go through,
// and the workers that make them.

// result is one request, and one line of the output when that is JSON lines.
// Lines rather than a JSON array so the output can be read as it is produced,
// and appended to across runs.
type result struct {
	URL      string `json:"url"`
	Proxy    string `json:"proxy,omitempty"`
	Status   int    `json:"status,omitempty"`
	FinalURL string `json:"final_url,omitempty"`
	// Header is the response's header fields, written when they were asked for
	// with --include.
	Header map[string][]string `json:"headers,omitempty"`
	Bytes  int                 `json:"bytes,omitempty"`
	Body   string              `json:"body,omitempty"`
	// BodyEncoding is "base64" when Body was not valid UTF-8. It is omitted
	// for text so existing JSONL consumers keep seeing the old shape normally.
	BodyEncoding string `json:"body_encoding,omitempty"`
	// File, Log and Trace are where the page, the log and the trace of the
	// request were kept, when there was somewhere to keep them.
	File    string    `json:"file,omitempty"`
	Log     string    `json:"log,omitempty"`
	Trace   string    `json:"trace,omitempty"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended"`
	Millis  int64     `json:"ms"`
	// Run is which time this request was made, under --repeat. Omitted when
	// every request is made once, as it always used to be.
	Run      int    `json:"run,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
	Error    string `json:"error,omitempty"`
	// Tries are the attempts one by one, with what each waited on. Kept for a
	// report and for nothing else: the lines are what they have always been.
	Tries []try `json:"-"`
	// ID is which request of the run this was, from one.
	ID int `json:"-"`
	// Exit is where the request came out, and ExitError why that is not known.
	// Through a proxy it is what the proxy said when it opened the connection
	// the request went out on: a proxy that hands every connection an address
	// of its own makes anything asked on another connection somebody else's
	// address. Without one it is where the run came out when that was asked,
	// before the first request.
	Exit      egress `json:"-"`
	ExitError string `json:"-"`
}

// exitSaid is where the request came out, as its log and its opened row say
// it, or empty when there is nothing to say.
func (r result) exitSaid() string {
	switch {
	case r.Exit.Known():
		return describeExit(r.Exit, nil, "")
	case r.ExitError != "":
		return "unknown · " + r.ExitError
	default:
		return ""
	}
}

// MarshalJSON writes the record with the proxy password removed.
//
// On the type rather than at the one place that encodes it, so that a second
// thing which learns to write these lines cannot forget: the output is a file
// people keep, diff and send on.
func (r result) MarshalJSON() ([]byte, error) {
	// An alias, because a named type with no methods does not inherit this one
	// and so cannot recurse into it.
	type plain result
	out := plain(r)
	out.Proxy = redactProxy(out.Proxy)
	return json.Marshal(out)
}

// redactProxy strips the password from a proxy URL for display.
//
// result.Proxy keeps the URL as given, because it is the key the client pool
// and the exit-address lookup are filed under. Everything a person can read —
// the JSON lines, the terminal summary, the HTML report, the note written into
// a saved cookie file — goes through here first, because all four are made to
// be kept and passed on, and a proxy password is not the kind of thing to hand
// over with them.
//
// The username stays: it is what tells two proxies apart in a report, and a
// report that calls every proxy the same thing is not worth writing.
func redactProxy(proxy string) string {
	if proxy == "" || !strings.Contains(proxy, "@") {
		return proxy
	}
	parsed := proxy
	schemeLess := !strings.Contains(proxy, "://")
	if schemeLess {
		// url.Parse reads "alice:secret@host" as an opaque URL whose scheme is
		// alice, so User is nil and the password used to pass through unchanged.
		parsed = "proxy://" + proxy
	}
	u, err := url.Parse(parsed)
	if err != nil {
		// Unparseable but carrying an "@" — drop everything before the last one
		// rather than guess at its shape and print a password by accident.
		return "[redacted]@" + proxy[strings.LastIndex(proxy, "@")+1:]
	}
	if u.User == nil {
		// Parsed, and the "@" belongs to the path or the query rather than to
		// any credentials. Rewriting it would corrupt a URL that holds nothing
		// worth hiding.
		return proxy
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return proxy
	}
	u.User = url.User(u.User.Username())
	safe := u.String()
	if schemeLess {
		safe = strings.TrimPrefix(safe, "proxy://")
	}
	return safe
}

// setError records a failure with the proxy password taken out of its text.
func (r *result) setError(err error) {
	r.Error = redactError(err, r.Proxy)
}

// redactError is what an error says, with the proxy password taken out of it.
//
// Needed on top of redactProxy because the proxy URL turns up inside error
// messages as well as in the proxy field: url.Parse quotes back the whole
// string it could not parse, so a mistyped proxy writes its own password into
// the output that was just cleaned of it.
func redactError(err error, proxy string) string {
	text := err.Error()
	safe := redactProxy(proxy)
	if safe != proxy {
		text = strings.ReplaceAll(text, proxy, safe)
		// The message may quote a normalised form rather than the string as
		// given, so the credentials are replaced in that shape too.
		if u, parseErr := url.Parse(proxy); parseErr == nil && u.User != nil {
			if _, ok := u.User.Password(); ok {
				text = strings.ReplaceAll(text, u.User.String()+"@",
					url.User(u.User.Username()).String()+"@")
			}
		}
	}
	return text
}

// listInput is os.Stdin, named so a test can supply a list.
var listInput io.Reader = os.Stdin

// numCPU is runtime.NumCPU, named so a test can answer for it. A machine's core
// count is not something a test can choose, and the warning below is worth
// checking on more than whatever the runner happens to have.
var numCPU = runtime.NumCPU

// progressWanted decides whether to draw the status line.
//
// `auto` means "only when someone is watching": redirected to a file or a log,
// a line rewritten five times a second is thousands of escape sequences nobody
// asked for.
func progressWanted(mode string, w io.Writer) (bool, error) {
	switch mode {
	case "never":
		return false, nil
	case "always":
		return true, nil
	case "auto":
		return isTerminal(w), nil
	default:
		return false, &badFlag{"--progress", mode, "auto, always or never"}
	}
}

// warnAboutConcurrency says something when more workers were asked for than
// there are CPUs to run them on.
//
// A warning and not a limit. Fetching waits on the network far more than on a
// core, so more workers than cores is often the right answer and capping it
// would make the tool slower for the thing it is for. What it usually means
// instead is a number typed without thinking, and past a point the extra
// workers only queue behind the same connections and the same exit IP.
//
// To stderr, so it cannot land in the middle of the JSON lines on stdout.
func warnAboutConcurrency(errOut *printer, workers int) {
	cpus, limited := cpuLimit()
	if workers <= cpus {
		return
	}
	// Named for where the number came from. "cores on this machine" would be a
	// puzzle to read on a 64-core host inside a container allowed two of them.
	where := "CPU cores on this machine"
	if limited {
		where = "CPUs this process is allowed"
	}
	errOut.printf("WARN: --concurrency %d is more than the %d %s.\n", workers, cpus, where)
	errOut.println("      Fetching waits on the network rather than on a core, so this may " +
		"be what you want.")
}

// stderrLog is what a run says while it runs.
//
// To standard error, with everything else that is commentary: standard output
// is carrying the page, or one JSON object per URL. When a status line is drawing there too,
// the log goes through it so the two do not land on each other; when there is
// none, it takes a lock of its own, because several workers write here.
type stderrLog struct {
	mu   sync.Mutex
	out  *printer
	line *statusLine
	on   bool
}

func (l *stderrLog) say(text string) {
	if !l.on {
		return
	}
	if l.line != nil {
		l.line.Log(text)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.println(text)
}

// verboseLine is one finished request.
//
// Printed when it finishes rather than when it starts: at any real concurrency
// a line per departure and a line per arrival interleave into something nobody
// reads, and what is in flight is what the status line is for. The columns are
// fixed width so a run scrolling past stays a column of statuses rather than a
// paragraph.
func verboseLine(r result) string {
	status := "---"
	if r.Status != 0 {
		status = strconv.Itoa(r.Status)
	}
	tries := "     "
	if r.Attempts > 1 {
		tries = fmt.Sprintf("x%-4d", r.Attempts)
	}
	line := fmt.Sprintf("  %-3s %10s %8s %s %s", status, humanBytes(int64(r.Bytes)),
		preciseDuration(time.Duration(r.Millis)*time.Millisecond), tries, r.URL)
	if r.Proxy != "" {
		line += "  via " + redactProxy(r.Proxy)
	}
	if r.Error != "" {
		line += "  " + r.Error
	}
	return line
}

// withoutBody is the record the run keeps for its summary and its report.
//
// Without the page and the header fields it came with, which neither of them
// shows. Kept whole, a run holds every page it fetched in memory until it
// ends: measured at 200 MB of pages, that was 353 MB of resident memory against
// 117 MB once the bodies went. What is left is a fixed couple of hundred bytes
// per URL.
func (r result) withoutBody() result {
	r.Body, r.Header = "", nil
	return r
}

// finish stamps when this URL was done with, however it turned out.
func (r *result) finish(started time.Time) {
	r.Ended = now()
	r.Millis = r.Ended.Sub(started).Milliseconds()
}

// pool hands out one client per proxy.
//
// One per proxy rather than one per worker, because the proxy is the identity.
// Two pages fetched through one exit IP sharing a cookie jar is what a browser
// does; two pages sharing a jar across two exit IPs is what none does. Clients
// are safe for concurrent use, so several workers can share one.
type pool struct {
	mu       sync.Mutex
	clients  map[string]*tlsforge.Client
	flags    clientFlags
	fallback string
}

func newPool(flags clientFlags, fallback string) *pool {
	return &pool{clients: map[string]*tlsforge.Client{}, flags: flags, fallback: fallback}
}

func (p *pool) resolveProxy(proxy string) string {
	if proxy == "" {
		return p.fallback
	}
	return proxy
}

// get returns the client for a proxy, building it on first use.
//
// Built lazily so that a list naming twenty proxies of which the run only
// reaches three opens three, and so that a proxy URL that will not parse fails
// against the URL that asked for it rather than at start-up against nothing.
func (p *pool) get(proxy string) (*tlsforge.Client, error) {
	proxy = p.resolveProxy(proxy)
	p.mu.Lock()
	defer p.mu.Unlock()
	if client, ok := p.clients[proxy]; ok {
		return client, nil
	}
	client, err := p.flags.clientVia(proxy)
	if err != nil {
		return nil, err
	}
	p.clients[proxy] = client
	return client, nil
}

// hold puts a client that is already made in the pool, under the proxy it was
// made for.
//
// For a run that goes one way. Its client is made before anything is fetched,
// so that a proxy or a session that cannot be used is the command's failure
// rather than every request's, and so that the session the run says it was
// warmed from is the one its client was given.
func (p *pool) hold(proxy string, client *tlsforge.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[p.resolveProxy(proxy)] = client
}

// saveSessions writes down what each client ended up holding, one set per
// proxy, so a run's warming survives it.
func (p *pool) saveSessions(flags clientFlags, records []result) (int, error) {
	if *flags.saveCookies == "" {
		return 0, nil
	}
	hostsByProxy := map[string][]string{}
	for _, r := range records {
		hostsByProxy[r.Proxy] = append(hostsByProxy[r.Proxy], r.URL)
	}

	proxies := make([]string, 0, len(hostsByProxy))
	for proxy := range hostsByProxy {
		proxies = append(proxies, proxy)
	}
	sort.Strings(proxies)

	saved := 0
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, proxy := range proxies {
		client, ok := p.clients[proxy]
		if !ok {
			continue
		}
		note := "direct"
		if proxy != "" {
			note = "via " + redactProxy(proxy)
		}
		n, err := flags.saveSession(client, hostsByProxy[proxy], note)
		if err != nil {
			return saved, err
		}
		saved += n
	}
	return saved, nil
}

func (p *pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, client := range p.clients {
		_ = client.Close()
	}
}

// runner is what requests are made with: everything runJobs needs that is not
// the list itself.
type runner struct {
	clients *pool
	workers int
	// request is what each URL is asked for with: the method, the header fields
	// and the body, which are the same for every one of them.
	request tlsforge.Request
	// retry is how many more times a URL is asked for when it does not come
	// back as a page, and repeat how many times the whole list is gone through.
	retry  int
	repeat int
	// out is what becomes of what each request brings back.
	out output
	// keep is the directory every request is kept in, with what it brought back,
	// a log of it and a trace of it; none when it is empty. about is what the
	// run knows of all of its requests, for those logs.
	keep  string
	about requestAbout
	// direct is where a request made without a proxy comes out, as it was asked
	// before the first request, and directError why that is not known.
	direct      egress
	directError string
	// exits are how where a request through a proxy came out is found: the
	// header fields its answers are read for, and what is asked when they say
	// nothing or say a name. names asks each name once.
	exits exitTable
	names *resolver
	// held keeps every URL's connection across its repeats and tries, when
	// --reuse-connection asks; nil gives every try a connection of its own.
	held   *heldClients
	counts *progress
	// note is told about a try that is about to be made again. Nil keeps quiet,
	// which is what a run of several requests at once wants: the tries of two
	// URLs would be said in turn with nothing to tell them apart.
	note  func(text string)
	trace *tracer
	// detailed says a report will be written, so every try is kept as it is
	// made, with what it waited on.
	detailed bool
}

// runJobs makes the requests and returns how many got no response. A failure
// is reported on its own record rather than returned, so one dead host does not
// end the run. What is returned is a run that could not go on: interrupted, or
// with nowhere left to put what it fetched.
func runJobs(ctx context.Context, jobs []job, b runner, records *[]result,
) (failures int, runErr error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	queue := make(chan job)
	var writeMu sync.Mutex
	// How many of the records may go on holding their tries, counted under the
	// same lock the records are added under.
	var room tryBudget
	var wg sync.WaitGroup

	for worker := 1; worker <= b.workers; worker++ {
		// A row of the trace per worker: one worker makes one request at a time,
		// so what is drawn on its row never overlaps. One worker alone is the
		// command, and draws on the command's own row.
		lane := b.trace.main()
		if b.workers > 1 {
			lane = b.trace.lane(mainLane+worker, "worker "+strconv.Itoa(worker))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			own := newWorkerClients()
			defer own.close()
			for j := range queue {
				b.counts.begin()
				r, res, kept := b.fetchOne(runCtx, j, lane, own)
				b.counts.finish(r)
				writeMu.Lock()
				if r.Error != "" {
					failures++
				}
				// Nothing more is handed on once handing on has failed, and
				// nothing more is fetched once there is nowhere to keep it: the
				// next result has nowhere to go either.
				if runErr == nil {
					if runErr = kept; runErr == nil {
						runErr = b.out.write(&r, res, lane)
					}
					if runErr != nil {
						cancel()
					}
				}
				*records = append(*records, room.trim(r.withoutBody()))
				writeMu.Unlock()
			}
		}()
	}

	b.dispatch(runCtx, jobs, queue)
	close(queue)
	wg.Wait()
	b.held.closeAll()
	if runErr != nil {
		return failures, runErr
	}
	if err := ctx.Err(); err != nil {
		return failures, fmt.Errorf("fetch: %w", err)
	}
	return failures, nil
}

// dispatch hands the list to the workers, once for every pass asked for.
//
// The whole list and then the whole list again, rather than each URL several
// times in a row: a repeat is the run made again, and several workers handed
// the same URL at once would be asking a different question, about what a
// server does under a burst.
func (b runner) dispatch(ctx context.Context, jobs []job, queue chan<- job) {
	occurrences := make(map[string]int)
	handed := 0
	for pass := 1; pass <= b.repeat; pass++ {
		for entry, j := range jobs {
			j.entry = entry
			occurrences[j.URL]++
			j.occurrence = occurrences[j.URL]
			j.run = pass
			handed++
			j.id = handed
			select {
			case <-ctx.Done():
				// Stop handing out work. Requests already in flight receive the same
				// cancellation through fetchOne.
				return
			case queue <- j:
			}
		}
	}
}

// fetchOne makes one request, however many tries that takes, and returns the
// record of it with what came back, which is nil when nothing did. The error is
// not the request's, which is on the record: it is that the request could not be
// kept where it was to be kept.
func (b runner) fetchOne(ctx context.Context, j job, lane *traceLane, own *workerClients,
) (result, *tlsforge.Response, error) {
	started := now()
	proxy := b.clients.resolveProxy(j.Proxy)
	r := result{URL: j.URL, Proxy: proxy, Started: started, ID: j.id}
	if proxy == "" {
		// Where the machine comes out, which every request made without a
		// proxy shares.
		r.Exit, r.ExitError = b.direct, b.directError
	}
	if b.repeat > 1 {
		// Only when there is more than one, so a request made once keeps the
		// shape its line has always had.
		r.Run = j.run
	}

	client, err := b.clients.get(proxy)
	if err != nil {
		r.setError(err)
		r.finish(started)
		lane.instant("error", "request", traceArgs{"url": safeURL(j.URL), "error": r.Error})
		return r, nil, b.kept(&r, nil, j, lane)
	}

	// Every try on a connection of its own, through the worker's client, unless
	// the URL keeps its own.
	conns := &connections{session: client, own: own, proxy: proxy, held: b.held, entry: j.entry}
	defer conns.close()

	request := b.request
	request.URL = j.URL
	res, attempts, tries, err := retrier{retries: b.retry, note: b.note, keep: b.detailed}.do(
		ctx, conns, request, lane, j.run, proxy)
	r.Attempts, r.Tries = attempts, tries
	r.finish(started)
	if proxy != "" {
		r.Exit, r.ExitError = b.cameOut(ctx, conns.current(), proxy, tries, res, lane)
	}

	if err != nil {
		r.setError(err)
		return r, nil, b.kept(&r, nil, j, lane)
	}
	r.Status = res.Status
	r.FinalURL = res.URL
	r.Bytes = len(res.Body)
	if err := b.kept(&r, res, j, lane); err != nil {
		return r, res, err
	}
	if keeps, ok := b.out.(filler); ok {
		keeps.fill(&r, res, j, lane)
	}
	return r, res, nil
}

// exitThrough is where a request through a proxy came out, or why that is not
// known: what the proxy said when it opened the connection the request's last
// try went out on, or failing that, what the answer to the request says, which
// a proxy that reads the traffic writes. Each try is given what its own
// connection's proxy said.
//
// Nothing, and no reason, when the tries were not kept, or the last of them
// never had a connection to come out of.
//
// The field that said it comes back with it, for how to turn a name it holds
// into an address.
func exitThrough(tries []try, answer map[string][]string, fields []exitField) (egress, string, exitField) {
	var said exitField
	for i := range tries {
		tries[i].Exit, said = exitIn(tries[i].Conn.ProxyHeader, fields, "connect")
	}
	if len(tries) == 0 || !tries[len(tries)-1].Connected {
		return egress{}, "", exitField{}
	}
	if found := tries[len(tries)-1].Exit; found.Known() {
		return found, "", said
	}
	if found, field := exitIn(headerOf(answer), fields, "response"); found.Known() {
		return found, "", field
	}
	if len(fields) == 0 {
		// Not that the proxy said nothing: nobody looked.
		return egress{}, "no field in exit-headers.json to read the proxy's answer with", exitField{}
	}
	return egress{}, "the proxy did not say", exitField{}
}

// kept writes the request down in the directory it is to be kept in, when
// there is one.
func (b runner) kept(r *result, res *tlsforge.Response, j job, lane *traceLane) error {
	if b.keep == "" {
		return nil
	}
	if err := keepRequest(b.keep, r, res, j, b.about, lane); err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	return nil
}
