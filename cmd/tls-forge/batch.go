package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// result is one line of the output. JSON lines rather than a JSON array so the
// output can be read as it is produced, and appended to across runs.
type result struct {
	URL      string `json:"url"`
	Proxy    string `json:"proxy,omitempty"`
	Status   int    `json:"status,omitempty"`
	FinalURL string `json:"final_url,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	Body     string `json:"body,omitempty"`
	// BodyEncoding is "base64" when Body was not valid UTF-8. It is omitted
	// for text so existing JSONL consumers keep seeing the old shape normally.
	BodyEncoding string    `json:"body_encoding,omitempty"`
	File         string    `json:"file,omitempty"`
	Started      time.Time `json:"started"`
	Ended        time.Time `json:"ended"`
	Millis       int64     `json:"ms"`
	// Run is which pass over the list this was, under --repeat. Omitted when
	// the list is gone through once, as it always used to be.
	Run      int    `json:"run,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
	Error    string `json:"error,omitempty"`
	// Tries are the attempts one by one, with what each waited on. Kept for a
	// report and for nothing else: the lines are what they have always been.
	Tries []try `json:"-"`
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

// batchInput is os.Stdin, named so a test can supply a list.
var batchInput io.Reader = os.Stdin
var closeBatchOutput = (*os.File).Close

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

func runBatch(ctx context.Context, args []string, out, errOut *printer) (runErr error) {
	fs := newFlagSet("batch", out)
	common := addClientFlags(fs)
	input := fs.StringP("input", "i", "", "file of URLs (default: standard input)")
	inline := fs.StringP("urls", "u", "", "URLs as a comma-separated list, instead of a file")
	format := fs.StringP("format", "F", formatAuto,
		"how to read the list: auto, lines, json or csv")
	workers := fs.IntP("concurrency", "c", 4, "how many requests to run at once")
	output := fs.StringP("output", "o", "", "write the JSON lines here instead of standard output")
	bodyDir := fs.StringP("body-dir", "d", "",
		"write bodies to this directory and reference them instead of inlining")
	again := addRunFlags(fs, 3)
	watch := addWatchFlags(fs,
		"print the JSON lines on stdout even when that is a terminal")
	reporting := addReportFlags(fs)
	reportIP := fs.Bool("report-ip", true,
		"with --report, ask "+askedOf()+" which address each proxy comes out of")
	setUsage(fs, out, "usage: tls-forge batch [flags] [urls...]")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *workers < 1 {
		return fmt.Errorf("%w: --concurrency must be at least 1", errUsage)
	}
	if err := again.check(); err != nil {
		return err
	}
	// Checked before the list is read, so a misspelling costs a message rather
	// than a run that turns out to have nowhere to report itself.
	wantProgress, paint, err := watch.settle(errOut)
	if err != nil {
		return err
	}
	formats, err := reporting.formats()
	if err != nil {
		return err
	}
	warnAboutConcurrency(errOut, *workers)

	// Nothing named a list and standard input is a terminal, so the next thing
	// that happens is a wait for someone to type. Said out loud, because a
	// command that goes quiet looks like one that has hung.
	if *inline == "" && *input == "" && fs.NArg() == 0 && isTerminalReader(batchInput) {
		errOut.println("reading URLs from standard input, one per line; end with Ctrl-D.")
		errOut.println("Give a list instead with --input FILE or --urls a,b,c.")
	}

	jobs, err := readJobs(ctx, *inline, *input, *format, fs.Args(), batchInput)
	if err != nil {
		return err
	}
	// The whole list is checked before anything is fetched, so a typo costs a
	// message rather than half a scrape.
	if err := validate(jobs); err != nil {
		return err
	}
	// Every pass over the list is counted before the first one is made, and a
	// count that does not fit in an int is a mistake rather than a long run.
	if *again.repeat > math.MaxInt/len(jobs) {
		return fmt.Errorf("%w: --repeat %d is too many passes over %d URLs",
			errUsage, *again.repeat, len(jobs))
	}
	requests := len(jobs) * *again.repeat

	about := traceArgs{
		"urls": len(jobs), "concurrency": *workers, "timeout": common.timeout.String(),
		"retry": *again.retry, "repeat": *again.repeat,
	}
	if *common.proxy != "" {
		about["proxy"] = redactProxy(*common.proxy)
	}
	trace, err := openTrace(*again.trace, "batch", *common.proxy, about)
	if err != nil {
		return err
	}
	defer func() {
		if err := trace.close(runErr); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}()

	if *bodyDir != "" {
		if err := os.MkdirAll(*bodyDir, 0o755); err != nil {
			return fmt.Errorf("batch: %w", err)
		}
	}

	// A file when one was named. Otherwise standard output, unless that is a
	// screen and nobody asked for the lines there: each one holds a whole page,
	// and a run being watched is watched for whether it is working.
	sink := io.Writer(out)
	var outputFile *os.File
	unprinted := false
	switch {
	case *output != "":
		file, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("batch: %w", err)
		}
		outputFile = file
		sink = file
	case !watch.wanted(out, false):
		sink = io.Discard
		unprinted = true
	}

	// Once for the run, before the pool: it builds a client per proxy and would
	// otherwise say the same line once per proxy.
	common.wear(errOut)
	trace.main().wearing(*common.profile)
	clients := newPool(common, *common.proxy)
	defer clients.close()

	counts := newProgress(requests)
	var line *statusLine
	if wantProgress {
		// The status line owns the sink from here: it erases itself before
		// every result and draws again after, so the two streams can share a
		// terminal without overwriting one another.
		line = newStatusLine(errOut, sink, counts, paint)
		sink = line
	}

	records := make([]result, 0, len(jobs))
	// Where a run talks while it runs. Several workers write here, so it is one
	// lock whether or not there is a status line to work around.
	notes := &stderrLog{out: errOut, line: line, on: *watch.verbose}

	failures, fetchErr := runJobs(ctx, jobs, batch{
		clients: clients, workers: *workers, sink: sink,
		retry: *again.retry, repeat: *again.repeat, bodyDir: *bodyDir,
		counts: counts, notes: notes, trace: trace,
		detailed: len(formats) > 0,
	}, &records)

	// Closed here rather than deferred, so the final counts land before the
	// summary below instead of after it.
	if line != nil {
		line.Close()
	}
	if outputFile != nil {
		if err := closeBatchOutput(outputFile); err != nil {
			fetchErr = errors.Join(fetchErr, fmt.Errorf("batch: closing output: %w", err))
		}
	}
	if fetchErr != nil {
		return fetchErr
	}

	// One lookup per proxy, not per URL: the address belongs to the proxy, and
	// asking once per URL would be a request to a third party for every page.
	exits := map[string]egress{}
	if len(formats) > 0 && *reportIP {
		errOut.printf("asking %s which address each proxy comes out of…\n", askedOf())
		var skipped int
		exits, skipped = lookupExits(clients, records, trace.main())
		if skipped > 0 {
			errOut.printf("  %d further proxies were not asked about, at %d per run\n",
				skipped, exitLookupLimit)
		}
	}

	// One set per client, which is one per proxy: a jar is an identity, and two
	// exits' sessions in one set would describe a browser that was two people.
	if saved, err := clients.saveSessions(common, records); err != nil {
		return err
	} else if saved > 0 {
		errOut.printf("saved %d cookies to %s\n", saved, *common.saveCookies)
		trace.main().instant("cookies saved", "cookies",
			traceArgs{"file": *common.saveCookies, "cookies": saved})
	}

	elapsed := now().Sub(counts.started)
	totals := summarise(records, elapsed, exits)
	totals.Output = *output
	totals.Unprinted = unprinted
	totals.Passes = *again.repeat
	trace.main().instant("summary", "run", traceArgs{
		"requests": totals.Total, "scraped": totals.Succeeded, "not_2xx": totals.Warned,
		"no_response": totals.Failed, "bytes": totals.Bytes, "retries": totals.Retries,
	})
	if len(formats) > 0 {
		written, err := writeReports(reportFiles(*reporting.path, formats, now()),
			"batch", records, totals, exits)
		for _, file := range written {
			errOut.printf("report written to %s\n", file.path)
			// Only the page stops at what a browser can open.
			if dropped := len(records) - reportRowLimit; dropped > 0 && file.format == formatHTML {
				errOut.printf("  %d rows are in %s but not in the report\n", dropped,
					either(*output, "the JSON lines"))
			}
		}
		if err != nil {
			return err
		}
	}

	// To stderr, with everything else that is commentary rather than data.
	errOut.println()
	errOut.printf("%s", totals.table())

	if failures > 0 {
		// Non-zero exit: a batch that half worked is not a batch that worked,
		// and a shell loop needs to be able to tell.
		return fmt.Errorf("batch: %d of %d %s failed", failures, requests, totals.Things())
	}
	return nil
}

// stderrLog is what a run says while it runs.
//
// To standard error, with everything else that is commentary: standard output
// is carrying one JSON object per URL. When a status line is drawing there too,
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

// either is the first of two strings that is not empty.
func either(first, fallback string) string {
	if first != "" {
		return first
	}
	return fallback
}

// withoutBody is the record the run keeps for its summary and its report.
//
// Without the page, which neither of them shows. Kept whole, a run holds every
// page it fetched in memory until it ends: measured at 200 MB of pages, that
// was 353 MB of resident memory against 117 MB once the bodies went. What is
// left is a fixed couple of hundred bytes per URL.
func (r result) withoutBody() result {
	r.Body = ""
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

// batch is what a list is fetched with: everything runJobs needs that is not
// the list itself.
type batch struct {
	clients *pool
	workers int
	sink    io.Writer
	// retry is how many more times a URL is asked for when it does not come
	// back as a page, and repeat how many times the whole list is gone through.
	retry   int
	repeat  int
	bodyDir string
	counts  *progress
	notes   *stderrLog
	trace   *tracer
	// detailed says a report will be written, so every try is kept as it is
	// made, with what it waited on.
	detailed bool
}

// runJobs fetches the list and returns how many entries failed. A failure is
// reported on its line rather than returned, so one dead host does not end the
// run.
func runJobs(ctx context.Context, jobs []job, b batch, records *[]result,
) (failures int, runErr error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	queue := make(chan job)
	var writeMu sync.Mutex
	// How many of the records may go on holding their tries, counted under the
	// same lock the records are added under.
	var room tryBudget
	encoder := json.NewEncoder(b.sink)
	var wg sync.WaitGroup

	for worker := 1; worker <= b.workers; worker++ {
		// A row of the trace per worker: one worker makes one request at a time,
		// so what is drawn on its row never overlaps.
		lane := b.trace.lane(mainLane+worker, "worker "+strconv.Itoa(worker))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				b.counts.begin()
				r := b.fetchOne(runCtx, j, lane)
				b.counts.finish(r)
				b.notes.say(verboseLine(r))
				writeMu.Lock()
				if r.Error != "" {
					failures++
				}
				*records = append(*records, room.trim(r.withoutBody()))
				if runErr == nil {
					if err := encoder.Encode(r); err != nil {
						runErr = fmt.Errorf("batch: writing result: %w", err)
						cancel()
					}
				}
				writeMu.Unlock()
			}
		}()
	}

	b.dispatch(runCtx, jobs, queue)
	close(queue)
	wg.Wait()
	if runErr != nil {
		return failures, runErr
	}
	if err := ctx.Err(); err != nil {
		return failures, fmt.Errorf("batch: %w", err)
	}
	return failures, nil
}

// dispatch hands the list to the workers, once for every pass asked for.
//
// The whole list and then the whole list again, rather than each URL several
// times in a row: a repeat is the run made again, and several workers handed
// the same URL at once would be asking a different question, about what a
// server does under a burst.
func (b batch) dispatch(ctx context.Context, jobs []job, queue chan<- job) {
	occurrences := make(map[string]int)
	for pass := 1; pass <= b.repeat; pass++ {
		for _, j := range jobs {
			occurrences[j.URL]++
			j.occurrence = occurrences[j.URL]
			j.run = pass
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

// exitLookupLimit bounds how many proxies are asked about.
//
// One request each, to somebody else's free service. A rotating list can name
// thousands of proxies, and asking about every one of them would take minutes
// and deserve the rate limit it would earn.
//
// A variable rather than a constant so a test can lower it, as with
// reportRowLimit.
var exitLookupLimit = 50

// lookupExits asks the service once for each proxy that carried anything, and
// once for the direct client if any URL went without one.
//
// Returns how many proxies were left unasked, so the caller can say so rather
// than let the report imply that the addresses it is missing were unavailable.
func lookupExits(clients *pool, records []result, lane *traceLane) (map[string]egress, int) {
	seen := map[string]bool{}
	exits := map[string]egress{}
	skipped := 0
	for _, r := range records {
		if seen[r.Proxy] {
			continue
		}
		seen[r.Proxy] = true
		if len(seen) > exitLookupLimit {
			skipped++
			continue
		}
		// A proxy that cannot answer for itself is a fact about that proxy, and
		// the report says "not looked up" rather than failing the run over it.
		// Asked with the run's flags rather than through its clients: those hold
		// the session, and an address service is not who the session is for.
		asked := lane.mark()
		found, err := lookupExit(context.Background(), clients.flags, r.Proxy)
		lane.since(asked, "exit-ip", "net", exitArgs(r.Proxy, found, err))
		if err == nil {
			exits[r.Proxy] = found
		}
	}
	return exits, skipped
}

func (b batch) fetchOne(ctx context.Context, j job, lane *traceLane) result {
	started := now()
	proxy := b.clients.resolveProxy(j.Proxy)
	r := result{URL: j.URL, Proxy: proxy, Started: started}
	if b.repeat > 1 {
		// Only when there is more than one, so a list gone through once keeps
		// the shape its lines have always had.
		r.Run = j.run
	}

	client, err := b.clients.get(proxy)
	if err != nil {
		r.setError(err)
		r.finish(started)
		lane.instant("error", "request", traceArgs{"url": safeURL(j.URL), "error": r.Error})
		return r
	}

	res, attempts, tries, err := retrier{retries: b.retry, keep: b.detailed}.do(ctx, client,
		tlsforge.Request{URL: j.URL}, lane, j.run, proxy)
	r.Attempts, r.Tries = attempts, tries
	r.finish(started)

	if err != nil {
		r.setError(err)
		return r
	}
	r.Status = res.Status
	r.FinalURL = res.URL
	r.Bytes = len(res.Body)

	if b.bodyDir == "" {
		if utf8.Valid(res.Body) {
			r.Body = string(res.Body)
		} else {
			r.Body = base64.StdEncoding.EncodeToString(res.Body)
			r.BodyEncoding = "base64"
		}
		return r
	}
	// Named from the URL so a re-run overwrites the same file. A repeated URL in
	// one input gets a stable occurrence suffix: concurrent workers must not
	// truncate each other's body or make two records point at one response. A
	// second pass over the list counts as a second occurrence, which is how each
	// run of a repeat keeps its own page.
	sum := sha256.Sum256([]byte(j.URL))
	name := hex.EncodeToString(sum[:8])
	if j.occurrence > 1 {
		name += "-" + strconv.Itoa(j.occurrence)
	}
	path := filepath.Join(b.bodyDir, name+".html")
	if err := os.WriteFile(path, res.Body, 0o644); err != nil {
		r.setError(err)
		return r
	}
	lane.instant("saved", "file", traceArgs{"file": path, "bytes": len(res.Body)})
	r.File = path
	return r
}
