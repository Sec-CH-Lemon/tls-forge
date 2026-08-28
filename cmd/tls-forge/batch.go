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
	Attempts     int       `json:"attempts,omitempty"`
	Error        string    `json:"error,omitempty"`
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
//
// Needed on top of redactProxy because the proxy URL turns up inside error
// messages as well as in the proxy field: url.Parse quotes back the whole
// string it could not parse, so a mistyped proxy writes its own password into
// the output that was just cleaned of it.
func (r *result) setError(err error) {
	text := err.Error()
	safe := redactProxy(r.Proxy)
	if safe != r.Proxy {
		text = strings.ReplaceAll(text, r.Proxy, safe)
		// The message may quote a normalised form rather than the string as
		// given, so the credentials are replaced in that shape too.
		if u, parseErr := url.Parse(r.Proxy); parseErr == nil && u.User != nil {
			if _, ok := u.User.Password(); ok {
				text = strings.ReplaceAll(text, u.User.String()+"@",
					url.User(u.User.Username()).String()+"@")
			}
		}
	}
	r.Error = text
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

func runBatch(ctx context.Context, args []string, out, errOut *printer) error {
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
	repeat := fs.Int("repeat", 3, "times to try a URL again when it does not load")
	verbose := fs.BoolP("verbose", "v", false, "print a line for every request as it finishes")
	showProgress := fs.String("progress", "auto",
		"live status line on stderr: auto, always or never")
	report := fs.StringP("report", "R", "",
		"write an HTML report here; a directory gets report-<date-time>.html")
	reportIP := fs.Bool("report-ip", true,
		"with --report, ask "+ipService+" which address each proxy comes out of")
	setUsage(fs, out, "usage: tls-forge batch [flags] [urls...]")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *workers < 1 {
		return fmt.Errorf("%w: --concurrency must be at least 1", errUsage)
	}
	if *repeat < 0 {
		return fmt.Errorf("%w: --repeat cannot be negative", errUsage)
	}
	// Checked before the list is read, so a misspelling costs a message rather
	// than a run that turns out to have nowhere to report itself.
	wantProgress, err := progressWanted(*showProgress, errOut)
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

	if *bodyDir != "" {
		if err := os.MkdirAll(*bodyDir, 0o755); err != nil {
			return fmt.Errorf("batch: %w", err)
		}
	}

	sink := io.Writer(out)
	var outputFile *os.File
	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("batch: %w", err)
		}
		outputFile = file
		sink = file
	}

	// Once for the run, before the pool: it builds a client per proxy and would
	// otherwise say the same line once per proxy.
	common.wear(errOut)
	clients := newPool(common, *common.proxy)
	defer clients.close()

	counts := newProgress(len(jobs))
	var line *statusLine
	if wantProgress {
		// The status line owns the sink from here: it erases itself before
		// every result and draws again after, so the two streams can share a
		// terminal without overwriting one another.
		line = newStatusLine(errOut, sink, counts)
		sink = line
	}

	records := make([]result, 0, len(jobs))
	// Where a run talks while it runs. Several workers write here, so it is one
	// lock whether or not there is a status line to work around.
	notes := &stderrLog{out: errOut, line: line, on: *verbose}

	failures, runErr := runJobs(ctx, jobs, clients, *workers, sink, *repeat, *bodyDir, counts,
		&records, notes)

	// Closed here rather than deferred, so the final counts land before the
	// summary below instead of after it.
	if line != nil {
		line.Close()
	}
	if outputFile != nil {
		if err := closeBatchOutput(outputFile); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("batch: closing output: %w", err))
		}
	}
	if runErr != nil {
		return runErr
	}

	// One lookup per proxy, not per URL: the address belongs to the proxy, and
	// asking once per URL would be a request to a third party for every page.
	exits := map[string]egress{}
	if *report != "" && *reportIP {
		errOut.printf("asking %s which address each proxy comes out of…\n", ipService)
		var skipped int
		exits, skipped = lookupExits(clients, records)
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
	}

	elapsed := now().Sub(counts.started)
	totals := summarise(records, elapsed, exits)
	totals.Output = *output
	if *report != "" {
		path := reportPath(*report, now())
		if err := writeReport(path, records, totals, exits); err != nil {
			return err
		}
		errOut.printf("report written to %s\n", path)
		if dropped := len(records) - reportRowLimit; dropped > 0 {
			errOut.printf("  %d rows are in %s but not in the report\n", dropped,
				either(*output, "the JSON lines"))
		}
	}

	// To stderr, with everything else that is commentary rather than data.
	errOut.println()
	errOut.printf("%s", totals.table())

	if failures > 0 {
		// Non-zero exit: a batch that half worked is not a batch that worked,
		// and a shell loop needs to be able to tell.
		return fmt.Errorf("batch: %d of %d URLs failed", failures, len(jobs))
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

// repeatWait is how long to wait before trying a URL again. A variable so the
// tests can take the waiting out of the runs where it is not the point; what it
// returns is checked on its own.
var repeatWait = backoff

// backoff doubles from a quarter of a second, capped at two.
//
// A repeat with no pause is not another try. Measured on an earlier run, a URL
// through a dead proxy recorded two attempts inside one millisecond: the same
// failure twice, in the same microsecond, against a host whose situation had
// not had time to change. Capped, because a batch has better things to do than
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

// runJobs fetches the list and returns how many entries failed. A failure is
// reported on its line rather than returned, so one dead host does not end the
// run.
func runJobs(ctx context.Context, jobs []job, clients *pool, workers int,
	sink io.Writer, repeat int, bodyDir string, counts *progress, records *[]result,
	notes *stderrLog,
) (failures int, runErr error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	queue := make(chan job)
	var writeMu sync.Mutex
	encoder := json.NewEncoder(sink)
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				counts.begin()
				r := fetchOne(runCtx, clients, j, repeat, bodyDir)
				counts.finish(r)
				notes.say(verboseLine(r))
				writeMu.Lock()
				if r.Error != "" {
					failures++
				}
				*records = append(*records, r.withoutBody())
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

	for _, j := range jobs {
		select {
		case <-runCtx.Done():
			// Stop handing out work. Requests already in flight receive the same
			// cancellation through fetchOne.
		case queue <- j:
			continue
		}
		break
	}
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
func lookupExits(clients *pool, records []result) (map[string]egress, int) {
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
		client, err := clients.get(r.Proxy)
		if err != nil {
			continue
		}
		// A proxy that cannot answer for itself is a fact about that proxy, and
		// the report says "not looked up" rather than failing the run over it.
		if found, err := lookupExit(client); err == nil {
			exits[r.Proxy] = found
		}
	}
	return exits, skipped
}

func fetchOne(ctx context.Context, clients *pool, j job, repeat int, bodyDir string) result {
	started := now()
	proxy := clients.resolveProxy(j.Proxy)
	r := result{URL: j.URL, Proxy: proxy, Started: started}

	client, err := clients.get(proxy)
	if err != nil {
		r.setError(err)
		r.finish(started)
		return r
	}

	var res *tlsforge.Response
	// One try, then as many again as asked for.
	for attempt := 1; attempt <= repeat+1; attempt++ {
		if attempt > 1 && !pause(ctx, repeatWait(attempt-1)) {
			break
		}
		r.Attempts = attempt
		res, err = client.Do(&tlsforge.Request{Context: ctx, URL: j.URL})
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	r.finish(started)

	if err != nil {
		r.setError(err)
		return r
	}
	r.Status = res.Status
	r.FinalURL = res.URL
	r.Bytes = len(res.Body)

	if bodyDir == "" {
		if utf8.Valid(res.Body) {
			r.Body = string(res.Body)
		} else {
			r.Body = base64.StdEncoding.EncodeToString(res.Body)
			r.BodyEncoding = "base64"
		}
		return r
	}
	// Named from the URL rather than from a counter, so a re-run overwrites the
	// same file instead of producing a second copy under a new number.
	sum := sha256.Sum256([]byte(j.URL))
	path := filepath.Join(bodyDir, hex.EncodeToString(sum[:8])+".html")
	if err := os.WriteFile(path, res.Body, 0o644); err != nil {
		r.setError(err)
		return r
	}
	r.File = path
	return r
}
