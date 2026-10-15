package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/cookie"
	"github.com/Sec-CH-Lemon/tls-forge/daemon"
	"github.com/Sec-CH-Lemon/tls-forge/internal/atomicfile"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// headerFlag collects repeated -H "Name: value" flags, in the order given.
//
// A slice rather than a map, and in the order given, because that order is part
// of what this tool exists to control.
type headerFlag tlsforge.Header

func (h *headerFlag) String() string { return "" }

// Type names the value in the usage line, where pflag prints it after the flag.
func (h *headerFlag) Type() string { return "name: value" }

func (h *headerFlag) Set(value string) error {
	name, val, found := strings.Cut(value, ":")
	if !found {
		return fmt.Errorf("expected \"Name: value\", got %q", value)
	}
	*h = append(*h, profile.Field{
		Name:  strings.ToLower(strings.TrimSpace(name)),
		Value: strings.TrimSpace(val),
	})
	return nil
}

// clientFlags are the flags every command that makes requests shares.
type clientFlags struct {
	cookies     *cookieFlag
	cookieFile  *string
	cookieSet   *string
	saveCookies *string

	profile  *string
	proxy    *string
	timeout  *time.Duration
	insecure *bool

	// chose reports whether a flag was given rather than defaulted, which is
	// how "no profile named" is told from "--profile chrome".
	chose func(string) bool

	// asked is what every CONNECT through a proxy says, for the proxies that
	// say where the tunnel comes out only when they are asked.
	asked tlsforge.Header
}

// addScopedClientFlags keeps unsupported flags out of --help. Accepting
// --save-cookies on a command that never saves a session is worse than rejecting
// it as a usage error; the same is true of cookie input on the jar-less proxy.
func addScopedClientFlags(fs *pflag.FlagSet, cookieInput, cookieOutput bool) clientFlags {
	flags := clientFlags{
		cookies:     &cookieFlag{},
		cookieFile:  new(string),
		cookieSet:   new(string),
		saveCookies: new(string),
		chose:       fs.Changed,
	}
	if cookieInput {
		// -b is curl's letter for handing a request a cookie.
		fs.VarP(flags.cookies, "cookie", "b", "cookie as name=value, repeatable")
		// Long only: -c is how many requests to run at once.
		flags.cookieFile = fs.String("cookies", "", "file of warmed cookies to start from")
		flags.cookieSet = fs.String("cookie-set", "",
			"which set in that file to use; one at random when not named")
	}
	if cookieOutput {
		flags.saveCookies = fs.String("save-cookies", "",
			"write the session this run ends with here; .txt writes a cookies.txt")
	}
	flags.profile = fs.StringP("profile", "p", tlsforge.DefaultProfile, "profile to impersonate")
	flags.proxy = fs.StringP("proxy", "x", "", "proxy URL, e.g. http://user:pass@host:port")
	flags.timeout = fs.DurationP("timeout", "t", tlsforge.Timeout, "request timeout")
	flags.insecure = fs.BoolP("insecure", "k", false, "skip certificate verification")
	return flags
}

// The full request flags, which are fetch's.
func addClientFlags(fs *pflag.FlagSet) clientFlags {
	return addScopedClientFlags(fs, true, true)
}

// Daemon can start from a warmed session, but does not retain visited hosts to
// save when stdin closes.
func addDaemonFlags(fs *pflag.FlagSet) clientFlags {
	return addScopedClientFlags(fs, true, false)
}

// Proxy forwards its caller's Cookie header and deliberately has no jar.
func addProxyClientFlags(fs *pflag.FlagSet) clientFlags {
	return addScopedClientFlags(fs, false, false)
}

// cookieFlag collects --cookie, which is name=value and nothing more: anything
// needing a domain or an expiry belongs in a file.
type cookieFlag struct{ cookies []cookie.Cookie }

func (f *cookieFlag) String() string { return "" }
func (f *cookieFlag) Type() string   { return "name=value" }

func (f *cookieFlag) Set(pair string) error {
	parsed, err := cookie.Parse(pair)
	if err != nil {
		return err
	}
	f.cookies = append(f.cookies, parsed)
	return nil
}

// warmedCookies is the session a client starts with: whatever was named on the
// command line, over whatever came out of the file.
//
// The file first and the flags on top, so a cookie given by hand overrides the
// one of the same name in a set rather than being overridden by it.
func (f clientFlags) warmedCookies() ([]cookie.Cookie, string, error) {
	var chosen []cookie.Cookie
	var from string
	if *f.cookieSet != "" && *f.cookieFile == "" {
		return nil, "", fmt.Errorf("%w: --cookie-set requires --cookies", errUsage)
	}

	if *f.cookieFile != "" {
		data, err := os.ReadFile(*f.cookieFile)
		if err != nil {
			return nil, "", fmt.Errorf("tlsforge: %w", err)
		}
		file, err := cookie.Load(data)
		if err != nil {
			return nil, "", err
		}
		set, err := file.Pick(*f.cookieSet, pickCookieSet)
		if err != nil {
			return nil, "", err
		}
		live := set.Live(now())
		chosen = append(chosen, live.Cookies...)
		from = fmt.Sprintf("%s, set %s, %d cookies", *f.cookieFile, set.ID, len(live.Cookies))
		if dead := len(set.Cookies) - len(live.Cookies); dead > 0 {
			from += fmt.Sprintf(" (%d expired)", dead)
		}
	}
	return append(chosen, f.cookies.cookies...), from, nil
}

// saveSession writes what the jar ended up holding for the hosts that were
// asked, so a session warmed by a run can be used by the next one.
//
// Under an id naming when it was warmed, and appended to whatever the file
// already held: a file of sessions is built up over time rather than replaced
// by the last run.
func (f clientFlags) saveSession(client *tlsforge.Client, hosts []string, note string) (int, error) {
	set := cookie.Set{ID: now().Format("2006-01-02-15-04-05"), Warmed: now(), Note: note}
	// The same cookie can be returned for every one of thousands of paths on a
	// host. Keep one copy of each cookie identity per host: including the host
	// preserves two independent host-only cookies with the same name, while
	// domain and path preserve the distinctions RFC 6265 gives them.
	type cookieKey struct{ host, name, domain, path string }
	seenCookie := map[cookieKey]bool{}
	for _, rawURL := range hosts {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		// CookiesFor can only fail while parsing the same URL already parsed
		// above, so its error path is unreachable here.
		held, _ := client.CookiesFor(rawURL)
		for _, c := range held {
			key := cookieKey{host: host, name: c.Name, domain: c.Domain, path: c.Path}
			if seenCookie[key] {
				continue
			}
			seenCookie[key] = true
			set.Cookies = append(set.Cookies, cookie.Cookie{
				Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
				Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: c.Expires,
			})
		}
	}
	if len(set.Cookies) == 0 {
		return 0, nil
	}

	data, err := sessionFile(*f.saveCookies, set)
	if err != nil {
		return 0, err
	}
	// 0600: a warmed session is a credential. Replace atomically so a full disk
	// or interrupted process cannot leave half a credential file behind.
	if err := atomicfile.Write(*f.saveCookies, data, 0o600); err != nil {
		return 0, fmt.Errorf("tlsforge: %w", err)
	}
	return len(set.Cookies), nil
}

// sessionFile writes the session out in whichever format the name asks for.
//
// A `.txt` is a Netscape cookie file, which is a jar written down: it holds one
// session and is replaced, because that is what it means to everything else that
// reads one. Anything else is this project's JSON, which holds sets, so a run is
// added to what the file already had rather than replacing it.
func sessionFile(path string, set cookie.Set) ([]byte, error) {
	if strings.EqualFold(filepath.Ext(path), ".txt") {
		return set.EncodeNetscape(), nil
	}
	file := &cookie.File{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		loaded, err := cookie.Load(data)
		if err != nil {
			return nil, fmt.Errorf("tlsforge: reading existing sessions from %s: %w", path, err)
		}
		file = loaded
	case os.IsNotExist(err):
	case err != nil:
		return nil, fmt.Errorf("tlsforge: reading existing sessions from %s: %w", path, err)
	}
	file.Add(set)
	return file.Encode(), nil
}

// pickCookieSet chooses which warmed session to use. Seeded from the clock and
// named, so a test can make the choice repeatable.
var pickCookieSet = rand.New(rand.NewSource(time.Now().UnixNano()))

func (f clientFlags) client(extra ...tlsforge.Option) (*tlsforge.Client, error) {
	return f.clientVia(*f.proxy, extra...)
}

// clientVia builds a client through a named proxy, which a list needs because
// there the proxy comes with the URL rather than from the flag.
func (f clientFlags) clientVia(proxy string, extra ...tlsforge.Option) (*tlsforge.Client, error) {
	warmed, _, err := f.warmedCookies()
	if err != nil {
		return nil, err
	}
	return f.clientViaWarmed(proxy, warmed, extra...)
}

// clientViaWarmed builds a client from a session already selected. Fetch uses
// this so the set named in its diagnostic is the same set the client received;
// selecting from a multi-set file twice could draw two different sessions.
func (f clientFlags) clientViaWarmed(proxy string, warmed []cookie.Cookie,
	extra ...tlsforge.Option,
) (*tlsforge.Client, error) {
	opts := []tlsforge.Option{
		tlsforge.WithProfile(*f.profile),
		tlsforge.WithTimeout(*f.timeout),
	}
	if len(warmed) > 0 {
		opts = append(opts, tlsforge.WithCookies(asClientCookies(warmed)))
	}
	if proxy != "" {
		opts = append(opts, tlsforge.WithProxy(proxy), tlsforge.WithProxyHeader(f.asked))
	}
	if *f.insecure {
		opts = append(opts, tlsforge.WithInsecureSkipVerify())
	}
	return tlsforge.New(append(opts, extra...)...)
}

// asClientCookies is the file's shape as the client's.
func asClientCookies(cookies []cookie.Cookie) []tlsforge.Cookie {
	out := make([]tlsforge.Cookie, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, tlsforge.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: c.Expires,
		})
	}
	return out
}

func runFetch(ctx context.Context, args []string, out, errOut *printer) (runErr error) {
	fs := newFlagSet("fetch", out)
	common := addClientFlags(fs)

	// The request, which is the same for every URL it is made to.
	method := fs.StringP("method", "X", "GET", "HTTP method")
	data := fs.StringP("data", "d", "", "request body")
	var headers headerFlag
	fs.VarP(&headers, "header", "H", "extra header, repeatable: -H \"Referer: https://…\"")

	// More URLs than the one.
	input := fs.String("input", "",
		"file of URLs to fetch; a list piped to standard input is read when no URL is named")
	inline := fs.StringP("urls", "u", "", "URLs as a comma-separated list, instead of a file")
	format := fs.StringP("format", "F", formatAuto,
		"how to read the list: auto, lines, json or csv")
	workers := fs.IntP("concurrency", "c", 4,
		"requests to run at once; one URL is asked for one at a time unless this is given")

	// What comes out, and where it goes.
	showHeaders := fs.BoolP("include", "i", false,
		"print the status and response headers; with JSON lines, add the headers to each")
	output := fs.StringP("output", "o", "",
		"keep every request in this directory: its page, a log of it and a trace of it")
	asLines := fs.Bool("json", false,
		"write a line of JSON for each request rather than the page, as for a list")
	again := addRunFlags(fs)
	watch := addWatchFlags(fs)
	reporting := addReportFlags(fs)
	exitHeaders := fs.String("exit-headers", "",
		"a JSON file laid over the exit header fields built in: one of the same key replaces ours, "+
			"\"off\" takes ours out, the rest are added")
	setUsage(fs, out, "usage: tls-forge fetch [flags] [url...]")
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
	exits, err := loadExitTable(*exitHeaders)
	if err != nil {
		return err
	}
	common.asked = askedBy(exits.Fields)

	// Nothing named a URL, and standard input is somebody at a keyboard rather
	// than a list: the command was typed without what it is for. Said at once,
	// because waiting to be typed at looks like having hung.
	named := *inline != "" || *input != "" || fs.NArg() == 0
	if fs.NArg() == 0 && *inline == "" && *input == "" && isTerminalReader(listInput) {
		fs.Usage()
		return fmt.Errorf("%w: fetch needs a URL, or a list of them: "+
			"--input FILE, --urls a,b,c, or one piped to standard input", errUsage)
	}
	jobs, err := readJobs(ctx, *inline, *input, *format, fs.Args(), listInput)
	if err != nil {
		return err
	}
	// The whole list is checked before anything is fetched, so a typo costs a
	// message rather than half a scrape.
	if err := validate(jobs); err != nil {
		if *reporting.path == reportBeside && fs.NArg() > 0 {
			// The likeliest reason for an argument that is not a URL, when
			// --report was given nothing: it was meant to be the report's path.
			err = fmt.Errorf("%w; a report's path is given as --report=PATH", err)
		}
		return err
	}
	// Every pass over the list is counted before the first one is made, and a
	// count that does not fit in an int is a mistake rather than a long run.
	if *again.repeat > math.MaxInt/len(jobs) {
		return fmt.Errorf("%w: --repeat %d is too many passes over %d URLs",
			errUsage, *again.repeat, len(jobs))
	}
	requests := len(jobs) * *again.repeat

	// The page, when the command names the one URL it is after. A line of JSON
	// for each request when it names several, or a list, or asks for lines: by
	// how it was asked rather than by how many URLs turned up, so that a list
	// which happens to hold one is not answered in another shape.
	asJSON := *asLines || named || len(jobs) > 1
	// One URL is asked for one request at a time, the way a page is reloaded,
	// unless somebody says how many at once.
	if len(jobs) == 1 && !fs.Changed("concurrency") {
		*workers = 1
	}
	warnAboutConcurrency(errOut, *workers)

	about := traceArgs{
		"method": *method, "timeout": common.timeout.String(), "concurrency": *workers,
		"retry": *again.retry, "repeat": *again.repeat,
	}
	if len(jobs) == 1 {
		about["url"] = safeURL(jobs[0].URL)
	} else {
		about["urls"] = len(jobs)
	}
	if *common.proxy != "" {
		about["proxy"] = redactProxy(*common.proxy)
	}
	trace, err := openTrace(*again.trace, "fetch", *common.proxy, about)
	if err != nil {
		return err
	}
	// Registered first so that it runs last: saving the session is a step of the
	// run, and belongs in the trace of it.
	defer func() {
		if err := trace.close(runErr); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}()
	lane := trace.main()

	// Left open, because the address the requests come out of is the report's
	// last line, and nobody is asked for it until the cookies and the proxy have
	// made a client: a run that cannot be made has no address to report. Closed
	// on every way out, so a run that stops before then still ends it.
	identity := common.wearOpen(errOut)
	defer identity.close()
	lane.wearing(*common.profile)

	clients := newPool(common, *common.proxy)
	defer clients.close()

	// A run that goes one way is one identity, and is treated as one: its client
	// is made now, so that a proxy or a session that cannot be used is the
	// command's failure rather than every request's, and where it comes out is
	// asked once and said before the first request. A list with a proxy for
	// each URL is as many identities as it has proxies. Their clients are made
	// as the list reaches them, and nobody is asked where any of them comes out.
	way, oneWay := sameWay(jobs, *common.proxy)
	var found egress
	var lookupErr error
	var from string
	if oneWay {
		warmed, session, err := common.warmedCookies()
		if err != nil {
			return err
		}
		client, err := common.clientViaWarmed(way, warmed)
		if err != nil {
			return err
		}
		clients.hold(way, client)
		from = session

		// With the profile and through the proxy the requests are about to use,
		// so the answer is for that identity. Not with its cookies: the session
		// is for the site being fetched, not for whoever is asked about the
		// address.
		asked := lane.mark()
		found, lookupErr = lookupExit(ctx, common, way)
		lane.since(asked, "exit-ip", "net", exitArgs(way, found, lookupErr))
		identity.field("exit-ip", describeExit(found, lookupErr, way))
	}
	identity.close()
	if from != "" {
		errOut.printf("warmed from %s\n", from)
		lane.instant("cookies loaded", "cookies", traceArgs{"from": from})
	}

	// What was asked before the run, for the report to say. It answers for the
	// requests made without a proxy, and for none made through one.
	var before *probe
	if oneWay {
		before = &probe{Proxy: redactProxy(way), Exit: found}
		if lookupErr != nil {
			before.Error = redactError(lookupErr, way)
		}
	}

	// Made rather than required, as a report's is: a run that has fetched a list
	// should not fail at the end for want of a directory.
	if *output != "" {
		if err := os.MkdirAll(*output, 0o755); err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
	}

	counts := newProgress(requests)
	// One request at a time, so how many are running is never news.
	counts.solo = *workers == 1

	// Where the output goes, and whether the status is redrawn beside it.
	var line *statusLine
	var pages *pageOutput
	var lines *linesOutput
	unprinted := false
	if asJSON {
		// Standard output, unless that is a screen and nobody asked for the lines
		// there: each one holds a whole page, and a run being watched is watched
		// for whether it is working.
		sink := io.Writer(out)
		if !watch.wanted(out, false) {
			sink = io.Discard
			unprinted = true
		}
		if wantProgress {
			// The status line owns the sink from here: it erases itself before
			// every result and draws again after, so the two streams can share a
			// terminal without overwriting one another.
			line = newStatusLine(errOut, sink, counts, paint)
			sink = line
		}
		lines = &linesOutput{encoder: json.NewEncoder(sink), headers: *showHeaders}
	} else {
		show := &showing{out: out, headers: *showHeaders, body: watch.wanted(out, *output != "")}
		// Redrawn as the run goes when somebody is watching, unless pages are
		// being printed on the same screen: then they are what is being watched,
		// and a status redrawn between them would land on the end of each.
		pagesOnScreen := show.body && onScreen(out)
		if wantProgress && !pagesOnScreen {
			line = newStatusLine(errOut, out, counts, paint)
			show.out = line
		}
		pages = &pageOutput{show: show, runs: requests}
	}
	// Where a run talks while it runs. Several workers write here, so it is one
	// lock whether or not there is a status line to work around.
	notes := &stderrLog{out: errOut, line: line, on: *watch.verbose}
	with := runner{
		clients: clients, workers: *workers,
		request: tlsforge.Request{Method: *method, Header: tlsforge.Header(headers), Body: []byte(*data)},
		retry:   *again.retry, repeat: *again.repeat,
		keep: *output,
		about: requestAbout{
			method: *method, profile: profileName(*common.profile),
			requests: requests, runs: *again.repeat,
		},
		exits: exits, names: &resolver{},
		counts: counts, trace: trace,
		// Every try is written down for a report, and for the log and the trace
		// each request is kept with.
		detailed: len(formats) > 0 || *output != "",
	}
	if *again.reuse {
		with.held = newHeldClients(*again.repeat)
	}
	switch {
	case !oneWay:
		with.directError = "not asked, as the run went more than one way"
	case way == "":
		with.direct, with.directError = found, before.Error
	}
	if asJSON {
		lines.say, with.out = notes.say, lines
	} else {
		pages.say, with.out = notes.say, pages
	}
	if *workers == 1 {
		// A try that is made again is said to somebody who asked to hear about
		// every request, while there is only the one request it can be about.
		with.note = notes.say
	}

	records := make([]result, 0, len(jobs))
	failures, failed := runJobs(ctx, jobs, with, &records)

	// The count, left where it ended: redrawn for the last time when it was being
	// redrawn, and said once when it was not.
	if line != nil {
		line.Close()
	} else {
		if pages != nil && pages.show.midLine && onScreen(out) {
			// A page rarely ends with a newline, and the count would start on
			// the end of its last line.
			errOut.println()
		}
		for _, row := range counts.frame(now(), paint) {
			errOut.println(row)
		}
	}

	totals := summarise(records, now().Sub(counts.started))
	totals.Passes = *again.repeat
	lane.instant("summary", "run", traceArgs{
		"requests": totals.Total, "scraped": totals.Succeeded, "not_2xx": totals.Warned,
		"no_response": totals.Failed, "bytes": totals.Bytes, "retries": totals.Retries,
	})

	// Whatever the run came to, and most of all when it came to nothing: a
	// request that failed is the one somebody opens a report about.
	var reported []string
	var reportErr error
	if len(formats) > 0 {
		var written []reportFile
		written, reportErr = writeReports(reportFiles(*reporting.path, *output, formats, now()),
			reportInput{command: "fetch", records: records, summary: totals, before: before,
				method: *method, trace: *again.trace})
		for _, file := range written {
			name := file.path
			// Only the page stops at what a browser can open. The document has
			// every request.
			if left := len(records) - reportRowLimit; left > 0 && file.format == formatHTML {
				name += fmt.Sprintf("  (without %d of the requests)", left)
			}
			reported = append(reported, name)
		}
	}

	// Under the count, what is read off a run when it is over.
	end := ending{saved: *output, reports: reported, unprinted: unprinted}
	if requests > 1 {
		figures := counts.summary()
		if *again.repeat > 1 && len(jobs) > 1 {
			// What turns the number back into a list.
			figures[0][1] += fmt.Sprintf("  (%d passes over %d URLs)", *again.repeat, len(jobs))
		}
		errOut.println()
		errOut.printf("%s", aligned(append(append(figures, totals.proxyRows()...), end.rows()...)))
	} else {
		// One request has said all of it on its one line, and has only files to
		// name.
		for _, said := range end.lines() {
			errOut.println("  " + said)
		}
	}

	// After the requests, so what is written down is the session the run ends
	// with rather than the one it started from. One set for each client, which
	// is one for each proxy: a jar is an identity, and two exits' sessions in
	// one set would describe a browser that was two people.
	saved, saveErr := clients.saveSessions(common, records)
	if saved > 0 {
		errOut.printf("saved %d cookies to %s\n", saved, *common.saveCookies)
		lane.instant("cookies saved", "cookies",
			traceArgs{"file": *common.saveCookies, "cookies": saved})
	}

	if failed == nil && failures > 0 {
		if requests == 1 {
			// One request is the whole of what was asked for, and its failure is
			// the command's.
			failed = errors.New(records[0].Error)
		} else {
			// Non-zero: a request made ten times that came back nine is not one
			// that worked, and a shell loop needs to be able to tell.
			failed = fmt.Errorf("fetch: %d of %d requests got no response", failures, requests)
		}
	}
	// All of them, so that the reason the fetch failed is not lost behind a
	// report or a session that could not be written.
	return errors.Join(failed, reportErr, saveErr)
}

// profileName is the profile a run wears, by the name it resolves to: "chrome"
// is whichever Chrome is newest, and a log read next month should say which.
func profileName(name string) string {
	if p, err := profile.Get(name); err == nil {
		return p.Name
	}
	return name
}

// sameWay is the proxy every request of a run goes through, when they all go
// the same way: through one proxy, or through none.
func sameWay(jobs []job, fallback string) (proxy string, same bool) {
	for i, j := range jobs {
		way := j.Proxy
		if way == "" {
			way = fallback
		}
		if i > 0 && way != proxy {
			return "", false
		}
		proxy = way
	}
	return proxy, true
}

// ending is where a run left what it made, for the last thing it says.
type ending struct {
	// saved is the directory the requests were kept in.
	saved string
	// unprinted says the JSON lines went nowhere: standard output was a
	// terminal, and nobody asked for them there or named a file.
	unprinted bool
	reports   []string
}

// unprintedNote is what is said of JSON lines that went nowhere. Said, because
// a run that fetched a list and kept none of it looks, from the outside, exactly
// like one that kept it somewhere.
const unprintedNote = "not printed on a terminal; > FILE keeps them, --print-body shows them"

// rows are those places as rows of the figures a run of several requests ends
// with, each under what it holds.
func (e ending) rows() [][2]string {
	var rows [][2]string
	if e.saved != "" {
		rows = append(rows, [2]string{"Saved to", e.saved})
	}
	if e.unprinted {
		rows = append(rows, [2]string{"JSON lines", unprintedNote})
	}
	for _, name := range e.reports {
		rows = append(rows, [2]string{"Report", name})
	}
	return rows
}

// lines are the same places as one request says them, under the line it has
// already said everything else on.
func (e ending) lines() []string {
	var lines []string
	if e.saved != "" {
		lines = append(lines, "saved to "+e.saved)
	}
	if e.unprinted {
		lines = append(lines, "JSON lines "+unprintedNote)
	}
	for _, name := range e.reports {
		lines = append(lines, "report written to "+name)
	}
	return lines
}

// describeExit is the address as fetch's report says it, or why there is none.
//
// A lookup that failed is said and is not an error: the address is commentary
// on the fetch, and the fetch is what was asked for. The country is its letters
// rather than the flag the HTML report draws, because not every terminal can
// draw one.
func describeExit(found egress, err error, proxy string) string {
	if err != nil {
		return "not looked up · " + redactError(err, proxy)
	}
	if found.IP == "" {
		// A proxy that will not say the address, and named it instead: a hash
		// of it, or whatever else the proxy calls it.
		return found.Hash + " (the proxy's name for the address)"
	}
	said := found.IP
	if country := found.countryCode(); country != "" {
		said += " · " + country
	}
	if found.By != "" {
		said += " (by " + found.By + ")"
	}
	return said
}

func runDaemon(_ context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("daemon", out)
	common := addDaemonFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}

	common.wear(errOut)
	client, err := common.client()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// stdin is read directly rather than through the writer the command was
	// given: the protocol is a pipe, and tests substitute it through daemonInput.
	return daemon.Serve(daemonInput, out, client)
}

// daemonInput is os.Stdin, named so a test can supply a script instead.
var daemonInput io.Reader = os.Stdin
