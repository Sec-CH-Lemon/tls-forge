package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
		// Long only: -c is concurrency in batch, and a letter that means two
		// things depending on the command is worse than no letter.
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

// The full request flags used by fetch and batch.
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
	if *f.saveCookies == "" {
		return 0, nil
	}
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

// clientVia builds a client through a named proxy, which batch needs because
// there the proxy comes from the list rather than from the flag.
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
		opts = append(opts, tlsforge.WithProxy(proxy))
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
	method := fs.StringP("method", "X", "GET", "HTTP method")
	data := fs.StringP("data", "d", "", "request body")
	showHeaders := fs.BoolP("include", "i", false, "print the status and response headers first")
	output := fs.StringP("output", "o", "",
		"write the body to a file instead of stdout; with --repeat, one numbered file per run")
	var headers headerFlag
	fs.VarP(&headers, "header", "H", "extra header, repeatable: -H \"Referer: https://…\"")
	again := addRunFlags(fs, 0)
	watch := addWatchFlags(fs)
	setUsage(fs, out, "usage: tls-forge fetch [flags] <url>")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("%w: fetch takes exactly one URL", errUsage)
	}
	if err := again.check(); err != nil {
		return err
	}
	wantProgress, paint, err := watch.settle(errOut)
	if err != nil {
		return err
	}

	about := traceArgs{
		"url": safeURL(fs.Arg(0)), "method": *method, "timeout": common.timeout.String(),
		"retry": *again.retry, "repeat": *again.repeat,
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

	// Left open, because the address the request comes out of is the report's
	// last line, and nobody is asked for it until the cookies and the proxy have
	// made a client: a run that cannot be made has no address to report. Closed
	// on every way out, so a run that stops before then still ends it.
	identity := common.wearOpen(errOut)
	defer identity.close()
	lane.wearing(*common.profile)

	warmed, from, err := common.warmedCookies()
	if err != nil {
		return err
	}
	client, err := common.clientViaWarmed(*common.proxy, warmed)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// Before the request, with the profile and through the proxy the request is
	// about to use, so the answer is for that identity. Not with its cookies:
	// the session is for the site being fetched, not for whoever is asked about
	// the address.
	asked := lane.mark()
	found, lookupErr := lookupExit(ctx, common, *common.proxy)
	lane.since(asked, "exit-ip", "net", exitArgs(*common.proxy, found, lookupErr))
	identity.field("exit-ip", describeExit(found, lookupErr, *common.proxy))
	identity.close()

	if from != "" {
		errOut.printf("warmed from %s\n", from)
		lane.instant("cookies loaded", "cookies", traceArgs{"from": from})
	}

	defer func() {
		// After the request, so what is written down is the session the run
		// ends with rather than the one it started from.
		if saved, err := common.saveSession(client, []string{fs.Arg(0)}, ""); err != nil {
			errOut.println("tlsforge:", err)
			if runErr == nil {
				runErr = err
			}
		} else if saved > 0 {
			errOut.printf("saved %d cookies to %s\n", saved, *common.saveCookies)
			lane.instant("cookies saved", "cookies",
				traceArgs{"file": *common.saveCookies, "cookies": saved})
		}
	}()

	request := tlsforge.Request{
		Method: *method,
		URL:    fs.Arg(0),
		Header: tlsforge.Header(headers),
		Body:   []byte(*data),
	}

	runs := *again.repeat
	counts := newProgress(runs)
	// One request at a time, so how many are running is never news.
	counts.solo = true

	show := showing{out: out, headers: *showHeaders, body: *output == ""}
	// Redrawn as the run goes when somebody is watching, unless pages are being
	// printed on the same screen: then they are what is being watched, and a
	// status redrawn between them would land on the end of each.
	pagesOnScreen := show.body && onScreen(out)
	var line *statusLine
	if wantProgress && !pagesOnScreen {
		line = newStatusLine(errOut, out, counts, paint)
		show.out = line
	}
	notes := &stderrLog{out: errOut, line: line, on: *watch.verbose}
	// A try that is made again is said only to somebody who asked to hear about
	// every request. Otherwise it is one more thing the count is not about.
	policy := retrier{retries: *again.retry, note: notes.say}

	// Through the one client, so a second run finds the connection the first
	// one opened and the cookies it was given: the request made again, the way
	// reloading a page makes it again.
	var kept []string
	var stopped error
	unanswered := 0
	for run := 1; run <= runs && stopped == nil; run++ {
		counts.begin()
		started := now()
		res, attempts, err := policy.do(ctx, client, request, lane, run, *common.proxy)
		r := runResult(res, err, attempts, now().Sub(started), *common.proxy)
		counts.finish(r)

		path := *output
		if path != "" && runs > 1 {
			path = numbered(path, run)
		}
		switch {
		case err != nil && runs == 1:
			// One run is the whole of what was asked for, and its failure is the
			// command's. One of several is a row in the count.
			stopped = err
		case err != nil:
			unanswered++
			if ctx.Err() != nil {
				stopped = fmt.Errorf("fetch: %w", ctx.Err())
			}
		case path != "":
			if stopped = os.WriteFile(path, res.Body, 0o644); stopped == nil {
				r.File = path
				kept = append(kept, path)
				lane.instant("saved", "file", traceArgs{"file": path, "bytes": len(res.Body)})
			}
		}
		notes.say(runLine(run, runs, r))
		if stopped == nil && err == nil {
			stopped = show.response(res)
		}
	}

	// The count, left where it ended: redrawn for the last time when it was being
	// redrawn, and said once when it was not.
	if line != nil {
		line.Close()
	} else {
		if show.midLine && onScreen(out) {
			// A page rarely ends with a newline, and the count would start on
			// the end of its last line.
			errOut.println()
		}
		for _, row := range counts.frame(now(), paint) {
			errOut.println(row)
		}
	}
	if len(kept) > 0 {
		errOut.printf("  %-11s %s\n", "saved to", span(kept))
	}

	if stopped != nil {
		return stopped
	}
	if unanswered > 0 {
		// Non-zero, as batch is for the same reason: a request made ten times
		// that came back nine is not one that worked.
		return fmt.Errorf("fetch: %d of %d runs got no response", unanswered, runs)
	}
	return nil
}

// showing is what of a response fetch prints on standard output.
type showing struct {
	out     io.Writer
	headers bool
	body    bool
	// midLine is set when the last thing printed did not end its line.
	midLine bool
}

// response prints what was asked for of one response: the status and headers,
// the body, both or neither.
func (s *showing) response(res *tlsforge.Response) error {
	if s.headers {
		var head strings.Builder
		fmt.Fprintf(&head, "%d %s\n", res.Status, res.URL)
		names := make([]string, 0, len(res.Header))
		for name := range res.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&head, "%s: %s\n", name, strings.Join(res.Header[name], "; "))
		}
		head.WriteString("\n")
		// In one write, so that a status being redrawn steps aside once for the
		// whole block rather than between its lines.
		if _, err := io.WriteString(s.out, head.String()); err != nil {
			return err
		}
		s.midLine = false
	}
	if !s.body || len(res.Body) == 0 {
		return nil
	}
	s.midLine = res.Body[len(res.Body)-1] != '\n'
	_, err := s.out.Write(res.Body)
	return err
}

// runResult is one run as the count and the lines about it see it: the record
// batch keeps for a URL, so that both commands count the same things the same
// way.
func runResult(res *tlsforge.Response, err error, attempts int, took time.Duration,
	proxy string,
) result {
	r := result{Attempts: attempts, Millis: took.Milliseconds()}
	if err != nil {
		r.Error = redactError(err, proxy)
		return r
	}
	r.Status, r.Bytes = res.Status, len(res.Body)
	return r
}

// runLine is one run, as fetch says it to somebody who asked to hear about
// every request.
//
// The columns batch prints for a URL, so that ten runs of one page and ten
// pages read the same way, with the file the run was written to where batch
// has the URL.
func runLine(run, runs int, r result) string {
	r.URL = r.File
	width := len(strconv.Itoa(runs))
	return strings.TrimRight(fmt.Sprintf("  %*d/%d%s", width, run, runs, verboseLine(r)), " ")
}

// span names the files a run wrote: the one, or the first and the last of
// several, which with numbered names is enough to say all of them. Runs that
// all went to one place, as into /dev/null, went to one place.
func span(files []string) string {
	if first, last := files[0], files[len(files)-1]; first == last {
		return first
	}
	return files[0] + " … " + files[len(files)-1]
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
	if country := found.countryCode(); country != "" {
		return found.IP + " · " + country
	}
	return found.IP
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
