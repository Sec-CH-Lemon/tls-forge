package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/Sec-CH-Lemon/tls-forge/v7"
	"github.com/Sec-CH-Lemon/tls-forge/v7/cookie"
	"github.com/Sec-CH-Lemon/tls-forge/v7/daemon"
	"github.com/Sec-CH-Lemon/tls-forge/v7/internal/atomicfile"
	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
)

// fetchFlagGroups is how fetch --help shows its flags: under what each is for,
// there being too many to find in one list. A flag left out of every group is
// shown under "other flags", and TestFetchHelpShowsEveryFlagUnderAGroup says so.
var fetchFlagGroups = []flagGroup{
	{"what to fetch", []string{"input", "urls", "format"}},
	{"the request", []string{"method", "header", "data", "request-kind", "initiator-url"}},
	{"fingerprint and transport", []string{"profile", "timeout", "insecure"}},
	{"proxy", []string{"proxy", "proxy-env", "exit-headers", "no-exit-lookup"}},
	{"session", []string{"cookie", "cookies", "cookie-set", "save-cookies"}},
	{"running", []string{"concurrency", "retry", "repeat", "reuse-connection", "wait-for", "wait-for-element",
		"html-decoding"}},
	{"output", []string{"output", "clear-output-dir", "pcap", "include", "json", "print-body", "verbose", "progress",
		"color"}},
	{"report, trace and log", []string{"report", "report-format", "trace", "log", "log-level", "keylog"}},
}

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
		Name:  strings.TrimSpace(name),
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
	proxyEnv *string
	timeout  *time.Duration
	insecure *bool

	// chose reports whether a flag was given rather than defaulted, which is
	// how "no profile named" is told from "--profile chrome".
	chose func(string) bool

	// asked is what every CONNECT through a proxy says, for the proxies that
	// say where the tunnel comes out only when they are asked.
	asked tlsforge.Header

	// log is what every client made with these flags writes down what it does
	// to, or nil, and keyLog where it writes the TLS secrets of its
	// connections, or nil.
	log    *slog.Logger
	keyLog io.Writer

	// run is what the run settles once and its parts share.
	run *runContext
}

// runContext is what a run settles once, before it starts, and every part of
// it then shares: the clients it makes, whenever it makes them, and what it
// says and writes about itself.
type runContext struct {
	// id names the run in everything it writes: its log and its report are
	// named after it, and each of them, its trace, the requests it keeps and
	// the sessions it saves say it. started is when the run began.
	id      string
	started time.Time
	// profile is the profile the run wears. Resolved once: a name is read off
	// the disk each time it is looked up, so a client made late in a run, for
	// a proxy the list reached last, would otherwise wear whatever a capture
	// installed meanwhile, while the run said it wore what it began with.
	profile *profile.Profile
	// sessions are what the clients of each identity start with: one for each
	// proxy the run goes through, or none, as the pool keys its clients.
	sessions map[string]warmSession
}

// warmSession is the session one identity's client starts with, and where
// the run says it came from: empty when it came from no file.
type warmSession struct {
	cookies []cookie.Cookie
	from    string
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
		run:         &runContext{},
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
	// No default for pflag to print: it is the browser measured on this machine
	// when there is one, which resolve finds, and a help that said chrome there
	// would say what the run does not wear.
	flags.profile = fs.StringP("profile", "p", "",
		"profile to impersonate; without one, the browser measured on this machine when there is one, else chrome, "+
			"the newest Chrome shipped")
	flags.proxy = fs.StringP("proxy", "x", "", "proxy URL, e.g. http://user:pass@host:port")
	flags.proxyEnv = fs.String("proxy-env", "",
		"name of an environment variable holding the proxy URL, such as `TLSFORGE_PROXY`, which keeps its password "+
			"off the command line; no variable is read unless named")
	flags.timeout = fs.DurationP("timeout", "t", tlsforge.Timeout, "request timeout")
	flags.insecure = fs.BoolP("insecure", "k", false, "skip certificate verification")
	return flags
}

// proxyFromEnv sets the proxy from the environment variable --proxy-env names.
//
// A password on the command line is one `ps` shows every user of the machine,
// and the environment is one only the process's owner can read. The variable
// is read only when it is named: one that happened to be set would otherwise
// send a run through a proxy nobody asked for. Usage errors, before anything
// is read or asked: a name that is empty, a variable that is not set or is
// empty, and --proxy given as well, since a run's proxy comes from one place.
//
// It is all the daemon checks before it starts. The packages that start it
// read its exit code 2 as arguments it does not understand, which from them
// is only --proxy-stdin, from a tls-forge older than they are; a proxy or a
// profile that cannot be used ends it with 1, as the client it cannot make.
func (f clientFlags) proxyFromEnv() (string, error) {
	given := "--proxy " + redactProxy(*f.proxy)
	if f.chose("proxy-env") {
		name := *f.proxyEnv
		value, set := os.LookupEnv(name)
		switch {
		case name == "":
			return "", fmt.Errorf("%w: --proxy-env needs the name of an environment variable", errUsage)
		case f.chose("proxy"):
			return "", fmt.Errorf("%w: --proxy and --proxy-env both name the proxy: give one of them", errUsage)
		case !set:
			return "", fmt.Errorf("%w: --proxy-env %s: there is no such environment variable", errUsage, name)
		case value == "":
			return "", fmt.Errorf("%w: --proxy-env %s: the variable is empty", errUsage, name)
		}
		*f.proxy = value
		given = "--proxy-env " + name + ": " + redactProxy(value)
	}
	return given, nil
}

// settle is what a command that makes requests of its own checks before it
// starts, as usage errors: the proxy from where it is named, a proxy that is
// no proxy's URL, a timeout of nothing and a profile there is none of, which
// the transport would otherwise refuse only once a run had emptied a
// directory, opened its log or made its authority. It is the profile the run
// wears.
func (f clientFlags) settle() (*profile.Profile, error) {
	given, err := f.proxyFromEnv()
	if err != nil {
		return nil, err
	}
	if *f.proxy != "" {
		if why := proxyProblem(*f.proxy); why != "" {
			return nil, fmt.Errorf("%w: %s %s", errUsage, given, why)
		}
	}
	if *f.timeout <= 0 {
		return nil, fmt.Errorf("%w: --timeout is %v, and has to be more than nothing", errUsage, *f.timeout)
	}
	worn, err := f.resolve()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	return worn, nil
}

// resolve settles the profile the run wears, once, for everything that comes
// after: the one named, else this machine's measured browser when there is
// one, else the default that ships.
func (f clientFlags) resolve() (*profile.Profile, error) {
	if !f.chose("profile") {
		*f.profile = defaultProfileName()
	}
	worn, err := profile.Get(*f.profile)
	if err != nil {
		return nil, err
	}
	f.run.profile = worn
	return worn, nil
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

// warmup reads the cookie file and chooses, for each identity the run goes
// through, each named once, the session its clients start with: whatever was
// named on the command line, over the set chosen from the file.
//
// Once, before the run. The file was read, and a set drawn, as each identity's
// client was made, which for a list that goes several ways is as the list
// reaches each: under the lock every worker waits on, and from the file as it
// was by then, which a run writing its session back into it may have changed.
// A set drawn at random is drawn once for each identity, and the run says
// which.
func (f clientFlags) warmup(identities ...string) error {
	if *f.cookieSet != "" && *f.cookieFile == "" {
		return fmt.Errorf("%w: --cookie-set requires --cookies", errUsage)
	}
	var file *cookie.File
	if *f.cookieFile != "" {
		data, err := os.ReadFile(*f.cookieFile)
		if err != nil {
			return fmt.Errorf("tlsforge: %w", err)
		}
		if file, err = cookie.Load(data); err != nil {
			return err
		}
	}
	f.run.sessions = map[string]warmSession{}
	for _, identity := range identities {
		session, err := f.warmFrom(file)
		if err != nil {
			return err
		}
		f.run.sessions[identity] = session
	}
	return nil
}

// warmFrom is one identity's session: a set from the file, when there is one,
// and the cookies named on the command line on top, so that a cookie given by
// hand overrides the one of the same name in the set rather than the other way
// round.
func (f clientFlags) warmFrom(file *cookie.File) (warmSession, error) {
	var session warmSession
	if file != nil {
		set, err := file.Pick(*f.cookieSet, pickCookieSet)
		if err != nil {
			return warmSession{}, err
		}
		live := set.Live(now())
		session.cookies = append(session.cookies, live.Cookies...)
		session.from = fmt.Sprintf("%s, set %s, %d cookies", *f.cookieFile, set.ID, len(live.Cookies))
		if dead := len(set.Cookies) - len(live.Cookies); dead > 0 {
			session.from += fmt.Sprintf(" (%d expired)", dead)
		}
		if file.Unscoped() {
			// Not silent: a host's cookie in such a file goes to its subdomains
			// as well, as it did when the file was written.
			session.from += "; written before tls-forge kept which cookies are their host's alone, " +
				"so each goes to its domain's subdomains as well, until the session is saved again"
		}
	}
	session.cookies = append(session.cookies, f.cookies.cookies...)
	return session, nil
}

// saveSession writes down everything the client's jar ended up holding, so a
// session warmed by a run can be used by the next one: every cookie of every
// host, a redirect's as well as the URLs', each with its scope, its lifetime
// and its SameSite.
//
// Under an id naming when it was warmed, and appended to whatever the file
// already held: a file of sessions is built up over time rather than replaced
// by the last run.
func (f clientFlags) saveSession(client *tlsforge.Client, note string) (int, error) {
	set := cookie.Set{ID: now().Format("2006-01-02-15-04-05"), Warmed: now(), Note: note}
	for _, c := range client.AllCookies() {
		set.Cookies = append(set.Cookies, cookie.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, HostOnly: c.HostOnly, Path: c.Path,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: c.Expires, SameSite: c.SameSite,
		})
	}
	if len(set.Cookies) == 0 {
		return 0, nil
	}

	data, err := sessionFile(*f.saveCookies, set)
	if err != nil {
		return 0, err
	}
	// In a directory made for it, as every file a run writes is: the run is
	// over, and failing for want of one would lose the session it came to.
	if err := os.MkdirAll(filepath.Dir(*f.saveCookies), 0o755); err != nil {
		return 0, fmt.Errorf("tlsforge: %w", err)
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
	if netscapeFile(path) {
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
	encoded, err := file.Encode()
	if err != nil {
		return nil, fmt.Errorf("tlsforge: writing the session to %s: %w", path, err)
	}
	return encoded, nil
}

// netscapeFile says a session is written to path as a Netscape cookie file: a
// name ending in .txt, in any case.
func netscapeFile(path string) bool { return strings.EqualFold(filepath.Ext(path), ".txt") }

// pickCookieSet chooses which warmed session to use. Seeded from the clock and
// named, so a test can make the choice repeatable.
var pickCookieSet = rand.New(rand.NewSource(time.Now().UnixNano()))

func (f clientFlags) client(extra ...tlsforge.Option) (*tlsforge.Client, error) {
	return f.clientVia(*f.proxy, extra...)
}

// clientVia builds a client through a named proxy, which a list needs because
// there the proxy comes with the URL rather than from the flag, with the
// session warmup chose for that identity.
func (f clientFlags) clientVia(proxy string, extra ...tlsforge.Option) (*tlsforge.Client, error) {
	return f.clientViaWarmed(proxy, f.run.sessions[proxy].cookies, extra...)
}

// clientViaWarmed builds a client from a session already selected, or none.
func (f clientFlags) clientViaWarmed(proxy string, warmed []cookie.Cookie,
	extra ...tlsforge.Option,
) (*tlsforge.Client, error) {
	opts := []tlsforge.Option{
		tlsforge.WithProfileValue(f.run.profile),
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
	if f.log != nil {
		opts = append(opts, tlsforge.WithLogger(f.log))
	}
	if f.keyLog != nil {
		opts = append(opts, tlsforge.WithKeyLogWriter(f.keyLog))
	}
	return newClient(proxy, append(opts, extra...)...)
}

// newClient makes the client for a proxy: tlsforge.New, named so that a test
// can have it fail. What it would refuse of the flags is refused before a
// command starts (settle), so what is left is the library's own trouble,
// which a test cannot otherwise cause.
var newClient = func(_ string, opts ...tlsforge.Option) (*tlsforge.Client, error) {
	return tlsforge.New(opts...)
}

// asClientCookies is the file's shape as the client's.
func asClientCookies(cookies []cookie.Cookie) []tlsforge.Cookie {
	out := make([]tlsforge.Cookie, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, tlsforge.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, HostOnly: c.HostOnly, Path: c.Path,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: c.Expires, SameSite: c.SameSite,
		})
	}
	return out
}

func runFetch(ctx context.Context, args []string, out, errOut *printer) (runErr error) {
	plan, err := planFetch(ctx, args, out, errOut)
	if err != nil {
		return err
	}
	run := &fetchRun{fetchPlan: plan, out: out, errOut: errOut}
	defer run.close(&runErr)
	if err := run.open(ctx); err != nil {
		return err
	}
	records, failures, failed := run.execute(ctx)
	return run.finish(records, failures, failed)
}

// fetchPlan is a fetch as its flags and its list ask for it, every part of it
// checked: what the run is to do, settled before anything is cleared, opened,
// written or asked of anybody. planFetch makes it.
type fetchPlan struct {
	common clientFlags
	worn   *profile.Profile

	// The request, which is the same for every URL it is made to, and what in
	// a browser it is sent as.
	method, data              string
	headers                   headerFlag
	requestKind, initiatorURL string
	browser                   *tlsforge.BrowserContext

	// The list, the identities it goes as, how many requests it comes to and
	// how many are made at once.
	jobs     []job
	ways     []string
	requests int
	workers  int

	// What comes out, and where it goes.
	asJSON, showHeaders                   bool
	output                                string
	clearOutputDir, pcap                  bool
	again                                 runFlags
	check                                 *pageCheck
	waitFor, waitForElement, htmlDecoding string
	watch                                 watchFlags
	wantProgress                          bool
	paint                                 palette
	reporting                             reportFlags
	formats                               []string
	logging                               logFlags
	logLevel                              slog.Level
	exits                                 exitTable
	noExitLookup                          bool

	// When the run began, the files it reads and writes, and what its log and
	// its trace say of it first.
	started time.Time
	files   fetchFiles
	about   traceArgs
}

// planFetch reads fetch's flags and its list into a plan, and refuses one it
// cannot carry out: with a usage error, exit code 2, before anything is
// cleared, opened, written or asked. It reads what the run reads, the list and
// the cookie file among them, and writes nothing.
func planFetch(ctx context.Context, args []string, out, errOut *printer) (*fetchPlan, error) {
	fs := newFlagSet("fetch", out)
	common := addClientFlags(fs)

	// The request, which is the same for every URL it is made to.
	method := fs.StringP("method", "X", "GET", "HTTP method")
	data := fs.StringP("data", "d", "", "request body")
	requestKind := fs.String("request-kind", "",
		"send each request as Chrome sends this kind: navigation, form, fetch or xhr, from the page "+
			"--initiator-url names; without it, as a navigation typed into the address bar, with what -H and -d give")
	initiatorURL := fs.String("initiator-url", "",
		"the page a --request-kind request is sent from: a form, fetch and xhr need one, and a navigation "+
			"without one is typed into the address bar")
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
		"keep every request in this directory: its page, a log of it and a trace of it, and a log of the run")
	clearOutputDir := fs.Bool("clear-output-dir", false,
		"empty the --output directory before the run writes into it: every file and directory in it")
	pcap := fs.Bool("pcap", false,
		"with --output, keep beside each request's files the connections it went out on, as NAME.pcapng: every "+
			"byte each way and the TLS secrets that open them, so that Wireshark reads it as it was sent, and so "+
			"does anybody else who has it")
	asLines := fs.Bool("json", false,
		"write a line of JSON for each request rather than the page, as for a list")
	again := addRunFlags(fs)
	waitFor := fs.String("wait-for", "",
		"count an answer as the page when its body has this text in it, whatever its status, or, written as "+
			"/regexp/ with any of the flags i, m, s and U, text this regular expression matches")
	waitForElement := fs.String("wait-for-element", "",
		"count an answer as the page when its HTML has an element matching this CSS selector, whatever its "+
			"status; the HTML as it came: no script runs")
	htmlDecoding := fs.String("html-decoding", decodingLegacy,
		"how --wait-for and --wait-for-element read a body as text: legacy, by its byte order mark or "+
			"Content-Type, else as UTF-8 when it is UTF-8 throughout, whatever a <meta> says; or browser, as "+
			"Chrome 155 decodes the document, by those, then what a document of its type names in itself")
	watch := addWatchFlags(fs)
	reporting := addReportFlags(fs)
	logging := addLogFlags(fs)
	exitHeaders := fs.String("exit-headers", "",
		"a JSON file laid over the exit header fields built in: one of the same key replaces ours, "+
			"\"off\" takes ours out, the rest are added")
	noExitLookup := fs.Bool("no-exit-lookup", false,
		"make no request to learn where requests come out: no address service, no probe of the site, no "+
			"name resolved; what the proxy says when it opens a connection is still read")
	setUsage(fs, out, "usage: tls-forge fetch [flags] [url...]", fetchFlagGroups...)
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	worn, err := common.settle()
	if err != nil {
		return nil, err
	}
	if *workers < 1 {
		return nil, fmt.Errorf("%w: --concurrency must be at least 1", errUsage)
	}
	if *clearOutputDir && *output == "" {
		return nil, fmt.Errorf("%w: --clear-output-dir requires --output", errUsage)
	}
	if *pcap && *output == "" {
		return nil, fmt.Errorf("%w: --pcap keeps each request's connections beside its other files, and requires --output",
			errUsage)
	}
	check, err := newPageCheck(*waitForElement, *waitFor, *htmlDecoding)
	if err != nil {
		return nil, err
	}
	browser, err := browserContextOf(*requestKind, *initiatorURL, fs.Changed("initiator-url"))
	if err != nil {
		return nil, err
	}
	// It reads nothing on its own, and a run that seemed to read its pages as
	// Chrome does, printed or kept, would not have.
	if check == nil && fs.Changed("html-decoding") {
		return nil, fmt.Errorf("%w: --html-decoding says how --wait-for and --wait-for-element read a body: give one of them",
			errUsage)
	}
	// A HEAD gets no body, and every answer to it would be without what the
	// page has, whatever came back.
	if check != nil && strings.EqualFold(*method, "HEAD") {
		return nil, fmt.Errorf("%w: --wait-for and --wait-for-element look into the body, and -X HEAD gets none", errUsage)
	}
	if err := again.check(); err != nil {
		return nil, err
	}
	// Checked before the list is read, so a misspelling costs a message rather
	// than a run that turns out to have nowhere to report itself.
	wantProgress, paint, err := watch.settle(errOut)
	if err != nil {
		return nil, err
	}
	formats, err := reporting.formats()
	if err != nil {
		return nil, err
	}
	logLevel, err := logging.levelOf()
	if err != nil {
		return nil, err
	}
	if *logging.keylog == "-" {
		return nil, fmt.Errorf("%w: --keylog takes a file: TLS secrets go to no stream", errUsage)
	}
	exits, err := loadExitTable(*exitHeaders)
	if err != nil {
		return nil, err
	}
	common.asked = askedBy(exits.Fields)

	// Every file the run reads or writes, settled before the list is read, a
	// directory emptied or a file opened: two flags naming one file is a
	// mistake to refuse, rather than a file to lose. The log and the report are
	// named after the moment the run began, so the files of one run share it.
	started := now()
	common.run.id, common.run.started = stamp(started), started
	files := fetchFiles{
		input: *input, cookies: *common.cookieFile, exitHeaders: *exitHeaders,
		saveCookies: *common.saveCookies, trace: *again.trace,
		log:     runLogPath(*logging.path, *output, started),
		keylog:  *logging.keylog,
		reports: reportFiles(*reporting.path, *output, formats, started),
		output:  *output, cleared: *clearOutputDir,
	}
	if err := files.plan(out.w, errOut.w).check(); err != nil {
		return nil, err
	}

	// Nothing named a URL, and standard input is somebody at a keyboard rather
	// than a list: the command was typed without what it is for. Said at once,
	// because waiting to be typed at looks like having hung.
	named := *inline != "" || *input != "" || fs.NArg() == 0
	if fs.NArg() == 0 && *inline == "" && *input == "" && isTerminalReader(listInput) {
		fs.Usage()
		return nil, fmt.Errorf("%w: fetch needs a URL, or a list of them: "+
			"--input FILE, --urls a,b,c, or one piped to standard input", errUsage)
	}
	jobs, err := readJobs(ctx, *inline, *input, *format, fs.Args(), listInput)
	if err != nil {
		return nil, err
	}
	// The whole list is checked before anything is fetched, so a typo costs a
	// message rather than half a scrape.
	if err := validate(jobs); err != nil {
		if *reporting.path == reportBeside && fs.NArg() > 0 {
			// The likeliest reason for an argument that is not a URL, when
			// --report was given nothing: it was meant to be the report's path.
			err = fmt.Errorf("%w; a report's path is given as --report=PATH", err)
		}
		return nil, err
	}
	// What a browser would not send, or this profile cannot send as one, for
	// any URL of the list, before anything is warmed, cleared or sent.
	if err := checkBrowser(common.run.profile, jobs, *method, headers, *data, browser); err != nil {
		return nil, err
	}
	// Every pass over the list is counted before the first one is made, and a
	// count that does not fit in an int is a mistake rather than a long run.
	if *again.repeat > math.MaxInt/len(jobs) {
		return nil, fmt.Errorf("%w: --repeat %d is too many passes over %d URLs",
			errUsage, *again.repeat, len(jobs))
	}
	// A Netscape cookie file holds one session, and a run through more than one
	// proxy has one for each: written into one file, each would replace the one
	// before, and the count would say they were all kept. Refused before
	// anything is fetched or written, rather than found out afterwards.
	if _, single := sameWay(jobs, *common.proxy); !single && netscapeFile(*common.saveCookies) {
		return nil, fmt.Errorf("%w: --save-cookies %s is a Netscape cookie file, which holds one session, and this "+
			"run has one for each proxy it goes through: name a .json file, which keeps each as a set of its own",
			errUsage, *common.saveCookies)
	}
	// The session each identity starts from, chosen now, before anything is
	// cleared, opened or asked, from the cookie file as it is now.
	ways := waysOf(jobs, *common.proxy)
	if err := common.warmup(ways...); err != nil {
		return nil, err
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
		"run_id": common.run.id,
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
	return &fetchPlan{
		common: common, worn: worn,
		method: *method, data: *data, headers: headers,
		requestKind: *requestKind, initiatorURL: *initiatorURL, browser: browser,
		jobs: jobs, ways: ways, requests: requests, workers: *workers,
		asJSON: asJSON, showHeaders: *showHeaders, output: *output, clearOutputDir: *clearOutputDir, pcap: *pcap,
		again: again, check: check,
		waitFor: *waitFor, waitForElement: *waitForElement, htmlDecoding: *htmlDecoding,
		watch: watch, wantProgress: wantProgress, paint: paint,
		reporting: reporting, formats: formats, logging: logging, logLevel: logLevel,
		exits: exits, noExitLookup: *noExitLookup,
		started: started, files: files, about: about,
	}, nil
}

// fetchRun is a fetch being made: its plan, what it opened to give an account
// of itself, and how far it has got. open opens it, execute makes its
// requests, finish says what came of them, and close ends what open opened.
type fetchRun struct {
	*fetchPlan
	out, errOut *printer

	log      *runLog
	keys     *keyLogFile
	wire     *wire
	trace    *tracer
	lane     *traceLane
	identity *identityReport
	clients  *pool

	// The way the run goes when it goes one, where it comes out there and what
	// asking said, and what was asked before the run, for the report.
	way       string
	oneWay    bool
	found     egress
	lookupErr error
	before    *probe

	// The count, the status line redrawn beside the output when somebody is
	// watching, the pages when a page is the answer, and whether the lines
	// went unprinted.
	counts    *progress
	line      *statusLine
	pages     *pageOutput
	unprinted bool
}

// open does what a run does before its first request: empties the output
// directory when asked, opens the log and the trace, says what the run is
// wearing, makes the client of a run that goes one way and asks where it comes
// out, and makes the output directory. What it opened, close ends, on every
// way out.
func (r *fetchRun) open(ctx context.Context) error {
	// Emptied once everything the run reads before it starts has been read, and
	// before anything is written: the trace may be opened in it.
	if r.clearOutputDir {
		cleared, err := clearOutput(r.output, r.files.reads(), streamFiles(r.out.w, r.errOut.w))
		if err != nil {
			return err
		}
		r.errOut.printf("cleared %s: %s removed\n", r.output, counted(cleared, "entry", "entries"))
	}
	// Once the directory is emptied, so that the log in it is this run's, and
	// before anything is asked of anybody, so that it has all of it.
	var err error
	if r.log, err = openRunLog(*r.logging.path, r.logLevel, r.output, r.started, r.errOut); err != nil {
		return err
	}
	r.common.log = r.log.logger()
	r.log.say(slog.LevelInfo, "run", runAttrs(r.about, "version", version, "profile", r.worn.Name,
		"output", r.output, "wait_for", r.waitFor, "wait_for_element", r.waitForElement, "html_decoding", r.htmlDecoding,
		"request_kind", r.requestKind, "initiator_url", safeURL(r.initiatorURL),
		"reuse_connection", *r.again.reuse, "log_level", strings.ToLower(*r.logging.level), "keylog", *r.logging.keylog)...)
	// Before any client is made, so that every connection of the run has its
	// secrets in it, the address lookup's too.
	if r.keys, err = openKeyLog(*r.logging.keylog); err != nil {
		return err
	}
	r.common.keyLog = r.keys.writer()
	if r.pcap {
		// Every connection of the run keeps what it carried until its requests
		// are kept, and its secrets with it, which the key log, when there is
		// one, has too.
		r.wire = newWire()
		r.common.keyLog = keysTo(r.common.keyLog, r.wire)
	}
	if r.trace, err = openTrace(*r.again.trace, "fetch", *r.common.proxy, r.started, r.about); err != nil {
		return err
	}
	r.lane = r.trace.main()

	// Left open, because the address the requests come out of is the report's
	// last line, and nobody is asked for it until the cookies and the proxy have
	// made a client: a run that cannot be made has no address to report. Closed
	// on every way out, so a run that stops before then still ends it.
	r.identity = r.common.wearOpen(r.errOut)
	r.identity.field("sent as", describeContext(r.browser))
	r.identity.field("keylog", r.keys.said())
	r.lane.wearing(r.worn)

	r.clients = newPool(r.common, *r.common.proxy)

	// A run that goes one way is one identity, and is treated as one: its client
	// is made now, so that a proxy or a session that cannot be used is the
	// command's failure rather than every request's, and where it comes out is
	// asked once and said before the first request. A list with a proxy for
	// each URL is as many identities as it has proxies. Their clients are made
	// as the list reaches them, and nobody is asked where any of them comes out.
	r.way, r.oneWay = sameWay(r.jobs, *r.common.proxy)
	var from string
	if r.oneWay {
		client, err := r.common.clientVia(r.way)
		if err != nil {
			return err
		}
		r.clients.hold(r.way, client)
		from = r.common.run.sessions[r.way].from

		// With the profile and through the proxy the requests are about to use,
		// so the answer is for that identity. Not with its cookies: the session
		// is for the site being fetched, not for whoever is asked about the
		// address.
		asked := r.lane.mark()
		if r.noExitLookup {
			r.lookupErr = errNotAsked
		} else {
			r.found, r.lookupErr = lookupExit(ctx, r.common, r.way)
		}
		r.lane.since(asked, "exit-ip", "net", exitArgs(r.way, r.found, r.lookupErr))
		r.identity.field("exit-ip", describeExit(r.found, r.lookupErr, r.way))
		r.log.say(slog.LevelInfo, "exit", runAttrs(nil, "proxy", redactProxy(r.way),
			"said", describeExit(r.found, r.lookupErr, r.way))...)
	}
	r.identity.close()
	if from != "" {
		r.errOut.printf("warmed from %s\n", from)
	}
	// Each identity's session, as it was chosen when the run began: what a
	// run that went several ways can be read back from, set by set.
	for _, way := range r.ways {
		if session := r.common.run.sessions[way]; session.from != "" {
			r.lane.instant("cookies loaded", "cookies", traceArgs{"proxy": redactProxy(way), "from": session.from})
			r.log.say(slog.LevelInfo, "cookies loaded", "proxy", redactProxy(way), "from", session.from)
		}
	}

	// What was asked before the run, for the report to say. It answers for the
	// requests made without a proxy, and for none made through one.
	if r.oneWay {
		r.before = &probe{Proxy: redactProxy(r.way), Exit: r.found}
		if r.lookupErr != nil {
			r.before.Error = redactError(r.lookupErr, r.way)
		}
	}

	// Made rather than required, as a report's is: a run that has fetched a list
	// should not fail at the end for want of a directory.
	if r.output != "" {
		if err := os.MkdirAll(r.output, 0o755); err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
	}
	return nil
}

// close ends what open opened, in the order a run ends: the clients, the line
// of what it wore, then the trace, and last the log, which says how the run
// ended, the trace's failure included.
func (r *fetchRun) close(runErr *error) {
	if r.clients != nil {
		r.clients.close()
	}
	if r.identity != nil {
		r.identity.close()
	}
	if err := r.trace.close(*runErr); err != nil {
		*runErr = errors.Join(*runErr, err)
	}
	if err := r.keys.close(); err != nil {
		*runErr = errors.Join(*runErr, err)
	}
	if err := r.log.close(*runErr); err != nil {
		*runErr = errors.Join(*runErr, err)
	}
}

// execute makes the run's requests, its output going where the plan says, and
// is what each came to, how many got no response, and why the run stopped
// short, if it did.
func (r *fetchRun) execute(ctx context.Context) (records []result, failures int, failed error) {
	r.counts = newProgress(r.requests)
	// One request at a time, so how many are running is never news.
	r.counts.solo = r.workers == 1

	// Where the output goes, and whether the status is redrawn beside it.
	var lines *linesOutput
	if r.asJSON {
		// Standard output, unless that is a screen and nobody asked for the lines
		// there: each one holds a whole page, and a run being watched is watched
		// for whether it is working.
		sink := io.Writer(r.out)
		if !r.watch.wanted(r.out, false) {
			sink = io.Discard
			r.unprinted = true
		}
		if r.wantProgress {
			// The status line owns the sink from here: it erases itself before
			// every result and draws again after, so the two streams can share a
			// terminal without overwriting one another.
			r.line = newStatusLine(r.errOut, sink, r.counts, r.paint)
			sink = r.line
		}
		lines = &linesOutput{encoder: json.NewEncoder(sink), headers: r.showHeaders}
	} else {
		show := &showing{out: r.out, headers: r.showHeaders, body: r.watch.wanted(r.out, r.output != "")}
		// Redrawn as the run goes when somebody is watching, unless pages are
		// being printed on the same screen: then they are what is being watched,
		// and a status redrawn between them would land on the end of each.
		pagesOnScreen := show.body && onScreen(r.out)
		if r.wantProgress && !pagesOnScreen {
			r.line = newStatusLine(r.errOut, r.out, r.counts, r.paint)
			show.out = r.line
		}
		r.pages = &pageOutput{show: show, runs: r.requests}
	}
	if r.line != nil {
		r.log.shareStderr(r.line)
	}
	// Where a run talks while it runs. Several workers write here, so it is one
	// lock whether or not there is a status line to work around.
	notes := &stderrLog{out: r.errOut, line: r.line, on: *r.watch.verbose}
	with := runner{
		check:   r.check,
		clients: r.clients, workers: r.workers,
		request: tlsforge.Request{Method: r.method, Header: tlsforge.Header(r.headers), Body: []byte(r.data),
			Browser: r.browser},
		retry: *r.again.retry, repeat: *r.again.repeat,
		keep: r.output, wire: r.wire,
		about: requestAbout{
			method: r.method, profile: r.worn.Name, run: r.common.run.id,
			requests: r.requests, runs: *r.again.repeat,
		},
		exits: r.exits, names: &resolver{}, noLookup: r.noExitLookup,
		counts: r.counts, trace: r.trace, log: r.log.logger(),
		// Every try is written down for a report, and for the log and the trace
		// each request is kept with.
		detailed: len(r.formats) > 0 || r.output != "",
	}
	if *r.again.reuse {
		with.held = newHeldClients(*r.again.repeat)
	}
	switch {
	case !r.oneWay:
		with.directError = "not asked, as the run went more than one way"
	case r.way == "":
		with.direct, with.directError = r.found, r.before.Error
	}
	if r.asJSON {
		lines.say, with.out = notes.say, lines
	} else {
		r.pages.say, with.out = notes.say, r.pages
	}
	if r.workers == 1 {
		// A try that is made again is said to somebody who asked to hear about
		// every request, while there is only the one request it can be about.
		with.note = notes.say
	}

	records = make([]result, 0, len(r.jobs))
	failures, failed = runJobs(ctx, r.jobs, with, &records)
	return records, failures, failed
}

// finish says what the run came to, on standard error, in its log and its
// trace, and in its reports, writes down the sessions it ends with, and is the
// error the command ends with: every reason it failed, none lost behind
// another.
func (r *fetchRun) finish(records []result, failures int, failed error) error {
	// The count, left where it ended: redrawn for the last time when it was being
	// redrawn, and said once when it was not.
	if r.line != nil {
		r.log.closeStatus(r.line)
	} else {
		if r.pages != nil && r.pages.show.midLine && onScreen(r.out) {
			// A page rarely ends with a newline, and the count would start on
			// the end of its last line.
			r.errOut.println()
		}
		for _, row := range r.counts.frame(now(), r.paint) {
			r.errOut.println(row)
		}
	}

	totals := summarise(records, now().Sub(r.counts.started))
	totals.Passes = *r.again.repeat
	totals.WantedElement, totals.WantedText = r.check.wants()
	totals.Decoding = r.check.readAs()
	r.lane.instant("summary", "run", totals.facts())
	r.log.say(slog.LevelInfo, "summary", runAttrs(totals.facts(), "took", totals.Elapsed)...)

	// Whatever the run came to, and most of all when it came to nothing: a
	// request that failed is the one somebody opens a report about.
	var reported []string
	var reportErr error
	if len(r.formats) > 0 {
		var written []reportFile
		written, reportErr = writeReports(r.files.reports,
			reportInput{command: "fetch", records: records, summary: totals, before: r.before,
				method: r.method, trace: *r.again.trace,
				run: r.common.run.id, started: r.started, profile: r.worn.Name})
		for _, file := range written {
			r.log.say(slog.LevelInfo, "report", "file", file.path, "format", file.format)
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
	end := ending{saved: r.output, reports: reported, unprinted: r.unprinted}
	if r.requests > 1 {
		figures := totals.rows(r.requests)
		if *r.again.repeat > 1 && len(r.jobs) > 1 {
			// What turns the number back into a list.
			figures[0][1] += fmt.Sprintf("  (%d passes over %d URLs)", *r.again.repeat, len(r.jobs))
		}
		r.errOut.println()
		r.errOut.printf("%s", aligned(append(append(figures, totals.proxyRows()...), end.rows()...)))
	} else {
		// One request has said all of it on its one line, and has only files to
		// name.
		for _, said := range end.lines() {
			r.errOut.println("  " + said)
		}
	}

	// After the requests, so what is written down is the session the run ends
	// with rather than the one it started from. One set for each client, which
	// is one for each proxy: a jar is an identity, and two exits' sessions in
	// one set would describe a browser that was two people.
	saved, saveErr := r.clients.saveSessions(r.common, records)
	if saved > 0 {
		r.errOut.printf("saved %d cookies to %s\n", saved, *r.common.saveCookies)
		r.log.say(slog.LevelInfo, "cookies saved", "file", *r.common.saveCookies, "cookies", saved)
		r.lane.instant("cookies saved", "cookies",
			traceArgs{"file": *r.common.saveCookies, "cookies": saved})
	}

	if failed == nil && failures > 0 {
		if r.requests == 1 {
			// One request is the whole of what was asked for, and its failure is
			// the command's.
			failed = errors.New(records[0].Error)
		} else {
			// Non-zero: a request made ten times that came back nine is not one
			// that worked, and a shell loop needs to be able to tell.
			failed = fmt.Errorf("fetch: %d of %d requests got no response", failures, r.requests)
		}
	}
	// A page without what the page has is not the page, and a run that asked
	// for it fails for it as for a request that got nothing: a line for each
	// thing, saying how many were without it.
	failed = errors.Join(failed,
		pagesWithout(totals.NoElement, r.requests, "element matching "+totals.WantedElement),
		pagesWithout(totals.NoText, r.requests, "text matching "+totals.ShownText()))
	// All of them, so that the reason the fetch failed is not lost behind a
	// report or a session that could not be written.
	return errors.Join(failed, reportErr, saveErr)
}

// fetchFiles are the files a fetch reads and writes, as its flags name them,
// and the directory it keeps its requests in.
type fetchFiles struct {
	input, cookies, exitHeaders, saveCookies, trace, log, keylog string
	reports                                                      []reportFile
	output                                                       string
	cleared                                                      bool
}

// plan is those files in one plan: what the run reads, then what it writes,
// then where its output and errors go, so that a message about two of them
// names the one that would have done the damage.
func (f fetchFiles) plan(stdout, stderr io.Writer) *filePlan {
	plan := newFilePlan()
	plan.keepIn(f.output, f.cleared)
	plan.add("--input", f.input, readsFile)
	plan.add(flagCookies, f.cookies, readsFile)
	plan.add("--exit-headers", f.exitHeaders, readsFile)
	plan.add(flagSaveCookies, f.saveCookies, writesFile)
	plan.add("--trace", f.trace, writesFile)
	plan.add("--log", f.log, writesFile)
	plan.add("--keylog", f.keylog, writesFile)
	for _, report := range f.reports {
		plan.add("--report", report.path, writesFile)
	}
	plan.stream("standard output", stdout)
	plan.stream("standard error", stderr)
	return plan
}

// reads are the files the run reads, by flag, for --clear-output-dir to keep
// out of the directory it empties: a .json --save-cookies among them, since a
// run adds its session to those already there.
func (f fetchFiles) reads() map[string]string {
	reads := map[string]string{"--input": f.input, flagCookies: f.cookies, "--exit-headers": f.exitHeaders}
	if !netscapeFile(f.saveCookies) {
		reads[flagSaveCookies] = f.saveCookies
	}
	return reads
}

// pagesWithout is why a run fails for the pages that came back without
// something the page has, or nil when none did.
func pagesWithout(count, requests int, what string) error {
	switch {
	case count == 0:
		return nil
	case requests == 1:
		return fmt.Errorf("fetch: the page has no %s", what)
	}
	return fmt.Errorf("fetch: %d of %d pages have no %s", count, requests, what)
}

// waysOf are the ways a run goes, each once, in the order its list first goes
// each: through a proxy, or through none.
func waysOf(jobs []job, fallback string) []string {
	var ways []string
	seen := map[string]bool{}
	for _, j := range jobs {
		way := j.Proxy
		if way == "" {
			way = fallback
		}
		if !seen[way] {
			seen[way] = true
			ways = append(ways, way)
		}
	}
	return ways
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

func runDaemon(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("daemon", out)
	common := addDaemonFlags(fs)
	proxyStdin := fs.Bool("proxy-stdin", false, "take the proxy URL from the first line of standard input, "+
		"an init line, which keeps it off the command line and out of the environment")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *proxyStdin && (fs.Changed("proxy") || fs.Changed("proxy-env")) {
		return fmt.Errorf("%w: --proxy-stdin takes the proxy from the input: give neither --proxy nor "+
			"--proxy-env with it", errUsage)
	}
	if _, err := common.proxyFromEnv(); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}
	// Not settle: a profile there is none of ends the daemon as the client it
	// cannot make does, with 1, which the packages that start it read as such.
	if _, err := common.resolve(); err != nil {
		return err
	}
	input, init, err := daemonProxy(*proxyStdin, common, out)
	if err != nil {
		return err
	}
	if err := init.failed(common.warmup(*common.proxy)); err != nil {
		return err
	}

	common.wear(errOut)
	client, err := common.client()
	if err := init.failed(err); err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := init.ready(); err != nil {
		return err
	}

	// stdin is read directly rather than through the writer the command was
	// given: the protocol is a pipe, and tests substitute it through daemonInput.
	//
	// Until ctx is done, which a signal does: the request in flight is
	// cancelled and answered, and the daemon ends as it does at the end of its
	// input, since being told to stop is how a daemon is meant to end.
	err = daemon.ServeContext(ctx, input, out, client)
	if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		return nil
	}
	return err
}

// daemonProxy is where a daemon reads its requests from, and the init line
// it answers before it reads them. With --proxy-stdin the proxy is the init
// line's, the first of the input, read before the client that goes through
// it is made; without it, the input is all requests, and there is no init
// line to answer.
//
// What goes wrong with an init line ends the daemon with 1, never 2: the
// packages that start it read 2 as arguments a tls-forge older than they are
// did not understand.
func daemonProxy(fromInput bool, common clientFlags, out *printer) (io.Reader, *initLine, error) {
	if !fromInput {
		return daemonInput, nil, nil
	}
	said, input, err := daemon.ReadInit(daemonInput)
	init := &initLine{out: out, id: said.ID}
	if err != nil {
		return nil, nil, init.failed(err)
	}
	*common.proxy = said.Proxy
	if why := proxyProblem(said.Proxy); why != "" {
		return nil, nil, init.failed(fmt.Errorf("daemon: the init line's proxy %s %s", redactProxy(said.Proxy), why))
	}
	return input, init, nil
}

// initLine is the init line a daemon was given, which it answers once: with
// why it cannot take requests, which ends it, or that it can. Nil for a
// daemon given none, which answers nothing.
type initLine struct {
	out *printer
	id  uint64
}

// failed answers err, when there is one, and is it.
func (l *initLine) failed(err error) error {
	if err != nil && l != nil {
		_ = daemon.AnswerInit(l.out, l.id, err)
	}
	return err
}

// ready answers that the daemon takes requests now.
func (l *initLine) ready() error {
	if l == nil {
		return nil
	}
	return daemon.AnswerInit(l.out, l.id, nil)
}

// daemonInput is os.Stdin, named so a test can supply a script instead.
var daemonInput io.Reader = os.Stdin
