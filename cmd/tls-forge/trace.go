package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v7"
	"github.com/Sec-CH-Lemon/tls-forge/v7/internal/redact"
	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
)

// A run, written down while it happens.
//
// As Trace Event JSON, the format chrome://tracing reads and ui.perfetto.dev
// opens. What a trace is asked is where the time went and in what order, and
// that is a picture before it is a list: a row per worker, a bar per request,
// and inside it a bar for each thing the request waited on.
//
// One event to a line all the same, so that the file answers grep and jq
// without a viewer, and written as each thing happens rather than at the end:
// the run somebody needs a trace of is often the one that did not finish. The
// format allows for that. A file that stops before its closing bracket is still
// a trace.

// traceArgs is what an event knows beyond when it happened.
type traceArgs map[string]any

// traceEvent is one line of the file, under the format's own names.
type traceEvent struct {
	Phase string    `json:"ph"`
	PID   int       `json:"pid"`
	TID   int       `json:"tid"`
	TS    int64     `json:"ts,omitempty"`
	Dur   int64     `json:"dur,omitempty"`
	Cat   string    `json:"cat,omitempty"`
	Name  string    `json:"name,omitempty"`
	Scope string    `json:"s,omitempty"`
	Args  traceArgs `json:"args,omitempty"`
}

// The phases used, of the many the format has. A begin and an end bracket
// something still going on when it is written; a complete event is something
// that is over, and so knows how long it took; an instant has no length; and
// metadata names the rows.
const (
	phaseBegin    = "B"
	phaseEnd      = "E"
	phaseComplete = "X"
	phaseInstant  = "i"
	phaseMetadata = "M"
)

// mainLane is the row the command itself is drawn on. Workers take the rows
// after it.
const mainLane = 1

// tracer writes the file.
type tracer struct {
	mu   sync.Mutex
	out  io.WriteCloser
	err  error
	home *traceLane

	command string
	// proxy is the run's own, kept to take its password out of the error the
	// run ends with.
	proxy string

	pid   int
	began time.Time
	epoch int64
	last  int64
	wrote bool
}

// createTrace opens the file a trace goes to. A variable so a test can hand
// back something that will not be written to.
//
// 0600, as with the report: a trace names every URL a run asked for and every
// address it went through, and is made to be kept.
var createTrace = func(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

// openTrace starts a trace, or returns nil when none was asked for.
//
// Nil is a tracer that does nothing, and so is everything made from one: a run
// that is not being traced calls the same methods and pays for none of them.
func openTrace(path, command, proxy string, started time.Time, about traceArgs) (*tracer, error) {
	if path == "" {
		return nil, nil
	}
	// In a directory made for it, as a report and a log are: `--trace
	// traces/run.json` is a trace, not a reason to stop before the first
	// request.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}
	file, err := createTrace(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}

	began := now()
	t := &tracer{
		out: file, command: command, proxy: proxy,
		pid: os.Getpid(), began: began, epoch: began.UnixMicro(),
	}
	t.emit(traceEvent{Phase: phaseMetadata, TID: mainLane, Name: "process_name",
		Args: traceArgs{"name": "tls-forge " + command}})
	t.home = t.lane(mainLane, command)

	// The clock in the file counts microseconds, which is what the format asks
	// for and not what a person reads. When the run began, said once in words,
	// so the rest can be placed against its log and its report.
	about["started"] = started.Format(time.RFC3339Nano)
	about["version"] = version
	t.emit(traceEvent{Phase: phaseBegin, TID: mainLane, TS: t.at(), Cat: "run",
		Name: command, Args: about})
	return t, nil
}

// main is the command's own row.
func (t *tracer) main() *traceLane {
	if t == nil {
		return nil
	}
	return t.home
}

// lane adds a row and names it.
func (t *tracer) lane(tid int, name string) *traceLane {
	if t == nil {
		return nil
	}
	t.emit(traceEvent{Phase: phaseMetadata, TID: tid, Name: "thread_name",
		Args: traceArgs{"name": name}})
	// Rows are otherwise sorted by name, which puts worker 10 above worker 2.
	t.emit(traceEvent{Phase: phaseMetadata, TID: tid, Name: "thread_sort_index",
		Args: traceArgs{"sort_index": tid}})
	return &traceLane{t: t, tid: tid}
}

// at is the moment an event is filed under: microseconds since 1970, and never
// the same one twice.
//
// Never twice, because a viewer sorts the file by time before it reads it and
// decides what is inside what from the order. Two events in the same
// microsecond leave that to the sort, and a request that begins when the one
// before it ends is drawn inside it or after it depending on which came out
// first.
func (t *tracer) at() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stamp()
}

func (t *tracer) stamp() int64 {
	at := t.epoch + now().Sub(t.began).Microseconds()
	if at <= t.last {
		at = t.last + 1
	}
	t.last = at
	return at
}

// emit writes one event.
func (t *tracer) emit(event traceEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.put(event)
}

// put writes one event as one line. The caller holds the lock.
func (t *tracer) put(event traceEvent) {
	event.PID = t.pid

	// The separator goes in front of an event, not behind it, so that the file
	// is a well-formed array up to wherever it stops.
	separator := ",\n"
	if !t.wrote {
		separator = "[\n"
		t.wrote = true
	}
	t.send(append([]byte(separator), eventLine(event)...))
}

// eventLine is one event as one line of a trace file.
func eventLine(event traceEvent) []byte {
	var line bytes.Buffer
	encoder := json.NewEncoder(&line)
	// A URL is mostly ampersands, and escaped for HTML it no longer matches the
	// one somebody is searching the file for.
	encoder.SetEscapeHTML(false)
	// Nothing an event holds can fail to encode: strings, numbers, booleans and
	// lists of strings.
	_ = encoder.Encode(event)
	return bytes.TrimSuffix(line.Bytes(), []byte("\n"))
}

// send writes to the file, and remembers the first time that fails rather than
// failing the run in the middle: the trace is commentary on the run, and the
// run is what was asked for. It is reported when the trace is closed.
func (t *tracer) send(data []byte) {
	if t.err != nil {
		return
	}
	_, t.err = t.out.Write(data)
}

// close ends the trace, with what the run ended as, and reports a trace that
// could not be written.
func (t *tracer) close(runErr error) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	var about traceArgs
	if runErr != nil {
		about = traceArgs{"error": redactError(runErr, t.proxy)}
	}
	t.put(traceEvent{Phase: phaseEnd, TID: mainLane, TS: t.stamp(), Args: about})
	t.send([]byte("\n]\n"))

	if err := errors.Join(t.err, t.out.Close()); err != nil {
		return fmt.Errorf("%s: writing the trace: %w", t.command, err)
	}
	return nil
}

// traceLane is one row of the picture: the worker whose requests are drawn on
// it, one after another.
type traceLane struct {
	t   *tracer
	tid int
}

// instant marks something that happened and took no time doing it.
func (l *traceLane) instant(name, category string, about traceArgs) {
	if l == nil {
		return
	}
	l.t.emit(traceEvent{Phase: phaseInstant, TID: l.tid, TS: l.t.at(), Cat: category,
		Name: name, Scope: "t", Args: about})
}

// mark is a moment to measure from.
func (l *traceLane) mark() int64 {
	if l == nil {
		return 0
	}
	return l.t.at()
}

// since draws what took from a mark until now.
func (l *traceLane) since(mark int64, name, category string, about traceArgs) {
	if l == nil {
		return
	}
	l.span(name, category, mark, l.t.at(), about)
}

// span draws something that is over.
func (l *traceLane) span(name, category string, from, to int64, about traceArgs) {
	l.t.emit(traceEvent{Phase: phaseComplete, TID: l.tid, TS: from, Dur: to - from,
		Cat: category, Name: name, Args: about})
}

// wearing files which browser the run is being, which is the first thing to
// rule out when a request is turned away: the profile the run resolved before
// it started.
func (l *traceLane) wearing(p *profile.Profile) {
	if l == nil {
		return
	}
	l.instant("profile", "run", traceArgs{
		"name": p.Name, "origin": origin(p), "from": from(p), "user_agent": p.UserAgent,
	})
}

// attempt opens one try at a URL: the bar everything the try does is drawn
// inside, and the record of it when somebody is keeping one.
//
// Either is enough to open it. A run that is neither traced nor reported gets
// nil, and the client is not asked to report anything.
func (l *traceLane) attempt(method, url string, run, attempt int, proxy string, log *try,
) *attemptTrace {
	if l == nil && log == nil {
		return nil
	}
	a := &attemptTrace{lane: l, log: log, proxy: proxy, secure: isHTTPS(url)}
	a.opened = a.at()
	if log != nil {
		log.Began = now()
	}
	if l != nil {
		if method == "" {
			method = "GET"
		}
		about := traceArgs{"url": safeURL(url), "run": run, "attempt": attempt}
		if proxy != "" {
			about["proxy"] = redactProxy(proxy)
		}
		l.t.emit(traceEvent{Phase: phaseBegin, TID: l.tid, TS: a.opened, Cat: "request",
			Name: method + " " + safeURL(url), Args: about})
	}
	return a
}

// attemptTrace turns what the client reports about one try into the steps the
// try went through.
//
// The client reports moments: a lookup began, a dial ended. A picture wants
// lengths, so each moment ends the step in progress and usually begins the
// next, and a step is drawn when it ends. Only one is ever in progress. Steps
// drawn side by side would overlap, and a viewer drops what overlaps.
//
// The steps go to the trace, to the record a report is written from, or to
// both. One reading of what the client said rather than two, so that the
// report and the trace of a run cannot tell it differently.
type attemptTrace struct {
	lane  *traceLane
	log   *try
	proxy string
	// opened is when the try began, on the clock its steps are measured by.
	opened int64

	mu sync.Mutex
	// over is set when the try has ended. A hook can still be called after
	// that, by a dial that lost its race, and what it reports would otherwise
	// land inside whichever request the worker has moved on to.
	over bool
	// secure says the hop in progress is HTTPS, so that a dial is followed by a
	// handshake and not by the request.
	secure   bool
	step     string
	category string
	since    int64
	facts    stepFacts
}

// stepFacts is what a step of a try says beyond its name and how long it
// took, gathered as the client reports it. One record, which the trace writes
// out as the step's args and a report reads the step's note and the request as
// written from, so that neither can say a fact under a name the other does not
// know.
type stepFacts struct {
	// host is what a lookup looked up.
	host string
	// addrs are the addresses a lookup found, which may be none, or those a
	// dial tried; said says the lookup ended or the dial began, which is when
	// there are any to say.
	addrs []string
	said  bool
	// network is what a dial went over, addr the address that answered, and
	// failed why each of the others did not.
	network string
	addr    string
	failed  []string
	// conn is the connection a handshake made, or a request went out on.
	conn *tlsforge.ConnInfo
	// written is the request as it went out, without the values a session is
	// worth, and wrote says it went.
	written []string
	wrote   bool
	// status is what the step ended with: the status of a redirect, or of the
	// answer the try ended with. unfinished says the try ended in the middle
	// of it, and err why it failed.
	status     int
	unfinished bool
	err        string
}

// args are the facts as the trace says them, each under its name and only
// once it is a fact.
func (f stepFacts) args() traceArgs {
	args := traceArgs{}
	if f.conn != nil {
		args = connArgs(*f.conn)
	}
	if f.host != "" {
		args["host"] = f.host
	}
	if f.said {
		args["addrs"] = f.addrs
	}
	if f.network != "" {
		args["network"] = f.network
	}
	if f.addr != "" {
		args["addr"] = f.addr
	}
	if len(f.failed) > 0 {
		args["failed"] = f.failed
	}
	if f.wrote {
		args["headers"] = f.written
	}
	if f.status != 0 {
		args["status"] = f.status
	}
	if f.unfinished {
		args["unfinished"] = true
	}
	if f.err != "" {
		args["error"] = f.err
	}
	return args
}

// fail says why the step failed, when there is a why.
func (f *stepFacts) fail(err error, proxy string) {
	if err != nil {
		f.err = redactError(err, proxy)
	}
}

// hooks is what the client is given to report through.
func (a *attemptTrace) hooks() *tlsforge.Trace {
	if a == nil {
		return nil
	}
	return &tlsforge.Trace{
		DNSStart:     a.dnsStart,
		DNSDone:      a.dnsDone,
		ConnectStart: a.connectStart,
		ConnectDone:  a.connectDone,
		GotConn:      a.gotConn,
		WroteRequest: a.wroteRequest,
		FirstByte:    a.firstByte,
		Redirect:     a.redirect,
	}
}

// at is the moment something is filed under: the trace's own clock when there
// is a trace, so that the report and the trace agree to the microsecond, and
// the wall clock when there is not.
func (a *attemptTrace) at() int64 {
	if a.lane != nil {
		return a.lane.t.at()
	}
	return now().UnixMicro()
}

// when runs one report's worth of bookkeeping at the moment it arrived, unless
// the try is over.
func (a *attemptTrace) when(do func(at int64)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.over {
		return
	}
	do(a.at())
}

// begin starts a step at a moment already taken, with nothing yet to say of
// it.
func (a *attemptTrace) begin(step, category string, at int64) {
	a.step, a.category, a.since, a.facts = step, category, at, stepFacts{}
}

// finish ends the step in progress, if there is one, and draws it with what
// there is to say of it.
func (a *attemptTrace) finish(at int64) {
	if a.step == "" {
		return
	}
	if a.lane != nil {
		a.lane.span(a.step, a.category, a.since, at, a.facts.args())
	}
	if a.log != nil {
		a.log.keep(a.step, micros(a.since-a.opened), micros(at-a.since), a.facts)
	}
	a.step = ""
}

// handshake is the name of the step between a dial and a connection that can
// carry a request. Through a proxy it is the tunnel as well, and calling the
// two of them the handshake would blame TLS for a slow proxy.
func (a *attemptTrace) handshake() string {
	if a.proxy != "" {
		return "proxy+tls"
	}
	return "tls"
}

func (a *attemptTrace) dnsStart(host string) {
	a.when(func(at int64) {
		a.finish(at)
		a.begin("dns", "net", at)
		a.facts.host = host
	})
}

func (a *attemptTrace) dnsDone(addrs []string, err error) {
	a.when(func(at int64) {
		if a.step == "dns" {
			a.facts.addrs, a.facts.said = addrs, true
			a.facts.fail(err, a.proxy)
			a.finish(at)
		}
	})
}

func (a *attemptTrace) connectStart(network, addr string) {
	a.when(func(at int64) {
		// A host with two addresses is dialled twice, and the second dial can
		// begin before the first has given up. One step for all of them.
		if a.step == "connect" {
			a.facts.addrs = append(a.facts.addrs, addr)
			return
		}
		a.finish(at)
		a.begin("connect", "net", at)
		a.facts.network, a.facts.addrs, a.facts.said = network, []string{addr}, true
	})
}

func (a *attemptTrace) connectDone(_, addr string, err error) {
	a.when(func(at int64) {
		if a.step != "connect" {
			// A dial that lost its race, reporting in after the winner moved on.
			return
		}
		if err != nil {
			// Not the end of the step: another address may still answer. If none
			// does, the try ends and takes the step with it.
			a.facts.failed = append(a.facts.failed, redactError(err, a.proxy))
			return
		}
		a.facts.addr = addr
		a.finish(at)
		if a.secure {
			a.begin(a.handshake(), "net", at)
		}
	})
}

func (a *attemptTrace) gotConn(conn tlsforge.ConnInfo) {
	a.when(func(at int64) {
		if a.log != nil {
			a.log.Conn, a.log.Connected = conn, true
		}
		// What the handshake settled on belongs to the handshake when there was
		// one. It is said again on the request, because a connection that was
		// already open had no handshake to say it on.
		if a.step == a.handshake() {
			a.facts.conn = &conn
		}
		a.finish(at)
		a.begin("send", "http", at)
		a.facts.conn = &conn
	})
}

func (a *attemptTrace) wroteRequest(sent tlsforge.Header, err error) {
	a.when(func(at int64) {
		if a.step != "send" {
			return
		}
		a.facts.written, a.facts.wrote = safeHeaders(sent), true
		a.facts.fail(err, a.proxy)
		a.finish(at)
		a.begin("wait", "http", at)
	})
}

func (a *attemptTrace) firstByte() {
	a.when(func(at int64) {
		// Normally the wait ends here. A server that answers before it has read
		// the whole request ends the sending instead.
		if a.step != "wait" && a.step != "send" {
			return
		}
		a.finish(at)
		a.begin("receive", "http", at)
	})
}

func (a *attemptTrace) redirect(status int, location string) {
	a.when(func(at int64) {
		a.facts.status = status
		a.finish(at)
		if a.lane != nil {
			a.lane.t.emit(traceEvent{Phase: phaseInstant, TID: a.lane.tid, TS: at, Cat: "http",
				Name: "redirect", Scope: "t",
				Args: traceArgs{"status": status, "location": safeURL(location)}})
		}
		if a.log != nil {
			a.log.redirected(micros(at-a.opened), status, safeURL(location))
		}
		a.secure = isHTTPS(location)
	})
}

// end closes the try: the step it was in the middle of, then the try itself,
// with how it came out.
func (a *attemptTrace) end(res *tlsforge.Response, err error) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// A step that was still going when the try failed is where it failed, and
	// is drawn as far as it got: a request that timed out waiting for its first
	// byte shows the wait, which is the answer to what went wrong.
	if err == nil {
		a.facts.status = res.Status
	} else {
		a.facts.unfinished = true
	}
	at := a.at()
	a.finish(at)
	a.over = true
	if a.lane != nil {
		a.lane.t.emit(traceEvent{Phase: phaseEnd, TID: a.lane.tid, TS: a.lane.t.at(),
			Args: outcome(res, err, a.proxy)})
	}
	if a.log != nil {
		a.log.ended(micros(at-a.opened), res, err, a.proxy)
	}
}

// micros is a length on the trace's clock as a duration.
func micros(n int64) time.Duration { return time.Duration(n) * time.Microsecond }

// connArgs is a connection as the trace describes it.
func connArgs(conn tlsforge.ConnInfo) traceArgs {
	about := traceArgs{"reused": conn.Reused, "remote": conn.RemoteAddr}
	if len(conn.ProxyHeader) > 0 {
		// Where a proxy says where the connection came out, when it says.
		about["proxy_answer"] = safeHeaders(conn.ProxyHeader)
	}
	if conn.TLSVersion != "" {
		about["tls"] = conn.TLSVersion
		about["cipher"] = conn.CipherSuite
		about["alpn"] = conn.ALPN
		about["resumed"] = conn.Resumed
	}
	return about
}

// outcome is how a try ended.
func outcome(res *tlsforge.Response, err error, proxy string) traceArgs {
	if err != nil {
		return traceArgs{"error": redactError(err, proxy)}
	}
	about := traceArgs{
		"status":    res.Status,
		"bytes":     len(res.Body),
		"final_url": safeURL(res.URL),
		"headers":   safeResponseHeaders(res.Header),
	}
	if len(res.Cookies) > 0 {
		about["cookies"] = cookieNames(res.Cookies)
	}
	if !res.OK() {
		// The start of a page that was not the one asked for, which is usually
		// where it says why. It is the only place it is kept when the request is
		// tried again: the next answer replaces this one everywhere else.
		about["body"] = preview(res.Body)
	}
	return about
}

// exitArgs is where a run came out, or why nobody could say.
func exitArgs(proxy string, found egress, err error) traceArgs {
	about := traceArgs{}
	if proxy != "" {
		about["proxy"] = redactProxy(proxy)
	}
	if err != nil {
		about["error"] = redactError(err, proxy)
		return about
	}
	about["ip"] = found.IP
	if country := found.countryCode(); country != "" {
		about["country"] = country
	}
	return about
}

// previewBytes is how much of a page that was not the page is kept.
const previewBytes = 512

// preview is the start of a body, as text.
func preview(body []byte) string {
	if len(body) > previewBytes {
		body = body[:previewBytes]
	}
	// Cut wherever the limit fell, which can be inside a character.
	return strings.ToValidUTF8(string(body), "�")
}

func isHTTPS(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "https:")
}

// safeURL is a URL without the password it may carry, which is what a proxy
// URL is shown as and for the same reason.
func safeURL(url string) string { return redactProxy(url) }

// What a trace leaves out.
//
// A trace is written to be kept and sent on, to whoever is being asked why a
// request failed, so it holds what a session was called and not what it was
// worth: the names of cookies without their values, and the scheme of an
// Authorization header without its credentials.

// safeHeaders is a request's header fields as written, in the order written.
func safeHeaders(sent tlsforge.Header) []string {
	lines := make([]string, 0, len(sent))
	for _, field := range sent {
		lines = append(lines, field.Name+": "+safeValue(field.Name, field.Value))
	}
	return lines
}

// safeResponseHeaders is a response's header fields. By name, because a
// response arrives as a map and a map has no order to keep.
func safeResponseHeaders(header map[string][]string) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)

	var lines []string
	for _, name := range names {
		for _, value := range header[name] {
			lines = append(lines, name+": "+safeValue(name, value))
		}
	}
	return lines
}

// safeValue is a header's value, or what is left of it once the secret is out.
func safeValue(name, value string) string { return redact.Value(name, value) }

// cookieNames is the jar as name=value pairs, without the values.
func cookieNames(pairs []string) []string {
	names := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		name, _, _ := strings.Cut(pair, "=")
		names = append(names, name)
	}
	return names
}
