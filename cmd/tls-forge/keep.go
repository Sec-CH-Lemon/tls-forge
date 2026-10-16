package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// What is kept of each request, in the directory --output names.
//
// Three files for every request, under one name: the page, when anything came
// back, whatever its status, ending in what its Content-Type says it is; a log
// of the request that a person reads; and a trace of it that ui.perfetto.dev
// draws. The name is the host the request
// went to, when it was made, and which request of the run it was, so that a
// directory of them lists by host and then by time, and the three files of one
// request sit beside one another.

// requestAbout is what a run knows of all of its requests, which each of their
// logs repeats so that one can be read without the others.
type requestAbout struct {
	method  string
	profile string
	// requests is how many the run makes, and runs how many times each URL is
	// made.
	requests, runs int
}

// keepRequest writes one request down in dir, and notes on its record where.
func keepRequest(dir string, r *result, res *tlsforge.Response, j job, about requestAbout,
	lane *traceLane,
) error {
	name := requestName(r.URL, r.Started, j.id)
	// 0600, all three, as for a report or a trace of the whole run: the log and
	// the trace name what was asked for and where it went, and a page can be
	// one that only a session could open.
	if res != nil {
		// Whatever came back, an error page included: what a server says when it
		// turns a request away is the most interesting page it sends.
		page := filepath.Join(dir, name+pageExtension(res.Header, res.Body))
		if err := os.WriteFile(page, res.Body, 0o600); err != nil {
			return err
		}
		r.File = page
		lane.instant("saved", "file", traceArgs{"file": page, "bytes": len(res.Body)})
	}
	log := filepath.Join(dir, name+".log")
	trace := filepath.Join(dir, "trace-"+name+".json")
	r.Log, r.Trace = log, trace
	if err := os.WriteFile(log, []byte(requestLog(*r, j, about)), 0o600); err != nil {
		return err
	}
	return os.WriteFile(trace, traceFileOf(requestTrace(*r, about.method)), 0o600)
}

// traceFileOf is events as a file of them, in the shape a trace of the whole
// run has: one event to a line.
func traceFileOf(events []traceEvent) []byte {
	var file bytes.Buffer
	separator := "[\n"
	for _, event := range events {
		file.WriteString(separator)
		file.Write(eventLine(event))
		separator = ",\n"
	}
	file.WriteString("\n]\n")
	return file.Bytes()
}

// either is the first of two strings that is not empty.
func either(first, fallback string) string {
	if first != "" {
		return first
	}
	return fallback
}

// maxNameHost is the most of a host the name of a request's files keeps.
//
// A file name is at most 255 bytes on the file systems anybody uses, and what
// the files of a request add to the host is under 60: a trace's prefix, the
// moment, the request's number and the longest extension. A host is at most
// 253 bytes to DNS, and a URL may name a longer one still.
const maxNameHost = 100

// requestName is what the files of a request are called, without what each
// one ends in.
//
// The host as it is written, in lower case, and with anything that is not a
// letter, a digit, a dot or a hyphen made an underscore: an IPv6 address is
// full of colons, and a colon cannot name a file on Windows. So the name is
// ASCII, a byte to each character of the host. A host longer than
// maxNameHost keeps its beginning and a hash of the whole of it, so two such
// hosts still list apart.
func requestName(rawURL string, started time.Time, id int) string {
	host := "request"
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		host = strings.ToLower(u.Hostname())
	}
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, host)
	if len(name) > maxNameHost {
		sum := sha256.Sum256([]byte(host))
		name = name[:maxNameHost-9] + "_" + hex.EncodeToString(sum[:4])
	}
	return name + "-" + stamp(started) + "-" + strconv.Itoa(id)
}

// requestLog is the request written out for a person: what it was, how it
// ended, and every try at it with what each waited on, what went out and what
// came back.
func requestLog(r result, j job, about requestAbout) string {
	var log strings.Builder
	fmt.Fprintf(&log, "%s %s\n\n", about.method, r.URL)

	facts := [][2]string{{"request", fmt.Sprintf("%d of %d", j.id, about.requests)}}
	if about.runs > 1 && about.runs != about.requests {
		// A list gone through more than once. One URL made several times has
		// said which run this was in the line above.
		facts = append(facts, [2]string{"pass", fmt.Sprintf("%d of %d", j.run, about.runs)})
	}
	facts = append(facts, [2]string{"profile", about.profile},
		[2]string{"proxy", either(redactProxy(r.Proxy), "direct")})
	if exit := r.exitSaid(); exit != "" {
		facts = append(facts, [2]string{"exit-ip", exit})
	}
	facts = append(facts,
		[2]string{"started", atPrecisely(r.Started)},
		[2]string{"ended", atPrecisely(r.Ended)},
		[2]string{"took", preciseDuration(r.Ended.Sub(r.Started))},
		[2]string{"outcome", outcomeOf(r.Status, r.Bytes, r.Error, r.finding)},
		[2]string{"tries", strconv.Itoa(max(r.Attempts, len(r.Tries)))},
	)
	if r.FinalURL != "" && r.FinalURL != r.URL {
		facts = append(facts, [2]string{"final URL", r.FinalURL})
	}
	if r.File != "" {
		facts = append(facts, [2]string{"page", r.File})
	}
	log.WriteString(aligned(facts))

	for _, t := range tryRows(r.Tries, r.Started, r.Ended.Sub(r.Started)) {
		fmt.Fprintf(&log, "\ntry %d of %d: %s, %s\n", t.Number, t.Of,
			outcomeOf(t.Status, t.Bytes, t.Error, t.finding), t.Length())
		about := [][2]string{{"began", atPrecisely(t.Began)}}
		if connection := t.Connection(); connection != "" {
			about = append(about, [2]string{"connection", connection})
		}
		log.WriteString(aligned(about))
		steps := t.Listed()
		if len(steps) > 0 {
			log.WriteString("\n")
		}
		var written []string
		for _, s := range steps {
			length := s.Length()
			if s.Moment() {
				length = ""
			}
			note := s.Note
			if s.Cut {
				note = strings.TrimPrefix(note+" · the try ended here", " · ")
			}
			log.WriteString(strings.TrimRight(fmt.Sprintf("  %-9s %7s  %s", s.Name, length, note), " ") + "\n")
			if s.Written != "" {
				written = append(written, s.Written)
			}
		}
		if answered := t.ProxyAnswer(); answered != "" {
			indented(&log, "the proxy's answer to CONNECT", answered)
		}
		// Under the steps rather than among them, and numbered only when a
		// redirect made the request more than once.
		for i, request := range written {
			heading := "request headers, as written"
			if len(written) > 1 {
				heading += fmt.Sprintf(" (%d of %d)", i+1, len(written))
			}
			indented(&log, heading, request)
		}
		if t.Answer != "" {
			indented(&log, "response headers", t.Answer)
		}
		if t.Body != "" {
			indented(&log, "the body began", t.Body)
		}
		if waited := t.Waited(); waited != "" {
			fmt.Fprintf(&log, "\n  then %s of waiting before the next try\n", waited)
		}
	}
	return log.String()
}

// outcomeOf is how a request or a try ended, as a log says it.
func outcomeOf(status, bytes int, failure string, found finding) string {
	if failure != "" {
		return "no response · " + failure
	}
	said := fmt.Sprintf("%d %s · %s", status, http.StatusText(status), humanBytes(int64(bytes)))
	if what := found.said(); what != "" {
		said += " · " + what
	}
	return said
}

// indented writes a block under a heading, every line of it set in.
func indented(log *strings.Builder, heading, block string) {
	fmt.Fprintf(log, "\n  %s\n", heading)
	for _, line := range strings.Split(block, "\n") {
		log.WriteString("    " + line + "\n")
	}
}

// requestTrace is the request as a trace of its own: the whole of it, and
// inside that every try, and inside each try the steps it waited on.
//
// Drawn from what was written down while the request was made, rather than by
// a tracer of its own, so that it does not need one and does not take anything
// from the trace of the whole run. Every event is given a moment of its own and
// every bar ends no earlier than what is drawn inside it, which is what a
// viewer needs to put the bars inside one another.
func requestTrace(r result, method string) []traceEvent {
	const row = mainLane
	pid := os.Getpid()
	last := int64(0)
	// at is a moment no event has had yet.
	at := func(micros int64) int64 {
		if micros <= last {
			micros = last + 1
		}
		last = micros
		return micros
	}
	event := func(e traceEvent) traceEvent {
		e.PID, e.TID = pid, row
		return e
	}

	request := traceArgs{"url": safeURL(r.URL), "request": r.ID}
	if r.Run > 0 {
		request["run"] = r.Run
	}
	if r.Proxy != "" {
		request["proxy"] = redactProxy(r.Proxy)
	}
	events := []traceEvent{
		event(traceEvent{Phase: phaseMetadata, Name: "process_name", Args: traceArgs{"name": "tls-forge fetch"}}),
		event(traceEvent{Phase: phaseMetadata, Name: "thread_name",
			Args: traceArgs{"name": "request " + strconv.Itoa(r.ID)}}),
		event(traceEvent{Phase: phaseBegin, TS: at(r.Started.UnixMicro()), Cat: "request",
			Name: method + " " + safeURL(r.URL), Args: request}),
	}

	for i, t := range r.Tries {
		began := t.Began.UnixMicro()
		events = append(events, event(traceEvent{Phase: phaseBegin, TS: at(began), Cat: "try",
			Name: "try " + strconv.Itoa(i+1), Args: traceArgs{"attempt": i + 1}}))
		// Each step from where the one before it ended at the earliest: they
		// follow one another, and a moment moved on so as not to be shared would
		// otherwise start a step inside the last.
		reached := last
		for _, s := range t.Steps {
			from := at(max(began+s.From.Microseconds(), reached))
			if s.Name == redirectStep {
				events = append(events, event(traceEvent{Phase: phaseInstant, TS: from, Cat: "http",
					Name: redirectStep, Scope: "t", Args: traceArgs{"note": s.Note}}))
				continue
			}
			// A viewer has no use for a bar of no length, and most of what is
			// over within a microsecond is a step that never really began.
			length := max(s.Took.Microseconds(), 1)
			args := traceArgs{}
			if s.Note != "" {
				args["note"] = s.Note
			}
			if s.Written != "" {
				args["headers"] = strings.Split(s.Written, "\n")
			}
			if s.Cut {
				args["unfinished"] = true
			}
			events = append(events, event(traceEvent{Phase: phaseComplete, TS: from, Dur: length,
				Cat: "step", Name: s.Name, Args: args}))
			reached = from + length
		}
		ended := traceArgs{}
		if t.Error != "" {
			ended["error"] = t.Error
		} else {
			ended["status"], ended["bytes"] = t.Status, t.Bytes
		}
		if t.Answer != "" {
			ended["headers"] = strings.Split(t.Answer, "\n")
		}
		if t.Body != "" {
			ended["body"] = t.Body
		}
		t.missingInto(ended)
		if len(t.Conn.ProxyHeader) > 0 {
			ended["proxy_answer"] = safeHeaders(t.Conn.ProxyHeader)
		}
		t.Exit.into(ended)
		events = append(events, event(traceEvent{Phase: phaseEnd,
			TS: at(max(began+t.Took.Microseconds(), reached)), Args: ended}))
		if t.Wait > 0 {
			events = append(events, event(traceEvent{Phase: phaseInstant, TS: at(last), Cat: "retry",
				Name: "retry", Scope: "t", Args: traceArgs{"wait_ms": t.Wait.Milliseconds()}}))
		}
	}

	ended := traceArgs{"attempts": r.Attempts}
	r.missingInto(ended)
	r.Exit.into(ended)
	if r.Error != "" {
		ended["error"] = r.Error
	} else {
		ended["status"], ended["bytes"], ended["final_url"] = r.Status, r.Bytes, safeURL(r.FinalURL)
	}
	if r.File != "" {
		ended["file"] = r.File
	}
	return append(events, event(traceEvent{Phase: phaseEnd, TS: at(r.Ended.UnixMicro()), Args: ended}))
}
