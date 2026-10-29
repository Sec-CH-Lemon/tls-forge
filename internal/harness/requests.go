package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RequestsFixture is what testdata/chrome155-requests.json holds, what a
// browser asked for in each scenario, and testdata/chrome155-connections.json,
// which connection it asked on.
type RequestsFixture struct {
	// Browser says which browser was measured, how it was run and where.
	Browser string `json:"browser"`
	// Measured are the dates it was, and How says how.
	Measured  string                      `json:"measured"`
	How       string                      `json:"how"`
	Scenarios map[string]MeasuredScenario `json:"scenarios"`
}

// MeasuredScenario is what a scenario's page asked of the server, over HTTP/2
// and over HTTP/1.1 alone, in the order asked.
type MeasuredScenario struct {
	Note string    `json:"note"`
	H2   []Request `json:"h2"`
	H1   []Request `json:"h1"`
	// Unfinished says over which protocol the browser began the scenario and
	// never asked for the page it ends at, and so: what it asked is kept, a
	// difference for a check to say, and never written into a fixture.
	Unfinished []string `json:"-"`
}

// Request is a request as the fixture keeps it: no port in its URL or in any
// of its values, since they change every run.
type Request struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	// Conn numbers the connection it came on among its scenario's, in the
	// order requests first came on them, and Resumed says that connection
	// resumed a TLS session: in a fixture of connections alone.
	Conn    int         `json:"conn,omitempty"`
	Resumed bool        `json:"resumed,omitempty"`
	Headers [][2]string `json:"headers"`
	// Priority is an HTTP/2 HEADERS frame's: exclusive, the stream it depends
	// on, the weight as on the wire.
	Priority []uint32 `json:"priority,omitempty"`
	Body     string   `json:"body,omitempty"`
}

// LoadRequests reads a fixture of requests.
func LoadRequests(path string) (*RequestsFixture, error) { return load[RequestsFixture](path) }

// load reads a fixture of type T.
func load[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f T
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("harness: %s: %w", path, err)
	}
	return &f, nil
}

// Write writes the fixture to path as it is kept: one space of indent, no
// escape a reader would have to undo, and no newline at the end.
func (f *RequestsFixture) Write(path string) error { return writeJSON(path, f) }

func writeJSON(path string, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("harness: %w", err)
	}
	return os.WriteFile(path, bytes.TrimSuffix(buf.Bytes(), []byte("\n")), 0o644)
}

// Measure is what b asks of a server for each scenario of the catalogue named
// in only, or every one, over HTTP/2 and over HTTP/1.1 alone: what the
// fixture holds for them. It says each scenario it ran to progress, when there
// is one.
func Measure(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]MeasuredScenario, error) {
	return measure(ctx, b, catalogue, only, measured, progress)
}

func measure(ctx context.Context, b Browser, scenarios map[string]scenario, only []string, t timing,
	progress io.Writer) (map[string]MeasuredScenario, error) {
	ids, err := selected(scenarios, only)
	if err != nil {
		return nil, err
	}
	s, err := startServer(scenarios)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if progress == nil {
		progress = io.Discard
	}
	out := map[string]MeasuredScenario{}
	// loaded says the browser has asked for something in a scenario of this
	// measurement: it loads pages.
	loaded := false
	for _, proto := range []string{"h2", "h1"} {
		port := map[string]int{"h2": s.H2, "h1": s.H1}[proto]
		o := origins(port, s.Plain)
		for _, id := range ids {
			sc, browser := scenarios[id], b
			if trusts, ok := b.(trusting); ok && sc.connections {
				browser = trusts.trusting(s.spki)
			}
			entries, err := s.run(ctx, browser, id, sc, o, t, progress)
			var short *unfinished
			if errors.As(err, &short) && len(entries) == 0 && loaded {
				// Nothing asked, where the browser has loaded other pages: a
				// browser slow to start, or what it does here. Once more.
				entries, err = s.run(ctx, browser, id, sc, o, t, progress)
			}
			// A scenario the browser began and did not finish is what the
			// browser did, there, and so is one it asked nothing of, twice,
			// once it has loaded others: one it never began, before it loaded
			// any, measures nothing.
			began := errors.As(err, &short) && (len(entries) > 0 || loaded)
			if err != nil && !began {
				return nil, fmt.Errorf("harness: %s over %s: %w", id, proto, err)
			}
			loaded = loaded || len(entries) > 0
			got := out[id]
			got.Note = sc.note
			if began {
				got.Unfinished = append(got.Unfinished, "over "+proto+": "+err.Error())
			}
			requests := s.kept(entries, sc.connections)
			if proto == "h2" {
				got.H2 = requests
			} else {
				got.H1 = requests
			}
			out[id] = got
			ended := ""
			if began {
				ended = ", " + err.Error()
			}
			_, _ = fmt.Fprintf(progress, "%s %s: %d requests%s\n", proto, id, len(requests), ended)
		}
	}
	return out, nil
}

// selected are the names of the scenarios named in only, or of every one,
// sorted; a name of none is refused.
func selected(scenarios map[string]scenario, only []string) ([]string, error) {
	for _, id := range only {
		if _, ok := scenarios[id]; !ok {
			return nil, fmt.Errorf("harness: there is no scenario %s", id)
		}
	}
	if len(only) > 0 {
		return slices.Sorted(slices.Values(only)), nil
	}
	return slices.Sorted(maps.Keys(scenarios)), nil
}

// reloadRuns is how often a scenario is run, at most, before its first page
// comes as no reload (reloaded).
const reloadRuns = 3

// run runs one scenario in a profile of its own, and is what was asked of the
// server while it did. A run whose first page came as a reload is run again,
// said to said, reloadRuns times at most: the browser's start broke the
// navigation the scenario begins with, and its error page loaded it again, so
// the run measures the start, not the scenario. One that came so every time
// did not finish as planned.
func (s *Server) run(ctx context.Context, b Browser, id string, sc scenario, o map[string]string, t timing,
	said io.Writer) ([]Entry, error) {
	p := sc.planned(id, o)
	for runs := 1; ; runs++ {
		// Only a run that did not finish comes with an error and requests:
		// any other trouble holds none, so no reload.
		entries, err := s.runOnce(ctx, b, p, t)
		page, again := reloaded(entries, p, id)
		switch {
		case !again:
			return entries, err
		case runs == reloadRuns:
			return entries, &unfinished{fmt.Sprintf("%s came as a reload in each of %d runs", page, reloadRuns)}
		}
		_, _ = fmt.Fprintf(said, "%s: %s came as a reload, run again\n", id, page)
	}
}

// reloaded is the path of the page a scenario begins with, its start or its
// run page, when the browser asked for it with a Cache-Control: a page a
// browser opens, typed or from another, carries none, and a reload does, as
// Chrome's error page asks again for a navigation that failed. Chrome's start
// closes its connections when its certificate verifier is told of the
// system's store ("Cert verifier changed"), which on a hosted runner's Linux
// came while it asked for the first page (2026-10-20: Beta 157 in 7 scenarios
// a run). No fixture holds such a request (a form's POST and the GET of its
// redirect carry one of their own), not even the reload Chrome's error page
// makes after a scenario has ended, too many redirects or answers on: a run
// ends before it.
func reloaded(entries []Entry, p plan, id string) (string, bool) {
	pages := []string{pathOf(p.start), "/run/" + id}
	for _, e := range entries {
		path := pathOf(e.Target)
		if e.Method == http.MethodGet && slices.Contains(pages, path) &&
			slices.ContainsFunc(e.Headers, func(h [2]string) bool { return strings.EqualFold(h[0], "cache-control") }) {
			return path, true
		}
	}
	return "", false
}

// runOnce runs a scenario as p plans it once, in a profile of its own.
func (s *Server) runOnce(ctx context.Context, b Browser, p plan, t timing) ([]Entry, error) {
	dir, err := os.MkdirTemp("", "tls-forge-harness-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if p.pre != "" {
		// A first visit, for what the browser keeps of it: left open long
		// enough to write it down, as Chrome does only every 30 s.
		s.Reset()
		stop, err := b.Open(ctx, p.pre, dir)
		if err != nil {
			return nil, err
		}
		visited := s.until(ctx, pathOf(p.pre), 1, 0, t)
		if visited {
			visited = sleep(ctx, t.persist)
		}
		stop()
		if !visited {
			return nil, fmt.Errorf("the first visit, %s, was not made: %v", p.pre, ctx.Err())
		}
	}
	s.Reset()
	stop, err := b.Open(ctx, p.start, dir)
	if err != nil {
		return nil, err
	}
	// A settled scenario observes the page's behavior for a fixed interval.
	// Process startup must not consume that interval or make no page look
	// like a successfully observed scenario that sent no requests.
	wait, finished := p.wait, true
	if p.settle > 0 {
		startup := t
		startup.after = 0
		wait = pathOf(p.start)
		finished = s.until(ctx, wait, 1, 0, startup)
	}
	if finished {
		wait = p.wait
		finished = s.until(ctx, wait, p.times, p.settle, t)
	}
	stop()
	entries, trouble := s.Requests()
	switch {
	case trouble != nil:
		return nil, trouble
	case !finished && ctx.Err() != nil:
		return nil, fmt.Errorf("%s was not asked for: %w", wait, ctx.Err())
	case !finished:
		return entries, &unfinished{fmt.Sprintf("%s was not asked for within %s", wait, t.limit)}
	}
	return entries, nil
}

// unfinished is a scenario the browser did not run as planned, the context
// still going: the page it ends at not asked for in time, or the page it
// begins with a reload every time; it says which.
type unfinished struct{ why string }

func (u *unfinished) Error() string { return u.why }

// sleep waits d, and says whether ctx let it.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// until waits for the page at path to be asked for times times, then a
// little longer for what follows, and says whether it was; a scenario that
// settles is waited for that long instead.
func (s *Server) until(ctx context.Context, path string, times int, settle time.Duration, t timing) bool {
	if settle > 0 {
		return sleep(ctx, settle)
	}
	for deadline := time.Now().Add(t.limit); time.Now().Before(deadline); {
		entries, _ := s.Requests()
		asked := 0
		for _, e := range entries {
			if pathOf(e.Target) == path {
				asked++
			}
		}
		if asked >= times {
			return sleep(ctx, t.after)
		}
		if !sleep(ctx, t.poll) {
			return false
		}
	}
	return false
}

// pathOf is the path of a URL, or nothing of one that is none.
func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

// port is a port in a URL or a value.
var port = regexp.MustCompile(`:([0-9]+)`)

// bare is text without any port of the server's: they change every run.
func (s *Server) bare(text string) string {
	ours := map[string]bool{strconv.Itoa(s.H2): true, strconv.Itoa(s.H1): true, strconv.Itoa(s.Plain): true}
	for _, settled := range s.Settled {
		ours[strconv.Itoa(settled)] = true
	}
	for _, alps := range s.ALPS {
		ours[strconv.Itoa(alps)] = true
	}
	return port.ReplaceAllStringFunc(text, func(found string) string {
		if ours[found[1:]] {
			return ""
		}
		return found
	})
}

// kept are the requests of a scenario as the fixture keeps them: the run page
// and whatever came before it left out, since they set the scene, and so is
// the run page saying it is done, and any favicon; no port of the server's is
// in a URL or a value. A scenario of connections keeps its run page, the page
// whose connections it measures, and says which connection each request came
// on and whether that one resumed a TLS session.
func (s *Server) kept(entries []Entry, connections bool) []Request {
	if run := slices.IndexFunc(entries, func(e Entry) bool { return strings.HasPrefix(pathOf(e.Target), "/run/") }); run >= 0 {
		if !connections {
			run++
		}
		entries = entries[run:]
	}
	out := []Request{}
	numbered := map[int]int{}
	for _, e := range entries {
		if path := pathOf(e.Target); strings.HasPrefix(path, "/done/") || path == "/favicon.ico" {
			continue
		}
		r := Request{Method: e.Method, URL: s.bare(e.Target), Body: e.Body}
		if connections {
			if numbered[e.Conn] == 0 {
				numbered[e.Conn] = len(numbered) + 1
			}
			r.Conn, r.Resumed = numbered[e.Conn], e.Resumed
		}
		for _, h := range e.Headers {
			r.Headers = append(r.Headers, [2]string{h[0], s.bare(h[1])})
		}
		if e.Priority != nil {
			r.Priority = e.Priority[:]
		}
		out = append(out, r)
	}
	return out
}
