package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RequestsFixture is what testdata/chrome155-requests.json holds: what a
// browser asked for in each scenario.
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
}

// Request is a request as the fixture keeps it: no port in its URL or in any
// of its values, since they change every run.
type Request struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers [][2]string `json:"headers"`
	// Priority is an HTTP/2 HEADERS frame's: exclusive, the stream it depends
	// on, the weight as on the wire.
	Priority []uint32 `json:"priority,omitempty"`
	Body     string   `json:"body,omitempty"`
}

// LoadRequests reads a fixture of requests.
func LoadRequests(path string) (*RequestsFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f RequestsFixture
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
	for _, id := range only {
		if _, ok := scenarios[id]; !ok {
			return nil, fmt.Errorf("harness: there is no scenario %s", id)
		}
	}
	ids := slices.Sorted(maps.Keys(scenarios))
	if len(only) > 0 {
		ids = slices.Sorted(slices.Values(only))
	}
	s, err := startServer(scenarios)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	out := map[string]MeasuredScenario{}
	for _, proto := range []string{"h2", "h1"} {
		port := map[string]int{"h2": s.H2, "h1": s.H1}[proto]
		o := origins(port, s.Plain)
		for _, id := range ids {
			entries, err := s.run(ctx, b, id, scenarios[id], o, t)
			if err != nil {
				return nil, fmt.Errorf("harness: %s over %s: %w", id, proto, err)
			}
			got := out[id]
			got.Note = scenarios[id].note
			requests := s.kept(entries)
			if proto == "h2" {
				got.H2 = requests
			} else {
				got.H1 = requests
			}
			out[id] = got
			if progress != nil {
				_, _ = fmt.Fprintf(progress, "%s %s: %d requests\n", proto, id, len(requests))
			}
		}
	}
	return out, nil
}

// run runs one scenario in a profile of its own, and is what was asked of the
// server while it did.
func (s *Server) run(ctx context.Context, b Browser, id string, sc scenario, o map[string]string, t timing) ([]Entry, error) {
	p := sc.planned(id, o)
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
		visited := s.until(ctx, pathOf(p.pre), 0, t)
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
	finished := s.until(ctx, p.wait, p.settle, t)
	stop()
	entries, trouble := s.Requests()
	if trouble != nil {
		return nil, trouble
	}
	if !finished {
		return nil, fmt.Errorf("%s was not asked for within %s: %v", p.wait, t.limit, ctx.Err())
	}
	return entries, nil
}

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

// until waits for the page at path to be asked for, then a little longer for
// what follows it, and says whether it was; a scenario that settles is
// waited for that long instead.
func (s *Server) until(ctx context.Context, path string, settle time.Duration, t timing) bool {
	if settle > 0 {
		return sleep(ctx, settle)
	}
	for deadline := time.Now().Add(t.limit); time.Now().Before(deadline); {
		entries, _ := s.Requests()
		if slices.ContainsFunc(entries, func(e Entry) bool { return pathOf(e.Target) == path }) {
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

// kept are the requests of a scenario as the fixture keeps them: the run page
// and whatever came before it left out, since they set the scene, and so is
// the run page saying it is done, and any favicon; no port of the server's is
// in a URL or a value.
func (s *Server) kept(entries []Entry) []Request {
	ours := map[string]bool{strconv.Itoa(s.H2): true, strconv.Itoa(s.H1): true, strconv.Itoa(s.Plain): true}
	bare := func(text string) string {
		return port.ReplaceAllStringFunc(text, func(found string) string {
			if ours[found[1:]] {
				return ""
			}
			return found
		})
	}
	if run := slices.IndexFunc(entries, func(e Entry) bool { return strings.HasPrefix(pathOf(e.Target), "/run/") }); run >= 0 {
		entries = entries[run+1:]
	}
	out := []Request{}
	for _, e := range entries {
		if path := pathOf(e.Target); strings.HasPrefix(path, "/done/") || path == "/favicon.ico" {
			continue
		}
		r := Request{Method: e.Method, URL: bare(e.Target), Body: e.Body}
		for _, h := range e.Headers {
			r.Headers = append(r.Headers, [2]string{h[0], bare(h[1])})
		}
		if e.Priority != nil {
			r.Priority = e.Priority[:]
		}
		out = append(out, r)
	}
	return out
}
