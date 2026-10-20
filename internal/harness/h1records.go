package harness

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// RecordsFixture is what testdata/chrome155-records.json holds: how a
// browser's TLS records carried the requests of each scenario over HTTP/1.1.
type RecordsFixture struct {
	// Browser says which browser was measured, how it was run and where.
	Browser string `json:"browser"`
	// Measured are the dates it was, and How says how.
	Measured  string                     `json:"measured"`
	How       string                     `json:"how"`
	Scenarios map[string]RecordsScenario `json:"scenarios"`
}

// RecordsScenario is how a browser's TLS records carried the requests of a
// scenario over HTTP/1.1, in the order they were asked.
type RecordsScenario struct {
	Note     string            `json:"note"`
	Requests []RecordedRequest `json:"requests"`
}

// RecordedRequest is a request as TLS records carried it: its method, its URL
// with no port, the length of its body, and how the records carried its head
// and its body (Entry.Records).
type RecordedRequest struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Body    int      `json:"body,omitempty"`
	Records []string `json:"records"`
}

// LoadRecords reads a fixture of records.
func LoadRecords(path string) (*RecordsFixture, error) { return load[RecordsFixture](path) }

// Write writes the fixture to path as it is kept, as the fixture of requests
// is.
func (f *RecordsFixture) Write(path string) error { return writeJSON(path, f) }

// recordsCatalogue is every scenario the TLS records of requests over
// HTTP/1.1 were measured in, by its name in the fixture: a page over
// HTTP/1.1 alone, and what its script asked for, each page naming an icon of
// its own (quiet). URLs are as in catalogue.
var recordsCatalogue = map[string]scenario{
	"h1-records-header": {note: "a page, then fetch() of its origin with an X-Foo of 8,000 letters, a head of about 9 KB",
		script: "fetch('{A}/p/h1-records-header',{headers:{'X-Foo':'a'.repeat(8000)}}).then(done);", quiet: true},
	"h1-records-big-header": {note: "a page, then fetch() of its origin with an X-Foo of 30,000 letters, a head of more than a record",
		script: "fetch('{A}/p/h1-records-big-header',{headers:{'X-Foo':'a'.repeat(30000)}}).then(done);", quiet: true},
	"h1-records-bigger-header": {note: "a page, then fetch() of its origin with an X-Foo of 60,000 letters, a head of four records",
		script: "fetch('{A}/p/h1-records-bigger-header',{headers:{'X-Foo':'a'.repeat(60000)}}).then(done);", quiet: true},
	"h1-records-long-url": {note: "a page, then fetch() of a URL of its origin whose query is 8,000 letters",
		script: "fetch('{A}/p/h1-records-long-url?'+'a'.repeat(8000)).then(done);", quiet: true},
	"h1-records-cookie-2k": {note: "a page whose answer set a cookie of 2,048 bytes with its name, then fetch() of its origin, which carries it",
		start: "{A}/run/{ID}?big=2044", script: "fetch('{A}/p/h1-records-cookie-2k').then(done);", quiet: true},
	"h1-records-cookie-4k": {note: "a page whose answer set a cookie of 4,096 bytes with its name, then fetch() of its origin, which carries it",
		start: "{A}/run/{ID}?big=4092", script: "fetch('{A}/p/h1-records-cookie-4k').then(done);", quiet: true},
	"h1-records-cookie-16k": {note: "a page whose answer set four cookies of 4,096 bytes with their names, 16 KiB, then fetch() of its origin, which carries them",
		start: "{A}/run/{ID}?big=4091&bigs=4", script: "fetch('{A}/p/h1-records-cookie-16k').then(done);", quiet: true},
	"h1-records-post-100": {note: "a page, then fetch() POST of 100 letters to its origin",
		script: "fetch('{A}/p/h1-records-post-100',{method:'POST',body:'a'.repeat(100)}).then(done);", quiet: true},
	"h1-records-post-1k": {note: "a page, then fetch() POST of 1,000 letters to its origin",
		script: "fetch('{A}/p/h1-records-post-1k',{method:'POST',body:'a'.repeat(1000)}).then(done);", quiet: true},
	"h1-records-post-at-1400": {note: "a page, then fetch() POST of 705 letters to its origin, its head and body 1,400 bytes",
		script: "fetch('{A}/p/h1-records-post-at-1400',{method:'POST',body:'a'.repeat(705)}).then(done);", quiet: true},
	"h1-records-post-at-1401": {note: "a page, then fetch() POST of 706 letters to its origin, its head and body 1,401 bytes",
		script: "fetch('{A}/p/h1-records-post-at-1401',{method:'POST',body:'a'.repeat(706)}).then(done);", quiet: true},
	"h1-records-post-16k": {note: "a page, then fetch() POST of 16,385 letters to its origin, a record's 16,384 and one more",
		script: "fetch('{A}/p/h1-records-post-16k',{method:'POST',body:'a'.repeat(16385)}).then(done);", quiet: true},
	"h1-records-post-64k": {note: "a page, then fetch() POST of 65,536 letters to its origin",
		script: "fetch('{A}/p/h1-records-post-64k',{method:'POST',body:'a'.repeat(65536)}).then(done);", quiet: true},
	"h1-records-form": {note: "a form posted to the same origin, a body of 9 bytes",
		html: formHTML("post", "{A}/p/h1-records-form?quiet", ""), script: submit, wait: "/p/h1-records-form", quiet: true},
}

// StartRecordsServer starts the bench's server for the records catalogue: the
// one its scenarios were measured on, for a client to be held to them.
func StartRecordsServer() (*Server, error) { return startServer(recordsCatalogue) }

// MeasureRecords is how b's TLS records carry the requests of each scenario of
// the records catalogue named in only, or of every one, over HTTP/1.1: what
// the fixture holds for them. It says each scenario it ran to progress, when
// there is one.
func MeasureRecords(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]RecordsScenario, error) {
	return measureRecords(ctx, b, recordsCatalogue, only, measured, progress)
}

func measureRecords(ctx context.Context, b Browser, scenarios map[string]scenario, only []string, t timing,
	progress io.Writer) (map[string]RecordsScenario, error) {
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
	out := map[string]RecordsScenario{}
	for _, id := range ids {
		sc := scenarios[id]
		entries, err := s.run(ctx, b, id, sc, origins(s.H1, s.Plain), t)
		if err != nil {
			return nil, fmt.Errorf("harness: %s over http/1.1: %w", id, err)
		}
		recorded := s.Recorded(entries)
		out[id] = RecordsScenario{Note: sc.note, Requests: recorded}
		_, _ = fmt.Fprintf(progress, "h1 %s: %d requests\n", id, len(recorded))
	}
	return out, nil
}

// Recorded is how TLS records carried the HTTP/1.1 requests of entries that
// came over TLS, in the order asked; no port of the server's is in a URL.
func (s *Server) Recorded(entries []Entry) []RecordedRequest {
	out := []RecordedRequest{}
	for _, e := range entries {
		if e.Proto != "http/1.1" || !strings.HasPrefix(e.Target, "https://") {
			continue
		}
		out = append(out, RecordedRequest{Method: e.Method, URL: s.bare(e.Target), Body: len(e.Body), Records: e.Records})
	}
	return out
}

// DiffRecords is how the records of got carried its requests otherwise than
// want's: a line for each difference, none when they carried them alike.
func DiffRecords(want, got RecordsScenario) []string {
	if len(got.Requests) != len(want.Requests) {
		return []string{fmt.Sprintf("%d requests, want %d", len(got.Requests), len(want.Requests))}
	}
	var out []string
	for i, w := range want.Requests {
		g := got.Requests[i]
		switch {
		case g.Method != w.Method || g.URL != w.URL:
			out = append(out, fmt.Sprintf("request %d: %s %s, want %s %s", i+1, g.Method, g.URL, w.Method, w.URL))
		case g.Body != w.Body || !slices.Equal(g.Records, w.Records):
			out = append(out, fmt.Sprintf("request %d, %s %s: a body of %d in records %v, want %d in %v", i+1,
				w.Method, w.URL, g.Body, g.Records, w.Body, w.Records))
		}
	}
	return out
}

// CompareRecordsNewer is CompareRecords for a newer build of the browser,
// whose heads may be longer or shorter than the fixture's by what its version
// writes in each of them (sec-ch-ua's GREASE brand says a version of one digit
// or two) and its platform (the user agent, sec-ch-ua-platform): a scenario's
// heads are held to the fixture's as much longer as its first request's head
// is, and a head and a body held in memory to one write or two as Chrome's rule
// says for their lengths (mergedHeadAndBody): on Linux a POST whose head and
// body are 1,401 bytes on macOS went in one.
func CompareRecordsNewer(want, got map[string]RecordsScenario) []string {
	shifted := map[string]RecordsScenario{}
	for id, w := range want {
		if g, ok := got[id]; ok && len(g.Requests) > 0 && len(w.Requests) > 0 {
			w = shiftedHeads(w, headLength(g.Requests[0].Records)-headLength(w.Requests[0].Records))
		}
		shifted[id] = w
	}
	return CompareRecords(shifted, got)
}

// headLength is how many bytes of a request's head its records carried: the
// sum of their R and r parts.
func headLength(records []string) int {
	n := 0
	for _, record := range records {
		for _, part := range strings.Split(record, "+") {
			if size, ok := headPart(part); ok {
				n += size
			}
		}
	}
	return n
}

// headPart is how many bytes of a head a part of a record carried, R or r,
// and whether it carried any.
func headPart(part string) (int, bool) {
	if !strings.HasPrefix(part, "R") && !strings.HasPrefix(part, "r") {
		return 0, false
	}
	size, err := strconv.Atoi(part[1:])
	return size, err == nil
}

// shiftedHeads is scenario with each request's head delta bytes longer: the
// last part of its records that carried the head, the part a longer head
// grows; and a head and a body together or apart as Chrome's rule says for
// their lengths, as they are in a fixture Chrome wrote.
func shiftedHeads(scenario RecordsScenario, delta int) RecordsScenario {
	out := RecordsScenario{Note: scenario.Note}
	for _, r := range scenario.Requests {
		records := slices.Clone(r.Records)
	last:
		for i := len(records) - 1; i >= 0; i-- {
			parts := strings.Split(records[i], "+")
			for j := len(parts) - 1; j >= 0; j-- {
				if size, ok := headPart(parts[j]); ok {
					parts[j] = parts[j][:1] + strconv.Itoa(size+delta)
					records[i] = strings.Join(parts, "+")
					break last
				}
			}
		}
		r.Records = merged(records)
		out.Requests = append(out.Requests, r)
	}
	return out
}

// mergedHeadAndBody is the most a request's head and a body held in memory
// may be together for Chrome to write them at once: HttpStreamParser's
// kMaxMergedHeaderAndBodySize (h1-records-post-at-1400 and -1401).
const mergedHeadAndBody = 1400

// merged are records of a whole head and a body, in one record or two, as
// Chrome writes them for their lengths; any others as they are.
func merged(records []string) []string {
	var head, body string
	switch len(records) {
	case 1:
		head, body, _ = strings.Cut(records[0], "+")
	case 2:
		head, body = records[0], records[1]
	default:
		return records
	}
	h, errHead := strconv.Atoi(strings.TrimPrefix(head, "R"))
	b, errBody := strconv.Atoi(strings.TrimPrefix(body, "B"))
	switch {
	case errHead != nil || errBody != nil:
		return records
	case h+b <= mergedHeadAndBody:
		return []string{head + "+" + body}
	}
	return []string{head, body}
}

// CompareRecords is how what a browser's records carried, got, differs from
// what the fixture holds, want, as CompareHPACK says it: a scenario not
// measured, one the fixture has not, and every difference DiffRecords finds in
// the others, after the scenario's name. Nothing when they are the same.
func CompareRecords(want, got map[string]RecordsScenario) []string {
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(want)) {
		measured, ok := got[id]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s was not measured", id))
			continue
		}
		for _, d := range DiffRecords(want[id], measured) {
			diff = append(diff, id+": "+d)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[id]; !ok {
			diff = append(diff, fmt.Sprintf("%s was measured, and the fixture has no such scenario", id))
		}
	}
	return diff
}
