package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// What a run turned out to be.
//
// Two shapes of the same facts: a table on the terminal for the question "did
// that go well", and an HTML file for "what happened to this URL".

// proxyStat is one proxy's showing.
//
// Alive means at least one URL came back through it. That is the useful
// reading: a proxy every request failed through is the reason those URLs are
// missing, and it should not take the blame for a site being down either, which
// is why the count of what went through it is here too.
type proxyStat struct {
	Proxy     string
	Requests  int
	Succeeded int
	Exit      egress
}

func (p proxyStat) Alive() bool { return p.Succeeded > 0 }

// summary is the whole run in numbers.
// Three outcomes, not two. A 503 is neither a page nor a dead connection:
// something came back and it was not what was asked for. Counting it as a
// success answers "did the transport work" when the question was "did I get the
// page".
type summary struct {
	Total     int
	Succeeded int
	Warned    int
	Failed    int
	Bytes     int64
	Retries   int
	Elapsed   time.Duration
	// Spent is how long the requests took between them, which is not Elapsed:
	// several are out at once.
	Spent   time.Duration
	Proxies []proxyStat
	Direct  bool
	Output  string
	// Unprinted says the JSON lines went nowhere: standard output was a
	// terminal, and nobody asked for them there or named a file.
	Unprinted bool
	// Passes is how many times the list was gone through. Each pass is counted
	// in Total, so this is what turns that number back into a list.
	Passes int
}

// things is what Total counts: URLs when the list was gone through once, and
// requests when it was not, because then a URL is no longer one line.
func (s summary) things() string {
	if s.Passes > 1 {
		return "requests"
	}
	return "URLs"
}

// Failed means nothing came back at all; Warned that something did and it was
// not a 2xx. On the record rather than on the row that displays it, so the
// summary and the table cannot come to different conclusions about a 503.
func (r result) Failed() bool { return r.Error != "" }

func (r result) Warned() bool {
	return r.Error == "" && (r.Status < 200 || r.Status > 299)
}

func summarise(records []result, elapsed time.Duration, exits map[string]egress) summary {
	s := summary{Total: len(records), Elapsed: elapsed}
	byProxy := map[string]*proxyStat{}

	for _, r := range records {
		switch {
		case r.Failed():
			s.Failed++
		case r.Warned():
			s.Warned++
		default:
			s.Succeeded++
		}
		s.Bytes += int64(r.Bytes)
		// One attempt is the request; the rest are the retries.
		if r.Attempts > 1 {
			s.Retries += r.Attempts - 1
		}
		s.Spent += time.Duration(r.Millis) * time.Millisecond
		if r.Proxy == "" {
			s.Direct = true
			continue
		}
		stat, seen := byProxy[r.Proxy]
		if !seen {
			// Filed under the URL as given, shown without its password.
			stat = &proxyStat{Proxy: redactProxy(r.Proxy), Exit: exits[r.Proxy]}
			byProxy[r.Proxy] = stat
		}
		stat.Requests++
		if r.Error == "" {
			stat.Succeeded++
		}
	}

	for _, stat := range byProxy {
		s.Proxies = append(s.Proxies, *stat)
	}
	// Dead ones first: they are the reason someone is reading this.
	sort.Slice(s.Proxies, func(i, j int) bool {
		if s.Proxies[i].Alive() != s.Proxies[j].Alive() {
			return !s.Proxies[i].Alive()
		}
		return s.Proxies[i].Proxy < s.Proxies[j].Proxy
	})
	return s
}

// The three outcomes as percentages of the whole list.
func (s summary) SuccessRate() string { return percent(s.Succeeded, s.Total) }
func (s summary) WarnRate() string    { return percent(s.Warned, s.Total) }
func (s summary) FailRate() string    { return percent(s.Failed, s.Total) }

// The widths of the meter's three segments.
func (s summary) SuccessWidth() string { return width(s.Succeeded, s.Total) }
func (s summary) WarnWidth() string    { return width(s.Warned, s.Total) }

func width(part, total int) string {
	if total == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.4f%%", float64(part)*100/float64(total))
}

// Took is the run's length.
func (s summary) Took() string { return preciseDuration(s.Elapsed) }

// Average is how long one request took, from when it went out to its last
// answer: a URL that was tried again counts the tries and the waits between
// them.
func (s summary) Average() time.Duration { return s.Spent / time.Duration(max(s.Total, 1)) }

// AliveProxies is how many of the proxies used carried at least one page.
func (s summary) AliveProxies() int {
	alive := 0
	for _, p := range s.Proxies {
		if p.Alive() {
			alive++
		}
	}
	return alive
}

// percent of the total, as a string, with the zero total handled: a run of
// nothing is 0%, not a division by zero.
func percent(part, total int) string {
	if total == 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(part)*100/float64(total))
}

// ran is the first line of the table: how much was asked for and how long it
// took.
func (s summary) ran() string {
	if s.Passes > 1 {
		return fmt.Sprintf("%d requests (%d passes over %d URLs) in %s",
			s.Total, s.Passes, s.Total/s.Passes, preciseDuration(s.Elapsed))
	}
	return fmt.Sprintf("%d URLs in %s", s.Total, preciseDuration(s.Elapsed))
}

// table is the run as a block of aligned lines.
func (s summary) table() string {
	rows := [][2]string{
		{"Ran", s.ran()},
		{"Scraped", fmt.Sprintf("%d  (%s)", s.Succeeded, percent(s.Succeeded, s.Total))},
		{"Not 2xx", fmt.Sprintf("%d  (%s)", s.Warned, percent(s.Warned, s.Total))},
		{"No response", fmt.Sprintf("%d  (%s)", s.Failed, percent(s.Failed, s.Total))},
		{"Data", humanBytes(s.Bytes)},
		{"Retries", fmt.Sprintf("%d", s.Retries)},
		{"Avg time", preciseDuration(s.Average())},
	}
	if len(s.Proxies) > 0 {
		used := fmt.Sprintf("%d used, %d alive", len(s.Proxies), s.AliveProxies())
		if s.Direct {
			used += ", some direct"
		}
		rows = append(rows, [2]string{"Proxies", used})
	}
	if s.Output != "" {
		rows = append(rows, [2]string{"Written to", s.Output})
	}
	if s.Unprinted {
		// Said, because a run that fetched a list and kept none of it looks, from
		// the outside, exactly like one that kept it somewhere.
		rows = append(rows, [2]string{"JSON lines",
			"not printed on a terminal; -o FILE keeps them, --body shows them"})
	}

	// Named, not just counted: "6 of 8 alive" does not say which two to replace.
	for _, p := range s.Proxies {
		if p.Alive() {
			continue
		}
		rows = append(rows, [2]string{"dead proxy",
			fmt.Sprintf("%s  (%d requests, none came back)", p.Proxy, p.Requests)})
	}
	return aligned(rows)
}

// reportRow is one URL as the HTML report shows it.
type reportRow struct {
	result
	// Proxy shadows the embedded result's field so the template renders the
	// URL without its password. The embedded one stays as given, because it is
	// what the exit-address lookup is keyed by.
	Proxy string
	Exit  egress
}

// Duration is how long this URL took, including any retries.
func (r reportRow) Duration() string {
	return preciseDuration(time.Duration(r.Millis) * time.Millisecond)
}

// Outcome and Glyph are how a row shows the state Failed and Warned decide.
//
// Three states rather than two, because a 503 is neither: something came back,
// and it was not the page. Colour never carries this alone; the glyph and the
// word go with it everywhere it is shown.
func (r reportRow) Outcome() string {
	if r.Failed() {
		return "no response"
	}
	return fmt.Sprintf("%d", r.Status)
}

func (r reportRow) Glyph() string {
	switch {
	case r.Failed():
		return "✕"
	case r.Warned():
		return "!"
	default:
		return "✓"
	}
}

// Size is the body volume, decompressed.
func (r reportRow) Size() string { return humanBytes(int64(r.Bytes)) }

// Timestamps formatted for reading rather than for parsing. The JSON lines
// carry the machine-readable form, so nothing here has to stay sortable.
func at(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	// The month named rather than numbered: 08-09 is the ninth of August to half
	// the world and the eighth of September to the other half, and a report is
	// read by whoever is handed it. Shortened, because it is repeated on every
	// row and the column is wide enough already.
	return t.Format("02 Jan 2006 15:04:05")
}

func (r reportRow) StartedAt() string { return at(r.Started) }
func (r reportRow) EndedAt() string   { return at(r.Ended) }

// reportRowLimit bounds the table of URLs.
//
// A run of 100,000 measured 140 MB of HTML, which no browser opens comfortably
// and no one reads. The JSON lines carry every row for whatever wants them all,
// so what is dropped here is dropped from a view, not from the data.
//
// A variable rather than a constant so a test can lower it: reaching the limit
// honestly would mean two thousand requests for one assertion.
var reportRowLimit = 2_000

// limitRows keeps the rows worth looking at when there are too many.
//
// Everything that failed or answered with something other than a page comes
// first, because that is what a report is opened for; the rest fills what is
// left. Never silently: the count that went is printed in the document and on
// the terminal.
func limitRows(records []result, limit int) (kept []result, dropped int) {
	if len(records) <= limit {
		return records, 0
	}
	var trouble, fine []result
	for _, r := range records {
		if r.Failed() || r.Warned() {
			trouble = append(trouble, r)
		} else {
			fine = append(fine, r)
		}
	}
	kept = trouble
	if len(kept) > limit {
		kept = kept[:limit]
	}
	for _, r := range fine {
		if len(kept) >= limit {
			break
		}
		kept = append(kept, r)
	}
	return kept, len(records) - len(kept)
}

type reportData struct {
	Generated string
	Dropped   int
	Summary   summary
	Rows      []reportRow
	Cards     []card
	Service   string
	CSS       template.CSS
}

// card is one figure in the row above the tables.
type card struct {
	Label string
	Value string
	Note  string
}

func cards(s summary) []card {
	list := []card{
		{Label: "URLs", Value: fmt.Sprintf("%d", s.Total)},
		{Label: "Data", Value: humanBytes(s.Bytes), Note: "decompressed"},
		{Label: "Retries", Value: fmt.Sprintf("%d", s.Retries)},
		{Label: "Elapsed", Value: preciseDuration(s.Elapsed)},
	}
	if len(s.Proxies) > 0 {
		note := "all carried a page"
		if dead := len(s.Proxies) - s.AliveProxies(); dead > 0 {
			note = fmt.Sprintf("%d carried nothing", dead)
		}
		list = append(list, card{
			Label: "Proxies alive",
			Value: fmt.Sprintf("%d/%d", s.AliveProxies(), len(s.Proxies)),
			Note:  note,
		})
	}
	return list
}

//go:embed report.html
var reportMarkup string

// reportCSS is generated from report.html by `make report-css` and committed,
// so the report stays one self-contained file and `go build` needs nothing but
// Go. TestReportStylesheetCoversTheTemplate fails if the two drift apart.
//
//go:embed report.css
var reportCSS string

var reportTemplate = template.Must(template.New("report").Parse(reportMarkup))

// reportPath turns what --report was given into the file to write.
//
// A directory, or a path ending in a separator, gets a name of its own. Naming
// the file by hand is a chore for every run, and forgetting to means the second
// run overwrites the first. The stamp is ordered largest unit first so a
// directory of them sorts into the order they were made, which the named month
// used elsewhere in the report would not.
//
// Both separators are accepted as a directory hint. Go accepts forward slashes
// on Windows too, and that is the spelling the cross-platform README uses.
func reportPath(given string, when time.Time) string {
	directoryHint := strings.HasSuffix(given, "/") || strings.HasSuffix(given, `\`)
	if !directoryHint {
		if info, err := os.Stat(given); err != nil || !info.IsDir() {
			return given
		}
	}
	return filepath.Join(given, "report-"+stamp(when)+".html")
}

// stamp is the time in a report's file name.
//
// Ordered largest unit first, so a directory of reports sorts into the order
// they were made, which the named month used inside the report would not.
// Milliseconds, because a batch can be started twice inside one second.
// Hyphens, rather than clock colons, keep the same spelling portable to Windows
// where a colon denotes an alternate data stream and cannot name a normal file.
func stamp(t time.Time) string {
	return t.Format("2006-01-02-150405") + fmt.Sprintf("-%03d", t.Nanosecond()/int(time.Millisecond))
}

var chmodReport = (*os.File).Chmod

// writeReport renders the run as one self-contained HTML file.
//
// Self-contained on purpose: no stylesheet, no script and no font from
// anywhere else, so it can be opened from a laptop with no network and mailed
// to someone as one attachment.
func writeReport(path string, records []result, s summary, exits map[string]egress) error {
	// The directory is made rather than required. `--report reports/` is what
	// README and example/README both show, and before this it fetched the whole
	// list and then failed at the last step because nothing had created the
	// directory — losing the report and exiting non-zero on a run that worked.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("batch: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("batch: %w", err)
	}
	if err := chmodReport(file, 0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("batch: securing report: %w", err)
	}
	defer func() { _ = file.Close() }()
	return renderReport(file, records, s, exits)
}

// renderReport is the document itself, separate from the file it lands in, so
// what it produces can be checked without one and so the failure to write it
// can be reached at all.
func renderReport(w io.Writer, records []result, s summary, exits map[string]egress) error {
	// Cut down before the display structs are built: a run of a million would
	// otherwise materialise a million of them to show two thousand.
	kept, dropped := limitRows(records, reportRowLimit)
	rows := make([]reportRow, 0, len(kept))
	for _, r := range kept {
		rows = append(rows, reportRow{result: r, Proxy: redactProxy(r.Proxy), Exit: exits[r.Proxy]})
	}
	// By when the request went out, which is the order someone reading a run
	// expects, rather than the order answers happened to come back in.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Started.Before(rows[j].Started) })

	data := reportData{
		Generated: at(now()),
		Dropped:   dropped,
		Summary:   s,
		Rows:      rows,
		Cards:     cards(s),
		Service:   askedOf(),
		// Trusted because it is this repository's own file, compiled in.
		CSS: template.CSS(reportCSS),
	}
	if err := reportTemplate.Execute(w, data); err != nil {
		return fmt.Errorf("batch: writing the report: %w", err)
	}
	return nil
}
