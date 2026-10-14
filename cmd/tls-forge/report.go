package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"
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
	// Exits are the addresses its requests came out of, each once, in the order
	// they were first seen: a proxy that hands every request an address of its
	// own has as many as it carried requests.
	Exits []egress
}

func (p proxyStat) Alive() bool { return p.Succeeded > 0 }

// exitsListed is how many of a proxy's addresses its row lists before it says
// how many more there were. A rotating proxy can have thousands, and the row
// is there to say which proxy it is and how it did.
const exitsListed = 3

// ListedExits are the addresses a proxy's row lists, and MoreExits how many it
// leaves out.
func (p proxyStat) ListedExits() []egress { return p.Exits[:min(len(p.Exits), exitsListed)] }
func (p proxyStat) MoreExits() int        { return max(len(p.Exits)-exitsListed, 0) }

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
	// Passes is how many times the list was gone through. Each pass is counted
	// in Total, so this is what turns that number back into a list.
	Passes int
}

// Things is what Total counts: URLs when the list was gone through once, and
// requests when it was not, because then a URL is no longer one line. Thing is
// one of them.
func (s summary) Things() string { return s.Thing() + "s" }

func (s summary) Thing() string {
	if s.Passes > 1 {
		return "request"
	}
	return "URL"
}

// Failed means nothing came back at all; Warned that something did and it was
// not a 2xx. On the record rather than on the row that displays it, so the
// summary and the table cannot come to different conclusions about a 503.
func (r result) Failed() bool { return r.Error != "" }

func (r result) Warned() bool {
	return r.Error == "" && (r.Status < 200 || r.Status > 299)
}

func summarise(records []result, elapsed time.Duration) summary {
	s := summary{Total: len(records), Elapsed: elapsed}
	byProxy := map[string]*proxyStat{}
	// The addresses each proxy has been seen to come out of, so that one met a
	// thousand times is listed once without a thousand comparisons each time.
	type exitOf struct {
		proxy string
		exit  egress
	}
	seenExits := map[exitOf]bool{}

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
			stat = &proxyStat{Proxy: redactProxy(r.Proxy)}
			byProxy[r.Proxy] = stat
		}
		stat.Requests++
		if r.Error == "" {
			stat.Succeeded++
		}
		if key := (exitOf{r.Proxy, r.Exit}); r.Exit.IP != "" && !seenExits[key] {
			seenExits[key] = true
			stat.Exits = append(stat.Exits, r.Exit)
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

// proxyRows are the proxies a run went through, as rows of the figures it ends
// with: how many, how many of them carried anything, and each one that did not.
// None when the run used no proxy.
func (s summary) proxyRows() [][2]string {
	if len(s.Proxies) == 0 {
		return nil
	}
	used := fmt.Sprintf("%d used, %d alive", len(s.Proxies), s.AliveProxies())
	if s.Direct {
		used += ", some direct"
	}
	rows := [][2]string{{"Proxies", used}}
	// Named, not just counted: "6 of 8 alive" does not say which two to replace.
	for _, p := range s.Proxies {
		if p.Alive() {
			continue
		}
		rows = append(rows, [2]string{"dead proxy",
			fmt.Sprintf("%s  (%d requests, none came back)", p.Proxy, p.Requests)})
	}
	return rows
}

// reportRow is one URL as the HTML report shows it.
type reportRow struct {
	result
	// Proxy shadows the embedded result's field so the template renders the
	// URL without its password. The embedded one stays as given, because it is
	// what the client pool is keyed by.
	Proxy string
	// at is where the report is written, which the files a row names are
	// linked from.
	at string
	// trace is the file the request was traced to: its own, when it was kept,
	// or the trace of the whole run. Perfetto is the request's own trace, to be
	// handed to ui.perfetto.dev, when it was traced at all.
	trace    string
	Perfetto *perfettoTrace
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

// StartedAt is when the request went out, as its row says it: without the
// year, which the top of the report gives and every row would repeat. Opened,
// the row gives the moment in full.
func (r reportRow) StartedAt() string {
	if r.Started.IsZero() {
		return ""
	}
	return r.Started.Format("02 Jan 15:04:05")
}

// atPrecisely is a moment to the millisecond, for the one place a report gives
// it: beside a request that has been opened to see where its time went.
func atPrecisely(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("02 Jan 2006 15:04:05.000")
}

// fact is one line of what a request's row leaves out.
type fact struct {
	Label, Value string
	// Code says the value is to be read letter by letter, as a URL or a path is.
	Code bool
	// Link is where the value is to be opened, when it names a file to open.
	Link template.URL
	// Open is a trace that the line offers to open at ui.perfetto.dev.
	Open *perfettoTrace
}

// Facts are what there is to say about a request beyond its row.
func (r reportRow) Facts() []fact {
	var facts []fact
	// Where it ended up, when that is somewhere other than where it was sent.
	if r.FinalURL != "" && r.FinalURL != r.URL {
		facts = append(facts, fact{Label: "Final URL", Value: r.FinalURL, Code: true})
	}
	// The page is named and not linked: opened in a browser, it would load
	// whatever it loads from the site, from the browser's own address.
	if r.File != "" {
		facts = append(facts, fact{Label: "Saved to", Value: r.File, Code: true})
	}
	if r.Log != "" {
		facts = append(facts, fact{Label: "Log", Value: r.Log, Code: true, Link: linkTo(r.Log, r.at)})
	}
	if r.trace != "" {
		facts = append(facts, fact{Label: "Trace", Value: r.trace, Code: true, Link: linkTo(r.trace, r.at),
			Open: r.Perfetto})
	}
	facts = append(facts,
		fact{Label: "Started", Value: atPrecisely(r.Started)},
		fact{Label: "Ended", Value: atPrecisely(r.Ended)},
	)
	if r.ExitError != "" {
		// Why the row says the address was not looked up.
		facts = append(facts, fact{Label: "Exit address", Value: "not looked up · " + r.ExitError})
	}
	if r.Error != "" {
		// In full, and where it can be selected. On the row it is a tooltip.
		facts = append(facts, fact{Label: "Error", Value: r.Error})
	}
	return facts
}

// linkTo is a file the run kept, as a link from the report written at report.
//
// Relative, so that a directory holding both can be moved or sent on whole. A
// file there is no relative way to, because one path was given in full and the
// other was not, or because they are on two drives, is linked where it is.
func linkTo(file, report string) template.URL {
	if rel, err := filepath.Rel(filepath.Dir(report), file); err == nil {
		// Escaped by the URL rather than the template, which is why it can be
		// trusted with the href: a path is not a URL until it has been.
		return template.URL((&url.URL{Path: filepath.ToSlash(rel)}).String())
	}
	// Abs fails only when the working directory has gone, and then the path as
	// it was given is the best there is.
	full, _ := filepath.Abs(file)
	path := filepath.ToSlash(either(full, file))
	return template.URL((&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(path, "/")}).String())
}

// perfettoTrace is a request's trace as the report hands it to ui.perfetto.dev:
// compressed, as text an attribute can hold, with the title and the file name
// it is opened under.
//
// The viewer makes a space of anything in those two but letters, digits and
// the few marks a URL is made of, so they are written in nothing else.
type perfettoTrace struct {
	Data, Title, Name string
}

// perfettoOf is the trace of a request, drawn from its record as the trace it
// is kept with is, ready to be opened from the report.
//
// In the page rather than fetched when it is wanted, because a page opened from
// a file is allowed to read no other file. Compressed, because a report of two
// thousand rows carries two thousand of them.
func perfettoOf(r result, method string) *perfettoTrace {
	var packed bytes.Buffer
	zipper := gzip.NewWriter(&packed)
	// A buffer takes whatever it is given, so neither of these can fail.
	_, _ = zipper.Write(traceFileOf(requestTrace(r, method)))
	_ = zipper.Close()
	return &perfettoTrace{
		Data:  base64.StdEncoding.EncodeToString(packed.Bytes()),
		Title: fmt.Sprintf("%s %s - request %d", method, safeURL(r.URL), r.ID),
		Name:  "trace-" + requestName(r.URL, r.Started, r.ID) + ".json",
	}
}

// TryRows are the tries the request took, each laid out against how long the
// whole of it lasted. None when they were not kept.
func (r reportRow) TryRows() []tryRow {
	return tryRows(r.Tries, r.Started, r.Ended.Sub(r.Started))
}

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
	// Command is the one that made the run.
	Command   string
	Generated string
	Dropped   int
	Summary   summary
	Rows      []reportRow
	Cards     []card
	Service   string
	CSS       template.CSS
	// Detailed says some row has its tries to show, so the key to how they are
	// drawn is worth printing.
	Detailed bool
	// Route is how the requests went out, said once above the rows as far as
	// they all went the same way. Via says they went through different proxies,
	// and Exited that they came out in different places, so that each row has
	// to say its own.
	Route  *route
	Via    bool
	Exited bool
	// Asked is how where they came out was found out.
	Asked asking
	// Traced says some row has a trace to open, and RunTrace is the trace of
	// the whole run, when there was one.
	Traced   bool
	RunTrace *keptFile
}

// keptFile is a file the run left, by the name it was given and as a link.
type keptFile struct {
	Path string
	Link template.URL
}

// route is how the requests of a run went out: through which proxy, or none,
// and where that came out.
type route struct {
	// Proxy is the one they all went through, when SameProxy says they did.
	Proxy     string
	SameProxy bool
	// Exit is where they all came out, when SameExit says they did. When they
	// did not, Exits is how many addresses they came out of between them, and
	// Unknown how many of the requests were not looked up.
	Exit     egress
	SameExit bool
	Exits    int
	Unknown  int
}

// routes is how the requests of a run went out, or nothing for a run of none.
//
// What every request had in common is said once, above the rows, and leaves
// them the width of a column that would have said the same thing on every
// line. What they did not is that column.
func routes(records []result) *route {
	if len(records) == 0 {
		return nil
	}
	first := records[0]
	way := &route{Proxy: first.Proxy, SameProxy: true, Exit: first.Exit, SameExit: true}
	seen := map[egress]bool{}
	for _, r := range records {
		way.SameProxy = way.SameProxy && r.Proxy == first.Proxy
		way.SameExit = way.SameExit && r.Exit == first.Exit
		switch {
		case r.Exit.IP == "":
			way.Unknown++
		case !seen[r.Exit]:
			seen[r.Exit] = true
			way.Exits++
		}
	}
	way.Proxy = redactProxy(way.Proxy)
	return way
}

// Spread is how many places the requests came out of, when that was more than
// one, as the line above the rows says it.
func (r route) Spread() string {
	said := "one address"
	if r.Exits > 1 {
		said = fmt.Sprintf("%d different addresses", r.Exits)
	}
	if r.Unknown > 0 {
		said += fmt.Sprintf("; where %d of them came out was not looked up", r.Unknown)
	}
	return said
}

// asking is how a run found out where its requests came out.
type asking int

const (
	// askedNobody: a list that went several ways, without a report that asked.
	askedNobody asking = iota
	// askedOnce: a run that went one way, asked before its first request.
	askedOnce
	// askedEach: a report, which asked beside every request.
	askedEach
)

func (a asking) Once() bool { return a == askedOnce }
func (a asking) Each() bool { return a == askedEach }

// Columns are the tracks every row is laid out on, the row of headings
// included: the same for all of them, which is what lines the rows up without
// their being a table.
//
// Lengths this file chose, so they are written into the document as they are.
func (d reportData) Columns() template.CSS {
	tracks := []string{"0.75rem"}
	if d.Numbered() {
		tracks = append(tracks, "2.5rem")
	}
	// The URL takes what the rest leave.
	tracks = append(tracks, "1fr", "7.5rem", "4.5rem", "8rem", "4.5rem", "2.5rem")
	if d.Via {
		tracks = append(tracks, "11rem")
	}
	if d.Exited {
		tracks = append(tracks, "9rem")
	}
	return template.CSS(strings.Join(tracks, " "))
}

// Width is the least the rows are laid out on before they scroll sideways
// instead: enough that the URL keeps a readable share, and no more than the
// page is wide on a desktop.
func (d reportData) Width() template.CSS {
	width := 56
	if d.Via {
		width += 11
	}
	if d.Exited {
		width += 9
	}
	return template.CSS(fmt.Sprintf("%drem", width))
}

// Numbered says the rows are told apart by which run they were, because a URL
// was asked for more than once.
func (d reportData) Numbered() bool { return d.Summary.Passes > 1 }

// card is one figure in the row above the tables.
type card struct {
	Label string
	Value string
	Note  string
}

func cards(s summary) []card {
	things := s.Things()
	list := []card{
		{Label: strings.ToUpper(things[:1]) + things[1:], Value: fmt.Sprintf("%d", s.Total)},
		{Label: "Data", Value: humanBytes(s.Bytes), Note: "decompressed"},
		{Label: "Retries", Value: fmt.Sprintf("%d", s.Retries)},
		{Label: "Elapsed", Value: preciseDuration(s.Elapsed)},
		// Not the one above divided by the count: several requests are out at
		// once, and what one of them took is its own time.
		{Label: "Avg time", Value: preciseDuration(s.Average()), Note: "per request"},
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

// reportFlags are where a run is written down when it is over, and as what.
type reportFlags struct {
	path   *string
	format *string
	// chose reports whether a flag was given rather than defaulted.
	chose func(string) bool
}

// formatHTML is the page a report is written as for whoever opens it, unless
// somebody asks for formatJSON, the same word a list of URLs is read by: the
// same run as a document, for whatever program comes next.
const formatHTML = "html"

// reportWriters is how each of the two is written.
var reportWriters = map[string]func(io.Writer, reportInput) error{
	formatHTML: renderReport,
	formatJSON: renderReportJSON,
}

// reportInput is what a report is written from.
type reportInput struct {
	// command is the one that made the run. It is named in the document, and in
	// front of whatever goes wrong writing it.
	command string
	records []result
	summary summary
	// asked is how where the requests came out was found out.
	asked asking
	// method is what every request asked with, and trace the file the whole run
	// was traced to, if it was.
	method, trace string
	// at is the file being written, which what the report links to is linked
	// from. Set as each file is written.
	at string
}

// reportBeside is what --report is given when it is given no path: the report
// goes into the directory the run keeps its requests in, or into the current
// one when there is none, named after the moment it was written.
const reportBeside = "auto"

func addReportFlags(fs *pflag.FlagSet) reportFlags {
	flags := reportFlags{
		path: fs.StringP("report", "R", "",
			"write a report of the run into --output, or here, as report-<date-time>; --report=PATH says where"),
		format: fs.String("report-format", formatHTML,
			"what to write the report as: html, json, or html,json for both"),
		chose: fs.Changed,
	}
	// A path of its own is optional, so the flag alone is enough to ask for a
	// report. The price is that a path is given as --report=PATH: given after a
	// space, it would be read as the path the flag does not need.
	fs.Lookup("report").NoOptDefVal = reportBeside
	return flags
}

// formats settles what the report is to be written as, and returns none when
// no report was asked for.
//
// Before anything is fetched, so a misspelling costs a message rather than a
// run that turns out to have nowhere to report itself.
func (f reportFlags) formats() ([]string, error) {
	if *f.path == "" {
		if f.chose("report-format") {
			return nil, fmt.Errorf("%w: --report-format requires --report", errUsage)
		}
		return nil, nil
	}
	var chosen []string
	for _, word := range strings.Split(*f.format, ",") {
		word = strings.ToLower(strings.TrimSpace(word))
		if _, known := reportWriters[word]; !known {
			return nil, &badFlag{"--report-format", *f.format, "html, json or html,json"}
		}
		if !slices.Contains(chosen, word) {
			chosen = append(chosen, word)
		}
	}
	return chosen, nil
}

// reportFile is one file a report is written to, and what it is written as.
type reportFile struct {
	format, path string
}

// reportFiles turns what --report was given into the files to write, one for
// each format.
//
// Given no path, the report goes beside what the run kept, in the directory
// --output names, or in the current directory when it names none. One format
// is written to a path as it was given, whatever that is called: the format
// says what goes in the file, and the name stays the caller's. Two cannot both
// go there, so the path then names them both: an extension that is one of the
// formats comes off, and each gets its own.
func reportFiles(given, kept string, formats []string, when time.Time) []reportFile {
	if given == reportBeside {
		// As a directory, which is what names the file after the moment.
		given = either(kept, ".") + string(os.PathSeparator)
	}
	files := make([]reportFile, 0, len(formats))
	for _, format := range formats {
		path := reportPath(given, format, when)
		if path == given && len(formats) > 1 {
			base := given
			if _, known := reportWriters[strings.ToLower(strings.TrimPrefix(filepath.Ext(given), "."))]; known {
				base = strings.TrimSuffix(given, filepath.Ext(given))
			}
			path = base + "." + format
		}
		files = append(files, reportFile{format: format, path: path})
	}
	return files
}

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
func reportPath(given, format string, when time.Time) string {
	directoryHint := strings.HasSuffix(given, "/") || strings.HasSuffix(given, `\`)
	if !directoryHint {
		if info, err := os.Stat(given); err != nil || !info.IsDir() {
			return given
		}
	}
	return filepath.Join(given, "report-"+stamp(when)+"."+format)
}

// stamp is the time in a report's file name.
//
// Ordered largest unit first, so a directory of reports sorts into the order
// they were made, which the named month used inside the report would not.
// Milliseconds, because a run can be started twice inside one second.
// Hyphens, rather than clock colons, keep the same spelling portable to Windows
// where a colon denotes an alternate data stream and cannot name a normal file.
func stamp(t time.Time) string {
	return t.Format("2006-01-02-150405") + fmt.Sprintf("-%03d", t.Nanosecond()/int(time.Millisecond))
}

var chmodReport = (*os.File).Chmod

// writeReports writes the run down as every file asked for.
//
// All of them are tried, and the ones that were written come back whatever
// became of the others: a page that is there is worth naming beside the reason
// its companion is not.
func writeReports(files []reportFile, in reportInput) (written []reportFile, err error) {
	for _, file := range files {
		if failed := writeReport(file, in); failed != nil {
			err = errors.Join(err, failed)
			continue
		}
		written = append(written, file)
	}
	return written, err
}

// writeReport writes the run to one file, as that file's format.
//
// The page is self-contained on purpose: no stylesheet, no script and no font
// from anywhere else, so it can be opened from a laptop with no network and
// mailed to someone as one attachment.
func writeReport(to reportFile, in reportInput) error {
	command, path := in.command, to.path
	in.at = path
	// The directory is made rather than required. `--report reports/` is what
	// README and example/README both show, and before this it fetched the whole
	// list and then failed at the last step because nothing had created the
	// directory — losing the report and exiting non-zero on a run that worked.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("%s: %w", command, err)
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}
	if err := chmodReport(file, 0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("%s: securing report: %w", command, err)
	}
	defer func() { _ = file.Close() }()
	return reportWriters[to.format](file, in)
}

// renderReport is the document itself, separate from the file it lands in, so
// what it produces can be checked without one and so the failure to write it
// can be reached at all.
func renderReport(w io.Writer, in reportInput) error {
	// Cut down before the display structs are built: a run of a million would
	// otherwise materialise a million of them to show two thousand.
	kept, dropped := limitRows(in.records, reportRowLimit)
	rows := make([]reportRow, 0, len(kept))
	detailed, traced := false, false
	for _, r := range kept {
		row := reportRow{result: r, Proxy: redactProxy(r.Proxy), at: in.at, trace: either(r.Trace, in.trace)}
		if row.trace != "" {
			// Traced, so it can be opened as a trace: its own, drawn from what was
			// written down of it, whether or not it was kept in a file of its own.
			row.Perfetto, traced = perfettoOf(r, in.method), true
		}
		rows = append(rows, row)
		detailed = detailed || len(r.Tries) > 0
	}
	// By when the request went out, which is the order someone reading a run
	// expects, rather than the order answers happened to come back in.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Started.Before(rows[j].Started) })
	// Of every request, shown or not: a run did not go one way because the rows
	// that were kept did.
	way := routes(in.records)

	data := reportData{
		Command:   in.command,
		Generated: at(now()),
		Dropped:   dropped,
		Summary:   in.summary,
		Rows:      rows,
		Cards:     cards(in.summary),
		Service:   askedOf(),
		Detailed:  detailed,
		Route:     way,
		Via:       way != nil && !way.SameProxy,
		Exited:    way != nil && !way.SameExit,
		Asked:     in.asked,
		Traced:    traced,
		// Trusted because it is this repository's own file, compiled in.
		CSS: template.CSS(reportCSS),
	}
	if in.trace != "" {
		data.RunTrace = &keptFile{Path: in.trace, Link: linkTo(in.trace, in.at)}
	}
	if err := reportTemplate.Execute(w, data); err != nil {
		return fmt.Errorf("%s: writing the report: %w", in.command, err)
	}
	return nil
}
