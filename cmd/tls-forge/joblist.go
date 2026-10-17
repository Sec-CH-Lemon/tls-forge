package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"unicode"

	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
)

// Reading a list of URLs.
//
// Kept apart from the fetching, because the two fail for unrelated reasons and
// a list that will not parse should say so before a single request goes out.

// job is one URL and the identity to fetch it with.
//
// The proxy travels with the URL rather than being a setting for the whole run,
// because that is the shape a scrape usually has: this page through the
// residential exit it was found on, that page through a datacentre one.
type job struct {
	URL   string `json:"url"`
	Proxy string `json:"proxy,omitempty"`
	// entry is which URL of the list this is, from zero, the same in every
	// pass over it.
	entry int
	// run is which pass over the list this is, from one.
	run int
	// id is which request of the run this is, from one, in the order they are
	// handed out: what tells apart the files of two requests made to one host
	// in one millisecond.
	id int
}

// Formats a list can arrive in. `auto` reads the file's extension and falls
// back to lines, which is what a list pasted from anywhere looks like.
const (
	formatAuto  = "auto"
	formatLines = "lines"
	formatJSON  = "json"
	formatCSV   = "csv"
)

var listFormats = []string{formatAuto, formatLines, formatJSON, formatCSV}

// resolveFormat turns `auto` into a real format, by extension.
//
// Only the extension, never the contents. Sniffing would guess right almost
// always and then guess wrong on someone's CSV whose first cell begins with a
// brace, at which point the fix is a flag they did not know existed.
func resolveFormat(format, path string) (string, error) {
	switch format {
	case formatLines, formatJSON, formatCSV:
		return format, nil
	case formatAuto:
		switch {
		case strings.HasSuffix(strings.ToLower(path), ".json"):
			return formatJSON, nil
		case strings.HasSuffix(strings.ToLower(path), ".csv"):
			return formatCSV, nil
		default:
			return formatLines, nil
		}
	default:
		return "", badValue("--format", format, strings.Join(listFormats, ", "))
	}
}

// readJobs collects the list from whichever source was given.
//
// --urls, --input or arguments, and standard input when none of them is. Each
// is a deliberate way to say "here is the list", so two of them are a usage
// error rather than one quietly preferred to the other, or the two merged
// into a pile nobody can account for.
func readJobs(ctx context.Context, inline, path, format string, args []string,
	stdin io.Reader,
) ([]job, error) {
	var given []string
	if inline != "" {
		given = append(given, "--urls")
	}
	if path != "" {
		given = append(given, "--input")
	}
	if len(args) > 0 {
		given = append(given, "URLs on the command line")
	}
	if len(given) > 1 {
		return nil, fmt.Errorf("%w: %s each give the list of URLs: give one", errUsage, strings.Join(given, " and "))
	}

	// Resolved first, before the source is chosen. A misspelled format is a
	// mistake whether or not the list happens to come from somewhere the format
	// applies to, and a flag that is silently ignored under some inputs is
	// worse than one that is always wrong.
	//
	// An empty path is the stdin case, which has no name to take an extension
	// from, so `auto` means lines there and --format says otherwise.
	resolved, err := resolveFormat(format, path)
	if err != nil {
		return nil, err
	}

	if inline != "" {
		return splitInline(inline), nil
	}
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}
		defer func() { _ = file.Close() }()
		return decodeJobs(file, resolved, path)
	}
	if len(args) > 0 {
		return jobsFromURLs(args), nil
	}
	return decodeStream(ctx, stdin, resolved)
}

// decodeStream reads a list from a stream that may never end.
//
// On a goroutine of its own, so an interrupt is answered while the read is
// still blocked. A read on an idle terminal blocks until there is a line or the
// process ends, and without this the first Ctrl-C is caught, turned into a
// cancelled context, and then noticed by nobody.
//
// The goroutine outlives the wait when the context ends first. It is blocked on
// a descriptor that is about to be closed by the process exiting, and nothing
// is waiting on its answer.
func decodeStream(ctx context.Context, r io.Reader, format string) ([]job, error) {
	type outcome struct {
		jobs []job
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		jobs, err := decodeJobs(r, format, "standard input")
		done <- outcome{jobs, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-done:
		return got.jobs, got.err
	}
}

func decodeJobs(r io.Reader, format, source string) ([]job, error) {
	r = withoutBOM(r)
	switch format {
	case formatJSON:
		return decodeJSONJobs(r, source)
	case formatCSV:
		return decodeCSVJobs(r, source)
	default:
		return decodeLineJobs(r, source)
	}
}

// splitInline reads --urls, which is a comma-separated list.
//
// A URL may legally contain a comma, in a query string. One that does belongs
// in a file rather than in this flag, and the alternative, some escaping
// convention, would be a worse trade than that sentence in the documentation.
func splitInline(value string) []job {
	var urls []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			urls = append(urls, part)
		}
	}
	return jobsFromURLs(urls)
}

func jobsFromURLs(urls []string) []job {
	jobs := make([]job, 0, len(urls))
	for _, url := range urls {
		jobs = append(jobs, job{URL: url})
	}
	return jobs
}

// byteOrderMark is what a list saved by some Windows editors begins with.
var byteOrderMark = []byte("\xef\xbb\xbf")

// withoutBOM is r without the UTF-8 byte order mark it may begin with. Read
// as text, it would be the first character of the first URL, which would then
// be no URL; anywhere but the beginning it is text, and left alone.
func withoutBOM(r io.Reader) io.Reader {
	buffered := bufio.NewReader(r)
	if mark, err := buffered.Peek(len(byteOrderMark)); err == nil && bytes.Equal(mark, byteOrderMark) {
		_, _ = buffered.Discard(len(byteOrderMark))
	}
	return buffered
}

// maxListLine is the longest line a list of lines can have, its newline
// included: a URL a megabyte long is a file read as the wrong format.
const maxListLine = 1 << 20

// decodeLineJobs reads one URL per line.
//
// Optionally followed by a proxy, separated by whitespace, so the plainest
// format is not the one that cannot express a per-URL proxy.
func decodeLineJobs(r io.Reader, source string) ([]job, error) {
	var jobs []job
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxListLine)
	read := 0
	for scanner.Scan() {
		read++
		line := strings.TrimSpace(scanner.Text())
		// Blank lines and comments, so a list can be annotated and a line can
		// be commented out rather than deleted.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		url, proxy := line, ""
		if split := strings.IndexFunc(line, unicode.IsSpace); split >= 0 {
			url, proxy = line[:split], line[split:]
		}
		jobs = append(jobs, job{URL: strings.TrimSpace(url), Proxy: strings.TrimSpace(proxy)})
	}
	switch err := scanner.Err(); {
	case errors.Is(err, bufio.ErrTooLong):
		return nil, fmt.Errorf("%w: fetch: %s: line %d is longer than %d bytes, its newline included",
			errUsage, source, read+1, maxListLine)
	case err != nil:
		return nil, fmt.Errorf("fetch: %s: %w", source, err)
	}
	return jobs, nil
}

// jsonJob is the object form. A separate type from job so that a misspelled key
// can be rejected rather than silently producing an empty URL.
type jsonJob struct {
	URL   string `json:"url"`
	Proxy string `json:"proxy"`
}

// decodeJSONJobs reads either an array of objects or an array of strings.
//
// Both, because an array of strings is what someone writes when no URL needs
// its own proxy, and making them write `{"url": …}` for that would be a tax on
// the common case.
func decodeJSONJobs(r io.Reader, source string) ([]job, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("fetch: %s: %w", source, err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: fetch: %s: expected a JSON array: %w", errUsage, source, err)
	}

	jobs := make([]job, 0, len(raw))
	for i, item := range raw {
		var url string
		if err := json.Unmarshal(item, &url); err == nil {
			jobs = append(jobs, job{URL: strings.TrimSpace(url)})
			continue
		}
		var entry jsonJob
		decoder := json.NewDecoder(strings.NewReader(string(item)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("%w: fetch: %s: entry %d: %w", errUsage, source, i+1, err)
		}
		jobs = append(jobs, job{
			URL:   strings.TrimSpace(entry.URL),
			Proxy: strings.TrimSpace(entry.Proxy),
		})
	}
	return jobs, nil
}

// decodeCSVJobs reads url,proxy.
//
// A first row holding a cell that reads exactly "url" is a header, and then the
// columns are taken by name in whatever order they appear. Otherwise the
// columns are positional: first the URL, then the proxy.
//
// Any cell rather than the first, or `proxy,url` would be read as data. A data
// row cannot be mistaken for a header the other way round, because its URL cell
// holds a URL and never the bare word.
func decodeCSVJobs(r io.Reader, source string) ([]job, error) {
	reader := csv.NewReader(r)
	// Rows are allowed to be ragged: a list where only some URLs carry a proxy
	// is the normal case, not a malformed file.
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	var malformed *csv.ParseError
	switch {
	case errors.As(err, &malformed):
		return nil, fmt.Errorf("%w: fetch: %s: %w", errUsage, source, err)
	case err != nil:
		return nil, fmt.Errorf("fetch: %s: %w", source, err)
	}
	if len(records) == 0 {
		return nil, nil
	}

	urlAt, proxyAt := 0, 1
	if named := columns(records[0]); named != nil {
		urlAt, proxyAt = named[0], named[1]
		records = records[1:]
	}

	jobs := make([]job, 0, len(records))
	for _, record := range records {
		jobs = append(jobs, job{
			URL:   strings.TrimSpace(field(record, urlAt)),
			Proxy: strings.TrimSpace(field(record, proxyAt)),
		})
	}
	return jobs, nil
}

// columns finds the url and proxy columns in a header row, or reports that the
// row is not a header by returning nil.
func columns(row []string) []int {
	urlAt, proxyAt := -1, -1
	for i, name := range row {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "url":
			urlAt = i
		case "proxy":
			proxyAt = i
		}
	}
	if urlAt < 0 {
		return nil
	}
	return []int{urlAt, proxyAt}
}

func field(record []string, at int) string {
	if at < 0 || at >= len(record) {
		return ""
	}
	return record[at]
}

// validate rejects a list before any of it is fetched, as a usage error, and
// writes the scheme of every URL in lower case, as a browser does: `HTTP://`
// is an http URL.
//
// All of it, rather than the first problem: someone who mistyped two lines of a
// hundred should learn that from one run.
func validate(jobs []job) error {
	if len(jobs) == 0 {
		return fmt.Errorf("%w: fetch: no URLs given", errUsage)
	}
	var problems []string
	for i := range jobs {
		j := &jobs[i]
		switch u, err := url.Parse(j.URL); {
		case j.URL == "":
			problems = append(problems, fmt.Sprintf("entry %d has no URL", i+1))
		case err != nil:
			problems = append(problems, fmt.Sprintf("entry %d: %q is not a URL: %v", i+1, j.URL, parseReason(err)))
		case u.Scheme != "http" && u.Scheme != "https":
			problems = append(problems, fmt.Sprintf("entry %d: %q is not an http or https URL", i+1, j.URL))
		case u.Hostname() == "":
			problems = append(problems, fmt.Sprintf("entry %d: %q names no host", i+1, j.URL))
		default:
			j.URL = u.Scheme + j.URL[len(u.Scheme):]
		}
		if j.Proxy == "" {
			continue
		}
		if why := proxyProblem(j.Proxy); why != "" {
			problems = append(problems, fmt.Sprintf("entry %d: the proxy %s %s", i+1, redact.URL(j.Proxy), why))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: fetch: %s", errUsage, strings.Join(problems, "; "))
	}
	return nil
}

// proxySchemes are the proxies the transport can go through.
var proxySchemes = []string{"http", "https", "socks4", "socks4a", "socks5", "socks5h"}

// proxyProblem is what is wrong with a proxy's URL, or nothing: what the
// transport would refuse only when a client for it is made, after a run had
// emptied a directory and opened its log, or half way through a list.
func proxyProblem(proxy string) string {
	switch u, err := url.Parse(proxy); {
	case err != nil:
		return "is not a URL: " + parseReason(err)
	case !slices.Contains(proxySchemes, u.Scheme):
		return "is not an " + strings.Join(proxySchemes[:len(proxySchemes)-1], ", ") + " or " +
			proxySchemes[len(proxySchemes)-1] + " URL"
	case u.Hostname() == "":
		return "names no host"
	}
	return ""
}

// parseReason is why url.Parse would not read a URL, without the URL, which
// it quotes whole, password and all.
func parseReason(err error) string {
	var parse *url.Error
	if errors.As(err, &parse) {
		return parse.Err.Error()
	}
	return err.Error()
}
