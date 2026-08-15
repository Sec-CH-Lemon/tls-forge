package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
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
		return "", &badFlag{"--format", format, strings.Join(listFormats, ", ")}
	}
}

// readJobs collects the list from whichever source was given.
//
// In order of precedence: --urls, then --input, then any arguments, then
// standard input. Each is a deliberate way to say "here is the list", so the
// first one present wins rather than the four being merged into a pile nobody
// can account for.
func readJobs(inline, path, format string, args []string, stdin io.Reader) ([]job, error) {
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
			return nil, fmt.Errorf("batch: %w", err)
		}
		defer func() { _ = file.Close() }()
		return decodeJobs(file, resolved, path)
	}
	if len(args) > 0 {
		return jobsFromURLs(args), nil
	}
	return decodeJobs(stdin, resolved, "standard input")
}

func decodeJobs(r io.Reader, format, source string) ([]job, error) {
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

// decodeLineJobs reads one URL per line.
//
// Optionally followed by a proxy, separated by whitespace, so the plainest
// format is not the one that cannot express a per-URL proxy.
func decodeLineJobs(r io.Reader, source string) ([]job, error) {
	var jobs []job
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Blank lines and comments, so a list can be annotated and a line can
		// be commented out rather than deleted.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		url, proxy, _ := strings.Cut(line, " ")
		jobs = append(jobs, job{URL: strings.TrimSpace(url), Proxy: strings.TrimSpace(proxy)})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("batch: %s: %w", source, err)
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
		return nil, fmt.Errorf("batch: %s: %w", source, err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("batch: %s: expected a JSON array: %w", source, err)
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
			return nil, fmt.Errorf("batch: %s: entry %d: %w", source, i+1, err)
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
	if err != nil {
		return nil, fmt.Errorf("batch: %s: %w", source, err)
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

// validate rejects a list before any of it is fetched.
//
// All of it, rather than the first problem: someone who mistyped two lines of a
// hundred should learn that from one run.
func validate(jobs []job) error {
	if len(jobs) == 0 {
		return fmt.Errorf("batch: no URLs given")
	}
	var problems []string
	for i, j := range jobs {
		if j.URL == "" {
			problems = append(problems, fmt.Sprintf("entry %d has no URL", i+1))
			continue
		}
		if !strings.HasPrefix(j.URL, "http://") && !strings.HasPrefix(j.URL, "https://") {
			problems = append(problems,
				fmt.Sprintf("entry %d: %q is not an http or https URL", i+1, j.URL))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("batch: %s", strings.Join(problems, "; "))
	}
	return nil
}
