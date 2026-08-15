package main

import (
	"strings"
	"testing"
)

// Fuzzing the list readers.
//
// A list is a file, and files arrive from places their reader did not choose: a
// colleague, a scraper that generated one, a spreadsheet exported by something
// nobody here maintains. The same treatment as the wire parser, for the same
// reason: 100% statement coverage of a parser says only that every line ran on
// the malformed inputs someone thought of.
//
// The contract is narrow. Any of these may reject anything, and must reject it
// rather than panic; whatever they do return has to survive validate, which is
// what every real caller runs next.
func FuzzDecodeJobs(f *testing.F) {
	f.Add(formatJSON, `[{"url":"https://a/","proxy":"http://p/"},"https://b/"]`)
	f.Add(formatJSON, `[]`)
	f.Add(formatJSON, `[{}]`)
	f.Add(formatCSV, "url,proxy\nhttps://a/,http://p/\n")
	f.Add(formatCSV, "proxy,url\n,https://a/\n")
	f.Add(formatCSV, "https://a/\n")
	f.Add(formatCSV, `"unterminated`)
	f.Add(formatLines, "# comment\n\nhttps://a/ http://p/\n")
	f.Add(formatLines, "")

	f.Fuzz(func(t *testing.T, format, body string) {
		resolved, err := resolveFormat(format, "")
		if err != nil {
			return
		}
		jobs, err := decodeJobs(strings.NewReader(body), resolved, "fuzz")
		if err != nil {
			if jobs != nil {
				t.Fatalf("both a list and an error: %v", err)
			}
			return
		}
		// Whatever came back is about to be handed to validate by every real
		// caller, so that is part of what must not fall over.
		_ = validate(jobs)
	})
}

// FuzzSplitInline covers the one source that is not a file: --urls.
func FuzzSplitInline(f *testing.F) {
	f.Add("https://a/,https://b/")
	f.Add(",,,")
	f.Add("")

	f.Fuzz(func(t *testing.T, value string) {
		for _, j := range splitInline(value) {
			if j.URL == "" {
				t.Fatalf("an empty URL survived splitting %q", value)
			}
		}
	})
}
