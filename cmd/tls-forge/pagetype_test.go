package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPageExtensionGoesByContentType(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
	for _, c := range []struct {
		name, contentType, body, want string
	}{
		{"a page", "text/html; charset=utf-8", "<html></html>", ".html"},
		{"a type in capitals", "TEXT/HTML", "", ".html"},
		{"JSON", "application/json", `{"a":1}`, ".json"},
		{"JSON by its suffix", "application/problem+json", `{}`, ".json"},
		{"JSON by its suffix, with parameters", "application/vnd.api+json; charset=utf-8", "", ".json"},
		{"XML", "text/xml", "<a/>", ".xml"},
		{"XML by its suffix", "application/rss+xml", "<rss/>", ".xml"},
		{"SVG, which is XML but an image", "image/svg+xml", "<svg/>", ".svg"},
		{"a script", "text/javascript", "1", ".js"},
		{"a style sheet", "text/css", "a{}", ".css"},
		{"an image", "image/png", png, ".png"},
		{"a PDF", "application/pdf", "%PDF-1.7", ".pdf"},
		{"text the list does not name", "text/x-whatever", "", ".txt"},
		// What the server said, over what the body looks like: a browser would
		// have shown this as text.
		{"text that holds JSON", "text/plain", `{"a":1}`, ".txt"},
		{"a value too broken to parse", "text/html;;charset=", "", ".html"},
		{"whitespace around the type", " \tapplication/json  ", "", ".json"},
		{"a comment after the type", "text/html (cached)", "", ".html"},
		{"a tab where the semicolon should be", "text/html\tcharset=utf-8", "", ".html"},
		{"a parameter with a comma in quotes", `text/html; x="a, application/json"`, "", ".html"},
		{"a quoted comma behind an escaped quote", `text/html; x="a\", application/json"`, "", ".html"},
		{"a quote that is never closed", `text/html; x="a, application/json`, "", ".html"},
		{"a backslash outside quotes is no escape", `text/html; x=a\, application/json`, "", ".json"},

		// Two types in one field: the last, as a browser reads it.
		{"two types in one field", "text/plain, application/json", "", ".json"},
		{"a type, then nothing", "text/html,, ", "", ".html"},
		{"a type, then */*", "text/html, */*", "", ".html"},
		{"a type, then one that is not", "text/html, nonsense", "", ".html"},
		{"a type, then bytes: the body decides", "text/html, application/octet-stream", `{"a":1}`, ".json"},

		// Only bytes said, or nothing a type can be read from: the body decides.
		{"octet-stream holding JSON", "application/octet-stream", `{"a":1}`, ".json"},
		{"*/*, which names nothing", "*/*", `{"a":1}`, ".json"},
		{"only whitespace", "  \t ", "<!DOCTYPE html>", ".html"},
		{"only parameters", "; charset=utf-8", `{"a":1}`, ".json"},
		{"a type without a subtype", "html", `{"a":1}`, ".json"},
		{"a type with nothing after the slash", "text/", "plain words", ".txt"},
		{"a slash with nothing before it", "/json", "\x00\x01", ".bin"},
		{"no type, JSON", "", " [1, 2]\n", ".json"},
		{"no type, JSON behind a byte order mark", "", "\xef\xbb\xbf{\"a\":1}", ".json"},
		{"no type, a page", "", "<!DOCTYPE html><html>", ".html"},
		{"no type, an image", "", png, ".png"},
		{"no type, a PDF", "", "%PDF-1.7", ".pdf"},
		{"no type, words", "", "plain words", ".txt"},
		{"no type, braces that are not JSON", "", "{not json", ".txt"},
		{"no type, bytes", "", "\x00\x01\x02\x03", ".bin"},
		{"no type, nothing at all", "", "", ".txt"},
		{"no type, only whitespace", "", " \r\n\t", ".txt"},
		{"no type, a JSON number is text", "", "42", ".txt"},
		{"no type, JSON with more after it", "", `{"a":1} trailing`, ".txt"},
		{"no type, two JSON objects", "", "{}\n{}", ".txt"},
		{"no type, XML", "", `<?xml version="1.0"?><a/>`, ".xml"},
		{"no type, UTF-16 text", "", "\xff\xfeh\x00i\x00", ".txt"},
		{"no type, bytes Go knows and the list does not", "", "Rar!\x1a\x07\x00", ".bin"},
		{"a type nobody named, JSON in it", "application/x-amz-json-1.1", `{"a":1}`, ".json"},
		{"a type nobody named, bytes in it", "application/x-custom", "\x00\x01\x02", ".bin"},
	} {
		header := map[string][]string{}
		if c.contentType != "" {
			header["Content-Type"] = []string{c.contentType}
		}
		if got := pageExtension(header, []byte(c.body)); got != c.want {
			t.Errorf("%s: %q with %q kept as %q, want %q", c.name, c.contentType, c.body, got, c.want)
		}
	}

	// HTTP/2 answers come with their field names in lower case.
	if got := pageExtension(map[string][]string{"content-type": {"application/json"}}, nil); got != ".json" {
		t.Errorf("a lower-case content-type was not read: %q", got)
	}
}

func TestPageExtensionReadsEveryContentType(t *testing.T) {
	for _, c := range []struct {
		name   string
		header map[string][]string
		body   string
		want   string
	}{
		{"no header at all", nil, `{"a":1}`, ".json"},
		{"a field with no value", map[string][]string{"content-type": nil}, `{"a":1}`, ".json"},
		{"a field with an empty value", map[string][]string{"content-type": {""}}, "plain words", ".txt"},
		{"another field only", map[string][]string{"content-length": {"7"}}, `{"a":1}`, ".json"},
		// A browser goes by the last of two fields, not the first.
		{"two fields", map[string][]string{"content-type": {"text/html", "application/json"}}, "", ".json"},
		{"two fields, the last naming nothing", map[string][]string{"content-type": {"application/json", "*/*"}}, "", ".json"},
		{"two fields, the last broken", map[string][]string{"content-type": {"application/json", "json"}}, "", ".json"},
		{"two fields, each with two types", map[string][]string{
			"content-type": {"text/plain, image/png", "text/css, application/pdf"},
		}, "", ".pdf"},
		{"fields that name nothing", map[string][]string{"content-type": {"*/*", ""}}, "<!DOCTYPE html>", ".html"},
	} {
		if got := pageExtension(c.header, []byte(c.body)); got != c.want {
			t.Errorf("%s: %v kept as %q, want %q", c.name, c.header, got, c.want)
		}
	}

	// The same field under two spellings, which an answer from one parser
	// never has but a map can: always the same one of them, whatever order the
	// map is read in.
	twice := map[string][]string{"Content-Type": {"text/html"}, "content-type": {"application/json"}}
	for range 100 {
		if got := pageExtension(twice, nil); got != ".json" {
			t.Fatalf("Content-Type and content-type kept as %q, want .json every time", got)
		}
	}
}

func TestSplitOutsideQuotes(t *testing.T) {
	for _, c := range []struct {
		value string
		sep   byte
		want  []string
	}{
		{"", ',', []string{""}},
		{"text/html", ',', []string{"text/html"}},
		{"a, b", ',', []string{"a", " b"}},
		{",a,", ',', []string{"", "a", ""}},
		{`a; x="1,2", b`, ',', []string{`a; x="1,2"`, " b"}},
		{`a; x="1\",2", b`, ',', []string{`a; x="1\",2"`, " b"}},
		{`a; x="1\\", b`, ',', []string{`a; x="1\\"`, " b"}},
		{`a\, b`, ',', []string{`a\`, " b"}},
		{`a; x="1, b`, ',', []string{`a; x="1, b`}},
		// A quote just after one closed opens another, as the Fetch standard
		// splits a field: it runs to the end.
		{`a; x="1"", b`, ',', []string{`a; x="1"", b`}},
		// Parameters, split the same way at their semicolons, and the commas
		// between items are not theirs to split at.
		{`a; x="1;2"; y=3`, ';', []string{"a", ` x="1;2"`, " y=3"}},
		{"a; x=1, b; y=2", ';', []string{"a", " x=1, b", " y=2"}},
	} {
		if got := splitOutsideQuotes(c.value, c.sep); !slices.Equal(got, c.want) {
			t.Errorf("splitOutsideQuotes(%q, %q) = %q, want %q", c.value, c.sep, got, c.want)
		}
	}
}

func TestOutputNamesEachPageForWhatItIs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!doctype html><title>a</title>"))
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/unsaid":
			// Without a Content-Type at all: Go would otherwise guess one.
			w.Header()["Content-Type"] = nil
			_, _ = w.Write([]byte(`[1,2,3]`))
		case "/logo":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n"))
		case "/twice":
			// Two Content-Type fields, as a server behind a proxy that adds its
			// own sends them: the last is the one a browser goes by.
			w.Header()["Content-Type"] = []string{"text/html", "application/json"}
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	t.Cleanup(server.Close)
	dir := filepath.Join(t.TempDir(), "out")

	code, _, stderr := exec(t, "fetch", "-c", "1", "-o", dir,
		server.URL+"/page", server.URL+"/api", server.URL+"/unsaid", server.URL+"/logo", server.URL+"/twice")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Requests are numbered in the order they were handed out.
	for number, want := range map[string]string{"1": ".html", "2": ".json", "3": ".json", "4": ".png", "5": ".json"} {
		pages, _ := filepath.Glob(filepath.Join(dir, "127.0.0.1-*-"+number+want))
		if len(pages) != 1 {
			t.Errorf("request %s was not kept as %s: %v", number, want, keptIn(t, dir))
			continue
		}
		if body, err := os.ReadFile(pages[0]); err != nil || len(body) == 0 {
			t.Errorf("%s: %q, %v", pages[0], body, err)
		}
	}
}
