package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeList(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func TestResolveFormat(t *testing.T) {
	for _, tc := range []struct{ format, path, want string }{
		// A named format is taken at its word whatever the file is called,
		// which is the point of having the flag.
		{formatJSON, "list.csv", formatJSON},
		{formatCSV, "list.json", formatCSV},
		{formatLines, "list.json", formatLines},

		{formatAuto, "list.json", formatJSON},
		{formatAuto, "LIST.JSON", formatJSON},
		{formatAuto, "list.csv", formatCSV},
		{formatAuto, "list.txt", formatLines},
		// A stream has no name to take an extension from.
		{formatAuto, "", formatLines},
	} {
		got, err := resolveFormat(tc.format, tc.path)
		if err != nil {
			t.Errorf("resolveFormat(%q, %q): %v", tc.format, tc.path, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveFormat(%q, %q) = %q, want %q", tc.format, tc.path, got, tc.want)
		}
	}
}

func TestResolveFormatRejectsAnUnknownOne(t *testing.T) {
	_, err := resolveFormat("yaml", "list.yaml")
	if err == nil {
		t.Fatal("no error")
	}
	// The message has to name the alternatives, or the reader is left guessing
	// which spellings exist.
	for _, want := range []string{"--format", "yaml", "json", "csv"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestReadJobsFromEachSource(t *testing.T) {
	both := []job{
		{URL: "https://a.example/", Proxy: "http://p1:8080"},
		{URL: "https://b.example/"},
	}

	for _, tc := range []struct {
		name         string
		inline, path string
		format       string
		args         []string
		stdin        string
		want         []job
	}{
		{
			name:   "a JSON array of objects",
			path:   writeList(t, "list.json", `[{"url":"https://a.example/","proxy":"http://p1:8080"},{"url":"https://b.example/"}]`),
			format: formatAuto,
			want:   both,
		},
		{
			// What someone writes when no URL needs its own proxy.
			name:   "a JSON array of strings",
			path:   writeList(t, "plain.json", `["https://a.example/", "https://b.example/"]`),
			format: formatAuto,
			want:   []job{{URL: "https://a.example/"}, {URL: "https://b.example/"}},
		},
		{
			name:   "a JSON array mixing both",
			path:   writeList(t, "mixed.json", `[{"url":"https://a.example/","proxy":"http://p1:8080"},"https://b.example/"]`),
			format: formatAuto,
			want:   both,
		},
		{
			name:   "CSV with a header",
			path:   writeList(t, "list.csv", "url,proxy\nhttps://a.example/,http://p1:8080\nhttps://b.example/,\n"),
			format: formatAuto,
			want:   both,
		},
		{
			// Columns by name, so the file does not have to put them in the
			// order this program happens to prefer.
			name:   "CSV with the columns the other way round",
			path:   writeList(t, "swapped.csv", "proxy,url\nhttp://p1:8080,https://a.example/\n,https://b.example/\n"),
			format: formatAuto,
			want:   both,
		},
		{
			name:   "CSV without a header",
			path:   writeList(t, "bare.csv", "https://a.example/,http://p1:8080\nhttps://b.example/\n"),
			format: formatAuto,
			want:   both,
		},
		{
			name:   "one URL per line",
			path:   writeList(t, "list.txt", "# a comment\n\nhttps://a.example/\t  http://p1:8080\nhttps://b.example/\n"),
			format: formatAuto,
			want:   both,
		},
		{
			name:   "a comma-separated flag",
			inline: " https://a.example/ , https://b.example/ ,, ",
			format: formatAuto,
			want:   []job{{URL: "https://a.example/"}, {URL: "https://b.example/"}},
		},
		{
			name:   "arguments",
			args:   []string{"https://a.example/", "https://b.example/"},
			format: formatAuto,
			want:   []job{{URL: "https://a.example/"}, {URL: "https://b.example/"}},
		},
		{
			name:   "standard input",
			stdin:  "https://a.example/ http://p1:8080\nhttps://b.example/\n",
			format: formatAuto,
			want:   both,
		},
		{
			// A stream carries no extension, so a format for it has to be named.
			name:   "standard input told what it is",
			stdin:  `["https://a.example/","https://b.example/"]`,
			format: formatJSON,
			want:   []job{{URL: "https://a.example/"}, {URL: "https://b.example/"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readJobs(context.Background(), tc.inline, tc.path, tc.format, tc.args, strings.NewReader(tc.stdin))
			if err != nil {
				t.Fatalf("readJobs: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestReadJobsPrefersTheMostExplicitSource(t *testing.T) {
	// Each of these is a deliberate way to say "here is the list", so the first
	// one present wins rather than the four being merged into a pile nobody can
	// account for.
	path := writeList(t, "list.txt", "https://from-file/\n")
	got, err := readJobs(context.Background(), "https://from-flag/", path, formatAuto,
		[]string{"https://from-args/"}, strings.NewReader("https://from-stdin/\n"))
	if err != nil {
		t.Fatalf("readJobs: %v", err)
	}
	if len(got) != 1 || got[0].URL != "https://from-flag/" {
		t.Errorf("got %+v", got)
	}

	got, err = readJobs(context.Background(), "", path, formatAuto,
		[]string{"https://from-args/"}, strings.NewReader("https://from-stdin/\n"))
	if err != nil {
		t.Fatalf("readJobs: %v", err)
	}
	if len(got) != 1 || got[0].URL != "https://from-file/" {
		t.Errorf("got %+v", got)
	}
}

func TestReadJobsErrors(t *testing.T) {
	t.Run("a file that is not there", func(t *testing.T) {
		_, err := readJobs(context.Background(), "", filepath.Join(t.TempDir(), "absent.json"), formatAuto, nil, nil)
		if err == nil {
			t.Fatal("no error")
		}
	})

	// A misspelled format is rejected whichever source the list came from. It
	// applies only to a file or a stream, but a flag that is quietly ignored
	// under some inputs is worse than one that is always wrong.
	t.Run("an unknown format", func(t *testing.T) {
		path := writeList(t, "list.txt", "https://a.example/\n")
		for _, source := range []struct {
			name         string
			inline, path string
			args         []string
		}{
			{name: "a file", path: path},
			{name: "standard input"},
			{name: "arguments", args: []string{"https://a.example/"}},
			{name: "the comma-separated flag", inline: "https://a.example/"},
		} {
			t.Run(source.name, func(t *testing.T) {
				_, err := readJobs(context.Background(), source.inline, source.path, "yaml", source.args,
					strings.NewReader(""))
				if err == nil {
					t.Fatal("no error")
				}
			})
		}
	})
}

func TestDecodeJSONJobsErrors(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"not JSON at all", "<html>", "expected a JSON array"},
		{"an object rather than an array", `{"url":"https://a/"}`, "expected a JSON array"},
		// A misspelled key would otherwise produce an entry with no URL, which
		// fails much later and says much less.
		{"a misspelled key", `[{"urls":"https://a/"}]`, "entry 1"},
		{"a number where an entry should be", `[42]`, "entry 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeJSONJobs(strings.NewReader(tc.body), "list.json")
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// failingReader fails partway, which is what a truncated pipe or a disk error
// looks like to a decoder.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("input/output error") }

func TestDecodersReportAReadFailure(t *testing.T) {
	for name, decode := range map[string]func(io.Reader, string) ([]job, error){
		"json":  decodeJSONJobs,
		"csv":   decodeCSVJobs,
		"lines": decodeLineJobs,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decode(failingReader{}, "somewhere"); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestDecodeCSVJobs(t *testing.T) {
	t.Run("an empty file is an empty list", func(t *testing.T) {
		got, err := decodeCSVJobs(strings.NewReader(""), "list.csv")
		if err != nil || got != nil {
			t.Errorf("got %+v, %v", got, err)
		}
	})

	t.Run("a header naming neither column", func(t *testing.T) {
		// "url" in the first cell is what marks a header, so a file whose first
		// cell is a URL is data. This one is not, and names nothing usable.
		got, err := decodeCSVJobs(strings.NewReader("url,note\nhttps://a/,hello\n"), "list.csv")
		if err != nil {
			t.Fatalf("decodeCSVJobs: %v", err)
		}
		if len(got) != 1 || got[0].URL != "https://a/" || got[0].Proxy != "" {
			t.Errorf("got %+v", got)
		}
	})

	t.Run("rows may be ragged", func(t *testing.T) {
		// A list where only some URLs carry a proxy is the normal case, not a
		// malformed file.
		got, err := decodeCSVJobs(strings.NewReader("https://a/,http://p/\nhttps://b/\n"), "list.csv")
		if err != nil {
			t.Fatalf("decodeCSVJobs: %v", err)
		}
		want := []job{{URL: "https://a/", Proxy: "http://p/"}, {URL: "https://b/"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a quote that is never closed", func(t *testing.T) {
		if _, err := decodeCSVJobs(strings.NewReader("https://a/,\"unterminated\n"), "list.csv"); err == nil {
			t.Error("no error")
		}
	})
}

func TestValidate(t *testing.T) {
	if err := validate(nil); err == nil {
		t.Error("an empty list should be rejected")
	}
	if err := validate([]job{{URL: "https://a/"}, {URL: "http://b/"}}); err != nil {
		t.Errorf("a good list was rejected: %v", err)
	}

	// Every problem at once: someone who mistyped two lines of a hundred should
	// learn that from one run.
	err := validate([]job{
		{URL: "https://a/"},
		{Proxy: "http://p/"},
		{URL: "ftp://c/"},
	})
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"entry 2", "entry 3", "ftp://c/"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestReadJobsGivesUpWhenInterrupted(t *testing.T) {
	// A read on an idle terminal blocks until there is a line or the process
	// ends. Without the read being on a goroutine of its own, the first Ctrl-C
	// is caught, turned into a cancelled context, and noticed by nobody:
	// `tls-forge batch` waiting on standard input survived four of them.
	ctx, cancel := context.WithCancel(context.Background())
	blocked, release := io.Pipe()
	t.Cleanup(func() { _ = release.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := readJobs(ctx, "", "", formatLines, nil, blocked)
		done <- err
	}()

	// Nothing has been typed, so the read is still waiting.
	select {
	case err := <-done:
		t.Fatalf("the read finished on its own: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want a cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read did not give up after the run was cancelled")
	}
}

func TestReadJobsStillReadsAStreamThatAnswers(t *testing.T) {
	// The interruptible path is still the reading path.
	got, err := readJobs(context.Background(), "", "", formatLines, nil,
		strings.NewReader("https://a.example/\nhttps://b.example/\n"))
	if err != nil {
		t.Fatalf("readJobs: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %+v", got)
	}
}
