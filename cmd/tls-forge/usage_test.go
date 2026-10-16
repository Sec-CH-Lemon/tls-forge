package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// askedFor is a server that keeps the paths it is asked for.
type askedFor struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func (a *askedFor) asked() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.paths)
}

func keepingPaths(t *testing.T) *askedFor {
	t.Helper()
	a := &askedFor{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.paths = append(a.paths, r.URL.EscapedPath())
		a.mu.Unlock()
		_, _ = fmt.Fprint(w, "page")
	}))
	t.Cleanup(a.Close)
	return a
}

// lookupsCounted has the run's question of where it comes out answered by a
// server of the test's own, and is how many times it was asked.
func lookupsCounted(t *testing.T) *atomic.Int32 {
	t.Helper()
	var asked atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","country":"PL"}`))
	}))
	t.Cleanup(service.Close)
	original := ipServices
	t.Cleanup(func() { ipServices = original })
	ipServices = []addressService{{URL: service.URL, read: readJSON}}
	return &asked
}

func TestEveryBadFlagIsAUsageErrorThatTouchesNothing(t *testing.T) {
	// Exit code 2 and the reason, before a directory is emptied or made, a
	// file opened, the address asked about or a request made.
	server := keepingPaths(t)
	lookups := lookupsCounted(t)
	list := writeList(t, "list.txt", server.URL+"/listed\n")
	for _, tc := range []struct {
		args []string
		says string
	}{
		{[]string{"--progress", "bogus"}, `--progress is "bogus", want auto, always or never`},
		{[]string{"--color", "bogus"}, `--color is "bogus", want auto, always or never`},
		{[]string{"--format", "bogus"}, `--format is "bogus", want auto, lines, json, csv`},
		{[]string{"--report-format", "pdf"}, `--report-format is "pdf", want html, json or html,json`},
		{[]string{"--log-level", "loud"}, `--log-level is "loud", want error, warn, info, debug or trace`},
		{[]string{"--concurrency", "0"}, "--concurrency must be at least 1"},
		{[]string{"--repeat", "0"}, "--repeat must be at least 1"},
		{[]string{"--timeout", "0s"}, "--timeout is 0s, and has to be more than nothing"},
		{[]string{"--timeout", "-1s"}, "--timeout is -1s, and has to be more than nothing"},
		{[]string{"--profile", "netscape_4"}, `unknown profile "netscape_4"`},
		{[]string{"--proxy", "socks9://p.test:1"}, "--proxy socks9://p.test:1 is not an http, https, socks4, socks4a, socks5 or socks5h URL"},
		{[]string{"--proxy", "http:///nowhere"}, "--proxy http:///nowhere names no host"},
		{[]string{"--wait-for", "/x/g"}, "g is not a flag a regular expression takes"},
		{[]string{"--html-decoding", "chrome", "--wait-for", "x"}, `--html-decoding is "chrome", want legacy or browser`},
		{[]string{"--html-decoding", "", "--wait-for-element", "p"}, `--html-decoding is "", want legacy or browser`},
		{[]string{"--html-decoding", "browser"}, "--html-decoding says how --wait-for and --wait-for-element read a " +
			"body: give one of them"},
		{[]string{"--html-decoding", "legacy", "--wait-for", ""}, "--html-decoding says how --wait-for and"},
		{[]string{"--input", list}, "--input and URLs on the command line each give the list of URLs: give one"},
		{[]string{"--urls", server.URL + "/inline"}, "--urls and URLs on the command line each give the list"},
	} {
		dir := t.TempDir()
		args := append([]string{"fetch", "-o", filepath.Join(dir, "out"), "--trace", filepath.Join(dir, "t.json"),
			"--log", filepath.Join(dir, "run.log"), "--report=" + filepath.Join(dir, "r.html"),
			"--save-cookies", filepath.Join(dir, "s.json")}, tc.args...)
		args = append(args, server.URL+"/named")
		code, _, stderr := exec(t, args...)
		if code != 2 || !strings.HasPrefix(stderr, "tlsforge: bad usage: ") || !strings.Contains(stderr, tc.says) {
			t.Errorf("%q: exit code = %d, want 2 and %q\n%s", tc.args, code, tc.says, stderr)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%q made %v", tc.args, entries)
		}
	}
	if got := server.asked(); len(got) != 0 {
		t.Errorf("asked for %v", got)
	}
	if got := lookups.Load(); got != 0 {
		t.Errorf("the address was asked about %d times", got)
	}
}

func TestWhatGoesWrongWhileRunningExitsOne(t *testing.T) {
	// Not the arguments: the network, a file that is not there, a session
	// that does not read as one.
	dir := t.TempDir()
	broken := filepath.Join(dir, "session.json")
	if err := os.WriteFile(broken, []byte("{not a session"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	nowhere := "http://" + deadAddr(t) + "/"
	for _, args := range [][]string{
		{"fetch", nowhere},
		{"fetch", "--input", filepath.Join(dir, "absent.txt")},
		{"fetch", "--cookies", broken, nowhere},
	} {
		if code, _, stderr := exec(t, args...); code != 1 {
			t.Errorf("%q: exit code = %d, want 1\n%s", args, code, stderr)
		}
	}
}

func TestAListMayBeginWithAByteOrderMark(t *testing.T) {
	// As a list saved by some Windows editors does, in any format, from a file
	// or standard input. Anywhere but the beginning it is text, and a URL
	// that begins with it is no URL.
	server := keepingPaths(t)
	bom := "\xef\xbb\xbf"
	for _, tc := range []struct{ name, format, body string }{
		{"lines", "lines", bom + server.URL + "/lines\n"},
		{"csv", "csv", bom + "url\n" + server.URL + "/csv\n"},
		{"json", "json", bom + `["` + server.URL + `/json"]`},
	} {
		path := writeList(t, "list."+tc.format, tc.body)
		if code, _, stderr := exec(t, "fetch", "--input", path); code != 0 {
			t.Errorf("%s from a file: exit code = %d\n%s", tc.name, code, stderr)
		}
		original := listInput
		listInput = strings.NewReader(tc.body)
		code, _, stderr := exec(t, "fetch", "--format", tc.format)
		listInput = original
		if code != 0 {
			t.Errorf("%s from standard input: exit code = %d\n%s", tc.name, code, stderr)
		}
	}
	if got, want := server.asked(), []string{"/lines", "/lines", "/csv", "/csv", "/json", "/json"}; !slices.Equal(got, want) {
		t.Errorf("asked for %v, want %v", got, want)
	}

	path := writeList(t, "list.txt", server.URL+"/first\n"+bom+server.URL+"/second\n")
	if code, _, stderr := exec(t, "fetch", "--input", path); code != 2 || !strings.Contains(stderr, "entry 2:") {
		t.Errorf("a mark in the middle: exit code = %d\n%s", code, stderr)
	}
}

func TestWithoutBOM(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"\xef\xbb", "\xef\xbb"},
		{"\xef\xbb\xbf", ""},
		{"\xef\xbb\xbfhttp://a/", "http://a/"},
		{"\xef\xbbhttp://a/", "\xef\xbbhttp://a/"},
		{"http://a/\xef\xbb\xbf", "http://a/\xef\xbb\xbf"},
	} {
		var got bytes.Buffer
		if _, err := got.ReadFrom(withoutBOM(strings.NewReader(tc.in))); err != nil || got.String() != tc.want {
			t.Errorf("withoutBOM(%q) = %q, %v; want %q", tc.in, got.String(), err, tc.want)
		}
	}
}

func TestAURLsSchemeIsReadWhateverItsCase(t *testing.T) {
	// As a browser reads it: HTTP:// is an http URL, and goes out as one.
	server := keepingPaths(t)
	upper := "HTTP" + strings.TrimPrefix(server.URL, "http") + "/upper"
	mixed := "Http" + strings.TrimPrefix(server.URL, "http") + "/mixed"
	code, stdout, stderr := exec(t, "fetch", "--json", upper, mixed)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	got := lines(t, stdout)
	if _, ok := got[server.URL+"/upper"]; !ok {
		t.Errorf("the lines name %v, want the scheme in lower case", slices.Collect(func(yield func(string) bool) {
			for url := range got {
				if !yield(url) {
					return
				}
			}
		}))
	}
	if paths := server.asked(); !slices.Contains(paths, "/upper") || !slices.Contains(paths, "/mixed") {
		t.Errorf("asked for %v", paths)
	}
}

func TestAURLWithAnythingInItsPathIsMade(t *testing.T) {
	server := keepingPaths(t)
	if code, _, stderr := exec(t, "fetch", server.URL+"/путь"); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if got := server.asked(); len(got) != 1 || got[0] != "/"+url.PathEscape("путь") {
		t.Errorf("asked for %v", got)
	}
}

func TestEveryEntryThatIsNoURLIsSaidAtOnce(t *testing.T) {
	server := keepingPaths(t)
	list := writeList(t, "list.csv", "url,proxy\n"+strings.Join([]string{
		"http://[::1,",
		"ftp://files.test/,",
		"http:///nohost,",
		"://nothing,",
		server.URL + "/fine,",
		server.URL + "/through,http://alice:s3cr3t@[bad",
		server.URL + "/also,socks9://p.test:1",
		server.URL + "/and,http:///nohost",
	}, "\n")+"\n")
	code, _, stderr := exec(t, "fetch", "--input", list)
	if code != 2 {
		t.Errorf("exit code = %d, want 2\n%s", code, stderr)
	}
	for _, want := range []string{
		`entry 1: "http://[::1" is not a URL: missing ']' in host`,
		`entry 2: "ftp://files.test/" is not an http or https URL`,
		`entry 3: "http:///nohost" names no host`,
		`entry 4: "://nothing" is not a URL: missing protocol scheme`,
		"entry 6: the proxy [redacted]@[bad is not a URL: missing ']' in host",
		"entry 7: the proxy socks9://p.test:1 is not an http, https, socks4, socks4a, socks5 or socks5h URL",
		"entry 8: the proxy http:///nohost names no host",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "entry 5") || strings.Contains(stderr, "s3cr3t") {
		t.Errorf("stderr says too much:\n%s", stderr)
	}
	if got := server.asked(); len(got) != 0 {
		t.Errorf("asked for %v", got)
	}
}

func TestParseReason(t *testing.T) {
	// What url.Parse says is held to in TestEveryEntryThatIsNoURLIsSaidAtOnce;
	// anything else is said as it is.
	if got := parseReason(errors.New("odd")); got != "odd" {
		t.Errorf("parseReason(odd) = %q", got)
	}
}

func TestALineOfAListIsAtMostAMegabyte(t *testing.T) {
	// A comment is a line as much as a URL is. One the size of the limit, its
	// newline included, is read; one byte more is a usage error that says
	// which line.
	server := keepingPaths(t)
	comment := func(size int) string { return "#" + strings.Repeat("x", size-2) + "\n" }
	path := writeList(t, "at.txt", server.URL+"/first\n"+comment(maxListLine)+server.URL+"/last\n")
	if code, _, stderr := exec(t, "fetch", "--input", path); code != 0 {
		t.Errorf("a line of %d bytes: exit code = %d\n%s", maxListLine, code, stderr)
	}
	path = writeList(t, "over.txt", server.URL+"/first\n"+comment(maxListLine+1)+server.URL+"/last\n")
	code, _, stderr := exec(t, "fetch", "--input", path)
	if code != 2 || !strings.Contains(stderr, "over.txt: line 2 is longer than 1048576 bytes, its newline included") {
		t.Errorf("a line of %d bytes: exit code = %d\n%s", maxListLine+1, code, stderr)
	}
	if got := server.asked(); !slices.Equal(slices.Sorted(slices.Values(got)), []string{"/first", "/last"}) {
		t.Errorf("asked for %v", got)
	}
}

// failingClients has every client made for a proxy that names fail.
func failingClients(t *testing.T, fails func(proxy string) bool) {
	t.Helper()
	original := newClient
	t.Cleanup(func() { newClient = original })
	newClient = func(proxy string, opts ...tlsforge.Option) (*tlsforge.Client, error) {
		if fails(proxy) {
			return nil, errors.New("tlsforge: the transport would not have it")
		}
		return original(proxy, opts...)
	}
}

func TestAClientTheLibraryWillNotMake(t *testing.T) {
	// What the flags could ask that the library refuses is refused before a
	// command starts. What is left is the library's own trouble.
	t.Run("for a run that goes one way", func(t *testing.T) {
		failingClients(t, func(string) bool { return true })
		path := filepath.Join(t.TempDir(), "trace.json")
		code, _, stderr := exec(t, "fetch", "--trace", path, "http://127.0.0.1:1/")
		if code != 1 || !strings.Contains(stderr, "the transport would not have it") {
			t.Errorf("exit code = %d\n%s", code, stderr)
		}
		if last := traceFile(t, path); !strings.Contains(fmt.Sprint(last[len(last)-1].Args["error"]), "would not have it") {
			t.Errorf("the trace ends as %v", last[len(last)-1].Args)
		}
	})
	t.Run("for one way of a list", func(t *testing.T) {
		server := keepingPaths(t)
		failingClients(t, func(proxy string) bool { return proxy == "http://127.0.0.1:2" })
		path := filepath.Join(t.TempDir(), "trace.json")
		list := writeList(t, "list.csv", fmt.Sprintf("url,proxy\n%[1]s/direct,\n%[1]s/through,http://127.0.0.1:2\n", server.URL))
		code, stdout, stderr := exec(t, "fetch", "--input", list, "--trace", path)
		if code != 1 {
			t.Errorf("exit code = %d\n%s", code, stderr)
		}
		got := lines(t, stdout)
		if r := got[server.URL+"/through"]; !strings.Contains(r.Error, "would not have it") {
			t.Errorf("the entry through it: %+v", r)
		}
		if r := got[server.URL+"/direct"]; r.Status != 200 {
			t.Errorf("the entry without it: %+v", r)
		}
		refused := one(t, traceFile(t, path), phaseInstant, "error")
		if refused.Args["url"] != server.URL+"/through" {
			t.Errorf("the entry that never became a request was traced as %+v", refused)
		}
	})
	t.Run("for the proxy command", func(t *testing.T) {
		failingClients(t, func(string) bool { return true })
		dir := t.TempDir()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var out bytes.Buffer
		code := run(ctx, []string{"proxy", "--addr", "127.0.0.1:0", "--ca-cert", filepath.Join(dir, "ca.pem"),
			"--ca-key", filepath.Join(dir, "ca.key")}, &out, &out)
		if code != 1 || !strings.Contains(out.String(), "would not have it") {
			t.Errorf("exit code = %d\n%s", code, out.String())
		}
	})
}

func TestAListThatDoesNotReadAsOneIsAUsageErrorAndAFailedReadIsNot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		decode func() error
		usage  bool
	}{
		{"csv with a quote left open", func() error { _, err := decodeCSVJobs(strings.NewReader(`"https://a/`), "l.csv"); return err }, true},
		{"json that is not an array", func() error { _, err := decodeJSONJobs(strings.NewReader("{"), "l.json"); return err }, true},
		{"json with an entry of the wrong shape", func() error { _, err := decodeJSONJobs(strings.NewReader("[7]"), "l.json"); return err }, true},
		{"csv that cannot be read", func() error { _, err := decodeCSVJobs(failingReader{}, "l.csv"); return err }, false},
		{"json that cannot be read", func() error { _, err := decodeJSONJobs(failingReader{}, "l.json"); return err }, false},
		{"lines that cannot be read", func() error { _, err := decodeLineJobs(failingReader{}, "l.txt"); return err }, false},
	} {
		if err := tc.decode(); err == nil || errors.Is(err, errUsage) != tc.usage {
			t.Errorf("%s: %v, want a usage error: %v", tc.name, err, tc.usage)
		}
	}
}
