package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/igor-lemon/fhttp/http2"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// logRecord is one record of a JSON log, each value as fmt.Sprint says it.
type logRecord map[string]any

// testing redirects os.Stderr to os.Stdout after package initialization in
// test2json mode. The logger must retain the standard error it was given at
// initialization, even when the test runner later replaces the global file.
var standardErrorAtInit = os.Stderr

func (r logRecord) get(key string) string {
	if value, ok := r[key]; ok {
		return fmt.Sprint(value)
	}
	return ""
}

// logRecords are the records of a log written as JSON lines.
func logRecords(t *testing.T, path string) []logRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}
	var out []logRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record logRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("a line of the log is not JSON: %q: %v", line, err)
		}
		out = append(out, record)
	}
	return out
}

// recordsOf are the records of a message with these fields, in order.
func recordsOf(records []logRecord, msg string, fields ...string) []logRecord {
	var out []logRecord
	for _, record := range records {
		if record.get("msg") != msg {
			continue
		}
		matches := true
		for i := 0; i+1 < len(fields); i += 2 {
			if record.get(fields[i]) != fields[i+1] {
				matches = false
			}
		}
		if matches {
			out = append(out, record)
		}
	}
	return out
}

func TestFetchKeepsARunLogInItsOutput(t *testing.T) {
	clock := fakeClock(t)
	server := startEcho(t)
	dir := filepath.Join(t.TempDir(), "out")

	code, _, stderr := exec(t, "fetch", "--insecure", "-o", dir, server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Named for the moment the run began, beside what it kept.
	path := filepath.Join(dir, "run-"+stamp(clock.now())+".log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no log of the run: %v\n%s", err, keptIn(t, dir))
	}
	text := string(data)
	// Everything, by default: the run, each step of the request, the handshake,
	// the frames that came back, and how it ended.
	for _, want := range []string{
		"level=INFO msg=run version=v1.0.0 profile=", "level=INFO msg=client client=",
		"level=INFO msg=request worker=1 req=1 try=1 client=", "level=DEBUG msg=\"dns lookup\"",
		"level=DEBUG msg=connected", "level=TRACE msg=\"client hello\"", "level=TRACE msg=certificate",
		"level=TRACE msg=transport said=\"http2: Transport received SETTINGS", "level=DEBUG msg=\"request sent\"",
		"level=INFO msg=result worker=1 req=1 url=" + server.URL() + "/api/all outcome=scraped status=200",
		"level=INFO msg=summary", "level=INFO msg=\"run ended\"",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the log has no %q:\n%s", want, text)
		}
	}
	// To the microsecond, which is what a handshake is measured in.
	if !regexp.MustCompile(`(?m)^time=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}[+-Z]`).MatchString(text) {
		t.Errorf("the times are not to the microsecond:\n%s", text)
	}
	// The header fields the transport encodes are not said by it: they are in
	// what the request sent, without their secrets.
	if strings.Contains(text, "encoding header") {
		t.Errorf("the transport's header fields were written down:\n%s", text)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the log has mode %v (%v), want 0600", info.Mode().Perm(), err)
		}
	}
}

func TestFetchLogsWhereItIsTold(t *testing.T) {
	server, _ := replying(t, 503, 200)
	dir := filepath.Join(t.TempDir(), "out")
	// A directory that is not there yet is made for it, and a name ending in
	// .jsonl is written as JSON lines.
	path := filepath.Join(t.TempDir(), "logs", "run.jsonl")

	code, _, stderr := exec(t, "fetch", "--retry", "1", "-o", dir, "--log", path, "--log-level", "INFO", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if kept := keptIn(t, dir); slices.ContainsFunc(kept, func(name string) bool { return strings.HasPrefix(name, "run-") }) {
		t.Errorf("a log was kept in the output as well: %v", kept)
	}
	records := logRecords(t, path)
	for _, record := range records {
		if level := record.get("level"); level != "INFO" && level != "WARN" {
			t.Errorf("an info log has %v", record)
		}
	}
	if run := recordsOf(records, "run"); len(run) != 1 || run[0].get("log_level") != "info" || run[0].get("retry") != "1" {
		t.Errorf("the run was said as %v", run)
	}
	// The try that was turned away, why it was made again, and the one that
	// came back.
	if answers := recordsOf(records, "response", "req", "1"); len(answers) != 2 ||
		answers[0].get("status") != "503" || answers[0].get("try") != "1" || answers[1].get("try") != "2" {
		t.Errorf("the answers were said as %v", answers)
	}
	if again := recordsOf(records, "retry", "req", "1", "try", "1"); len(again) != 1 ||
		again[0].get("reason") != "HTTP 503" || again[0].get("next") != "2" {
		t.Errorf("the retry was said as %v", again)
	}
	if result := recordsOf(records, "result"); len(result) != 1 || result[0].get("outcome") != "scraped" ||
		result[0].get("attempts") != "2" || result[0].get("worker") != "1" {
		t.Errorf("the result was said as %v", result)
	}

	// Added to, rather than replaced, by the next run.
	if code, _, stderr := exec(t, "fetch", "--log", path, "--log-level", "info", server.URL); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if runs := recordsOf(logRecords(t, path), "run"); len(runs) != 2 {
		t.Errorf("the log holds %d runs, want both", len(runs))
	}
}

func TestFetchLogsWhatItFoundOfThePage(t *testing.T) {
	server, _ := replying(t, 200, 200)
	path := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--retry", "1", "--wait-for", "answer-2", "--log", path, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	records := logRecords(t, path)
	if without := recordsOf(records, "page check", "try", "1"); len(without) != 1 ||
		without[0].get("found") != `no text matching "answer-2"` || without[0].get("level") != "WARN" {
		t.Errorf("the first try's page was said as %v", without)
	}
	if with := recordsOf(records, "page check", "try", "2"); len(with) != 1 || with[0].get("found") != "what the page has" {
		t.Errorf("the second try's page was said as %v", with)
	}
	if again := recordsOf(records, "retry"); len(again) != 1 || again[0].get("reason") != `no text matching "answer-2"` {
		t.Errorf("the retry was said as %v", again)
	}

	// One that never has it ends as lacking, and as a warning.
	path = filepath.Join(t.TempDir(), "run.json")
	if code, _, _ := exec(t, "fetch", "--wait-for", "nowhere", "--log", path, server.URL); code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if result := recordsOf(logRecords(t, path), "result"); len(result) != 1 || result[0].get("outcome") != "lacking" ||
		result[0].get("level") != "WARN" || result[0].get("page") != `no text matching "nowhere"` {
		t.Errorf("the result was said as %v", result)
	}
}

func TestFetchLogsHowARunThatFailedEnded(t *testing.T) {
	server, _ := replying(t, 503)
	path := filepath.Join(t.TempDir(), "run.json")
	nowhere := "https://" + deadAddr(t) + "/"
	if code, _, _ := exec(t, "fetch", "--log", path, server.URL, nowhere); code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	records := logRecords(t, path)
	byURL := map[string]logRecord{}
	for _, result := range recordsOf(records, "result") {
		byURL[result.get("url")] = result
	}
	if warned := byURL[server.URL+"/"]; warned.get("outcome") != "not_2xx" || warned.get("level") != "WARN" {
		t.Errorf("the 503 was said as %v", warned)
	}
	if failed := byURL[nowhere]; failed.get("outcome") != "no_response" ||
		failed.get("level") != "WARN" || !strings.Contains(failed.get("error"), "refused") {
		t.Errorf("the request that got nothing was said as %v", failed)
	}
	if ended := recordsOf(records, "run ended"); len(ended) != 1 || ended[0].get("level") != "WARN" ||
		!strings.Contains(ended[0].get("error"), "1 of 2 requests got no response") {
		t.Errorf("the end was said as %v", ended)
	}
}

func TestFetchLogToStandardError(t *testing.T) {
	server, _ := replying(t, 200)
	code, _, stderr := exec(t, "fetch", "--log", "-", "--log-level", "info", "--progress", "always",
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Each record whole, to the end of its line, where the status line was
	// erased to make room for it and is drawn again under it.
	for _, want := range []string{"level=INFO msg=run ", "level=INFO msg=result ", "level=INFO msg=\"run ended\""} {
		if !regexp.MustCompile(`time=\S+ ` + regexp.QuoteMeta(want) + "[^\n\x1b]*\n").MatchString(stderr) {
			t.Errorf("standard error has no line with %q:\n%s", want, stderr)
		}
	}
	// None written on the end of the status line, which is erased first.
	if regexp.MustCompile("elapsed[^\n\x1b]*(?:\x1b\\[K)*time=").MatchString(stderr) {
		t.Errorf("a record was written over the status line:\n%q", stderr)
	}
	// What is said after the count is left where it ended comes after it,
	// without drawing it again.
	last := strings.LastIndex(stderr, "2/2")
	if summary := strings.Index(stderr, "msg=summary"); summary < last {
		t.Errorf("the summary was written before the count was left:\n%s", stderr)
	}
}

func TestFetchLogFlagsThatAreRefused(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(input, []byte("https://example.test/\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	linked := filepath.Join(dir, "linked.txt")
	if err := os.Symlink(input, linked); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	hard := filepath.Join(dir, "hard.txt")
	if err := os.Link(input, hard); err != nil {
		t.Fatalf("Link: %v", err)
	}
	trace := filepath.Join(dir, "run.trace.json")
	for _, tc := range []struct {
		args []string
		says string
	}{
		{[]string{"--log-level", "loud", "https://example.test/"},
			`--log-level is "loud", want error, warn, info, debug or trace`},
		{[]string{"--log", input, "--input", input}, "--log " + input + " is the file --input names"},
		// Under another name, by a link of either kind.
		{[]string{"--log", linked, "--input", input}, "is the file --input names"},
		{[]string{"--log", hard, "--input", input}, "is the file --input names"},
		{[]string{"--log", trace, "--trace", trace, "https://example.test/"}, "is the file --trace names"},
	} {
		code, _, stderr := exec(t, append([]string{"fetch"}, tc.args...)...)
		if code != 2 || !strings.Contains(stderr, tc.says) {
			t.Errorf("%q: exit code = %d\n%s", tc.args, code, stderr)
		}
	}
	// Nothing was written to what the run reads.
	if data, _ := os.ReadFile(input); string(data) != "https://example.test/\n" {
		t.Errorf("the list was written to: %q", data)
	}
}

// unwritableLog takes nothing.
type unwritableLog struct{}

func (unwritableLog) Write([]byte) (int, error) { return 0, errors.New("disk full") }
func (unwritableLog) Close() error              { return nil }

func TestFetchLogThatCannotBeWritten(t *testing.T) {
	server, asked := replying(t, 200)
	original := openLogFile
	t.Cleanup(func() { openLogFile = original })

	// Said once, when the run is over, and the run made all the same.
	openLogFile = func(string) (io.WriteCloser, error) { return unwritableLog{}, nil }
	path := filepath.Join(t.TempDir(), "run.log")
	code, stdout, stderr := exec(t, "fetch", "--log", path, server.URL)
	if code != 1 || stdout != "answer-1" ||
		!strings.Contains(stderr, "tlsforge: fetch: writing the log "+path+": disk full") {
		t.Errorf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("the server was asked %d times", got)
	}

	// Nor when it cannot be closed.
	openLogFile = func(string) (io.WriteCloser, error) {
		return &closingBuffer{closeErr: errors.New("closed twice")}, nil
	}
	if code, _, stderr := exec(t, "fetch", "--log", path, server.URL); code != 1 ||
		!strings.Contains(stderr, "writing the log "+path+": closed twice") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}

	// Nor opened at all, which stops the run before it asks anybody anything.
	openLogFile = func(string) (io.WriteCloser, error) { return nil, errors.New("no such device") }
	if code, _, stderr := exec(t, "fetch", "--log", path, server.URL); code != 1 ||
		!strings.Contains(stderr, "tlsforge: fetch: no such device") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	openLogFile = original
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A file where its directory would go is refused before the run.
	if code, _, stderr := exec(t, "fetch", "--log", filepath.Join(file, "run.log"), server.URL); code != 2 ||
		!strings.Contains(stderr, "cannot be written: "+file+" is not a directory") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	// A directory it may not make one in is found out by trying, and stops
	// the run as one that will not open does.
	if runtime.GOOS != "windows" {
		notRoot(t)
		locked := filepath.Join(t.TempDir(), "locked")
		if err := os.Mkdir(locked, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		lock(t, locked, 0o500)
		path := filepath.Join(locked, "logs", "run.log")
		if code, _, stderr := exec(t, "fetch", "--log", path, server.URL); code != 1 ||
			!strings.Contains(stderr, "tlsforge: fetch: mkdir "+filepath.Dir(path)) {
			t.Errorf("exit code = %d\n%s", code, stderr)
		}
	}
	if got := asked.Load(); got != 2 {
		t.Errorf("the server was asked %d times", got)
	}
}

// closingBuffer keeps what is written, and fails to close.
type closingBuffer struct {
	bytes.Buffer
	closeErr error
}

func (b *closingBuffer) Close() error { return b.closeErr }

func TestFetchLogKeepsSecretsOut(t *testing.T) {
	server := startEcho(t)
	via := startProxy(t)
	path := filepath.Join(t.TempDir(), "run.log")
	code, _, stderr := exec(t, "fetch", "--insecure", "--log", path, "-x", "http://user:s3cr3t@"+via.addr,
		"-b", "session=s3cr3t-cookie", "-H", "Authorization: Bearer s3cr3t-token", server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	for _, want := range []string{
		"msg=\"proxy connect\"", "Proxy-Authorization: Basic ***", "msg=\"proxy answer\"",
		"proxy=http://user@" + via.addr, "cookie: session=***", "authorization: Bearer ***",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the log has no %q:\n%s", want, text)
		}
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("user:s3cr3t"))
	if strings.Contains(text, "s3cr3t") || strings.Contains(text, credentials) {
		t.Errorf("a secret was written down:\n%s", text)
	}
}

func TestFetchLogsWhatIsAskedAroundTheRequests(t *testing.T) {
	// Where the run comes out, the session it was warmed from and the one it
	// saved, and the report.
	server, _ := replying(t, 200)
	dir := t.TempDir()
	cookies := filepath.Join(dir, "cookies.json")
	saved := filepath.Join(dir, "saved.json")
	report := filepath.Join(dir, "run.html")
	path := filepath.Join(dir, "run.json")
	session := `[{"name":"seen","value":"1","domain":"127.0.0.1","path":"/"}]`
	if err := os.WriteFile(cookies, []byte(session), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	code, _, stderr := exec(t, "fetch", "--exit-lookup", "--log", path, "--cookies", cookies, "--save-cookies", saved,
		"--report="+report, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	records := logRecords(t, path)
	if exit := recordsOf(records, "exit"); len(exit) != 1 || exit[0].get("said") != "203.0.113.7 · PL (by "+ipServices[0].name()+")" ||
		exit[0].get("proxy") != "" {
		t.Errorf("where the run came out was said as %v", exit)
	}
	if asked := recordsOf(records, "request", "purpose", "where the run comes out"); len(asked) != 1 {
		t.Errorf("asking where the run comes out was said as %v", asked)
	}
	if loaded := recordsOf(records, "cookies loaded"); len(loaded) != 1 || !strings.Contains(loaded[0].get("from"), cookies) {
		t.Errorf("the session was said as %v", loaded)
	}
	if kept := recordsOf(records, "cookies saved", "file", saved); len(kept) != 1 || kept[0].get("cookies") != "1" {
		t.Errorf("the saved session was said as %v", kept)
	}
	if written := recordsOf(records, "report", "file", report, "format", "html"); len(written) != 1 {
		t.Errorf("the report was said as %v", recordsOf(records, "report"))
	}
}

func TestTransportLevel(t *testing.T) {
	for _, tc := range []struct {
		line   string
		level  slog.Level
		logged bool
	}{
		{`http2: Transport encoding header "cookie" = "session=s3cr3t"`, 0, false},
		{"http2: Transport received SETTINGS len=18", tlsforge.LevelTrace, true},
		{"http2: Transport creating client conn 0x1 to 127.0.0.1:443", tlsforge.LevelTrace, true},
		{"http2: Transport readFrame error on conn 0x1: EOF", tlsforge.LevelTrace, true},
		{"transport got GOAWAY with error code = ENHANCE_YOUR_CALM", tlsforge.LevelTrace, true},
		// Said without being asked: a server breaking the protocol, a cookie
		// that is not kept, and anything not known to be said only when asked.
		{"http2: Transport received unsolicited DATA frame; closing connection", slog.LevelWarn, true},
		{"protocol error: received DATA before a HEADERS frame", slog.LevelWarn, true},
		{`net/http: invalid Cookie.Domain "x y"; dropping domain attribute`, slog.LevelWarn, true},
		{"something new", slog.LevelWarn, true},
	} {
		level, logged := transportLevel(tc.line)
		if level != tc.level || logged != tc.logged {
			t.Errorf("transportLevel(%q) = %v, %v", tc.line, level, logged)
		}
	}
}

func TestTransportSaid(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		// A header field it decoded, which it says when GODEBUG asks: the
		// value without its secret, as every request's record has it.
		{`http2: decoded hpack field header field "set-cookie" = "sid=s3cr3t; Path=/"`,
			`http2: decoded hpack field header field "set-cookie" = "sid=***; Path=/"`},
		{`http2: decoded hpack field header field "authorization" = "Bearer s3cr3t" (sensitive)`,
			`http2: decoded hpack field header field "authorization" = "Bearer ***" (sensitive)`},
		{`http2: decoded hpack field header field "x-weird" = "a \"quoted\" s3cr3t-key"`,
			`http2: decoded hpack field header field "x-weird" = "a \"quoted\" s3cr3t-key"`},
		{`http2: decoded hpack field header field "x-api-key" = "s3cr3t"`,
			`http2: decoded hpack field header field "x-api-key" = "***"`},
		{`http2: decoded hpack field header field ":status" = "200"`,
			`http2: decoded hpack field header field ":status" = "200"`},
		// Anything else, with no URL's password in it.
		{"RoundTrip failure: proxyconnect http://alice:s3cr3t@proxy.test: refused",
			"RoundTrip failure: proxyconnect http://alice@proxy.test: refused"},
		{"http2: Transport received PING len=8", "http2: Transport received PING len=8"},
	} {
		if got := transportSaid(tc.line); got != tc.want {
			t.Errorf("transportSaid(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestTheTransportIsHeardThroughTheStandardLogger(t *testing.T) {
	if !http2.VerboseLogs || log.Writer() != transportLines || log.Flags() != 0 || transportLines.unlogged != standardErrorAtInit {
		t.Fatalf("the transport's HTTP/2 is not heard: verbose=%v writer_matches=%v flags=%d stderr_matches=%v", http2.VerboseLogs, log.Writer() == transportLines, log.Flags(), transportLines.unlogged == standardErrorAtInit)
	}
	// Nobody listening: what it says only when asked is said to nobody, and
	// what it says unasked goes to standard error, as it always did.
	var unlogged bytes.Buffer
	swap := func(w io.Writer) io.Writer {
		transportLines.mu.Lock()
		defer transportLines.mu.Unlock()
		was := transportLines.unlogged
		transportLines.unlogged = w
		return was
	}
	original := swap(&unlogged)
	t.Cleanup(func() { swap(original) })
	log.Print("http2: Transport received PING len=8")
	log.Print("protocol error: received DATA before a HEADERS frame")
	if !regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d protocol error: received DATA before a HEADERS frame\n$`).
		MatchString(unlogged.String()) {
		t.Errorf("standard error had %q", unlogged.String())
	}
	unlogged.Reset()

	var first, second bytes.Buffer
	one := slog.New(slog.NewJSONHandler(&first, &slog.HandlerOptions{Level: tlsforge.LevelTrace}))
	two := slog.New(slog.NewJSONHandler(&second, &slog.HandlerOptions{Level: slog.LevelWarn}))
	transportLines.add(one)
	transportLines.add(two)
	log.Print("http2: Transport received PING len=8")
	log.Print("protocol error: received DATA on a HEAD request")
	log.Printf("http2: Transport encoding header %q = %q", "cookie", "session=s3cr3t")
	log.Printf("http2: decoded hpack field header field %q = %q", "set-cookie", "session=s3cr3t")
	transportLines.remove(one)
	transportLines.remove(two)
	log.Print("http2: Transport received GOAWAY len=8")

	if got := strings.Count(first.String(), `"msg":"transport"`); got != 3 ||
		!strings.Contains(first.String(), `"said":"http2: Transport received PING len=8"`) {
		t.Errorf("the first log heard:\n%s", first.String())
	}
	if !strings.Contains(second.String(), "received DATA on a HEAD request") || strings.Contains(second.String(), "PING") {
		t.Errorf("the second log heard:\n%s", second.String())
	}
	if strings.Contains(first.String()+second.String(), "s3cr3t") || strings.Contains(first.String(), "GOAWAY") {
		t.Errorf("heard too much:\n%s\n%s", first.String(), second.String())
	}
	// With a log open, none of it is on standard error.
	if unlogged.Len() != 0 {
		t.Errorf("standard error had %q", unlogged.String())
	}
}

func TestLogAttr(t *testing.T) {
	when := time.Date(2026, 10, 15, 9, 8, 7, 123456789, time.UTC)
	if got := logAttr(nil, slog.Time(slog.TimeKey, when)); got.Value.String() != "2026-10-15T09:08:07.123456Z" {
		t.Errorf("time = %v", got.Value)
	}
	for level, want := range map[slog.Level]string{
		tlsforge.LevelTrace: "TRACE", slog.LevelDebug: "DEBUG", slog.LevelWarn: "WARN",
	} {
		if got := logAttr(nil, slog.Any(slog.LevelKey, level)); got.Value.String() != want {
			t.Errorf("level %v = %v", level, got.Value)
		}
	}
	// Only the record's own: a field of a group called time is a field, and so
	// is one called time that holds no time.
	if got := logAttr([]string{"group"}, slog.Time(slog.TimeKey, when)); got.Value.Kind() != slog.KindTime {
		t.Errorf("a grouped time = %v", got.Value)
	}
	if got := logAttr(nil, slog.String(slog.TimeKey, "noon")); got.Value.String() != "noon" {
		t.Errorf("a time that is not one = %v", got.Value)
	}
	if got := logAttr(nil, slog.String(slog.LevelKey, "loud")); got.Value.String() != "loud" {
		t.Errorf("a level that is not one = %v", got.Value)
	}
}

func TestRunAttrs(t *testing.T) {
	got := runAttrs(traceArgs{"b": 2, "a": 1}, "kept", "yes", "empty", "", "zero", 0)
	want := []any{"kept", "yes", "zero", 0, "a", 1, "b", 2}
	if !slices.Equal(got, want) {
		t.Errorf("runAttrs = %v, want %v", got, want)
	}
}

func TestTheRunLogEndsSayingNoPasswordOfAnyURL(t *testing.T) {
	// However the run's error came to quote one: the library masks its own,
	// and this is the log's own guard, whoever made the error.
	original := openLogFile
	t.Cleanup(func() { openLogFile = original })
	written := &closingBuffer{}
	openLogFile = func(string) (io.WriteCloser, error) { return written, nil }
	l, err := openRunLog(filepath.Join(t.TempDir(), "run.log"), slog.LevelInfo, "", now(), newPrinter(io.Discard))
	if err != nil {
		t.Fatalf("openRunLog: %v", err)
	}
	ended := errors.Join(errors.New("fetch: 1 of 2 requests got no response"),
		errors.New(`tlsforge: parse "http://alice:s3cr3t@[bad": missing ']' in host`))
	if err := l.close(ended); err != nil {
		t.Fatalf("close: %v", err)
	}
	if said := written.String(); strings.Contains(said, "s3cr3t") || !strings.Contains(said, `http://alice@[bad`) {
		t.Errorf("the log ended:\n%s", said)
	}
}

func TestANilRunLogDoesNothing(t *testing.T) {
	var l *runLog
	if l.logger() != nil || l.close(errors.New("x")) != nil || withLog(nil, "a", 1) != nil {
		t.Error("a nil run log did something")
	}
	l.say(slog.LevelInfo, "nothing")
	l.shareStderr(nil)
	// A status line it does not share is closed as it always was.
	counts := newProgress(1)
	var out bytes.Buffer
	line := newStatusLine(newPrinter(&out), io.Discard, counts, palette{})
	l.closeStatus(line)
	(&runLog{}).closeStatus(newStatusLine(newPrinter(&out), io.Discard, counts, palette{}))
}

func TestALogOnStandardErrorGoesAroundTheStatusLine(t *testing.T) {
	var screen bytes.Buffer
	errOut := newPrinter(&screen)
	l, err := openRunLog("-", slog.LevelInfo, "", now(), errOut)
	if err != nil {
		t.Fatalf("openRunLog: %v", err)
	}
	line := newStatusLine(errOut, io.Discard, newProgress(1), palette{})
	l.shareStderr(line)
	line.draw()
	l.say(slog.LevelInfo, "between")
	l.closeStatus(line)
	l.say(slog.LevelInfo, "after")
	if err := l.close(nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	text := screen.String()
	const status = "waiting for the response"
	// The status taken off the screen, the record where it was, and the status
	// drawn again under it.
	between := strings.Index(text, "msg=between")
	record := strings.LastIndex(text[:between], "time=")
	if !strings.HasPrefix(text, lineStart+"  "+status) || !strings.HasSuffix(text[:record], eraseLine) {
		t.Errorf("the record was not written where the status was:\n%q", text)
	}
	if !strings.Contains(text[between:], status) {
		t.Errorf("the status was not drawn again under the record:\n%q", text)
	}
	// Once it is left where it ended, a record goes under it, and it is not
	// drawn again.
	after := strings.Index(text, "msg=after")
	if after < strings.LastIndex(text, status) || !strings.HasSuffix(text, "msg=\"run ended\"\n") {
		t.Errorf("what came after the status was:\n%q", text)
	}
}
