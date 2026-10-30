package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// traceFile is a trace file as the events in it. It has to parse as the JSON
// array it claims to be: that is what a viewer is going to do with it.
func traceFile(t *testing.T, path string) []traceEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the trace: %v", err)
	}
	return parseTrace(t, data)
}

func parseTrace(t *testing.T, data []byte) []traceEvent {
	t.Helper()
	var events []traceEvent
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatalf("the trace is not a JSON array: %v\n%s", err, data)
	}
	return events
}

// named are the events of one kind with one name, in file order.
func named(events []traceEvent, phase, name string) []traceEvent {
	var found []traceEvent
	for _, event := range events {
		if event.Phase == phase && event.Name == name {
			found = append(found, event)
		}
	}
	return found
}

// one is the only event of a kind with a name, which is what most tests want.
func one(t *testing.T, events []traceEvent, phase, name string) traceEvent {
	t.Helper()
	found := named(events, phase, name)
	if len(found) != 1 {
		t.Fatalf("%d %q events named %q, want 1:\n%s", len(found), phase, name, dump(events))
	}
	return found[0]
}

// steps are the names of what was drawn on one row, in the order it happened.
func steps(events []traceEvent, tid int) []string {
	drawn := make([]traceEvent, 0, len(events))
	for _, event := range events {
		if event.TID == tid && (event.Phase == phaseComplete || event.Phase == phaseInstant) {
			drawn = append(drawn, event)
		}
	}
	sort.SliceStable(drawn, func(i, j int) bool { return drawn[i].TS < drawn[j].TS })
	names := make([]string, 0, len(drawn))
	for _, event := range drawn {
		names = append(names, event.Name)
	}
	return names
}

func dump(events []traceEvent) string {
	var out strings.Builder
	for _, event := range events {
		line, _ := json.Marshal(event)
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// follows reports whether the names appear in the steps, in that order, with
// anything at all between them.
func follows(all []string, wanted ...string) bool {
	at := 0
	for _, step := range all {
		if at < len(wanted) && step == wanted[at] {
			at++
		}
	}
	return at == len(wanted)
}

// checkShape holds a trace to what a viewer assumes about one.
//
// Perfetto sorts the file by time and decides what is inside what from the
// order, so no two events may share a moment, and whatever is drawn on a row
// must either sit inside what is already there or come after it. A bar that
// starts inside another and ends outside it is dropped on import, silently.
func checkShape(t *testing.T, events []traceEvent) {
	t.Helper()
	type bar struct {
		name     string
		from, to int64
	}
	moments := map[int64]bool{}
	rows := map[int][]bar{}
	open := map[int][]bar{}

	for _, event := range events {
		if event.Phase == phaseMetadata {
			continue
		}
		if event.TS == 0 {
			t.Errorf("an event has no time: %+v", event)
		}
		if moments[event.TS] {
			t.Errorf("two events share the moment %d: %+v", event.TS, event)
		}
		moments[event.TS] = true

		switch event.Phase {
		case phaseBegin:
			open[event.TID] = append(open[event.TID], bar{name: event.Name, from: event.TS})
		case phaseEnd:
			stack := open[event.TID]
			if len(stack) == 0 {
				t.Fatalf("an end with nothing begun on row %d:\n%s", event.TID, dump(events))
			}
			begun := stack[len(stack)-1]
			open[event.TID] = stack[:len(stack)-1]
			begun.to = event.TS
			rows[event.TID] = append(rows[event.TID], begun)
		case phaseComplete:
			if event.Dur <= 0 {
				t.Errorf("%q took no time at all: %+v", event.Name, event)
			}
			rows[event.TID] = append(rows[event.TID],
				bar{name: event.Name, from: event.TS, to: event.TS + event.Dur})
		}
	}
	for tid, left := range open {
		if len(left) != 0 {
			t.Errorf("row %d was left with %d bars open: %+v", tid, len(left), left)
		}
	}

	for tid, bars := range rows {
		sort.Slice(bars, func(i, j int) bool { return bars[i].from < bars[j].from })
		var around []bar
		for _, b := range bars {
			for len(around) > 0 && around[len(around)-1].to <= b.from {
				around = around[:len(around)-1]
			}
			if len(around) > 0 && b.to > around[len(around)-1].to {
				t.Errorf("row %d: %q (%d–%d) starts inside %q (%d–%d) and ends outside it",
					tid, b.name, b.from, b.to, around[len(around)-1].name,
					around[len(around)-1].from, around[len(around)-1].to)
			}
			around = append(around, b)
		}
	}
}

func TestFetchTraceIsATraceEventFile(t *testing.T) {
	// Over TLS and by name, so every step a request can take is taken: a lookup,
	// a dial, a handshake, the request, the wait and the answer.
	server := startEcho(t)
	url := server.URL() + "/api/all"
	path := filepath.Join(t.TempDir(), "trace.json")

	code, stdout, stderr := exec(t, "fetch", "--exit-lookup", "--insecure", "--trace", path, url)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout, `"tls"`) {
		t.Errorf("tracing a fetch changed what it printed: %q", stdout)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no trace was written: %v", err)
	}
	// One event to a line, inside the brackets of an array.
	lines := strings.Split(string(raw), "\n")
	if lines[0] != "[" || lines[len(lines)-2] != "]" || lines[len(lines)-1] != "" {
		t.Fatalf("the trace is not bracketed as an array on lines of its own:\n%s", raw)
	}
	for i, line := range lines[1 : len(lines)-2] {
		closing := "},"
		if i == len(lines)-4 {
			closing = "}"
		}
		if !strings.HasPrefix(line, `{"ph":"`) || !strings.HasSuffix(line, closing) {
			t.Errorf("line %d is not one event: %s", i+2, line)
		}
	}

	events := traceFile(t, path)
	checkShape(t, events)

	// The rows are named, for whoever opens the file in a viewer.
	if got := one(t, events, phaseMetadata, "process_name").Args["name"]; got != "tls-forge fetch" {
		t.Errorf("process is named %v", got)
	}
	if lane := one(t, events, phaseMetadata, "thread_name"); lane.TID != mainLane || lane.Args["name"] != "fetch" {
		t.Errorf("the command's row is %+v", lane)
	}

	// The run itself, with what it was asked to do.
	began := one(t, events, phaseBegin, "fetch")
	for key, want := range map[string]any{
		"url": url, "method": "GET", "timeout": "30s", "retry": 0.0, "repeat": 1.0, "version": version,
	} {
		if got := began.Args[key]; got != want {
			t.Errorf("fetch was begun with %s = %v, want %v", key, got, want)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, fmt.Sprint(began.Args["started"])); err != nil {
		t.Errorf("the run does not say when it started in words: %v", began.Args["started"])
	}
	if agent := one(t, events, phaseInstant, "profile").Args["user_agent"]; agent == "" || agent == nil {
		t.Error("the trace does not say which browser the run was being")
	}
	if exit := one(t, events, phaseComplete, "exit-ip"); exit.Args["ip"] != "203.0.113.7" || exit.Args["country"] != "PL" {
		t.Errorf("exit address traced as %v", exit.Args)
	}

	// The request, and inside it what it went through, in the order it did.
	request := one(t, events, phaseBegin, "GET "+url)
	if request.Cat != "request" || request.Args["attempt"] != 1.0 || request.Args["run"] != 1.0 ||
		request.Args["url"] != url {
		t.Errorf("the request was begun as %+v", request)
	}
	if got := steps(events, mainLane); !follows(got, "dns", "connect", "tls", "send", "wait", "receive") {
		t.Errorf("steps = %v, want a lookup, a dial, a handshake, the request, the wait and the answer", got)
	}
	if lookup := one(t, events, phaseComplete, "dns"); lookup.Args["host"] != "localhost" || lookup.Args["addrs"] == nil {
		t.Errorf("the lookup was traced as %v", lookup.Args)
	}
	if dial := one(t, events, phaseComplete, "connect"); dial.Args["addr"] == nil || dial.Cat != "net" {
		t.Errorf("the dial was traced as %+v", dial)
	}
	handshake := one(t, events, phaseComplete, "tls")
	if handshake.Args["tls"] != "TLS 1.3" || handshake.Args["alpn"] != "h2" ||
		!strings.HasPrefix(fmt.Sprint(handshake.Args["cipher"]), "TLS_") {
		t.Errorf("the handshake was traced as %v", handshake.Args)
	}
	sent := one(t, events, phaseComplete, "send")
	headers, _ := sent.Args["headers"].([]any)
	if len(headers) < 5 || headers[0] != ":method: GET" {
		t.Errorf("the request was traced as %v, want its fields in wire order", sent.Args["headers"])
	}
	if sent.Args["reused"] != false || sent.Args["alpn"] != "h2" || sent.Cat != "http" {
		t.Errorf("the connection the request went out on was traced as %+v", sent)
	}
	if got := one(t, events, phaseComplete, "receive").Args["status"]; got != 200.0 {
		t.Errorf("the answer was received with status %v", got)
	}

	// How the request ended, and then the run, which is the last thing said.
	ended := named(events, phaseEnd, "")
	if len(ended) != 2 {
		t.Fatalf("%d ends, want the request's and the run's:\n%s", len(ended), dump(events))
	}
	outcome := ended[0].Args
	if outcome["status"] != 200.0 || outcome["final_url"] != url || outcome["bytes"].(float64) <= 0 {
		t.Errorf("the request ended as %v", outcome)
	}
	if got := fmt.Sprint(outcome["headers"]); !strings.Contains(got, "content-type: application/json") {
		t.Errorf("the answer's headers were traced as %v", got)
	}
	if _, has := outcome["body"]; has {
		t.Errorf("a page that was the page had its beginning kept: %v", outcome["body"])
	}
	if last := events[len(events)-1]; last.Phase != phaseEnd || last.TID != mainLane || len(last.Args) != 0 {
		t.Errorf("the trace ends with %+v, want the run ending with nothing to report", last)
	}
}

func TestTraceIsKeptPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits to check")
	}
	server := pathServer(t)
	path := filepath.Join(t.TempDir(), "trace.json")
	if code, _, stderr := exec(t, "fetch", "--trace", path, server.URL); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Every URL the run asked for and every address it went through.
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the trace was written %v, want 0600", mode)
	}
}

func TestTraceReplacesTheOneBefore(t *testing.T) {
	// An array has one closing bracket. A second run appended to the first
	// would leave a file no viewer opens.
	server := pathServer(t)
	path := filepath.Join(t.TempDir(), "trace.json")
	for range 2 {
		if code, _, stderr := exec(t, "fetch", "--trace", path, server.URL+"/again"); code != 0 {
			t.Fatalf("exit code = %d\n%s", code, stderr)
		}
	}
	if got := len(named(traceFile(t, path), phaseBegin, "fetch")); got != 1 {
		t.Errorf("the file holds %d runs, want the last one alone", got)
	}
}

func TestTraceLeavesOutWhatASessionIsWorth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "sid=s3rv3r-s3cr3t; Path=/; HttpOnly")
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "trace.json")

	code, _, stderr := exec(t, "fetch", "--trace", path,
		"-b", "session=cl13nt-s3cr3t",
		"-H", "Authorization: Bearer t0k3n-s3cr3t",
		"-H", "X-Api-Key: k3y-s3cr3t",
		server.URL+"/?first=1&second=2")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no trace was written: %v", err)
	}
	if strings.Contains(string(raw), "s3cr3t") {
		t.Errorf("the trace holds a secret:\n%s", raw)
	}
	// What each was called is kept, because that is what a session that will
	// not stick is debugged by: which cookie went out, and how one was scoped.
	for _, want := range []string{
		"Authorization: Bearer ***",
		"X-Api-Key: ***",
		"Cookie: session=***",
		"set-cookie: sid=***; Path=/; HttpOnly",
		// As somebody would search for it, and not escaped for a web page.
		"/?first=1&second=2",
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the trace has no %q:\n%s", want, raw)
		}
	}
	events := traceFile(t, path)
	checkShape(t, events)
	held := fmt.Sprint(named(events, phaseEnd, "")[0].Args["cookies"])
	if !strings.Contains(held, "session") || !strings.Contains(held, "sid") {
		t.Errorf("the jar was traced as %v, want the names of both cookies", held)
	}
}

func TestTraceThroughAProxyHidesItsPasswordAndNamesTheTunnel(t *testing.T) {
	target, proxy := tlsPathServer(t), startProxy(t)
	path := filepath.Join(t.TempDir(), "trace.json")
	via := "http://user:s3cr3t@" + proxy.addr

	code, _, stderr := exec(t, "fetch", "--exit-lookup", "--insecure", "--proxy", via, "--timeout", "20s",
		"--trace", path, target.URL+"/through")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "s3cr3t") {
		t.Errorf("the trace holds the proxy's password:\n%s", raw)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	// The username stays: it is what tells one proxy from another.
	safe := "http://user@" + proxy.addr
	if got := one(t, events, phaseBegin, "fetch").Args["proxy"]; got != safe {
		t.Errorf("the run's proxy was traced as %v, want %s", got, safe)
	}
	if got := one(t, events, phaseBegin, "GET "+target.URL+"/through").Args["proxy"]; got != safe {
		t.Errorf("the request's proxy was traced as %v, want %s", got, safe)
	}
	// The address is the proxy's to give, so the question goes through it, and
	// the trace says which proxy the answer is about.
	if exit := one(t, events, phaseComplete, "exit-ip"); exit.Args["ip"] != "203.0.113.7" || exit.Args["proxy"] != safe {
		t.Errorf("the lookup through the proxy was traced as %v", exit.Args)
	}
	// Between the dial and the request there was a tunnel as well as a
	// handshake, and the step says both rather than blaming TLS for a proxy.
	if got := steps(events, mainLane); !follows(got, "connect", "proxy+tls", "send", "wait", "receive") {
		t.Errorf("steps = %v", got)
	}
	if dial := one(t, events, phaseComplete, "connect"); dial.Args["addr"] != proxy.addr {
		t.Errorf("the dial went to %v, want the proxy at %s", dial.Args["addr"], proxy.addr)
	}
}

func TestTraceKeepsWhatAWrongAnswerSaidAndWhyItWasAskedAgain(t *testing.T) {
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if asked.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("<title>Service Unavailable</title>"))
			return
		}
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "trace.json")

	code, stdout, stderr := execWorkflow(t, "fetch", "--retry", "2", "--reuse-connection", "--trace", path, server.URL)
	if code != 0 || stdout != "page" {
		t.Fatalf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	tries := named(events, phaseBegin, "GET "+server.URL+"/")
	if len(tries) != 2 || tries[0].Args["attempt"] != 1.0 || tries[1].Args["attempt"] != 2.0 {
		t.Fatalf("tries traced as %+v, want two, numbered", tries)
	}
	ends := named(events, phaseEnd, "")
	// The first answer is replaced by the second everywhere else, so its
	// beginning is kept here, with the header that says when to come back.
	first := ends[0].Args
	if first["status"] != 503.0 || first["body"] != "<title>Service Unavailable</title>" {
		t.Errorf("the wrong answer was traced as %v", first)
	}
	if got := fmt.Sprint(first["headers"]); !strings.Contains(got, "retry-after: 1") {
		t.Errorf("the wrong answer's headers were traced as %v", got)
	}
	if second := ends[1].Args; second["status"] != 200.0 || second["body"] != nil {
		t.Errorf("the page was traced as %v", second)
	}

	again := one(t, events, phaseInstant, "retry")
	if again.Args["reason"] != "HTTP 503" || again.Args["attempt"] != 1.0 || again.Args["wait_ms"] != 0.0 {
		t.Errorf("the retry was traced as %v", again.Args)
	}
	// Between the two tries, where it happened.
	if again.TS <= ends[0].TS || again.TS >= tries[1].TS {
		t.Errorf("the retry is not between the tries it separates")
	}
	// The second try found the first one's connection still open, which the
	// URL kept for it.
	sends := named(events, phaseComplete, "send")
	if len(sends) != 2 || sends[0].Args["reused"] != false || sends[1].Args["reused"] != true {
		t.Errorf("connections traced as %v then %v", sends[0].Args["reused"], sends[1].Args["reused"])
	}
}

func TestTraceFollowsARedirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := 2
		if r.URL.Path == "/hop" {
			want = 1
		}
		// The assertion below describes an answer after WroteRequest. A
		// loopback server can otherwise answer before that hook runs, which
		// correctly leaves no wait span. Observing the send event establishes
		// the intended order: wroteRequest holds the attempt mutex through
		// emitting it and beginning wait, so firstByte cannot overtake it.
		for deadline := time.Now().Add(5 * time.Second); ; {
			data, _ := os.ReadFile(path)
			if bytes.Count(data, []byte(`"name":"send"`)) >= want {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("request %s never emitted send event %d", r.URL.Path, want)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			time.Sleep(time.Millisecond)
		}
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("landed"))
	}))
	t.Cleanup(server.Close)

	if code, _, stderr := exec(t, "fetch", "--trace", path, server.URL+"/hop"); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	hop := one(t, events, phaseInstant, "redirect")
	if hop.Args["status"] != 302.0 || hop.Args["location"] != server.URL+"/landed" {
		t.Errorf("the redirect was traced as %v", hop.Args)
	}
	// One try, two requests: each hop is sent, waited for and received.
	if got := steps(events, mainLane); !follows(got,
		"send", "wait", "receive", "redirect", "send", "wait", "receive") {
		t.Errorf("steps = %v", got)
	}
	received := named(events, phaseComplete, "receive")
	if len(received) != 2 || received[0].Args["status"] != 302.0 || received[1].Args["status"] != 200.0 {
		t.Errorf("the two answers were traced as %+v", received)
	}
	if got := named(events, phaseEnd, "")[0].Args["final_url"]; got != server.URL+"/landed" {
		t.Errorf("the request ended at %v", got)
	}
}

func TestTraceOfARequestThatNeverConnected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.json")
	nowhere := deadAddr(t)
	code, _, _ := exec(t, "fetch", "--timeout", "3s", "--trace", path, "https://"+nowhere+"/gone")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	// The dial is where it stopped, and is drawn as far as it got.
	dial := one(t, events, phaseComplete, "connect")
	if dial.Args["unfinished"] != true || !strings.Contains(fmt.Sprint(dial.Args["failed"]), nowhere) {
		t.Errorf("the dial that failed was traced as %v", dial.Args)
	}
	if got := steps(events, mainLane); follows(got, "send") {
		t.Errorf("a request that never connected was traced as sent: %v", got)
	}
	// Said twice, because it is true twice: the try failed, and so the run did.
	ends := named(events, phaseEnd, "")
	if len(ends) != 2 {
		t.Fatalf("%d ends, want the try's and the run's", len(ends))
	}
	for i, end := range ends {
		if !strings.Contains(fmt.Sprint(end.Args["error"]), nowhere) {
			t.Errorf("end %d does not say why: %v", i+1, end.Args)
		}
	}
}

func TestTraceOfARunThatCouldNotStart(t *testing.T) {
	// A client that cannot be made, found out once the run is under way, so
	// no request. The trace still closes, and ends with the reason.
	failingClients(t, func(string) bool { return true })
	path := filepath.Join(t.TempDir(), "trace.json")
	code, _, _ := exec(t, "fetch", "--trace", path, "https://example.invalid/")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	events := traceFile(t, path)
	checkShape(t, events)
	if len(named(events, phaseBegin, "GET https://example.invalid/")) != 0 {
		t.Error("a request was made by a run that could not start")
	}
	if last := events[len(events)-1]; !strings.Contains(fmt.Sprint(last.Args["error"]), "would not have it") {
		t.Errorf("the run ended as %v, want the reason it could not start", last.Args)
	}
}

func TestFetchTracesTheSessionItLoadsAndSaves(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "fresh=1; Path=/")
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	warmed := filepath.Join(dir, "warmed.json")
	if err := os.WriteFile(warmed, []byte(`[{"id":"one","cookies":[{"name":"kept","value":"v"}]}]`), 0o600); err != nil {
		t.Fatalf("writing the session: %v", err)
	}
	saved, path := filepath.Join(dir, "saved.json"), filepath.Join(dir, "trace.json")

	code, _, stderr := exec(t, "fetch", "--cookies", warmed, "--save-cookies", saved,
		"--trace", path, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	if got := fmt.Sprint(one(t, events, phaseInstant, "cookies loaded").Args["from"]); !strings.Contains(got, "set one, 1 cookies") {
		t.Errorf("the session loaded was traced as %q", got)
	}
	// Saving is a step of the run, so it is inside the trace of it: before the
	// run's own end, which stays the last thing in the file.
	kept := one(t, events, phaseInstant, "cookies saved")
	if kept.Args["file"] != saved || kept.Args["cookies"] != 2.0 {
		t.Errorf("the session saved was traced as %v", kept.Args)
	}
	if last := events[len(events)-1]; last.Phase != phaseEnd || kept.TS >= last.TS {
		t.Errorf("the session was saved after the trace had ended")
	}
}

func TestFetchTracesWhereEachRunWasWritten(t *testing.T) {
	server, _ := replying(t, 200)
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.json")

	kept := filepath.Join(dir, "out")
	code, _, stderr := exec(t, "fetch", "--repeat", "2", "-o", kept, "--trace", path, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	runs := named(events, phaseBegin, "GET "+server.URL+"/")
	written := named(events, phaseInstant, "saved")
	if len(runs) != 2 || len(written) != 2 {
		t.Fatalf("%d runs and %d files traced, want 2 of each", len(runs), len(written))
	}
	for i, file := range written {
		if runs[i].Args["run"] != float64(i+1) {
			t.Errorf("run %d was traced as run %v", i+1, runs[i].Args["run"])
		}
		saved, _ := file.Args["file"].(string)
		if !strings.HasPrefix(saved, kept+string(os.PathSeparator)) || !strings.HasSuffix(saved, fmt.Sprintf("-%d-response.txt", i+1)) ||
			file.Args["bytes"] != 8.0 || file.Cat != "file" {
			t.Errorf("run %d's file was traced as %+v", i+1, file)
		}
	}
}

func TestListTraceHasARowForEveryWorker(t *testing.T) {
	server := pathServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.json")
	nowhere := deadAddr(t)
	list := writeList(t, "list.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/one,\n%[1]s/two,\n%[1]s/three,\n%[1]s/four,\n%[1]s/five,http://%[2]s\n",
		server.URL, nowhere))

	code, _, stderr := exec(t, "fetch", "--input", list, "--concurrency", "2", "--retry", "0",
		"--output", filepath.Join(dir, "out"), "--trace", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (one URL names a proxy nothing answers at)\n%s", code, stderr)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	// A row for the command and one for each worker, named and in order.
	rows := map[int]string{}
	for _, lane := range named(events, phaseMetadata, "thread_name") {
		rows[lane.TID] = fmt.Sprint(lane.Args["name"])
	}
	if want := map[int]string{1: "fetch", 2: "worker 1", 3: "worker 2"}; fmt.Sprint(rows) != fmt.Sprint(want) {
		t.Errorf("rows = %v, want %v", rows, want)
	}
	for _, order := range named(events, phaseMetadata, "thread_sort_index") {
		if order.Args["sort_index"] != float64(order.TID) {
			t.Errorf("row %d sorts as %v", order.TID, order.Args["sort_index"])
		}
	}

	began := one(t, events, phaseBegin, "fetch")
	if began.Args["urls"] != 5.0 || began.Args["url"] != nil || began.Args["concurrency"] != 2.0 ||
		began.Args["retry"] != 0.0 || began.Args["repeat"] != 1.0 || began.TID != mainLane {
		t.Errorf("the run was begun as %+v", began)
	}

	// Requests are drawn on the workers' rows and never on the command's.
	requests, written := 0, 0
	for _, event := range events {
		switch {
		case event.Phase == phaseBegin && event.Cat == "request":
			requests++
			if event.TID == mainLane {
				t.Errorf("a request was drawn on the command's row: %+v", event)
			}
		case event.Phase == phaseInstant && event.Name == "saved":
			written++
		}
	}
	if requests != 5 || written != 4 {
		t.Errorf("%d requests and %d bodies traced, want 5 and 4", requests, written)
	}
	// The one through the proxy nothing answers at ends with why.
	failed := 0
	for _, event := range events {
		if event.Phase == phaseEnd && event.Args["error"] != nil && strings.Contains(fmt.Sprint(event.Args["error"]), nowhere) {
			failed++
		}
	}
	if failed == 0 {
		t.Error("the request through the proxy nothing answers at does not end with why")
	}

	sum := one(t, events, phaseInstant, "summary")
	for key, want := range map[string]any{
		"requests": 5.0, "scraped": 4.0, "not_2xx": 0.0, "no_response": 1.0, "retries": 0.0,
	} {
		if sum.Args[key] != want {
			t.Errorf("summary %s = %v, want %v", key, sum.Args[key], want)
		}
	}
	if last := events[len(events)-1]; last.Args["error"] != "fetch: 1 of 5 requests got no response" {
		t.Errorf("the run ended as %v", last.Args)
	}
}

func TestListTracesTheAddressesItAsksAboutAndTheSessionItSaves(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "fresh=1; Path=/")
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	path, saved := filepath.Join(dir, "trace.json"), filepath.Join(dir, "saved.json")

	code, _, stderr := exec(t, "fetch", "--exit-lookup", "--trace", path, "--save-cookies", saved,
		"--report="+filepath.Join(dir, "report.html"), server.URL+"/one")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	events := traceFile(t, path)
	checkShape(t, events)

	// Asked before the run, on the command's own row, and with no proxy to name.
	exit := one(t, events, phaseComplete, "exit-ip")
	if exit.TID != mainLane || exit.Args["ip"] != "203.0.113.7" || exit.Args["proxy"] != nil {
		t.Errorf("the address lookup was traced as %+v", exit)
	}
	if kept := one(t, events, phaseInstant, "cookies saved"); kept.Args["file"] != saved || kept.Args["cookies"] != 1.0 {
		t.Errorf("the session saved was traced as %v", kept.Args)
	}
}

func TestTraceGoesInADirectoryMadeForIt(t *testing.T) {
	// As a report and a log do: `--trace traces/run.json` is a trace, not a
	// reason to stop before the first request.
	server, _ := replying(t, 200)
	path := filepath.Join(t.TempDir(), "no-such-directory", "deeper", "trace.json")
	if code, _, stderr := exec(t, "fetch", "--trace", path, server.URL); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if events := traceFile(t, path); len(events) == 0 {
		t.Error("the trace is empty")
	}
}

func TestTraceThatCannotBeOpenedStopsTheRunBeforeItStarts(t *testing.T) {
	// A trace was asked for. Running without one would be doing something
	// else, so nobody is asked anything.
	server, asked := replying(t, 200)
	original := createTrace
	t.Cleanup(func() { createTrace = original })
	createTrace = func(string) (io.WriteCloser, error) { return nil, errors.New("no such device") }
	code, _, stderr := exec(t, "fetch", "--trace", filepath.Join(t.TempDir(), "trace.json"), server.URL)
	if code != 1 || !strings.Contains(stderr, "tlsforge: fetch: no such device") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr)
	}
	createTrace = original

	// Nor when its directory cannot be made, which only trying finds out.
	if runtime.GOOS != "windows" {
		notRoot(t)
		locked := filepath.Join(t.TempDir(), "locked")
		if err := os.Mkdir(locked, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		lock(t, locked, 0o500)
		path := filepath.Join(locked, "traces", "trace.json")
		code, _, stderr = exec(t, "fetch", "--trace", path, server.URL)
		if code != 1 || !strings.Contains(stderr, "tlsforge: fetch: mkdir "+filepath.Dir(path)) {
			t.Errorf("exit code = %d, stderr = %q", code, stderr)
		}
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("%d requests were made by runs that could not be traced", got)
	}
}

// brokenFile stands in for a trace file that cannot be written to, or cannot
// be closed, and keeps whatever did get through.
type brokenFile struct {
	bytes.Buffer
	writeErr, closeErr error
	closed             bool
}

func (f *brokenFile) Write(data []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.Buffer.Write(data)
}

func (f *brokenFile) Close() error {
	f.closed = true
	return f.closeErr
}

// traceInto sends the next trace to a stand-in instead of a file.
func traceInto(t *testing.T, file *brokenFile) {
	t.Helper()
	original := createTrace
	t.Cleanup(func() { createTrace = original })
	createTrace = func(string) (io.WriteCloser, error) { return file, nil }
}

func TestATraceThatCannotBeWrittenFailsTheRunWithoutStoppingIt(t *testing.T) {
	server, asked := replying(t, 200)

	t.Run("fetch", func(t *testing.T) {
		file := &brokenFile{writeErr: errors.New("no space left on device")}
		traceInto(t, file)

		code, stdout, stderr := exec(t, "fetch", "--trace", "anywhere", server.URL)
		// The page was fetched and printed: the trace is commentary on the run.
		if stdout != fmt.Sprintf("answer-%d", asked.Load()) {
			t.Errorf("stdout = %q, want the page", stdout)
		}
		// But a trace was asked for and there is none, and that is said.
		if code != 1 || !strings.Contains(stderr, "fetch: writing the trace: no space left on device") {
			t.Errorf("exit code = %d, stderr = %q", code, stderr)
		}
		if !file.closed {
			t.Error("the file was left open")
		}
	})

	t.Run("a list", func(t *testing.T) {
		file := &brokenFile{closeErr: errors.New("close failed")}
		traceInto(t, file)

		code, _, stderr := exec(t, "fetch", "--trace", "anywhere", server.URL+"/one", server.URL+"/two")
		if code != 1 || !strings.Contains(stderr, "fetch: writing the trace: close failed") {
			t.Errorf("exit code = %d, stderr = %q", code, stderr)
		}
		// Everything was written, and it is a whole trace: only the close failed.
		checkShape(t, parseTrace(t, file.Bytes()))
	})

	t.Run("the log says so", func(t *testing.T) {
		// The log is closed after the trace, so its end says how the run
		// ended, the trace's failure included.
		file := &brokenFile{closeErr: errors.New("close failed")}
		traceInto(t, file)
		log := filepath.Join(t.TempDir(), "run.jsonl")

		code, _, stderr := exec(t, "fetch", "--trace", "anywhere", "--log", log, server.URL)
		ended := recordsOf(logRecords(t, log), "run ended")
		if code != 1 || len(ended) != 1 || ended[0].get("level") != "WARN" ||
			!strings.Contains(ended[0].get("error"), "fetch: writing the trace: close failed") {
			t.Errorf("exit code = %d, the end was said as %v\n%s", code, ended, stderr)
		}
	})

	t.Run("a run that failed as well", func(t *testing.T) {
		file := &brokenFile{writeErr: errors.New("no space left on device")}
		traceInto(t, file)

		nowhere := deadAddr(t)
		code, _, stderr := exec(t, "fetch", "--timeout", "3s", "--trace", "anywhere", "https://"+nowhere+"/")
		// Both are said: the reason the fetch failed is not lost behind the trace.
		if code != 1 || !strings.Contains(stderr, nowhere) || !strings.Contains(stderr, "writing the trace") {
			t.Errorf("exit code = %d, stderr = %q", code, stderr)
		}
	})
}

// recording is a trace kept in memory, with one try opened on it.
func recording(t *testing.T, url, proxy string) (*brokenFile, *tracer, *attemptTrace) {
	t.Helper()
	file := &brokenFile{}
	traceInto(t, file)
	trace, err := openTrace("anywhere", "fetch", proxy, now(), traceArgs{})
	if err != nil {
		t.Fatalf("openTrace: %v", err)
	}
	return file, trace, trace.main().attempt("GET", url, 1, 1, proxy, nil)
}

// finished closes a trace and reads back what it holds.
func finished(t *testing.T, file *brokenFile, trace *tracer) []traceEvent {
	t.Helper()
	if err := trace.close(nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	events := parseTrace(t, file.Bytes())
	checkShape(t, events)
	return events
}

func TestTraceDrawsDialsThatOverlapAsOneStep(t *testing.T) {
	// A host with two addresses: the second dial starts while the first is
	// still trying, the first gives up, the second answers. Two bars side by
	// side would overlap, and a viewer drops what overlaps.
	file, trace, try := recording(t, "https://example.test/", "")
	hooks := try.hooks()

	hooks.DNSStart("example.test")
	hooks.DNSDone([]string{"2001:db8::1", "192.0.2.1"}, nil)
	hooks.ConnectStart("tcp", "[2001:db8::1]:443")
	hooks.ConnectStart("tcp", "192.0.2.1:443")
	hooks.ConnectDone("tcp", "[2001:db8::1]:443", errors.New("no route to host"))
	hooks.ConnectDone("tcp", "192.0.2.1:443", nil)
	// The loser of a race can report in after the winner has moved things on.
	hooks.ConnectDone("tcp", "[2001:db8::1]:443", errors.New("operation was canceled"))
	hooks.GotConn(tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:443", TLSVersion: "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2"})
	try.end(nil, errors.New("deadline exceeded"))

	events := finished(t, file, trace)
	dial := one(t, events, phaseComplete, "connect")
	if got := fmt.Sprint(dial.Args["addrs"]); got != "[[2001:db8::1]:443 192.0.2.1:443]" {
		t.Errorf("addresses dialled = %s", got)
	}
	if got := fmt.Sprint(dial.Args["failed"]); got != "[no route to host]" {
		t.Errorf("failed dials = %s, want the one that failed while it mattered", got)
	}
	if dial.Args["addr"] != "192.0.2.1:443" || dial.Args["unfinished"] != nil {
		t.Errorf("the dial was traced as %v", dial.Args)
	}
	// The try ended while the request was being sent, so that is the step left
	// unfinished, and the handshake before it is whole.
	if got := steps(events, mainLane); !follows(got, "dns", "connect", "tls", "send") {
		t.Errorf("steps = %v", got)
	}
	if sent := one(t, events, phaseComplete, "send"); sent.Args["unfinished"] != true {
		t.Errorf("the step the try stopped in was traced as %v", sent.Args)
	}
	if one(t, events, phaseComplete, "tls").Args["unfinished"] != nil {
		t.Error("a handshake that completed was traced as cut short")
	}
}

func TestTraceIgnoresWhatIsReportedOutOfTurn(t *testing.T) {
	file, trace, try := recording(t, "http://example.test/", "")
	hooks := try.hooks()

	// None of these has a step to end: nothing was looked up, dialled or sent.
	hooks.DNSDone(nil, nil)
	hooks.ConnectDone("tcp", "192.0.2.1:80", nil)
	hooks.WroteRequest(nil, nil)
	hooks.FirstByte()

	hooks.DNSStart("example.test")
	hooks.DNSDone(nil, errors.New("no such host"))
	hooks.GotConn(tlsforge.ConnInfo{Reused: true, RemoteAddr: "192.0.2.1:80"})
	// A server that answers before it has read the whole request: the sending
	// ends at the answer's first byte, and what the transport says of the
	// request after is the sending's still.
	hooks.FirstByte()
	hooks.WroteRequest(tlsforge.NewHeader("host", "example.test"), errors.New("broken pipe"))
	try.end(&tlsforge.Response{Status: 200, URL: "http://example.test/"}, nil)

	// The try is over, and the worker has moved on. Whatever arrives now would
	// be drawn inside somebody else's request.
	hooks.DNSStart("late.test")
	hooks.ConnectStart("tcp", "192.0.2.9:80")
	hooks.GotConn(tlsforge.ConnInfo{})
	hooks.Redirect(302, "http://late.test/")

	events := finished(t, file, trace)
	if got, want := steps(events, mainLane), []string{"dns", "send", "receive"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("steps = %v, want %v", got, want)
	}
	if lookup := one(t, events, phaseComplete, "dns"); lookup.Args["error"] != "no such host" {
		t.Errorf("the failed lookup was traced as %v", lookup.Args)
	}
	// Plain HTTP on a connection already open: no handshake to describe.
	sent := one(t, events, phaseComplete, "send")
	if sent.Args["reused"] != true || sent.Args["tls"] != nil || fmt.Sprint(sent.Args["headers"]) != "[host: example.test]" ||
		sent.Args["error"] != "broken pipe" {
		t.Errorf("the request was traced as %v", sent.Args)
	}
}

func TestASendingItsAnswerEndedKeepsWhatIsSaidOfItAfter(t *testing.T) {
	// The transport says a request was written after its write, which can be
	// after the answer's first byte and even after the answer was read: the
	// end of the try waits a moment for it (CI run 40403430568: a JSON
	// report's first try without its request).
	file := &brokenFile{}
	traceInto(t, file)
	trace, err := openTrace("anywhere", "fetch", "", now(), traceArgs{})
	if err != nil {
		t.Fatalf("openTrace: %v", err)
	}
	kept := &try{}
	a := trace.main().attempt("GET", "http://example.test/", 1, 1, "", kept)
	hooks := a.hooks()
	hooks.GotConn(tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:80"})
	hooks.FirstByte()
	go func() {
		time.Sleep(20 * time.Millisecond)
		hooks.WroteRequest(tlsforge.NewHeader("host", "example.test"), nil)
	}()
	a.end(&tlsforge.Response{Status: 200, URL: "http://example.test/"}, nil)
	if len(kept.Steps) != 2 || kept.Steps[0].Name != "send" || kept.Steps[0].Written != "host: example.test" ||
		kept.Steps[1].Name != "receive" {
		t.Errorf("kept %+v", kept.Steps)
	}
	events := finished(t, file, trace)
	if got := steps(events, mainLane); fmt.Sprint(got) != "[send receive]" {
		t.Errorf("steps = %v", got)
	}
	if sent := one(t, events, phaseComplete, "send"); fmt.Sprint(sent.Args["headers"]) != "[host: example.test]" {
		t.Errorf("the request was traced as %v", sent.Args)
	}

	// Never said: kept and drawn as it was, the end waiting earlyWait and no
	// longer; and what comes after the end goes nowhere.
	file = &brokenFile{}
	traceInto(t, file)
	if trace, err = openTrace("anywhere", "fetch", "", now(), traceArgs{}); err != nil {
		t.Fatalf("openTrace: %v", err)
	}
	alone := &try{}
	b := trace.main().attempt("GET", "http://example.test/", 1, 1, "", alone)
	late := b.hooks()
	late.GotConn(tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:80"})
	late.FirstByte()
	began := time.Now()
	b.end(&tlsforge.Response{Status: 200, URL: "http://example.test/"}, nil)
	if took := time.Since(began); took < earlyWait || took > earlyWait+time.Second {
		t.Errorf("the end waited %v, want %v", took, earlyWait)
	}
	late.WroteRequest(tlsforge.NewHeader("host", "example.test"), nil)
	if len(alone.Steps) != 2 || alone.Steps[0].Name != "send" || alone.Steps[0].Written != "" {
		t.Errorf("kept %+v", alone.Steps)
	}
	events = finished(t, file, trace)
	if sent := one(t, events, phaseComplete, "send"); sent.Args["headers"] != nil {
		t.Errorf("a request never said written was traced as %v", sent.Args)
	}

	// A hop that ended early is drawn as it was once the next hop's answer
	// comes, and the next hop's sending is its own.
	file = &brokenFile{}
	traceInto(t, file)
	if trace, err = openTrace("anywhere", "fetch", "", now(), traceArgs{}); err != nil {
		t.Fatalf("openTrace: %v", err)
	}
	hops := &try{}
	c := trace.main().attempt("GET", "http://example.test/", 1, 1, "", hops)
	h := c.hooks()
	h.GotConn(tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:80"})
	h.FirstByte()
	h.Redirect(302, "http://example.test/next")
	h.GotConn(tlsforge.ConnInfo{Reused: true, RemoteAddr: "192.0.2.1:80"})
	h.FirstByte()
	h.WroteRequest(tlsforge.NewHeader("host", "next"), nil)
	c.end(&tlsforge.Response{Status: 200, URL: "http://example.test/next"}, nil)
	var written []string
	for _, s := range hops.Steps {
		written = append(written, s.Name+"="+s.Written)
	}
	if got := strings.Join(written, " "); got != "send= receive= redirect= send=host: next receive=" {
		t.Errorf("kept %s", got)
	}
	if got := steps(finished(t, file, trace), mainLane); fmt.Sprint(got) != "[send receive redirect send receive]" {
		t.Errorf("steps = %v", got)
	}
}

func TestTraceReportsAWriteThatFailed(t *testing.T) {
	file, trace, try := recording(t, "http://example.test/", "http://user:s3cr3t@proxy.test:8080")
	hooks := try.hooks()

	hooks.ConnectStart("tcp", "proxy.test:8080")
	hooks.ConnectDone("tcp", "proxy.test:8080", nil)
	hooks.GotConn(tlsforge.ConnInfo{RemoteAddr: "proxy.test:8080"})
	hooks.WroteRequest(tlsforge.NewHeader("host", "example.test"),
		errors.New("write to http://user:s3cr3t@proxy.test:8080: broken pipe"))
	// The redirect leads somewhere that is HTTPS, so the next dial is followed
	// by a handshake, and through a proxy by a tunnel first.
	hooks.Redirect(307, "https://user:s3cr3t@example.test/next")
	hooks.ConnectStart("tcp", "proxy.test:8080")
	hooks.ConnectDone("tcp", "proxy.test:8080", nil)
	try.end(nil, errors.New("giving up"))

	raw := file.String()
	events := finished(t, file, trace)
	if strings.Contains(raw, "s3cr3t") {
		t.Errorf("the trace holds a password:\n%s", raw)
	}
	sent := one(t, events, phaseComplete, "send")
	if got := fmt.Sprint(sent.Args["error"]); !strings.Contains(got, "user@proxy.test:8080: broken pipe") {
		t.Errorf("the failed write was traced as %q", got)
	}
	if got := one(t, events, phaseInstant, "redirect").Args["location"]; got != "https://user@example.test/next" {
		t.Errorf("the redirect was traced to %v", got)
	}
	// Plain HTTP first, so no handshake after the first dial; HTTPS after the
	// redirect, so one after the second.
	if got, want := steps(events, mainLane),
		[]string{"connect", "send", "wait", "redirect", "connect", "proxy+tls"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("steps = %v, want %v", got, want)
	}
	if tunnel := one(t, events, phaseComplete, "proxy+tls"); tunnel.Args["unfinished"] != true {
		t.Errorf("the tunnel the try gave up in was traced as %v", tunnel.Args)
	}
}

func TestTraceCallsARequestWithNoMethodAGet(t *testing.T) {
	// Which is what the client makes of one, so it is what the trace calls it.
	file := &brokenFile{}
	traceInto(t, file)
	trace, err := openTrace("anywhere", "fetch", "", now(), traceArgs{})
	if err != nil {
		t.Fatalf("openTrace: %v", err)
	}
	trace.main().attempt("", "https://example.test/", 1, 1, "", nil).end(nil, errors.New("not sent"))

	if began := one(t, finished(t, file, trace), phaseBegin, "GET https://example.test/"); began.Cat != "request" {
		t.Errorf("the request was traced as %+v", began)
	}
}

func TestTraceNeverFilesTwoEventsUnderOneMoment(t *testing.T) {
	// A clock that does not move: everything happens in the same microsecond,
	// which on a fast machine is not far from the truth.
	clock := fakeClock(t)
	file, trace, try := recording(t, "http://example.test/", "")
	hooks := try.hooks()
	hooks.GotConn(tlsforge.ConnInfo{})
	hooks.WroteRequest(nil, nil)
	hooks.FirstByte()
	try.end(&tlsforge.Response{Status: 204}, nil)
	trace.main().instant("after", "run", nil)

	// checkShape, inside finished, is what fails if two of them collide.
	events := finished(t, file, trace)
	if first := one(t, events, phaseBegin, "fetch"); first.TS != clock.now().UnixMicro() {
		t.Errorf("the run began at %d, want the clock's own time %d", first.TS, clock.now().UnixMicro())
	}
	// And time still means something once the clock moves again.
	if again := one(t, events, phaseInstant, "after"); again.TS-clock.now().UnixMicro() > 100 {
		t.Errorf("the trace's clock ran %dµs ahead of the real one", again.TS-clock.now().UnixMicro())
	}
}

func TestTraceOffCostsNothing(t *testing.T) {
	// No file named, so no tracer, and everything made from one does nothing
	// when asked. This is every traced call a run makes.
	trace, err := openTrace("", "fetch", "", now(), traceArgs{})
	if trace != nil || err != nil {
		t.Fatalf("openTrace with no file = %v, %v", trace, err)
	}
	lane := trace.main()
	if lane != nil || trace.lane(2, "worker 1") != nil {
		t.Error("a tracer that is off handed out a row")
	}
	lane.wearing(nil)
	lane.instant("nothing", "run", nil)
	lane.since(lane.mark(), "nothing", "run", nil)
	try := lane.attempt("GET", "https://example.test/", 1, 1, "", nil)
	if try != nil || try.hooks() != nil {
		t.Error("a tracer that is off opened a try, or asked the client to report")
	}
	try.end(nil, nil)
	if err := trace.close(errors.New("ignored")); err != nil {
		t.Errorf("closing nothing failed: %v", err)
	}
}

func TestSafeHeadersKeepTheOrderTheyWereWrittenIn(t *testing.T) {
	sent := tlsforge.Header{
		profile.Field{Name: ":method", Value: "GET"},
		profile.Field{Name: "x-repeat", Value: "one"},
		profile.Field{Name: "cookie", Value: "a=1"},
		profile.Field{Name: "x-repeat", Value: "two"},
	}
	want := []string{":method: GET", "x-repeat: one", "cookie: a=***", "x-repeat: two"}
	if got := safeHeaders(sent); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("safeHeaders = %v, want %v", got, want)
	}

	// A response is a map, so its fields are put in an order that at least
	// does not change from one run to the next.
	received := map[string][]string{
		"server":     {"stand-in"},
		"set-cookie": {"a=1; Path=/", "b=2"},
		"age":        {"0"},
	}
	want = []string{"age: 0", "server: stand-in", "set-cookie: a=***; Path=/", "set-cookie: b=***"}
	if got := safeResponseHeaders(received); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("safeResponseHeaders = %v, want %v", got, want)
	}
}

func TestPreview(t *testing.T) {
	if got := preview([]byte("short")); got != "short" {
		t.Errorf("preview of a short body = %q", got)
	}
	// Cut at the limit, which falls in the middle of a two-byte letter here.
	// What is kept is still text, so the file is still JSON.
	long := strings.Repeat("a", previewBytes-1) + strings.Repeat("é", 20)
	got := preview([]byte(long))
	if want := strings.Repeat("a", previewBytes-1) + "\uFFFD"; got != want {
		t.Errorf("preview kept %d bytes ending %q", len(got), got[len(got)-6:])
	}
}

func TestExitArgs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proxy string
		found egress
		err   error
		want  string
	}{
		{"an address and its country", "", egress{IP: "203.0.113.7", Country: "pl"},
			nil, "map[country:PL ip:203.0.113.7]"},
		{"a service that names no country", "", egress{IP: "203.0.113.7"},
			nil, "map[ip:203.0.113.7]"},
		{"through a proxy", "http://user:s3cr3t@proxy.test:8080", egress{IP: "198.51.100.1", Country: "DE"},
			nil, "map[country:DE ip:198.51.100.1 proxy:http://user@proxy.test:8080]"},
		{"nobody answered", "http://user:s3cr3t@proxy.test:8080", egress{},
			errors.New("dialling http://user:s3cr3t@proxy.test:8080 failed"),
			"map[error:dialling http://user@proxy.test:8080 failed proxy:http://user@proxy.test:8080]"},
	} {
		if got := fmt.Sprint(exitArgs(tc.proxy, tc.found, tc.err)); got != tc.want {
			t.Errorf("%s: exitArgs = %s, want %s", tc.name, got, tc.want)
		}
	}
}
