package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// What a request took, try by try, and what a report shows of it.

func TestATryIsWrittenDownWithoutATrace(t *testing.T) {
	// No trace was asked for, so there is no row to draw on. The report still
	// wants every step, measured by the clock on the wall.
	clock := fakeClock(t)
	var log try
	var lane *traceLane
	shot := lane.attempt("GET", "https://example.test/", 1, 1, "", &log)
	if shot == nil || shot.hooks() == nil {
		t.Fatal("a try that is being kept did not ask the client to report")
	}
	if !log.Began.Equal(clock.now()) {
		t.Errorf("the try began at %s, want the moment it was opened", log.Began)
	}
	hooks := shot.hooks()

	hooks.DNSStart("example.test")
	clock.advance(2 * time.Millisecond)
	hooks.DNSDone([]string{"192.0.2.1", "2001:db8::1"}, nil)
	hooks.ConnectStart("tcp", "192.0.2.1:443")
	clock.advance(5 * time.Millisecond)
	hooks.ConnectDone("tcp", "192.0.2.1:443", nil)
	clock.advance(10 * time.Millisecond)
	conn := tlsforge.ConnInfo{
		RemoteAddr: "192.0.2.1:443", TLSVersion: "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2",
	}
	hooks.GotConn(conn)
	clock.advance(100 * time.Microsecond)
	hooks.WroteRequest(tlsforge.NewHeader("host", "example.test", "cookie", "session=abc123"), nil)
	clock.advance(80 * time.Millisecond)
	hooks.FirstByte()
	clock.advance(3 * time.Millisecond)
	shot.end(&tlsforge.Response{
		Status: 200, Body: []byte("page"),
		Header: map[string][]string{"Set-Cookie": {"id=42; Path=/"}, "Server": {"test"}},
	}, nil)

	// A dial that lost its race, reporting in after the try is over.
	hooks.DNSStart("late.test")

	const ms = time.Millisecond
	want := []step{
		{Name: "dns", Took: 2 * ms, Note: "example.test → 192.0.2.1, 2001:db8::1"},
		{Name: "connect", From: 2 * ms, Took: 5 * ms, Note: "192.0.2.1:443"},
		{Name: "tls", From: 7 * ms, Took: 10 * ms, Note: "TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2"},
		// The request as it went out: every field in the order it was written, and
		// none of what a session is worth.
		{Name: "send", From: 17 * ms, Took: 100 * time.Microsecond, Written: "host: example.test\ncookie: session=***"},
		{Name: "wait", From: 17100 * time.Microsecond, Took: 80 * ms},
		{Name: "receive", From: 97100 * time.Microsecond, Took: 3 * ms},
	}
	if !slices.Equal(log.Steps, want) {
		t.Errorf("steps:\n%+v\nwant\n%+v", log.Steps, want)
	}
	if log.Took != 100100*time.Microsecond || log.Status != 200 || log.Bytes != 4 || log.Error != "" {
		t.Errorf("the try ended as %+v", log)
	}
	if !log.Connected || !reflect.DeepEqual(log.Conn, conn) {
		t.Errorf("the connection was kept as %+v", log.Conn)
	}
	// What came back with the page, by name. The page itself is the output, and
	// is not kept a second time here.
	if log.Answer != "Server: test\nSet-Cookie: id=***; Path=/" || log.Body != "" {
		t.Errorf("the answer was kept as %q, with a body of %q", log.Answer, log.Body)
	}
}

func TestATryKeepsWhatAWrongAnswerSaid(t *testing.T) {
	// An answer that is not the page usually says why at the start of its body,
	// and when the request is made again that is the only place it is left.
	fakeClock(t)
	var log try
	var lane *traceLane
	shot := lane.attempt("GET", "https://example.test/", 1, 1, "", &log)
	shot.end(&tlsforge.Response{
		Status: 403, Body: []byte("<title>Just a moment...</title>"),
		Header: map[string][]string{"Cf-Mitigated": {"challenge"}},
	}, nil)

	if log.Status != 403 || log.Answer != "Cf-Mitigated: challenge" || log.Body != "<title>Just a moment...</title>" {
		t.Errorf("the try ended as %+v", log)
	}
	if got := (tryRow{try: log}).Fields(); got != "1 header field" {
		t.Errorf("Fields = %q", got)
	}
}

func TestATryThatWasRedirectedAndGaveUp(t *testing.T) {
	clock := fakeClock(t)
	const proxy = "http://user:s3cr3t@proxy.test:8080"
	var log try
	var lane *traceLane
	shot := lane.attempt("GET", "http://example.test/", 1, 2, proxy, &log)
	hooks := shot.hooks()

	hooks.GotConn(tlsforge.ConnInfo{Reused: true, RemoteAddr: "198.51.100.7:8080"})
	clock.advance(time.Millisecond)
	hooks.WroteRequest(nil, nil)
	clock.advance(40 * time.Millisecond)
	hooks.Redirect(301, "https://user:s3cr3t@example.test/next")
	hooks.ConnectStart("tcp", "198.51.100.7:8080")
	hooks.ConnectStart("tcp", "198.51.100.8:8080")
	clock.advance(3 * time.Second)
	hooks.ConnectDone("tcp", "198.51.100.7:8080", errors.New("dial "+proxy+": i/o timeout"))
	shot.end(nil, errors.New("proxyconnect "+proxy+": giving up"))

	const ms = time.Millisecond
	want := []step{
		{Name: "send", Took: ms, Note: "on the connection already open to 198.51.100.7:8080"},
		{Name: "wait", From: ms, Took: 40 * ms},
		// Where it falls among the steps is what a redirect has to say.
		{Name: "redirect", From: 41 * ms, Note: "301 → https://user@example.test/next"},
		// None of the dials answered, so all of them are what was tried, and the
		// step the try stopped in is marked as that.
		{
			Name: "connect", From: 41 * ms, Took: 3 * time.Second, Cut: true,
			Note: "198.51.100.7:8080, 198.51.100.8:8080 · failed: dial http://user@proxy.test:8080: i/o timeout",
		},
	}
	if !slices.Equal(log.Steps, want) {
		t.Errorf("steps:\n%+v\nwant\n%+v", log.Steps, want)
	}
	if log.Error != "proxyconnect http://user@proxy.test:8080: giving up" || log.Status != 0 {
		t.Errorf("the try ended as %q with status %d", log.Error, log.Status)
	}
	if strings.Contains(fmt.Sprintf("%+v", log), "s3cr3t") {
		t.Errorf("the record holds a password: %+v", log)
	}
}

func TestTheReportAndTheTraceTellATryTheSameWay(t *testing.T) {
	// One reading of what the client said, written down in two places.
	file := &brokenFile{}
	traceInto(t, file)
	trace, err := openTrace("anywhere", "fetch", "", now(), traceArgs{})
	if err != nil {
		t.Fatalf("openTrace: %v", err)
	}
	var log try
	shot := trace.main().attempt("GET", "https://example.test/", 1, 1, "", &log)
	hooks := shot.hooks()

	hooks.DNSStart("example.test")
	hooks.DNSDone(nil, errors.New("no such host"))
	hooks.ConnectStart("tcp", "192.0.2.1:443")
	hooks.ConnectDone("tcp", "192.0.2.1:443", nil)
	hooks.GotConn(tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:443", TLSVersion: "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256", Resumed: true})
	hooks.WroteRequest(nil, errors.New("broken pipe"))
	hooks.Redirect(302, "http://example.test/plain")
	shot.end(nil, errors.New("deadline exceeded"))

	events := finished(t, file, trace)
	drawn := steps(events, mainLane)
	var kept []string
	for _, s := range log.Steps {
		kept = append(kept, s.Name)
	}
	if !slices.Equal(kept, drawn) {
		t.Errorf("the record has %v and the trace %v", kept, drawn)
	}
	// And by the same clock, to the microsecond.
	for _, s := range log.Steps {
		if s.Name == redirectStep {
			continue
		}
		if drawn := one(t, events, phaseComplete, s.Name); drawn.Dur != s.Took.Microseconds() {
			t.Errorf("%s took %s in the record and %dµs in the trace", s.Name, s.Took, drawn.Dur)
		}
	}
	notes := map[string]string{}
	for _, s := range log.Steps {
		notes[s.Name] = s.Note
	}
	for name, want := range map[string]string{
		"dns":     "example.test · no such host",
		"tls":     "TLS 1.3 · TLS_AES_128_GCM_SHA256 · session resumed",
		"send":    "broken pipe",
		"connect": "192.0.2.1:443",
	} {
		if notes[name] != want {
			t.Errorf("%s is noted as %q, want %q", name, notes[name], want)
		}
	}
}

func TestNoteOnAStep(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts stepFacts
		want  string
	}{
		{"dns", stepFacts{host: "example.test"}, "example.test"},
		{"connect", stepFacts{addrs: []string{"192.0.2.1:443"}, said: true}, "192.0.2.1:443"},
		// A handshake that did not get as far as settling on anything.
		{"tls", stepFacts{unfinished: true}, ""},
		{"proxy+tls", stepFacts{conn: &tlsforge.ConnInfo{TLSVersion: "TLS 1.2", CipherSuite: "ECDHE", ALPN: "http/1.1"}},
			"TLS 1.2 · ECDHE · http/1.1"},
		// A connection that was made for this request says so where it was made.
		{"send", stepFacts{conn: &tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:443"}}, ""},
		{"wait", stepFacts{status: 301}, ""},
		{"receive", stepFacts{err: "connection reset"}, "connection reset"},
	} {
		if got := tc.facts.note(tc.name); got != tc.want {
			t.Errorf("%s noted as %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOnlySoManyRequestsKeepTheirTries(t *testing.T) {
	original := reportRowLimit
	t.Cleanup(func() { reportRowLimit = original })
	reportRowLimit = 2

	// As many of each kind as a report could show: it puts trouble first and
	// fills what is left with the rest, so either kind can fill it.
	var room tryBudget
	var kept []bool
	for _, r := range []result{
		{Status: 200}, {Status: 503}, {Status: 200}, {Error: "refused"}, {Status: 200}, {Status: 404},
	} {
		r.Tries = []try{{}}
		kept = append(kept, room.trim(r).Tries != nil)
	}
	if want := []bool{true, true, true, true, false, false}; !slices.Equal(kept, want) {
		t.Errorf("kept = %v, want %v", kept, want)
	}
}

func TestTryRowsAreLaidOutOnTheWholeRequest(t *testing.T) {
	const ms = time.Millisecond
	started := time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)
	tries := []try{
		{
			Began: started, Took: 100 * ms, Status: 503, Bytes: 19, Wait: 250 * ms,
			Steps: []step{
				{Name: "connect", Took: 20 * ms},
				// A gap, which is time the try spent that no step accounts for.
				{Name: "wait", From: 25 * ms, Took: 75 * ms},
			},
		},
		{
			Began: started.Add(350 * ms), Took: 50 * ms, Error: "connection reset",
			Steps: []step{
				{Name: redirectStep, From: 10 * ms, Note: "302 → https://example.test/"},
				{Name: "proxy+tls", From: 10 * ms, Took: 40 * ms, Cut: true},
			},
		},
	}
	rows := tryRows(tries, started, 400*ms)
	if len(rows) != 2 || rows[0].Number != 1 || rows[1].Number != 2 || rows[1].Of != 2 {
		t.Fatalf("rows = %+v", rows)
	}

	wantFirst := []segment{
		{Class: "bg-step-connect", Width: "5.0000%", Title: "connect 20ms"},
		{Width: "1.2500%"},
		{Class: "bg-step-wait", Width: "18.7500%", Title: "wait 75ms"},
	}
	if !slices.Equal(rows[0].Bar, wantFirst) {
		t.Errorf("the first try is drawn as %+v", rows[0].Bar)
	}
	// The second begins where it began in the request, after the first and the
	// wait between them, and a redirect has no length to draw.
	wantSecond := []segment{
		{Width: "90.0000%"},
		{Class: "bg-step-tls", Width: "10.0000%", Title: "proxy+tls 40ms"},
	}
	if !slices.Equal(rows[1].Bar, wantSecond) {
		t.Errorf("the second try is drawn as %+v", rows[1].Bar)
	}

	first, second := rows[0], rows[1]
	if first.Failed() || !first.Warned() || first.Glyph() != "!" || first.Outcome() != "503" {
		t.Errorf("a try that was refused shows as %s %s", first.Glyph(), first.Outcome())
	}
	if !second.Failed() || second.Warned() || second.Glyph() != "✕" || second.Outcome() != "no response" {
		t.Errorf("a try that got nothing shows as %s %s", second.Glyph(), second.Outcome())
	}
	if first.Length() != "100ms" || first.After() != "0µs" || first.Size() != "19 B" || first.Waited() != "250ms" {
		t.Errorf("the first try reads %s, after %s, %s, then %s", first.Length(), first.After(), first.Size(), first.Waited())
	}
	if second.After() != "350ms" || second.Waited() != "" {
		t.Errorf("the last try began after %s and waited %q", second.After(), second.Waited())
	}

	listed := second.Listed()
	if len(listed) != 2 || !listed[0].Moment() || listed[0].Class != "" || listed[1].Moment() {
		t.Fatalf("listed = %+v", listed)
	}
	if listed[1].Class != "bg-step-tls" || listed[1].Length() != "40ms" || !listed[1].Cut {
		t.Errorf("the handshake is listed as %+v", listed[1])
	}

	// Nothing to draw against: a request that took no time, or has no times.
	if bar := timeline(tries[0], 0, 0); bar != nil {
		t.Errorf("a request of no length drew %+v", bar)
	}
}

func TestTryRowConnection(t *testing.T) {
	for _, tc := range []struct {
		name string
		try  try
		want string
	}{
		{"never connected", try{}, ""},
		{
			"a new one, with what the handshake settled on",
			try{Connected: true, Conn: tlsforge.ConnInfo{
				RemoteAddr: "192.0.2.1:443", TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2",
			}},
			"new connection to 192.0.2.1:443 · TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2",
		},
		{
			"one that was open already, over plain HTTP",
			try{Connected: true, Conn: tlsforge.ConnInfo{Reused: true, RemoteAddr: "192.0.2.1:80"}},
			"connection already open to 192.0.2.1:80",
		},
	} {
		if got := (tryRow{try: tc.try}).Connection(); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFineDuration(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0µs"},
		{0, "0µs"},
		{640 * time.Nanosecond, "0µs"},
		{67 * time.Microsecond, "67µs"},
		{999 * time.Microsecond, "999µs"},
		{1900 * time.Microsecond, "1.9ms"},
		{9949 * time.Microsecond, "9.9ms"},
		{12 * time.Millisecond, "12ms"},
		{2500 * time.Millisecond, "2.5s"},
	} {
		if got := fineDuration(tc.d); got != tc.want {
			t.Errorf("fineDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestReportRowFacts(t *testing.T) {
	started := time.Date(2026, 3, 4, 9, 30, 0, 12_000_000, time.UTC)
	plain := reportRow{result: result{
		URL: "https://example.test/", FinalURL: "https://example.test/",
		Started: started, Ended: started.Add(1500 * time.Millisecond),
	}}
	want := []fact{
		{Label: "Started", Value: "04 Mar 2026 09:30:00.012"},
		{Label: "Ended", Value: "04 Mar 2026 09:30:01.512"},
	}
	if got := plain.Facts(); !slices.Equal(got, want) {
		t.Errorf("a request with nothing more to say: %+v", got)
	}
	if got := plain.StartedAt(); got != "04 Mar 09:30:00" {
		t.Errorf("StartedAt = %q", got)
	}

	// Somewhere else than it was sent, kept in a file, and with a reason.
	full := reportRow{result: result{
		URL: "http://example.test/", FinalURL: "https://www.example.test/home", File: "page-3.html",
		Error: "unexpected EOF",
	}}
	want = []fact{
		{Label: "Final URL", Value: "https://www.example.test/home", Code: true},
		{Label: "Saved to", Value: "page-3.html", Code: true},
		// A record that never started has no time to show, rather than the zero one.
		{Label: "Started"}, {Label: "Ended"},
		{Label: "Error", Value: "unexpected EOF"},
	}
	if got := full.Facts(); !slices.Equal(got, want) {
		t.Errorf("a request with everything to say: %+v", got)
	}
	if got := full.StartedAt(); got != "" {
		t.Errorf("StartedAt of a request that never started = %q", got)
	}
	if rows := full.TryRows(); len(rows) != 0 {
		t.Errorf("a request whose tries were not kept has %d of them", len(rows))
	}

	// Kept and traced: the log and the trace linked to from where the report
	// is, and the trace offered to a viewer.
	open := &perfettoTrace{Data: "H4sI"}
	kept := reportRow{
		result: result{URL: "https://example.test/", Log: "out/a.log", Trace: "out/trace-a.json"},
		at:     "out/report.html", trace: "out/trace-a.json", Perfetto: open,
	}
	want = []fact{
		{Label: "Log", Value: "out/a.log", Code: true, Link: "a.log"},
		{Label: "Trace", Value: "out/trace-a.json", Code: true, Link: "trace-a.json", Open: open},
		{Label: "Started"}, {Label: "Ended"},
	}
	if got := kept.Facts(); !slices.Equal(got, want) {
		t.Errorf("a request that was kept and traced: %+v", got)
	}
}

func TestRoutes(t *testing.T) {
	const p1 = "http://user:pw@p1"
	pl, de := egress{IP: "203.0.113.7", Country: "PL"}, egress{IP: "198.51.100.9", Country: "DE"}

	if way := routes(nil); way != nil {
		t.Errorf("a run of nothing went %+v", way)
	}
	for _, tc := range []struct {
		name    string
		records []result
		want    route
		spread  string
	}{
		{
			// Said once, without its password, with where it came out.
			"one proxy, one address", []result{{Proxy: p1, Exit: pl}, {Proxy: p1, Exit: pl}},
			route{Proxy: "http://user@p1", SameProxy: true, Exit: pl, SameExit: true, Exits: 1}, "one address",
		},
		{
			"every request direct, and nobody asked", []result{{}, {}},
			route{SameProxy: true, SameExit: true, Unknown: 2}, "one address; where 2 of them came out is not known",
		},
		{
			// A proxy that hands every request an address of its own.
			"one proxy, an address each", []result{{Proxy: p1, Exit: pl}, {Proxy: p1, Exit: de}, {Proxy: p1, Exit: pl}},
			route{Proxy: "http://user@p1", SameProxy: true, Exit: pl, Exits: 2}, "2 different addresses",
		},
		{
			"two ways out, one of them not looked up", []result{{Proxy: p1, Exit: pl}, {}},
			route{Proxy: "http://user@p1", Exit: pl, Exits: 1, Unknown: 1},
			"one address; where 1 of them came out is not known",
		},
	} {
		way := routes(tc.records)
		if way == nil || *way != tc.want {
			t.Errorf("%s: went %+v, want %+v", tc.name, way, tc.want)
			continue
		}
		if got := way.Spread(); got != tc.spread {
			t.Errorf("%s: spread %q, want %q", tc.name, got, tc.spread)
		}
	}
}

func TestReportColumns(t *testing.T) {
	for _, tc := range []struct {
		name          string
		data          reportData
		tracks, width string
	}{
		{"one pass, one way", reportData{}, "0.75rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem", "56rem"},
		{
			"numbered", reportData{Summary: summary{Passes: 2}},
			"0.75rem 2.5rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem", "56rem",
		},
		{
			"numbered, and several ways out", reportData{Summary: summary{Passes: 2}, Via: true, Exited: true},
			"0.75rem 2.5rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem 11rem 9rem", "76rem",
		},
		{
			"one proxy, an address for each request", reportData{Exited: true},
			"0.75rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem 9rem", "65rem",
		},
		{
			// Room for the whole of a hash a proxy gave instead of the address.
			"one proxy, a hash of the address for each request", reportData{Exited: true, Hashed: true},
			"0.75rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem 16rem", "72rem",
		},
		{
			"several proxies, nobody asked where", reportData{Via: true},
			"0.75rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem 11rem", "67rem",
		},
		{
			// An answer without what the page has, which a short selector fits in
			// the column as it is.
			"an answer without an element", reportData{Rows: []reportRow{{result: result{Status: 200, finding: finding{MissingElement: "#price"}}}}},
			"0.75rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem", "56rem",
		},
		{
			// And the column made as wide as the longest of them, on one line.
			"an answer without both", reportData{Rows: []reportRow{
				{result: result{Status: 200}},
				{result: result{Status: 200, finding: finding{MissingElement: "#price", MissingText: `/in stock: \d+/i`}}},
				{result: result{Status: 200, finding: finding{MissingText: "в наличии"}}},
			}},
			"0.75rem 1fr 7.5rem 4.5rem 18rem 4.5rem 2.5rem", "66rem",
		},
		{
			"an answer without text in Cyrillic", reportData{Rows: []reportRow{{result: result{Status: 200, finding: finding{MissingText: "в наличии"}}}}},
			"0.75rem 1fr 7.5rem 4.5rem 10rem 4.5rem 2.5rem", "58rem",
		},
	} {
		if got := string(tc.data.Columns()); got != tc.tracks {
			t.Errorf("%s: columns %q, want %q", tc.name, got, tc.tracks)
		}
		if got := string(tc.data.Width()); got != tc.width {
			t.Errorf("%s: width %q, want %q", tc.name, got, tc.width)
		}
	}
}

func TestReportShowsEveryTry(t *testing.T) {
	const ms = time.Millisecond
	started := time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)
	records := []result{{
		URL: "https://example.test/", Started: started, Ended: started.Add(400 * ms),
		Millis: 400, Status: 200, Bytes: 577, Attempts: 2,
		Tries: []try{
			{
				Began: started, Took: 100 * ms, Status: 503, Bytes: 19, Wait: 250 * ms,
				Connected: true, Conn: tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:443", TLSVersion: "TLS 1.3", CipherSuite: "AES", ALPN: "h2"},
				Answer: "Retry-After: 1\nServer: test", Body: "<h1>slow down</h1>",
				Steps: []step{
					{Name: "dns", Took: 10 * ms, Note: "example.test → 192.0.2.1"},
					{Name: "send", From: 10 * ms, Written: ":method: GET\n:path: /\ncookie: session=***"},
					{Name: "wait", From: 10 * ms, Took: 90 * ms},
				},
			},
			{
				Began: started.Add(350 * ms), Took: 50 * ms, Error: "<b>connection reset</b>",
				Steps: []step{{Name: "send", Took: 50 * ms, Cut: true}},
			},
		},
	}}
	var out strings.Builder
	if err := renderReport(&out, inputOf(records)); err != nil {
		t.Fatalf("renderReport: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		// The key to how a try is drawn, and the one way every request went.
		"A try is drawn on the length of the whole request",
		"Every request was made directly",
		"Where it came out is not known.",
		"grid-template-columns:0.75rem 1fr 7.5rem 4.5rem 8rem 4.5rem 2.5rem",
		"min-width:56rem",
		"04 Mar 2026 09:30:00.400",
		"Try 1 of 2", "Try 2 of 2",
		"new connection to 192.0.2.1:443 · TLS 1.3 · AES · h2",
		"began 350ms into the request",
		// The first try: a tenth of a second of a request of four tenths.
		`class="h-full bg-step-dns" style="width:2.5000%" title="dns 10ms"`,
		`class="h-full bg-step-wait" style="width:22.5000%" title="wait 90ms"`,
		"example.test → 192.0.2.1",
		"Then 250ms of waiting before the next try.",
		// The request as it went out, behind something that opens.
		"3 header fields, as they were written",
		":method: GET\n:path: /\ncookie: session=***",
		// What a wrong answer came with and how it began, open already.
		`<details class="group/part mt-2" open>`,
		"The answer came with 2 header fields, and its body began like this",
		"Retry-After: 1\nServer: test",
		"&lt;h1&gt;slow down&lt;/h1&gt;",
		// The second, which began after the first and the wait.
		`style="width:87.5000%"`,
		"the try ended here",
		"&lt;b&gt;connection reset&lt;/b&gt;",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	// The first try began with the request, which goes without saying, and the
	// reason a try failed is text and never markup.
	if strings.Count(html, "into the request") != 1 || strings.Contains(html, "<b>connection reset") {
		t.Error("the report says when the first try began, or wrote an error as markup")
	}
	if strings.Contains(html, "<h1>slow down") {
		t.Error("what a server answered with was written into the document as markup")
	}
	if strings.Contains(html, "ZgotmplZ") {
		t.Error("the template refused something this file wrote into it")
	}

	// Without tries there is no key to them, and with more than one way out
	// every row says its own.
	bare := []result{
		{URL: "https://a/", Status: 200, Exit: egress{IP: "198.51.100.1"}},
		{URL: "https://b/", Status: 200, Proxy: "http://p1", Exit: egress{IP: "198.51.100.2"}},
	}
	out.Reset()
	if err := renderReport(&out, inputOf(bare)); err != nil {
		t.Fatalf("renderReport: %v", err)
	}
	html = out.String()
	if strings.Contains(html, "A try is drawn") || strings.Contains(html, "Every request ") {
		t.Error("a report with no tries, of requests that went two ways, says otherwise")
	}
	for _, want := range []string{
		">Via</span>", ">Exit address</span>", "min-width:76rem", "direct", "http://p1",
		"The requests came out of 2 different addresses.", "198.51.100.2",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestStylesheetHasAShadeForEveryStep(t *testing.T) {
	// The classes are written into the document by this program rather than by
	// the template, where the check that the stylesheet covers the template
	// cannot see them.
	styled := stylesheetClasses(reportCSS)
	for name, class := range stepShades {
		if !styled[class] {
			t.Errorf("the stylesheet has no %s for the step %q; run `make report-css`", class, name)
		}
	}
}

func TestFetchReportShowsWhatEachRequestTook(t *testing.T) {
	// The wait between tries is part of what a request took, so this run keeps a
	// short one rather than none.
	original := retryWait
	t.Cleanup(func() { retryWait = original })
	retryWait = func(int) time.Duration { return 20 * time.Millisecond }

	server, _ := replying(t, 503, 200, 200)
	dir := t.TempDir()
	path := filepath.Join(dir, "run.html")

	kept := filepath.Join(dir, "out")
	code, _, stderr := exec(t, "fetch", "--repeat", "2", "--retry", "1", "--reuse-connection", "--report="+path,
		"-o", kept, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	html := reportOf(t, path)
	address := strings.TrimPrefix(server.URL, "http://")
	pages, _ := filepath.Glob(filepath.Join(kept, "*.txt"))
	logs, _ := filepath.Glob(filepath.Join(kept, "127.0.0.1-*.log"))
	traces, _ := filepath.Glob(filepath.Join(kept, "trace-*.json"))
	if len(pages) != 2 || len(logs) != 2 || len(traces) != 2 {
		t.Fatalf("the directory holds %v", keptIn(t, kept))
	}
	for _, want := range []string{
		// The first run: refused, then the page, on the connection the first try
		// had opened, which the URL kept.
		"Try 1 of 2", "Try 2 of 2",
		"new connection to " + address,
		"connection already open to " + address,
		"Then 20ms of waiting before the next try.",
		// The second run, which was answered at once.
		"Try 1 of 1",
		// Where each run was kept: its page, its log and its trace.
		pages[0], pages[1], logs[0], logs[1], traces[0], traces[1],
		"bg-step-wait",
		// What went out, and what the try that was refused got back for it: the
		// body the stand-in answers every request with.
		"as they were written",
		"Host: " + address,
		"its body began like this", "answer-1",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestListReportShowsEveryTryAndTheLinesDoNot(t *testing.T) {
	server, _ := replying(t, 503, 200)
	path := filepath.Join(t.TempDir(), "run.html")

	code, written, stderr := exec(t, "fetch", "--json", "--retry", "1", "--report="+path,
		server.URL+"/flaky")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	html := reportOf(t, path)
	for _, want := range []string{"Try 1 of 2", "Try 2 of 2", "A try is drawn on the length of the whole request"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	// The lines are what they have always been.
	if lower := strings.ToLower(written); strings.Contains(lower, "tries") || strings.Contains(lower, "steps") {
		t.Errorf("the JSON lines carry the tries: %s", written)
	}
}
