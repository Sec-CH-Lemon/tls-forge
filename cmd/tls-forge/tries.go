package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// What a request took, try by try.
//
// The count says how a run went, and the trace draws where its time went. A
// report is read one request at a time, by somebody asking why that one was
// slow or was turned away, so it keeps what every try at the request waited on
// and how the try ended.

// try is one attempt at a request.
type try struct {
	// Began is when it was made, and Took how long it was until it ended, one
	// way or the other.
	Began time.Time
	Took  time.Duration
	// How it ended: with a status, or with the reason there is none.
	Status int
	Bytes  int
	Error  string
	// Steps are the things it waited on, in the order it waited on them.
	Steps []step
	// Conn is the connection the request went out on, and Connected whether
	// the try got as far as having one. After a redirect it is the last of them.
	Conn      tlsforge.ConnInfo
	Connected bool
	// Wait is how long was let pass after it before the request was made again.
	Wait time.Duration
}

// step is one thing a try waited on.
type step struct {
	Name string
	// From is when it began, counted from when the try did.
	From time.Duration
	Took time.Duration
	// Note is what there is to say about it beyond how long it took.
	Note string
	// Cut says the try ended while this was going on, which makes it where the
	// try stopped.
	Cut bool
}

// redirectStep is the name a redirect is kept under. It is a moment and not a
// wait, and is listed among the steps because where it falls among them is
// what it has to say.
const redirectStep = "redirect"

// keep writes down a step that has ended.
func (t *try) keep(name string, from, took time.Duration, about traceArgs) {
	cut, _ := about["unfinished"].(bool)
	t.Steps = append(t.Steps, step{
		Name: name, From: from, Took: took, Note: noteOn(name, about), Cut: cut,
	})
}

// redirected writes down a redirect that is about to be followed.
func (t *try) redirected(at time.Duration, status int, location string) {
	t.Steps = append(t.Steps, step{
		Name: redirectStep, From: at, Note: strconv.Itoa(status) + " → " + location,
	})
}

// ended writes down how the try came out.
func (t *try) ended(took time.Duration, res *tlsforge.Response, err error, proxy string) {
	t.Took = took
	if err != nil {
		t.Error = redactError(err, proxy)
		return
	}
	t.Status, t.Bytes = res.Status, len(res.Body)
}

// noteOn is what a step has to say for itself, out of what the trace is told
// about it.
//
// The same facts under the same names, read back here rather than gathered a
// second time, so that a report cannot say something about a step that the
// trace of the same run does not.
func noteOn(name string, about traceArgs) string {
	var parts []string
	say := func(text string) {
		if text != "" {
			parts = append(parts, text)
		}
	}
	switch name {
	case "dns":
		host, _ := about["host"].(string)
		if addrs, _ := about["addrs"].([]string); len(addrs) > 0 {
			host += " → " + strings.Join(addrs, ", ")
		}
		say(host)
	case "connect":
		if addr, answered := about["addr"].(string); answered {
			say(addr)
		} else {
			// None of them answered, so all of them are what was tried.
			addrs, _ := about["addrs"].([]string)
			say(strings.Join(addrs, ", "))
		}
		if failed, _ := about["failed"].([]string); len(failed) > 0 {
			say("failed: " + strings.Join(failed, "; "))
		}
	case "tls", "proxy+tls":
		version, _ := about["tls"].(string)
		cipher, _ := about["cipher"].(string)
		alpn, _ := about["alpn"].(string)
		resumed, _ := about["resumed"].(bool)
		say(handshakeNote(version, cipher, alpn, resumed))
	case "send":
		if reused, _ := about["reused"].(bool); reused {
			remote, _ := about["remote"].(string)
			say("on the connection already open to " + remote)
		}
	}
	if why, failed := about["error"].(string); failed {
		say(why)
	}
	return strings.Join(parts, " · ")
}

// handshakeNote is what a handshake settled on, or nothing when there was none
// or it did not get that far.
func handshakeNote(version, cipher, alpn string, resumed bool) string {
	if version == "" {
		return ""
	}
	parts := []string{version, cipher}
	if alpn != "" {
		parts = append(parts, alpn)
	}
	if resumed {
		parts = append(parts, "session resumed")
	}
	return strings.Join(parts, " · ")
}

// tryBudget decides which requests keep their tries.
//
// Every request is a row for the summary, at a couple of hundred bytes. Its
// tries are several times that, and a report shows them for reportRowLimit
// rows at most: the requests that went wrong first, then the others. So the
// first of each kind to finish keep theirs, up to as many as the report could
// show, and a run of a million requests holds the tries of a few thousand.
type tryBudget struct {
	trouble, fine int
}

// trim is the record to keep: with its tries while there is room for them.
func (b *tryBudget) trim(r result) result {
	count := &b.fine
	if r.Failed() || r.Warned() {
		count = &b.trouble
	}
	if *count++; *count > reportRowLimit {
		r.Tries = nil
	}
	return r
}

// What a report shows of them.

// stepShades is the class each kind of step is drawn with, in a try's bar and
// beside its name. A tunnel through a proxy is drawn as the handshake it ends
// in.
var stepShades = map[string]string{
	"dns":       "bg-step-dns",
	"connect":   "bg-step-connect",
	"tls":       "bg-step-tls",
	"proxy+tls": "bg-step-tls",
	"send":      "bg-step-send",
	"wait":      "bg-step-wait",
	"receive":   "bg-step-receive",
}

// tryRow is one try as the report shows it.
type tryRow struct {
	try
	// Number is which try it was, of how many.
	Number, Of int
	// Offset is how far into the request it began, and Bar the try drawn on
	// the length of the whole request.
	Offset time.Duration
	Bar    []segment
}

// segment is a stretch of a try's bar: a step, or the gap in front of one.
type segment struct {
	Class string
	Width string
	Title string
}

// stepRow is one step as the report lists it.
type stepRow struct {
	step
	Class string
}

// Length is how long the step took.
func (s stepRow) Length() string { return fineDuration(s.Took) }

// Moment says the step is something that happened rather than something that
// was waited on, and so has no length to give.
func (s stepRow) Moment() bool { return s.Name == redirectStep }

// rows are the tries of one request, laid out against how long all of it took.
func tryRows(tries []try, started time.Time, whole time.Duration) []tryRow {
	rows := make([]tryRow, 0, len(tries))
	for i, t := range tries {
		offset := t.Began.Sub(started)
		rows = append(rows, tryRow{
			try: t, Number: i + 1, Of: len(tries),
			Offset: offset, Bar: timeline(t, offset, whole),
		})
	}
	return rows
}

// timeline is a try's steps as stretches of a bar the length of the request.
//
// Against the whole request rather than against the try, so that the bars of
// three tries line up as one picture: when each began, how long it lasted, and
// the waits between them as the gaps.
func timeline(t try, offset, whole time.Duration) []segment {
	if whole <= 0 {
		return nil
	}
	var bar []segment
	reached := time.Duration(0)
	for _, s := range t.Steps {
		if s.Took <= 0 {
			continue
		}
		from := offset + s.From
		if gap := from - reached; gap > 0 {
			bar = append(bar, segment{Width: share(gap, whole)})
		}
		bar = append(bar, segment{
			Class: stepShades[s.Name], Width: share(s.Took, whole),
			Title: s.Name + " " + fineDuration(s.Took),
		})
		reached = from + s.Took
	}
	return bar
}

// share is a length as a percentage of a longer one, for a width.
func share(part, whole time.Duration) string {
	return fmt.Sprintf("%.4f%%", float64(part)*100/float64(whole))
}

// How the try ended, in the words and marks a row uses for a request.
func (t tryRow) ending() reportRow {
	return reportRow{result: result{Status: t.Status, Error: t.Error}}
}

func (t tryRow) Failed() bool    { return t.ending().Failed() }
func (t tryRow) Warned() bool    { return t.ending().Warned() }
func (t tryRow) Glyph() string   { return t.ending().Glyph() }
func (t tryRow) Outcome() string { return t.ending().Outcome() }

// Length is how long the try took, and After how far into the request it
// began.
func (t tryRow) Length() string { return fineDuration(t.Took) }
func (t tryRow) After() string  { return fineDuration(t.Offset) }

// Size is how much came back, decompressed.
func (t tryRow) Size() string { return humanBytes(int64(t.Bytes)) }

// Connection is what the request went out on, or empty when the try never had
// a connection to send it on.
func (t tryRow) Connection() string {
	if !t.Connected {
		return ""
	}
	kind := "new connection to "
	if t.Conn.Reused {
		kind = "connection already open to "
	}
	parts := []string{kind + t.Conn.RemoteAddr}
	if settled := handshakeNote(t.Conn.TLSVersion, t.Conn.CipherSuite, t.Conn.ALPN, t.Conn.Resumed); settled != "" {
		parts = append(parts, settled)
	}
	return strings.Join(parts, " · ")
}

// Waited is how long was let pass before the next try, or empty for the last.
func (t tryRow) Waited() string {
	if t.Wait <= 0 {
		return ""
	}
	return preciseDuration(t.Wait)
}

// Listed are the try's steps, each with the shade it is drawn in.
func (t tryRow) Listed() []stepRow {
	rows := make([]stepRow, 0, len(t.Steps))
	for _, s := range t.Steps {
		rows = append(rows, stepRow{step: s, Class: stepShades[s.Name]})
	}
	return rows
}

// fineDuration is how long one step of a try took.
//
// Finer than preciseDuration, which is for a whole request: most of what a try
// waits on is over in less than the millisecond that counts in, and a column of
// "0ms" says nothing about where the time went.
func fineDuration(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return "0µs"
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < 10*time.Millisecond:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	default:
		return preciseDuration(d)
	}
}
