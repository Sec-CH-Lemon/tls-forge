package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

// The report for a program.
//
// The page is for whoever opens it. This is the same run for whatever comes
// next: a script that wants the ten slowest requests, a dashboard, a comparison
// of two runs. Everything the page shows is here under a name, and every
// request is here, where the page stops at what a browser can open.
//
// The names are the ones already in use. A request is the line of JSON a list
// is answered with, with its tries added, and a connection is described in the
// words a trace describes it in, so that what reads one of them reads this.

// reportDocument is the whole of it.
type reportDocument struct {
	// Command is which of them made the run, and Version which build of it.
	Command   string    `json:"command"`
	Version   string    `json:"version"`
	Generated time.Time `json:"generated"`
	// Trace is the file the whole run was traced to, when it was.
	Trace    string            `json:"trace,omitempty"`
	Summary  documentSummary   `json:"summary"`
	Proxies  []documentProxy   `json:"proxies,omitempty"`
	Requests []documentRequest `json:"requests"`
}

// documentSummary is the run in numbers: the three ways a request can end, and
// what the run cost.
type documentSummary struct {
	Requests   int `json:"requests"`
	Scraped    int `json:"scraped"`
	Not2xx     int `json:"not_2xx"`
	NoResponse int `json:"no_response"`
	// SuccessRate is the share that came back as the page, as a percentage.
	SuccessRate float64 `json:"success_rate"`
	Bytes       int64   `json:"bytes"`
	Retries     int     `json:"retries"`
	ElapsedMS   int64   `json:"elapsed_ms"`
	// AvgMS is what one request took, its retries included. It is not the
	// elapsed time divided by the requests: several are out at once.
	AvgMS int64 `json:"avg_ms"`
}

// documentProxy is one proxy's showing, with every address its requests came
// out of.
type documentProxy struct {
	Proxy    string         `json:"proxy"`
	Requests int            `json:"requests"`
	CameBack int            `json:"came_back"`
	Alive    bool           `json:"alive"`
	Exits    []documentExit `json:"exits,omitempty"`
}

// documentExit is where requests came out, when somebody could say.
type documentExit struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
}

// resultFields is a result without its own way of being written, so that
// something holding one is written field by field rather than as the result
// alone. A method that writes JSON is inherited by whatever embeds its type,
// and would leave out everything added beside it.
type resultFields result

// documentRequest is one request: the line of JSON that is written for it,
// where it came out, and every try that was made at it.
type documentRequest struct {
	resultFields
	Exit *documentExit `json:"exit,omitempty"`
	// ExitError is why nobody could say where it came out.
	ExitError string `json:"exit_error,omitempty"`
	// Tries are there for the requests whose tries were kept: the first few
	// thousand of a run, the ones that went wrong before the others.
	Tries []documentTry `json:"tries,omitempty"`
}

// documentTry is one attempt at a request. Times are milliseconds, with the
// fraction a step needs: most of what a try waits on is over in less than one.
type documentTry struct {
	Started time.Time `json:"started"`
	MS      float64   `json:"ms"`
	Status  int       `json:"status,omitempty"`
	Bytes   int       `json:"bytes,omitempty"`
	Error   string    `json:"error,omitempty"`
	// Connection is what the request went out on, when the try got that far.
	Connection *documentConnection `json:"connection,omitempty"`
	Steps      []documentStep      `json:"steps,omitempty"`
	// ResponseHeaders are the fields the answer came with, and BodyStart how
	// its body began when it was not the page.
	ResponseHeaders []string `json:"response_headers,omitempty"`
	BodyStart       string   `json:"body_start,omitempty"`
	// WaitMS is how long was let pass before the request was made again.
	WaitMS int64 `json:"wait_ms,omitempty"`
}

// documentConnection is a connection, under the names a trace gives it.
type documentConnection struct {
	Reused  bool   `json:"reused"`
	Remote  string `json:"remote"`
	TLS     string `json:"tls,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
	ALPN    string `json:"alpn,omitempty"`
	Resumed bool   `json:"resumed,omitempty"`
}

// documentStep is one thing a try waited on.
type documentStep struct {
	Name string `json:"name"`
	// FromMS is when it began, counted from when the try did.
	FromMS float64 `json:"from_ms"`
	MS     float64 `json:"ms"`
	Note   string  `json:"note,omitempty"`
	// RequestHeaders are the fields the request went out with, in the order
	// they were written, on the step that is the sending of it.
	RequestHeaders []string `json:"request_headers,omitempty"`
	// Unfinished says the try ended while this was going on.
	Unfinished bool `json:"unfinished,omitempty"`
}

// renderReportJSON is the run as that document.
func renderReportJSON(w io.Writer, in reportInput) error {
	s := in.summary
	doc := reportDocument{
		Command:   in.command,
		Version:   version,
		Generated: now(),
		Trace:     in.trace,
		Summary: documentSummary{
			Requests: s.Total, Scraped: s.Succeeded, Not2xx: s.Warned, NoResponse: s.Failed,
			SuccessRate: rate(s.Succeeded, s.Total),
			Bytes:       s.Bytes, Retries: s.Retries,
			ElapsedMS: s.Elapsed.Milliseconds(), AvgMS: s.Average().Milliseconds(),
		},
		// Never null: a run of nothing made no requests, which is a list of none.
		Requests: make([]documentRequest, 0, len(in.records)),
	}
	for _, p := range s.Proxies {
		proxy := documentProxy{Proxy: p.Proxy, Requests: p.Requests, CameBack: p.Succeeded, Alive: p.Alive()}
		// Every one of them, where the page lists a few: this is what a program
		// counts them from.
		for _, exit := range p.Exits {
			proxy.Exits = append(proxy.Exits, *exitOf(exit))
		}
		doc.Proxies = append(doc.Proxies, proxy)
	}
	for _, r := range in.records {
		request := documentRequest{resultFields: resultFields(r), Exit: exitOf(r.Exit), ExitError: r.ExitError}
		// Without its password, as everywhere else a person can read it.
		request.Proxy = redactProxy(r.Proxy)
		for _, t := range r.Tries {
			request.Tries = append(request.Tries, documentTryOf(t))
		}
		doc.Requests = append(doc.Requests, request)
	}
	// By when each went out, as the page has them, rather than by when the
	// answers happened to come back.
	sort.SliceStable(doc.Requests, func(i, j int) bool {
		return doc.Requests[i].Started.Before(doc.Requests[j].Started)
	})

	encoder := json.NewEncoder(w)
	// Indented, because this is also opened and read. And a URL is mostly
	// ampersands: escaped for HTML it no longer matches the one being looked for.
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("%s: writing the report: %w", in.command, err)
	}
	return nil
}

// documentTryOf is one try as the document has it.
func documentTryOf(t try) documentTry {
	out := documentTry{
		Started: t.Began, MS: millis(t.Took), Status: t.Status, Bytes: t.Bytes, Error: t.Error,
		ResponseHeaders: fieldLines(t.Answer), BodyStart: t.Body, WaitMS: t.Wait.Milliseconds(),
	}
	if t.Connected {
		out.Connection = &documentConnection{
			Reused: t.Conn.Reused, Remote: t.Conn.RemoteAddr, TLS: t.Conn.TLSVersion,
			Cipher: t.Conn.CipherSuite, ALPN: t.Conn.ALPN, Resumed: t.Conn.Resumed,
		}
	}
	for _, s := range t.Steps {
		out.Steps = append(out.Steps, documentStep{
			Name: s.Name, FromMS: millis(s.From), MS: millis(s.Took), Note: s.Note,
			RequestHeaders: fieldLines(s.Written), Unfinished: s.Cut,
		})
	}
	return out
}

// exitOf is where something came out, or nothing when nobody said.
func exitOf(found egress) *documentExit {
	if found.IP == "" {
		return nil
	}
	return &documentExit{IP: found.IP, Country: found.countryCode()}
}

// rate is a share as a percentage to one decimal place, which is what the page
// and the terminal give it to.
func rate(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return math.Round(float64(part)*1000/float64(total)) / 10
}

// millis is a length in milliseconds, to the microsecond.
func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// fieldLines is header fields kept one to a line, as a list of them.
func fieldLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}
