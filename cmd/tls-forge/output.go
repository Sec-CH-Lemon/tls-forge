package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// What becomes of what a request brought back.
//
// One of two things. A command that names one URL is handed the page, as it
// came: that is what was asked for, and `fetch URL > page.html` is the whole
// of using it. A command that names several, or a list, gets a line of JSON for
// each instead, because pages written one after another are not something a
// program can take apart again.

// output is where the results of a run go.
type output interface {
	// write hands one result on, with its response when there was one. It is
	// called for one result at a time, and an error from it ends the run.
	write(r *result, res *tlsforge.Response, lane *traceLane) error
}

// filler is an output with something to keep of a response in the record of
// its request, before the record is handed on.
//
// Apart from write, because this is called by the worker that got the
// response, several at once: it is where a page is written to its own file
// without every other worker waiting for it.
type filler interface {
	fill(r *result, res *tlsforge.Response, j job, lane *traceLane)
}

// linesOutput writes a line of JSON for each request.
type linesOutput struct {
	encoder *json.Encoder
	// headers says every line is to carry the header fields its response came
	// with.
	headers bool
	// say is told about each request as it finishes.
	say func(text string)
}

func (o *linesOutput) fill(r *result, res *tlsforge.Response, _ job, _ *traceLane) {
	if o.headers {
		r.Header = res.Header
	}
	if r.File != "" {
		// Kept in a file already, which the line names: a page is not carried
		// twice.
		return
	}
	if utf8.Valid(res.Body) {
		r.Body = string(res.Body)
	} else {
		r.Body = base64.StdEncoding.EncodeToString(res.Body)
		r.BodyEncoding = "base64"
	}
}

func (o *linesOutput) write(r *result, _ *tlsforge.Response, _ *traceLane) error {
	o.say(verboseLine(*r))
	if err := o.encoder.Encode(r); err != nil {
		return fmt.Errorf("fetch: writing result: %w", err)
	}
	return nil
}

// pageOutput hands the page over as it came.
type pageOutput struct {
	show *showing
	// runs is how many times the request is made.
	runs int
	// say is told about each run as it finishes.
	say func(text string)
}

func (o *pageOutput) write(r *result, res *tlsforge.Response, _ *traceLane) error {
	// A request made once is its own first run.
	o.say(runLine(max(r.Run, 1), o.runs, *r))
	// A request that got no answer has no page to hand over.
	if res == nil {
		return nil
	}
	return o.show.response(res)
}

// showing is what of a response is printed on standard output.
type showing struct {
	out     io.Writer
	headers bool
	body    bool
	// midLine is set when the last thing printed did not end its line.
	midLine bool
}

// response prints what was asked for of one response: the status and headers,
// the body, both or neither.
func (s *showing) response(res *tlsforge.Response) error {
	if s.headers {
		var head strings.Builder
		fmt.Fprintf(&head, "%d %s\n", res.Status, res.URL)
		names := make([]string, 0, len(res.Header))
		for name := range res.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&head, "%s: %s\n", name, strings.Join(res.Header[name], "; "))
		}
		head.WriteString("\n")
		// In one write, so that a status being redrawn steps aside once for the
		// whole block rather than between its lines.
		if _, err := io.WriteString(s.out, head.String()); err != nil {
			return err
		}
		s.midLine = false
	}
	if !s.body || len(res.Body) == 0 {
		return nil
	}
	s.midLine = res.Body[len(res.Body)-1] != '\n'
	_, err := s.out.Write(res.Body)
	return err
}

// runLine is one run of a request that is made several times, as it is said to
// somebody who asked to hear about every request.
//
// The columns a list prints for a URL, so that ten runs of one page and ten
// pages read the same way, with the file the run was written to where a list
// has the URL.
func runLine(run, runs int, r result) string {
	// Every run goes the same way, so which proxy that was is not said again on
	// each of them.
	r.URL, r.Proxy = r.File, ""
	width := len(strconv.Itoa(runs))
	return strings.TrimRight(fmt.Sprintf("  %*d/%d%s", width, run, runs, verboseLine(r)), " ")
}
