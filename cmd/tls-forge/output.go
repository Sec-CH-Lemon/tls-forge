package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// bodyDir is where the pages are written when they are kept out of the
	// lines, each of which then names its file.
	bodyDir string
	// headers says every line is to carry the header fields its response came
	// with.
	headers bool
	// say is told about each request as it finishes.
	say func(text string)
}

func (o *linesOutput) fill(r *result, res *tlsforge.Response, j job, lane *traceLane) {
	if o.headers {
		r.Header = res.Header
	}
	if o.bodyDir == "" {
		if utf8.Valid(res.Body) {
			r.Body = string(res.Body)
		} else {
			r.Body = base64.StdEncoding.EncodeToString(res.Body)
			r.BodyEncoding = "base64"
		}
		return
	}
	// Named from the URL so a re-run overwrites the same file. A repeated URL in
	// one input gets a stable occurrence suffix: concurrent workers must not
	// truncate each other's body or make two records point at one response. A
	// second pass over the list counts as a second occurrence, which is how each
	// run of a repeat keeps its own page.
	sum := sha256.Sum256([]byte(j.URL))
	name := hex.EncodeToString(sum[:8])
	if j.occurrence > 1 {
		name += "-" + strconv.Itoa(j.occurrence)
	}
	path := filepath.Join(o.bodyDir, name+".html")
	if err := os.WriteFile(path, res.Body, 0o644); err != nil {
		// On the request's own line rather than ending the run: the page was
		// fetched, and the next one may still be writable.
		r.setError(err)
		return
	}
	lane.instant("saved", "file", traceArgs{"file": path, "bytes": len(res.Body)})
	r.File = path
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
	// path is the file the page is written to, when one was named, and runs how
	// many times the request is made. Made more than once, each run writes a
	// file of its own.
	path string
	runs int
	// say is told about each run as it finishes.
	say func(text string)
	// kept is the file each run was written to, by which run it was.
	kept map[int]string
}

func (o *pageOutput) write(r *result, res *tlsforge.Response, lane *traceLane) error {
	// A request made once is its own first run.
	run := max(r.Run, 1)
	var failed error
	if res != nil && o.path != "" {
		path := o.path
		if o.runs > 1 {
			path = numbered(path, run)
		}
		if failed = os.WriteFile(path, res.Body, 0o644); failed == nil {
			r.File = path
			o.kept[run] = path
			lane.instant("saved", "file", traceArgs{"file": path, "bytes": len(res.Body)})
		}
	}
	o.say(runLine(run, o.runs, *r))
	// Nowhere to put this page is nowhere to put the next, so that ends the run.
	// A request that got no answer has no page to hand over.
	if failed != nil || res == nil {
		return failed
	}
	return o.show.response(res)
}

// saved names the files the runs were written to, in the order of the runs,
// whichever order they finished in.
func (o *pageOutput) saved() []string {
	runs := make([]int, 0, len(o.kept))
	for run := range o.kept {
		runs = append(runs, run)
	}
	sort.Ints(runs)
	files := make([]string, 0, len(runs))
	for _, run := range runs {
		files = append(files, o.kept[run])
	}
	return files
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

// span names the files a run wrote: the one, or the first and the last of
// several, which with numbered names is enough to say all of them. Runs that
// all went to one place, as into /dev/null, went to one place.
func span(files []string) string {
	if first, last := files[0], files[len(files)-1]; first == last {
		return first
	}
	return files[0] + " … " + files[len(files)-1]
}
