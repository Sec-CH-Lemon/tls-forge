// Package harness is the bench the Chrome fixtures were measured on, kept with
// the code they are held to: testdata/chrome155-requests.json, what Chrome sent
// for each scenario of a page (navigations, forms, fetch(), XHR, CORS,
// redirects, client hints), and testdata/chrome155-decoding.json, how it
// decoded each page.
//
// Measuring is opening each scenario's page in a fresh headless Google Chrome
// against a local server that keeps every request as the bytes said it, over
// HTTP/2, over HTTP/1.1 alone and over plain HTTP; and opening each page whose
// decoding is asked about with --dump-dom. internal/harness/measure measures a
// browser again, to write the fixtures or to hold it to them; the pinned gate
// holds the reference Google Chrome of a release to them with Compare and
// CompareDecoding.
package harness

import (
	"context"
	"time"
)

// A Browser opens pages for the bench, as Google Chrome does.
type Browser interface {
	// Open opens url at the top level, with the profile in dir, until stop
	// is called. A later Open with the same dir has what this one kept.
	Open(ctx context.Context, url, dir string) (stop func(), err error)
	// DumpDOM opens url at the top level in a fresh profile and is the
	// document as the browser serialized it once it had loaded.
	DumpDOM(ctx context.Context, url string) ([]byte, error)
}

// timing is how long the bench waits for what, which a test makes short.
type timing struct {
	// poll is how often the server is asked whether a page has been
	// asked for.
	poll time.Duration
	// limit is how long a scenario has to ask for the page it waits for.
	limit time.Duration
	// after is how long the browser is left open once it has, for the
	// requests that follow it.
	after time.Duration
	// persist is how long a browser is left open after a first visit that
	// a second one reads: Chrome writes its cookies down only every 30 s.
	persist time.Duration
}

// measured is the timing the fixtures were measured with.
var measured = timing{poll: 200 * time.Millisecond, limit: 15 * time.Second, after: 700 * time.Millisecond,
	persist: 35 * time.Second}
