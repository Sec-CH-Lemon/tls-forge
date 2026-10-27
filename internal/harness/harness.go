// Package harness is the bench the Chrome fixtures were measured on, kept with
// the code they are held to: testdata/chrome155-requests.json, what Chrome sent
// for each scenario of a page (navigations, forms, fetch(), XHR, CORS,
// redirects, client hints), testdata/chrome155-connections.json, which
// connection it sent each on, testdata/chrome155-hpack.json, how it wrote the
// header blocks of each connection into HPACK, testdata/chrome155-decoding.json,
// how it decoded each page, testdata/chrome155-flow.json, the WINDOW_UPDATEs
// it sent while it read an answer (flow.go), testdata/chrome155-urls.json,
// the server name, authority and target it sent for each URL a page or a
// Location gave it, or that it sent nothing (urls.go), and
// testdata/chrome155-hellos.json, the order of the extensions of the first
// ClientHello it sent to each of many names (hellos.go).
//
// Measuring is opening each scenario's page in a fresh headless Google Chrome
// against a local server that keeps every request as the bytes said it, over
// HTTP/2, over HTTP/1.1 alone and over plain HTTP; and opening each page whose
// decoding is asked about with --dump-dom. internal/harness/measure measures a
// browser again, to write the fixtures or to hold it to them; the pinned gate
// holds the Google Chrome a release's runner installs from Google to the
// fixtures of requests and decodings with Compare and CompareDecoding.
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

// trusting is a Browser that can take a server's certificate as a site's, one
// a public authority vouched for: what a scenario of connections is measured
// with, since Chrome sends a request over an HTTP/2 connection to another name
// only on a certificate it takes so.
type trusting interface {
	trusting(spki string) Browser
}

// remapping is a Browser that can take the ports a scheme means to the
// bench's: what the URL cases that name no port, or 443 or 80, are measured
// with.
type remapping interface {
	defaultPorts(tls, plain int) Browser
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
