package main

import (
	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// pageCheck is what an answer has to have to be the page, whatever its status:
// an element matching the selector --wait-for-element names. Nil asks nothing
// of it.
type pageCheck struct {
	element *elementCheck
}

// newPageCheck reads what the flag was given. Nothing is no check.
func newPageCheck(selector string) (*pageCheck, error) {
	element, err := newElementCheck(selector)
	if element == nil {
		return nil, err
	}
	return &pageCheck{element: element}, nil
}

// look is what an answer's body is without of what the page has, whatever its
// status. The body, and not the status, then says whether the answer is the
// page: a 200 without it is not, and a 403 with it is. No check, and no answer,
// finds nothing.
func (c *pageCheck) look(res *tlsforge.Response) finding {
	if c == nil || res == nil {
		return finding{}
	}
	found := finding{looked: true}
	if c.element.lacksIn(textOf(res)) {
		found.MissingElement = c.element.selector
	}
	return found
}

// wants is what the page has to have, as given: the selector, empty when
// nothing names it.
func (c *pageCheck) wants() string {
	if c == nil {
		return ""
	}
	return c.element.selector
}

// finding is what looking into an answer's body found: the element matching
// the selector --wait-for-element names that it was without, as it was given,
// and whether it was looked into at all.
type finding struct {
	MissingElement string `json:"missing_element,omitempty"`
	// looked says the body was looked into, as every answer's is when a run
	// names what the page has: then the body, and not the status, says
	// whether the answer is the page.
	looked bool
}

// misses says something looked for was not there: the answer is not the page,
// whatever its status.
func (f finding) misses() bool { return f.MissingElement != "" }

// brief is what it was without as a row says it, after the status: "no #price".
func (f finding) brief() string { return f.words("no ") }

// said is the same in words, as a log, a note and a line say it.
func (f finding) said() string { return f.words("no element matching ") }

func (f finding) words(element string) string {
	if f.MissingElement == "" {
		return ""
	}
	return element + f.MissingElement
}

// missingInto adds what it was without to what a trace says of a request or a
// try.
func (f finding) missingInto(args traceArgs) {
	if f.MissingElement != "" {
		args["missing_element"] = f.MissingElement
	}
}
