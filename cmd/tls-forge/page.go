package main

import (
	"strings"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v5"
)

// pageCheck is what an answer has to have to be the page, whatever its status:
// an element matching the selector --wait-for-element names, the text
// --wait-for names, or both. Nil asks nothing of it.
type pageCheck struct {
	element *elementCheck
	text    *textCheck
	// decode reads a body as text, as decoding, the name --html-decoding
	// gives it, says.
	decode   func(*tlsforge.Response) []byte
	decoding string
}

// newPageCheck reads what the three flags were given: what the page has, and
// how its body is read as text to look for it. Neither selector nor text is no
// check, but the decoding is checked all the same.
func newPageCheck(selector, text, decoding string) (*pageCheck, error) {
	decode, err := decoderOf(decoding)
	if err != nil {
		return nil, err
	}
	element, err := newElementCheck(selector)
	if err != nil {
		return nil, err
	}
	found, err := newTextCheck(text)
	if err != nil {
		return nil, err
	}
	if element == nil && found == nil {
		return nil, nil
	}
	return &pageCheck{element: element, text: found, decode: decode, decoding: decoding}, nil
}

// look is what an answer's body is without of what the page has: the element,
// the text or both, whatever its status. The body, and not the status, then
// says whether the answer is the page: a 200 without it is not, and a 403 with
// it is. No check, and no answer, finds nothing. The body is read as text once,
// for both, as --html-decoding says.
func (c *pageCheck) look(res *tlsforge.Response) finding {
	if c == nil || res == nil {
		return finding{}
	}
	found := finding{looked: true}
	text := c.decode(res)
	if c.element != nil && c.element.lacksIn(text) {
		found.MissingElement = c.element.selector
	}
	if c.text != nil && c.text.lacksIn(text) {
		found.MissingText = c.text.given
	}
	return found
}

// wants are what the page has to have, as given: the selector and the text,
// each empty when nothing names it.
func (c *pageCheck) wants() (selector, text string) {
	if c == nil {
		return "", ""
	}
	if c.element != nil {
		selector = c.element.selector
	}
	if c.text != nil {
		text = c.text.given
	}
	return selector, text
}

// readAs is how a body is read as text to look into it, as --html-decoding
// names it, or nothing when nothing is looked for.
func (c *pageCheck) readAs() string {
	if c == nil {
		return ""
	}
	return c.decoding
}

// finding is what looking into an answer's body found: the element matching
// the selector --wait-for-element names, or the text --wait-for names, that it
// was without, each as it was given, and whether it was looked into at all.
type finding struct {
	MissingElement string `json:"missing_element,omitempty"`
	MissingText    string `json:"missing_text,omitempty"`
	// looked says the body was looked into, as every answer's is when a run
	// names what the page has: then the body, and not the status, says
	// whether the answer is the page.
	looked bool
}

// misses says something looked for was not there: the answer is not the page,
// whatever its status.
func (f finding) misses() bool { return f.MissingElement != "" || f.MissingText != "" }

// brief is what it was without as a row says it, after the status: "no #price",
// or `no #price and no "In stock"`.
func (f finding) brief() string { return f.words("no ", "no ") }

// said is the same in words, as a log, a note and a line say it.
func (f finding) said() string { return f.words("no element matching ", "no text matching ") }

func (f finding) words(element, text string) string {
	var parts []string
	if f.MissingElement != "" {
		parts = append(parts, element+f.MissingElement)
	}
	if f.MissingText != "" {
		parts = append(parts, text+shownText(f.MissingText))
	}
	return strings.Join(parts, " and ")
}

// missingInto adds what it was without to what a trace says of a request or a
// try.
func (f finding) missingInto(args traceArgs) {
	if f.MissingElement != "" {
		args["missing_element"] = f.MissingElement
	}
	if f.MissingText != "" {
		args["missing_text"] = f.MissingText
	}
}
