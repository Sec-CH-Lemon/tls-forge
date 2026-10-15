package main

import (
	"bytes"
	"fmt"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// What --wait-for-element asks of a page: that the HTML the server sent has an
// element matching a CSS selector. A site that turns a client away often does
// it with a 200 and a page of its own, a challenge or a notice, rather than with
// a status that says so, and the element the real page has is what tells the
// two apart.
//
// Nothing is rendered and no script runs: the page is the HTML as it came, so
// an element a script would add later is not there to be found, and is not
// waited for.

// elementCheck is a selector, parsed once, and what it was given as.
type elementCheck struct {
	selector string
	group    cascadia.SelectorGroup
}

// newElementCheck parses a selector. None is no check at all; one of only
// spaces is not a selector, rather than none.
func newElementCheck(selector string) (*elementCheck, error) {
	if selector == "" {
		return nil, nil
	}
	group, err := cascadia.ParseGroup(selector)
	if err != nil {
		return nil, fmt.Errorf("%w: --wait-for-element %q is not a CSS selector: %v", errUsage, selector, err)
	}
	return &elementCheck{selector: selector, group: group}, nil
}

// lacksIn says a page, read as text, has no element matching the selector.
func (c *elementCheck) lacksIn(text []byte) bool {
	// A reader of bytes already in memory never fails, and that is all the
	// parser can fail on: it makes a document of whatever it is handed.
	page, _ := html.Parse(bytes.NewReader(text))
	return cascadia.Query(page, c.group) == nil
}
