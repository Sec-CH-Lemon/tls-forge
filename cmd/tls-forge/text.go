package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// What --wait-for asks of a page: that its body has some text in it, or text a
// regular expression matches, for a page whose element says less than its words
// do, or an answer that is not HTML at all.
//
// The body is read as it came, decoded to UTF-8 and nothing else: markup and
// entities as they are, so "Tom &amp; Jerry" is what has "&amp;" in it, and a
// script's text is in the body like any other.

// textCheck is what --wait-for was given, and what it is looked for with: the
// text itself, or the regular expression it is written as.
type textCheck struct {
	given string
	text  []byte
	re    *regexp.Regexp
}

// regexFlags are the flags a regular expression can have after its closing
// slash: Go's own, each meaning what it does in (?flags).
const regexFlags = "imsU"

// newTextCheck reads what --wait-for was given: a regular expression when it is
// written as one, between slashes, and text to be found as it is when not.
// Nothing is no check at all. Whatever would be looked for wrong without a word
// is refused before anything is fetched.
func newTextCheck(given string) (*textCheck, error) {
	if given == "" {
		return nil, nil
	}
	pattern, flags, isRegex := regexLiteral(given)
	if !isRegex {
		if !utf8.ValidString(given) {
			return nil, fmt.Errorf("%w: --wait-for %q is not UTF-8, which the body is read as", errUsage, given)
		}
		return &textCheck{given: given, text: []byte(given)}, nil
	}
	if i := strings.IndexFunc(flags, func(f rune) bool { return !strings.ContainsRune(regexFlags, f) }); i >= 0 {
		return nil, fmt.Errorf("%w: --wait-for %q: %c is not a flag a regular expression takes; they are i, m, s and U",
			errUsage, given, flags[i])
	}
	if pattern == "" {
		return nil, fmt.Errorf("%w: --wait-for %q is an empty regular expression, which every body matches", errUsage, given)
	}
	// A control character in a pattern is written as an escape, \n or \x{1b}:
	// as itself it would break the line everything the check says is shown on.
	if strings.ContainsFunc(pattern, unicode.IsControl) {
		return nil, fmt.Errorf(`%w: --wait-for %q has a control character in it; a regular expression writes one as \n, \t or \x{…}`,
			errUsage, given)
	}
	// Compiled alone first, so that a mistake is said in the words it was
	// written in and not with the flags in front of it.
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, fmt.Errorf("%w: --wait-for %q is not a regular expression: %v", errUsage, given, err)
	}
	if flags != "" {
		pattern = "(?" + flags + ")" + pattern
	}
	return &textCheck{given: given, re: regexp.MustCompile(pattern)}, nil
}

// regexLiteral splits a value written as a regular expression: one that begins
// with a slash, has another after it, and has nothing after the last but
// letters, its flags, as /\d+ in stock/i. Anything else is text, a path such as
// /catalog/item.html with it.
func regexLiteral(given string) (pattern, flags string, ok bool) {
	end := strings.LastIndexByte(given, '/')
	if !strings.HasPrefix(given, "/") || end < 1 {
		return "", "", false
	}
	flags = given[end+1:]
	if strings.ContainsFunc(flags, func(r rune) bool { return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') }) {
		return "", "", false
	}
	return given[1:end], flags, true
}

// lacksIn says a body, read as text, has nothing the check looks for.
func (c *textCheck) lacksIn(text []byte) bool {
	if c.re != nil {
		return !c.re.Match(text)
	}
	return !bytes.Contains(text, c.text)
}

// shownText is what --wait-for was given, as it is shown: a regular expression
// as it was written, between its slashes, and text in quotes, so that the two
// are told apart and where text begins and ends can be seen.
func shownText(given string) string {
	if _, _, ok := regexLiteral(given); ok {
		return given
	}
	return strconv.Quote(given)
}
