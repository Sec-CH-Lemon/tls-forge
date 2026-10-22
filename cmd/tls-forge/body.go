package main

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html/charset"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v3"
)

// textOf is an answer's body as UTF-8 text, as a browser reads it: in the
// encoding its byte order mark names, else the one its Content-Type does, else
// as UTF-8 when it is that throughout, else in the one a <meta> in its first
// 1024 bytes names, or windows-1252. A byte order mark is not text, and is
// left out.
//
// UTF-8 is tried over the whole body, and before a <meta> is believed. What a
// page names in its own markup is looked for in its first 1024 bytes, and the
// guess made from those alone says windows-1252 whenever they are ASCII: JSON
// sent without a charset, with Cyrillic further on, would be read as that and
// a word in it not found. Text in any other encoding is all but never valid
// UTF-8, so nothing in one is mistaken for it; a page that is UTF-8 throughout
// and names another is UTF-8 that names the wrong one.
func textOf(res *tlsforge.Response) []byte {
	body := res.Body
	enc, _, bom := charset.DetermineEncoding(body, "")
	if !bom {
		named, _ := charset.Lookup(charsetOf(res.Header))
		switch {
		case named != nil:
			enc = named
		case utf8.Valid(body):
			return body
		}
	}
	if text, err := enc.NewDecoder().Bytes(body); err == nil {
		body = text
	}
	return bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
}

// charsetOf is the charset named with the type a browser goes by, as the Fetch
// standard reads it: the last type's own, or, when it names none, that of the
// first of the run of the same type it ends.
func charsetOf(header map[string][]string) string {
	essence, ofEssence, said := "", "", ""
	for _, item := range contentTypeItems(header) {
		mediaType := mediaTypeOf(item)
		if mediaType == "" || mediaType == "*/*" {
			continue
		}
		own := charsetParam(item)
		if mediaType != essence {
			essence, ofEssence = mediaType, own
		}
		said = ofEssence
		if own != "" {
			said = own
		}
	}
	return said
}

// charsetParam is the charset a Content-Type value names among its parameters,
// as the MIME Sniffing standard reads them: the first charset that has a
// value, its name in any case and its value out of its quotes.
func charsetParam(value string) string {
	for _, param := range splitOutsideQuotes(value, ';')[1:] {
		name, said, ok := strings.Cut(strings.TrimLeft(param, httpSpace), "=")
		if !ok || !strings.EqualFold(name, "charset") {
			continue
		}
		if strings.HasPrefix(said, `"`) {
			said = unquoted(said)
		} else {
			said = strings.TrimRight(said, httpSpace)
		}
		if said != "" {
			return said
		}
	}
	return ""
}

// httpSpace is what HTTP counts as white space around a parameter.
const httpSpace = " \t\r\n"

// unquoted is what a quoted string says: everything to its closing quote, or
// to the end when it has none, with each backslash taken out and the character
// after it kept.
func unquoted(quoted string) string {
	var said strings.Builder
	for i := 1; i < len(quoted); i++ {
		switch c := quoted[i]; {
		case c == '\\' && i+1 < len(quoted):
			i++
			said.WriteByte(quoted[i])
		case c == '"':
			return said.String()
		default:
			said.WriteByte(c)
		}
	}
	return said.String()
}
