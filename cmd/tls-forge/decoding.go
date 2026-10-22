package main

import (
	"bytes"
	"net/http"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v5"
)

// The ways --html-decoding reads a body as text, for --wait-for and
// --wait-for-element to look into.
const (
	// decodingLegacy is textOf, as page checks have always read a body: in
	// the encoding its byte order mark or Content-Type names, else as UTF-8
	// when it is UTF-8 throughout, whatever a <meta> says. The default.
	decodingLegacy = "legacy"
	// decodingBrowser is browserTextOf: as Chrome decodes the document.
	decodingBrowser = "browser"
)

// decoderOf is the way of reading a body --html-decoding names.
func decoderOf(name string) (func(*tlsforge.Response) []byte, error) {
	switch name {
	case decodingLegacy:
		return textOf, nil
	case decodingBrowser:
		return browserTextOf, nil
	}
	return nil, badValue("--html-decoding", name, "legacy or browser")
}

// browserTextOf is an answer's body as UTF-8 text, decoded as Chrome 155
// decodes the document it opens: in the encoding chromeEncoding says, each
// byte or run of bytes the encoding has nothing for a U+FFFD. XML is read only
// up to the first of them, where Chrome's decoder stops reading it, except in
// UTF-16, which it reads on. testdata/chrome155-decoding.json is what Chrome
// was measured to do, case by case.
func browserTextOf(res *tlsforge.Response) []byte {
	kind := documentKind(res.Header, res.Body)
	label, body := chromeEncoding(kind, res.Header, res.Body)
	if kind == kindXML {
		return decodedToError(label, body)
	}
	return decodedAs(label, body)
}

// What Chrome decodes a document as, by its type.
const (
	kindHTML = "html"
	kindXML  = "xml"
	kindJSON = "json"
	kindCSS  = "css"
	kindText = "text"
)

// documentKind is what Chrome decodes a body of its Content-Type as. A body
// with no type, unknown/unknown or application/unknown is sniffed, as Chrome
// sniffs one. Chrome shows RSS and Atom as text, and reads text/xsl as text.
func documentKind(header map[string][]string, body []byte) string {
	mediaType := contentTypeOf(header)
	if mediaType == "" || mediaType == "unknown/unknown" || mediaType == "application/unknown" {
		mediaType = mediaTypeOf(http.DetectContentType(body))
	}
	switch {
	case mediaType == "text/html":
		return kindHTML
	case mediaType == "application/rss+xml" || mediaType == "application/atom+xml":
		return kindText
	case mediaType == "text/xml" || mediaType == "application/xml" || xmlSuffixed(mediaType):
		return kindXML
	case mediaType == "application/json" || mediaType == "text/json" || strings.HasSuffix(mediaType, "+json"):
		return kindJSON
	case mediaType == "text/css":
		return kindCSS
	}
	return kindText
}

// xmlSuffixed reports a subtype that ends in +xml after something, as Chrome
// tells XML by its type: image/svg+xml does, text/+xml does not.
func xmlSuffixed(mediaType string) bool {
	return strings.HasSuffix(mediaType, "+xml") && !strings.HasSuffix(mediaType, "/+xml")
}

// chromeEncoding is the encoding Chrome decodes a document of a kind in, by
// its canonical label, and the bytes it decodes: all but a byte order mark.
// It goes as Chrome's TextResourceDecoder does, the first to name one
// deciding:
//
//   - a byte order mark of UTF-8 or UTF-16;
//   - the charset of the Content-Type;
//   - in HTML and XML, "<?x" in UTF-16 at the very start, else an XML
//     declaration there (xmlDeclared), which in HTML a <meta> overrides
//     (metaCharset); in CSS, an @charset rule at the very start (cssCharset);
//   - else UTF-8 for XML and JSON, and for the rest windows-1252, which is
//     what Chrome in English falls back to.
//
// A document naming UTF-16 in itself is read as UTF-8, since it could not
// have been read to find the name otherwise. Chrome guesses the encoding of
// HTML, CSS and text that name none from their bytes before it falls back,
// and finds any but UTF-8 that way: this does not guess, and reads such a
// document as windows-1252, as Chrome reads one in UTF-8.
func chromeEncoding(kind string, header map[string][]string, body []byte) (string, []byte) {
	for _, bom := range byteOrderMarks {
		if rest, ok := bytes.CutPrefix(body, bom.mark); ok {
			return bom.label, rest
		}
	}
	if label := encodingLabel(strings.Trim(charsetOf(header), httpSpace)); label != "" {
		return label, body
	}
	switch kind {
	case kindHTML, kindXML:
		if label := utf16Declared(body); label != "" {
			return label, body
		}
		declared := byteBased(encodingLabel(xmlDeclared(body)))
		if kind == kindHTML {
			if label := metaCharset(body); label != "" {
				return label, body
			}
		}
		if declared != "" {
			return declared, body
		}
	case kindCSS:
		if label := byteBased(encodingLabel(cssCharset(body))); label != "" {
			return label, body
		}
	}
	if kind == kindXML || kind == kindJSON {
		return "utf-8", body
	}
	return "windows-1252", body
}

// byteOrderMarks are the byte order marks Chrome reads, and the encodings they
// mark.
var byteOrderMarks = []struct {
	mark  []byte
	label string
}{
	{[]byte("\xef\xbb\xbf"), "utf-8"},
	{[]byte("\xfe\xff"), "utf-16be"},
	{[]byte("\xff\xfe"), "utf-16le"},
}

// encodingLabel is the canonical name of the encoding a label names, as
// Chrome looks one up: a label of the Encoding standard, or replacement, in
// any case, and nothing else. Not one with white space around it, nor one
// spelt with a letter outside ASCII that folds to one inside, as the Kelvin
// sign folds to k.
func encodingLabel(label string) string {
	for i := 0; i < len(label); i++ {
		if label[i] >= utf8.RuneSelf {
			return ""
		}
	}
	if strings.TrimSpace(label) != label {
		return ""
	}
	_, canonical := charset.Lookup(label)
	return canonical
}

// byteBased is the encoding Chrome reads a document in that names one in
// itself: UTF-8 for UTF-16.
func byteBased(label string) string {
	if label == "utf-16be" || label == "utf-16le" {
		return "utf-8"
	}
	return label
}

// utf16Declared is the UTF-16 a body is in that begins with "<?x" in it, the
// start of an XML declaration, as Chrome takes one with no byte order mark.
func utf16Declared(body []byte) string {
	switch {
	case bytes.HasPrefix(body, []byte("<\x00?\x00x\x00")):
		return "utf-16le"
	case bytes.HasPrefix(body, []byte("\x00<\x00?\x00x")):
		return "utf-16be"
	}
	return ""
}

// xmlDeclared is the label an XML declaration at the very start of a body
// gives, as Chrome reads one, in HTML too: the body begins "<?xml", and up to
// the first ">" the first "encoding", in lower case, is followed, past any
// spaces and control characters, by an equals sign, more of them and a quoted
// name. Anything else gives none.
func xmlDeclared(body []byte) string {
	if !bytes.HasPrefix(body, []byte("<?xml")) {
		return ""
	}
	end := bytes.IndexByte(body, '>')
	if end < 0 {
		return ""
	}
	declaration := body[:end]
	at := bytes.Index(declaration, []byte("encoding"))
	if at < 0 {
		return ""
	}
	at = pastControls(declaration, at+len("encoding"))
	if at == len(declaration) || declaration[at] != '=' {
		return ""
	}
	at = pastControls(declaration, at+1)
	if at == len(declaration) || declaration[at] != '"' && declaration[at] != '\'' {
		return ""
	}
	name, _, closed := bytes.Cut(declaration[at+1:], declaration[at:at+1])
	if !closed {
		return ""
	}
	return string(name)
}

// cssCharset is the label an @charset rule at the very start of a style sheet
// gives, as Chrome reads one: exactly `@charset "`, the name and `";`.
func cssCharset(body []byte) string {
	rest, ok := bytes.CutPrefix(body, []byte(`@charset "`))
	if !ok {
		return ""
	}
	name, after, closed := bytes.Cut(rest, []byte(`"`))
	if !closed || !bytes.HasPrefix(after, []byte(";")) {
		return ""
	}
	return string(name)
}

// metaScanBytes is how far into a page Chrome looks for a <meta> naming its
// encoding once the page has left its head.
const metaScanBytes = 1024

// metaCharset is the encoding the first <meta> to name one names, as
// Chrome's HTMLMetaCharsetParser finds it. The tags are read as the HTML
// tokenizer reads them, so that a <meta> in a comment, <title>, <textarea>,
// <script>, <style>, <xmp>, <iframe>, <noembed> or <noframes> is text, but
// one in <noscript> is not: the parser reads a page as if scripts were off.
// It stops looking once the page has left its head, by a tag a head has no
// place for or by the end of the head, and is metaScanBytes in: a <meta> deep
// in a long head counts, as does one just past an early <body>.
func metaCharset(body []byte) string {
	tokens := html.NewTokenizer(bytes.NewReader(body))
	inHead, read := true, 0
	for {
		kind := tokens.Next()
		if kind == html.ErrorToken {
			return ""
		}
		raw := tokens.Raw()
		read += len(raw)
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken || kind == html.EndTagToken {
			name, _ := tokens.TagName()
			tag, start := string(name), kind != html.EndTagToken
			if start && tag == "noscript" {
				tokens.NextIsNotRawText()
			}
			if start && tag == "meta" {
				if label := metaLabel(attributesOf(raw)); label != "" {
					return label
				}
			}
			inHead = inHead && keepsHead(tag, start)
		}
		if !inHead && read >= metaScanBytes {
			return ""
		}
	}
}

// keepsHead reports a tag Chrome's scan for a <meta> takes to keep the page in
// its head: one a head has, or the start of html or head. Any other, and the
// end of html or head, leaves it.
func keepsHead(tag string, start bool) bool {
	switch tag {
	case "script", "noscript", "style", "link", "meta", "object", "title", "base":
		return true
	case "html", "head":
		return start
	}
	return false
}

// metaLabel is the encoding a <meta> names, as Chrome reads its attributes,
// in order: charset names one, the last of them winning; content does until a
// charset has, by what follows "charset" in it (contentCharset), and counts
// only with an http-equiv of Content-Type, wherever that is. The name is
// looked up with HTML white space around it taken off. UTF-16 is UTF-8 here,
// and x-user-defined windows-1252.
func metaLabel(attributes []attribute) string {
	named, viaCharset, pragma := "", false, false
	for _, a := range attributes {
		switch a.name {
		case "charset":
			named, viaCharset = a.value, true
		case "content":
			if !viaCharset {
				named = contentCharset(a.value)
			}
		case "http-equiv":
			pragma = pragma || strings.EqualFold(a.value, "content-type")
		}
	}
	if !viaCharset && !pragma {
		return ""
	}
	label := byteBased(encodingLabel(strings.Trim(named, htmlSpace)))
	if label == "x-user-defined" {
		return "windows-1252"
	}
	return label
}

// htmlSpace is white space as HTML has it.
const htmlSpace = " \t\n\f\r"

// attribute is one of a tag's: its name in lower case, and its value with its
// character references read.
type attribute struct{ name, value string }

// attributesOf are the attributes of a start tag, from "<" to ">" as it was
// written, read as the HTML tokenizer reads them but every one of them, in
// order: the tokenizer leaves out an attribute a tag has already, and Chrome's
// scan for a <meta> does not, which goes by the last charset of two.
func attributesOf(tag []byte) []attribute {
	at := pastName(tag, 1, "/>")
	var attributes []attribute
	for {
		for at < len(tag) && (isHTMLSpace(tag[at]) || tag[at] == '/') {
			at++
		}
		if at >= len(tag) || tag[at] == '>' {
			return attributes
		}
		// A name can begin with an equals sign, which ends any other.
		start := at
		at = pastName(tag, at+1, "/>=")
		name, value := lowerASCII(string(tag[start:at])), ""
		if at = pastHTMLSpace(tag, at); at < len(tag) && tag[at] == '=' {
			value, at = attributeValue(tag, pastHTMLSpace(tag, at+1))
		}
		attributes = append(attributes, attribute{name, html.UnescapeString(value)})
	}
}

// attributeValue is the value of an attribute that begins at in a tag, quoted
// or not, and where the tag goes on after it.
func attributeValue(tag []byte, at int) (string, int) {
	if at < len(tag) && (tag[at] == '"' || tag[at] == '\'') {
		value, _, _ := bytes.Cut(tag[at+1:], tag[at:at+1])
		return string(value), at + len(value) + 2
	}
	end := pastName(tag, at, ">")
	return string(tag[at:end]), end
}

// pastName is the first index from at in a tag that is white space or one of
// ends: where a name, or an unquoted value, ends.
func pastName(tag []byte, at int, ends string) int {
	for at < len(tag) && !isHTMLSpace(tag[at]) && strings.IndexByte(ends, tag[at]) < 0 {
		at++
	}
	return at
}

// isHTMLSpace reports a byte HTML takes for white space.
func isHTMLSpace(c byte) bool { return strings.IndexByte(htmlSpace, c) >= 0 }

// pastHTMLSpace is the first index from at in s that is not white space.
func pastHTMLSpace(s []byte, at int) int {
	for at < len(s) && isHTMLSpace(s[at]) {
		at++
	}
	return at
}

// contentCharset is what follows "charset" in the content of a <meta>, as
// Chrome's ExtractCharset reads it: past any spaces and control characters,
// an equals sign and more of them, then either everything up to the closing
// quote, or nothing when there is none, or everything up to a space, a control
// character, a quote or a semicolon. A "charset" with no equals sign after it
// is passed over for the next.
func contentCharset(content string) string {
	lower := lowerASCII(content)
	for at := 0; ; {
		found := strings.Index(lower[at:], "charset")
		if found < 0 {
			return ""
		}
		at = pastControls(content, at+found+len("charset"))
		if at == len(content) || content[at] != '=' {
			continue
		}
		at = pastControls(content, at+1)
		if at == len(content) {
			return ""
		}
		if quote := content[at]; quote == '"' || quote == '\'' {
			name, _, closed := strings.Cut(content[at+1:], content[at:at+1])
			if !closed {
				return ""
			}
			return name
		}
		end := at
		for end < len(content) && content[end] > ' ' && !strings.ContainsRune(`"';`, rune(content[end])) {
			end++
		}
		return content[at:end]
	}
}

// lowerASCII is s with its ASCII capitals in lower case and every other byte
// as it was, so that an index into it is one into s, as one into
// strings.ToLower(s) need not be.
func lowerASCII(s string) string {
	lower := []byte(s)
	for i, c := range lower {
		if 'A' <= c && c <= 'Z' {
			lower[i] = c + 'a' - 'A'
		}
	}
	return string(lower)
}

// pastControls is the first index from at in s that is neither a space nor a
// control character.
func pastControls[T string | []byte](s T, at int) int {
	for at < len(s) && s[at] <= ' ' {
		at++
	}
	return at
}

// decodedAs is body decoded from the encoding a canonical label names, each
// byte or run of bytes it has nothing for a U+FFFD, as the Encoding standard
// has it. Nothing is nothing in any, replacement too; a body that is UTF-8
// throughout, read as UTF-8, is itself.
func decodedAs(label string, body []byte) []byte {
	if len(body) == 0 || label == "utf-8" && utf8.Valid(body) {
		return body
	}
	enc, _ := charset.Lookup(label)
	text, _ := enc.NewDecoder().Bytes(body)
	return text
}

// decodedToError is body decoded up to the first bytes the encoding has
// nothing for, where Chrome stops reading XML: in UTF-8 its bytes say where,
// since a U+FFFD can be written in it; in the rest, the first U+FFFD decoding
// gives, which none of them can write but gb18030. UTF-16 Chrome reads to the
// end, as it does any other document.
func decodedToError(label string, body []byte) []byte {
	switch label {
	case "utf-16be", "utf-16le":
		return decodedAs(label, body)
	case "utf-8":
		return validUTF8Prefix(body)
	}
	text := decodedAs(label, body)
	if at := bytes.IndexRune(text, utf8.RuneError); at >= 0 {
		return text[:at]
	}
	return text
}

// validUTF8Prefix is body up to its first byte that is not UTF-8.
func validUTF8Prefix(body []byte) []byte {
	at := 0
	for at < len(body) {
		r, size := utf8.DecodeRune(body[at:])
		if r == utf8.RuneError && size == 1 {
			break
		}
		at += size
	}
	return body[:at]
}
