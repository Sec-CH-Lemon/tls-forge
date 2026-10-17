package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
)

// DecodingFixture is what testdata/chrome155-decoding.json holds: how a browser
// decoded each page.
type DecodingFixture struct {
	Browser  string         `json:"browser"`
	Measured string         `json:"measured"`
	How      string         `json:"how"`
	Cases    []DecodingCase `json:"cases"`
}

// DecodingCase is a page, and what the browser made of it.
type DecodingCase struct {
	Name, Note string
	// ContentType is the Content-Type it was served with: nil for none.
	ContentType *string
	// Body is the page; Word the bytes a word in it was written in.
	Body, Word []byte
	// Encoding is the document.characterSet a script in the page wrote into
	// its title, with the word as the browser decoded it, Text; empty for a
	// page with no such script. Text is the word as found in the DOM for any
	// other page, nil when it was nowhere in it. Shows says what the browser
	// showed instead of a document; Text is not said then.
	Encoding string
	Text     *string
	Shows    string
}

// caseJSON is a case as the fixture writes it, in this order.
type caseJSON struct {
	Name        string           `json:"name"`
	Note        string           `json:"note"`
	ContentType *string          `json:"content_type"`
	Body        []byte           `json:"body"`
	Word        []byte           `json:"word"`
	Encoding    string           `json:"chrome_encoding,omitempty"`
	Text        *json.RawMessage `json:"chrome_text,omitempty"`
	Shows       string           `json:"chrome_shows,omitempty"`
}

// MarshalJSON writes the case as the fixture keeps it: chrome_text, null too,
// unless it says what the browser showed instead.
func (c DecodingCase) MarshalJSON() ([]byte, error) {
	out := caseJSON{Name: c.Name, Note: c.Note, ContentType: c.ContentType, Body: c.Body, Word: c.Word,
		Encoding: c.Encoding, Shows: c.Shows}
	if c.Shows == "" {
		text := json.RawMessage("null")
		if c.Text != nil {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(*c.Text)
			text = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		}
		out.Text = &text
	}
	// Nothing in a case is a value JSON cannot write.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// UnmarshalJSON reads a case as the fixture keeps it.
func (c *DecodingCase) UnmarshalJSON(data []byte) error {
	var in struct {
		caseJSON
		Text *string `json:"chrome_text"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	*c = DecodingCase{Name: in.Name, Note: in.Note, ContentType: in.ContentType, Body: in.Body, Word: in.Word,
		Encoding: in.Encoding, Text: in.Text, Shows: in.Shows}
	return nil
}

// LoadDecoding reads a fixture of decodings.
func LoadDecoding(path string) (*DecodingFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f DecodingFixture
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("harness: %s: %w", path, err)
	}
	return &f, nil
}

// Write writes the fixture to path as it is kept.
func (f *DecodingFixture) Write(path string) error { return writeJSON(path, f) }

// MeasureDecoding is what b makes of each case's page, served over plain
// HTTP with its Content-Type: the cases as the fixture would hold them.
func MeasureDecoding(ctx context.Context, b Browser, cases []DecodingCase, progress io.Writer) ([]DecodingCase, error) {
	byName := map[string]DecodingCase{}
	for _, c := range cases {
		byName[c.Name] = c
	}
	ln, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("harness: %w", err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Minute, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := byName[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		// Nil, and not missing, so that nothing is sniffed and said for it.
		w.Header()["Content-Type"] = nil
		if c.ContentType != nil {
			w.Header()["Content-Type"] = []string{*c.ContentType}
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(c.Body)
	})}
	go func() { _ = server.Serve(ln) }()
	defer func() { _ = server.Close() }()
	out := make([]DecodingCase, 0, len(cases))
	for _, c := range cases {
		dump, err := b.DumpDOM(ctx, "http://"+ln.Addr().String()+"/"+c.Name)
		if err != nil {
			return nil, fmt.Errorf("harness: %s: %w", c.Name, err)
		}
		c.Encoding, c.Text, c.Shows = extract(dump, c.Word)
		out = append(out, c)
		if progress != nil {
			_, _ = fmt.Fprintf(progress, "decoding %s\n", c.Name)
		}
	}
	return out, nil
}

// CompareDecoding is how what a browser made of the pages, got, differs from
// what the fixture holds, want: nothing when every case is the same.
func CompareDecoding(want, got []DecodingCase) []string {
	byName := map[string]DecodingCase{}
	for _, c := range got {
		byName[c.Name] = c
	}
	shown := func(text *string) string {
		if text == nil {
			return "nothing"
		}
		return fmt.Sprintf("%q", *text)
	}
	var diff []string
	for _, w := range want {
		g, ok := byName[w.Name]
		switch {
		case !ok:
			diff = append(diff, fmt.Sprintf("%s was not measured", w.Name))
		case g.Encoding != w.Encoding || g.Shows != w.Shows || (g.Text == nil) != (w.Text == nil) ||
			g.Text != nil && *g.Text != *w.Text:
			diff = append(diff, fmt.Sprintf("%s: the browser read %s as %q and showed %q, the fixture %s as %q and %q",
				w.Name, shown(g.Text), g.Encoding, g.Shows, shown(w.Text), w.Encoding, w.Shows))
		}
	}
	return diff
}

// probe is the title a page's script wrote: the encoding it was read in,
// and the word as decoded, percent-encoded.
var (
	titleOf = regexp.MustCompile(`<title>([^<]*)</title>`)
	probe   = regexp.MustCompile(`^[0-9A-Za-z_-]+\|`)
)

// extract is what a browser made of a page whose DOM it dumped: the encoding
// and the word its script said in the title; else the longest decoding of the
// word that the DOM shows, nil for none; or, for an empty dump, that it showed
// no document.
func extract(dump, word []byte) (string, *string, string) {
	text := string(dump)
	if strings.TrimSpace(text) == "" {
		return "", nil, "nothing: no document"
	}
	if m := titleOf.FindStringSubmatch(text); m != nil && probe.MatchString(m[1]) {
		encoding, said, _ := strings.Cut(m[1], "|")
		word := unquote(said)
		return encoding, &word, ""
	}
	shown := html.UnescapeString(text)
	var found []string
	for _, d := range decoders {
		if decoded := d.decode(word); strings.Contains(shown, decoded) {
			found = append(found, decoded)
		}
	}
	if len(found) == 0 && strings.Contains(shown, "\uFFFD") && !strings.Contains(shown, "Привет") {
		found = []string{"\uFFFD"}
	}
	if len(found) == 0 {
		return "", nil, ""
	}
	longest := found[0]
	for _, f := range found[1:] {
		if utf8.RuneCountInString(f) > utf8.RuneCountInString(longest) {
			longest = f
		}
	}
	return "", &longest, ""
}

// unquote undoes percent-encoding, leaving a % that begins no escape as it
// is, and reads the bytes as UTF-8.
func unquote(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, ok := hexByte(s[i+1], s[i+2]); ok {
				out = append(out, b)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return utf8Decoded(out)
}

// utf8Decoded is b read as UTF-8, each maximal run of bytes that begins no
// character replaced with U+FFFD, as the encoding standard has it.
func utf8Decoded(b []byte) string { return with(unicode.UTF8)(b) }

func hexByte(hi, lo byte) (byte, bool) {
	h, okHi := hexDigit(hi)
	l, okLo := hexDigit(lo)
	return h<<4 | l, okHi && okLo
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decoder is an encoding the word is looked for in.
type decoder struct {
	name   string
	decode func([]byte) string
}

func with(e encoding.Encoding) func([]byte) string {
	return func(b []byte) string {
		decoded, _ := e.NewDecoder().Bytes(b)
		return string(decoded)
	}
}

// windows1252 maps 0x80 to 0x9f as the HTML standard's windows-1252 does, and
// every other byte to the code point of its value.
var windows1252 = map[byte]rune{0x80: '€', 0x82: '‚', 0x83: 'ƒ', 0x84: '„', 0x85: '…', 0x86: '†', 0x87: '‡',
	0x88: 'ˆ', 0x89: '‰', 0x8a: 'Š', 0x8b: '‹', 0x8c: 'Œ', 0x8e: 'Ž', 0x91: '‘', 0x92: '’', 0x93: '“', 0x94: '”',
	0x95: '•', 0x96: '–', 0x97: '—', 0x98: '˜', 0x99: '™', 0x9a: 'š', 0x9b: '›', 0x9c: 'œ', 0x9e: 'ž', 0x9f: 'Ÿ'}

// decoders are the encodings a word is looked for in, in the order the fixture
// was made with: the longest found is the one taken.
var decoders = []decoder{
	{"utf-8", utf8Decoded},
	{"windows-1251", with(charmap.Windows1251)},
	{"windows-1252", func(b []byte) string {
		var out strings.Builder
		for _, c := range b {
			if r, ok := windows1252[c]; ok {
				out.WriteRune(r)
			} else {
				out.WriteRune(rune(c))
			}
		}
		return out.String()
	}},
	{"koi8-r", with(charmap.KOI8R)},
	{"koi8-u", with(charmap.KOI8U)},
	{"utf-16le", with(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM))},
	{"utf-16be", with(unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM))},
	{"x-user-defined", func(b []byte) string {
		var out strings.Builder
		for _, c := range b {
			if c < 0x80 {
				out.WriteRune(rune(c))
			} else {
				out.WriteRune(0xF780 + rune(c) - 0x80)
			}
		}
		return out.String()
	}},
	{"gbk", with(simplifiedchinese.GBK)},
	{"big5", with(traditionalchinese.Big5)},
	{"shift_jis", with(japanese.ShiftJIS)},
	{"euc-jp", with(japanese.EUCJP)},
	{"euc-kr", with(korean.EUCKR)},
	{"iso-8859-5", with(charmap.ISO8859_5)},
	{"windows-1250", with(charmap.Windows1250)},
	{"ibm866", with(charmap.CodePage866)},
	{"x-mac-cyrillic", with(charmap.MacintoshCyrillic)},
}
