package main

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v3"
)

// chromeDecodings is testdata/chrome155-decoding.json: bodies, and how
// Chrome 155 decoded each, as its "how" says.
type chromeDecodings struct {
	Browser  string `json:"browser"`
	Measured string `json:"measured"`
	Cases    []struct {
		Name           string  `json:"name"`
		Note           string  `json:"note"`
		ContentType    *string `json:"content_type"`
		Body           []byte  `json:"body"`
		Word           []byte  `json:"word"`
		ChromeEncoding string  `json:"chrome_encoding"`
		ChromeText     *string `json:"chrome_text"`
	} `json:"cases"`
}

func loadChromeDecodings(t *testing.T) chromeDecodings {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/chrome155-decoding.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var measured chromeDecodings
	if err := json.Unmarshal(raw, &measured); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return measured
}

// notModelled are the measured cases browserTextOf reads otherwise than Chrome
// did, and why.
var notModelled = map[string]string{
	"h-1251-late":       "Chrome guessed windows-1251 from the bytes",
	"h-1251-nodecl":     "Chrome guessed windows-1251 from the bytes",
	"t-1251-nodecl":     "Chrome guessed windows-1251 from the bytes",
	"t-css-1251":        "Chrome guessed GBK from the bytes",
	"x-rss-1251-nodecl": "Chrome guessed windows-1251 from the bytes",
	"x-rss-decl1251":    "Chrome guessed windows-1251 from the bytes: a feed is text, its declaration unread",
	"x-utf8-error-late": "Chrome's XML parser leaves out the text it was in when the decoder stopped",
}

func TestBrowserDecodingIsChromes(t *testing.T) {
	measured := loadChromeDecodings(t)
	if !strings.Contains(measured.Browser, "Chrome 155.") || measured.Measured == "" || len(measured.Cases) < 170 {
		t.Fatalf("the fixture is %q of %q, %d cases", measured.Browser, measured.Measured, len(measured.Cases))
	}
	seen := map[string]bool{}
	var differ []string
	for _, c := range measured.Cases {
		if seen[c.Name] || c.Note == "" || len(c.Body) == 0 || len(c.Word) == 0 {
			t.Errorf("%s: named twice, or with no note, body or word", c.Name)
		}
		seen[c.Name] = true
		header := map[string][]string{}
		if c.ContentType != nil {
			header["Content-Type"] = []string{*c.ContentType}
		}
		res := &tlsforge.Response{Status: 200, Header: header, Body: c.Body}
		text := string(browserTextOf(res))
		label, _ := chromeEncoding(documentKind(header, c.Body), header, c.Body)
		same := c.ChromeEncoding == "" || strings.EqualFold(label, c.ChromeEncoding)
		if c.ChromeText != nil {
			same = same && strings.Contains(text, *c.ChromeText)
		} else {
			// Chrome showed nothing of the word: nor does this, as it reads it.
			same = same && !strings.Contains(text, string(decodedAs(label, c.Word)))
		}
		if same {
			continue
		}
		differ = append(differ, c.Name)
		if why, known := notModelled[c.Name]; !known {
			shown := "nothing"
			if c.ChromeText != nil {
				shown = *c.ChromeText
			}
			t.Errorf("%s (%s): read as %s, %q; Chrome read it as %q, %q", c.Name, c.Note, label, text,
				c.ChromeEncoding, shown)
		} else if strings.Contains(why, "guessed") && label != "windows-1252" {
			t.Errorf("%s: read as %s; what Chrome guesses this reads as windows-1252", c.Name, label)
		}
	}
	// What is not modelled is said, and only that: a case that comes to read as
	// Chrome did leaves the list.
	if want := slices.Sorted(maps.Keys(notModelled)); !slices.Equal(differ, want) {
		t.Errorf("read otherwise than Chrome: %v, want %v", differ, want)
	}
}

func TestTheTwoDecodingsSideBySide(t *testing.T) {
	// The word «Привет мир» in UTF-8; as windows-1251 and windows-1252 read
	// those bytes; and in windows-1251, and as windows-1252 reads that.
	const word, as1251, as1252 = "Привет мир", "РџСЂРёРІРµС‚ РјРёСЂ", "ÐŸÑ€Ð¸Ð²ÐµÑ‚ Ð¼Ð¸Ñ€"
	const cp1251Word, cp1251As1252 = "\xcf\xf0\xe8\xe2\xe5\xf2 \xec\xe8\xf0", "Ïðèâåò ìèð"
	ascii := strings.Repeat("x", 1100)
	for _, tc := range []struct {
		name, contentType, body string
		legacy, browser         string
	}{
		{"a byte order mark over the Content-Type and a <meta>", "text/html; charset=windows-1251",
			"\xef\xbb\xbf<meta charset=koi8-r>" + word, word, word},
		{"the Content-Type over a <meta>", "text/html; charset=windows-1251", "<meta charset=koi8-r>" + cp1251Word,
			word, word},
		{"UTF-8 HTML naming windows-1251", "text/html", `<meta charset="windows-1251">` + word, word, as1251},
		{"UTF-8 HTML naming nothing, past 1024 bytes", "text/html", "<!--" + ascii + "-->" + word, word, as1252},
		{"UTF-8 JSON, past 1024 bytes", "application/json", `{"a":"` + ascii + `","b":"` + word + `"}`, word, word},
		{"UTF-8 text, past 1024 bytes", "text/plain", ascii + word, word, as1252},
		{"windows-1251 in JSON", "application/json", `{"a":"` + cp1251Word + `"}`, cp1251As1252,
			strings.Repeat("�", 6) + " " + strings.Repeat("�", 3)},
		{"text with a <meta> naming windows-1251", "text/plain", `<meta charset="windows-1251">` + cp1251Word,
			word, cp1251As1252},
		{"XML declaring windows-1251", "application/xml",
			`<?xml version="1.0" encoding="windows-1251"?><r>` + cp1251Word + `</r>`, cp1251As1252, word},
		{"a stray byte after UTF-8 HTML", "text/html", word + "\xff", word, as1252 + "ÿ"},
	} {
		res := &tlsforge.Response{Status: 200, Header: map[string][]string{"Content-Type": {tc.contentType}},
			Body: []byte(tc.body)}
		legacy, browser := string(textOf(res)), string(browserTextOf(res))
		if !strings.Contains(legacy, tc.legacy) || !strings.Contains(browser, tc.browser) {
			t.Errorf("%s: legacy %q, browser %q", tc.name, legacy, browser)
		}
		if tc.legacy != tc.browser && (strings.Contains(browser, tc.legacy) || strings.Contains(legacy, tc.browser)) {
			t.Errorf("%s: each reads it as the other: legacy %q, browser %q", tc.name, legacy, browser)
		}
	}
}

func TestDecoderOf(t *testing.T) {
	res := &tlsforge.Response{Header: map[string][]string{"Content-Type": {"text/plain"}}, Body: []byte("Цена")}
	for name, want := range map[string]string{decodingLegacy: "Цена", decodingBrowser: "Ð¦ÐµÐ½Ð°"} {
		decode, err := decoderOf(name)
		if err != nil || string(decode(res)) != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "Legacy", "chrome", " browser"} {
		if _, err := decoderOf(bad); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestDocumentKindIsHowChromeDecodes(t *testing.T) {
	const page, declared = "<!doctype html><p>Цена", `<?xml version="1.0"?><r/>`
	for _, tc := range []struct {
		contentType []string
		body, want  string
	}{
		{[]string{"text/html"}, "{}", kindHTML},
		{[]string{"TEXT/HTML; charset=koi8-r"}, "", kindHTML},
		{[]string{"text/plain, text/html"}, "", kindHTML},
		{[]string{"text/html, */*"}, "", kindHTML},
		{[]string{"application/xhtml+xml"}, page, kindXML},
		{[]string{"image/svg+xml"}, "", kindXML},
		{[]string{"text/xml"}, "", kindXML},
		{[]string{"application/xml"}, page, kindXML},
		{[]string{"text/+xml"}, "", kindText},
		{[]string{"application/rss+xml"}, declared, kindText},
		{[]string{"application/atom+xml"}, declared, kindText},
		{[]string{"text/xsl"}, declared, kindText},
		{[]string{"application/json"}, "", kindJSON},
		{[]string{"text/json"}, "", kindJSON},
		{[]string{"application/problem+json"}, "", kindJSON},
		{[]string{"text/css"}, "", kindCSS},
		{[]string{"text/plain"}, page, kindText},
		{[]string{"text/javascript"}, "", kindText},
		{[]string{"application/octet-stream"}, page, kindText},
		// No type, or one that says it is of none: sniffed.
		{nil, page, kindHTML},
		{nil, declared, kindXML},
		{nil, `{"a":1}`, kindText},
		{[]string{"unknown/unknown"}, page, kindHTML},
		{[]string{"application/unknown"}, page, kindHTML},
		{[]string{"*/*"}, page, kindHTML},
		{[]string{"nonsense"}, declared, kindXML},
	} {
		header := map[string][]string{}
		if tc.contentType != nil {
			header["Content-Type"] = tc.contentType
		}
		if got := documentKind(header, []byte(tc.body)); got != tc.want {
			t.Errorf("%q, %q: %s, want %s", tc.contentType, tc.body, got, tc.want)
		}
	}
}

func TestChromeEncodingGoesInChromesOrder(t *testing.T) {
	// What the measured cases do not show on their own.
	for _, tc := range []struct {
		name, kind, contentType, body, want, rest string
	}{
		{"a UTF-16BE byte order mark", kindJSON, "", "\xfe\xff\x00{", "utf-16be", "\x00{"},
		{"a UTF-16LE byte order mark over the Content-Type", kindText, "text/plain; charset=koi8-r", "\xff\xfe{\x00",
			"utf-16le", "{\x00"},
		{"spaces around a quoted charset", kindText, `text/plain; charset=" koi8-r "`, "x", "koi8-r", "x"},
		{"a charset that is no label", kindText, "text/plain; charset=utf8mb4", "x", "windows-1252", "x"},
		{"a charset in UTF-16, from the Content-Type", kindHTML, "text/html; charset=utf-16", "<\x00", "utf-16le",
			"<\x00"},
		{"replacement, from the Content-Type", kindHTML, "text/html; charset=iso-2022-cn", "x", "replacement", "x"},
		{"a declaration over nothing in HTML", kindHTML, "text/html", `<?xml version="1.0" encoding="koi8-r"?><p>`,
			"koi8-r", `<?xml version="1.0" encoding="koi8-r"?><p>`},
		{"a <meta> over a declaration", kindHTML, "text/html",
			`<?xml encoding="koi8-r"?><meta charset="windows-1251">`, "windows-1251",
			`<?xml encoding="koi8-r"?><meta charset="windows-1251">`},
		{"a declaration naming no label, a <meta> naming none", kindHTML, "text/html",
			`<?xml encoding="bogus"?><meta charset="bogus">`, "windows-1252",
			`<?xml encoding="bogus"?><meta charset="bogus">`},
		{"a declaration naming UTF-16 in XML", kindXML, "application/xml", `<?xml encoding="utf-16"?><r/>`, "utf-8",
			`<?xml encoding="utf-16"?><r/>`},
		{"a <meta> in XML", kindXML, "application/xml", `<r><meta charset="koi8-r"/></r>`, "utf-8",
			`<r><meta charset="koi8-r"/></r>`},
		{"UTF-16BE that begins <?x, over a <meta>", kindHTML, "text/html", "\x00<\x00?\x00x<meta charset=koi8-r>",
			"utf-16be", "\x00<\x00?\x00x<meta charset=koi8-r>"},
		{"UTF-16LE that begins <?x in XML", kindXML, "application/xml", "<\x00?\x00x\x00", "utf-16le",
			"<\x00?\x00x\x00"},
		{"<?x in UTF-16 in JSON", kindJSON, "application/json", "<\x00?\x00x\x00", "utf-8", "<\x00?\x00x\x00"},
		{"an @charset naming UTF-16", kindCSS, "text/css", `@charset "utf-16le";`, "utf-8", `@charset "utf-16le";`},
		{"an @charset naming no label", kindCSS, "text/css", `@charset "bogus";`, "windows-1252", `@charset "bogus";`},
		{"an @charset in text", kindText, "text/plain", `@charset "koi8-r";`, "windows-1252", `@charset "koi8-r";`},
		{"a declaration in CSS", kindCSS, "text/css", `<?xml encoding="koi8-r"?>`, "windows-1252",
			`<?xml encoding="koi8-r"?>`},
		{"nothing at all, in JSON", kindJSON, "application/json", "", "utf-8", ""},
		{"nothing at all, in HTML", kindHTML, "text/html", "", "windows-1252", ""},
	} {
		header := map[string][]string{"Content-Type": {tc.contentType}}
		label, rest := chromeEncoding(tc.kind, header, []byte(tc.body))
		if label != tc.want || string(rest) != tc.rest {
			t.Errorf("%s: %s, %q; want %s, %q", tc.name, label, rest, tc.want, tc.rest)
		}
	}
}

func TestEncodingLabelIsChromes(t *testing.T) {
	for label, want := range map[string]string{
		"windows-1251": "windows-1251", "WINDOWS-1251": "windows-1251", "cp1251": "windows-1251",
		"x-cp1251": "windows-1251", "koi8-ru": "koi8-u", "latin1": "windows-1252", "utf-16": "utf-16le",
		"unicodefffe": "utf-16be", "replacement": "replacement", "iso-2022-kr": "replacement",
		"x-user-defined": "x-user-defined", "utf8": "utf-8",
		// Nothing else: not with white space around it, which Chrome does not
		// take off, nor with letters outside ASCII that fold to ones inside.
		"": "", "bogus": "", "windows1251": "", " windows-1251": "", "windows-1251 ": "", "windows-1251\v": "",
		"windows-1251\x00": "", "Koi8-r": "", "windows-1251 ": "", "utf-32": "", "utf-7": "",
	} {
		if got := encodingLabel(label); got != want {
			t.Errorf("%q: %q, want %q", label, got, want)
		}
	}
}

func TestContentCharsetIsChromes(t *testing.T) {
	for content, want := range map[string]string{
		"text/html; charset=koi8-r": "koi8-r",
		"text/html; CharSet=koi8-r": "koi8-r",
		"charset=koi8-r;x":          "koi8-r",
		"charset=koi8-r'x":          "koi8-r",
		`charset=koi8-r"x`:          "koi8-r",
		"charset=koi8-r\tx":         "koi8-r",
		"charset=koi8-r x":          "koi8-r",
		"charset = koi8-r":          "koi8-r",
		"charset=\x0bkoi8-r":        "koi8-r",
		"charset\x01=\x02koi8-r":    "koi8-r",
		"charset='koi8-r'":          "koi8-r",
		`charset="koi8 r";x`:        "koi8 r",
		`charset=""`:                "",
		"charset='koi8-r":           "",
		`charset="`:                 "",
		"charset=":                  "",
		"charset= \t":               "",
		"charset":                   "",
		"charset  ":                 "",
		"charsetx; charset=koi8-r":  "koi8-r",
		"charset charset=koi8-r":    "koi8-r",
		"charset; charset=":         "",
		"text/html":                 "",
		"":                          "",
		"charset=koi8-r x":          "koi8-r x",
		"charset= koi8-r":           " koi8-r",
		"ÇHARSET=koi8-r; charset=x": "x",
		strings.Repeat("İ", 40) + "charset=koi8-r":                  "koi8-r",
		strings.Repeat("K", 40) + "charset=koi8-r":                  "koi8-r",
		strings.Repeat("İ", 3) + "CHARSET" + strings.Repeat("İ", 9): "",
	} {
		if got := contentCharset(content); got != want {
			t.Errorf("%q: %q, want %q", content, got, want)
		}
	}
}

func TestXMLDeclaredIsChromes(t *testing.T) {
	for body, want := range map[string]string{
		`<?xml version="1.0" encoding="windows-1251"?><r/>`: "windows-1251",
		`<?xml encoding='koi8-r'?>`:                         "koi8-r",
		`<?xml version="1.0" encoding = "koi8-r"?>`:         "koi8-r",
		"<?xml encoding\x01=\x02\"koi8-r\"?>":               "koi8-r",
		`<?xml-stylesheet encoding="koi8-r"?>`:              "koi8-r",
		`<?xml encoding=" koi8-r "?>`:                       " koi8-r ",
		`<?xml encoding=""?>`:                               "",
		`<?xml version="1.0"?>`:                             "",
		`<?xml version="1.0" encoding="koi8-r"`:             "",
		`<?xml version="1.0" encoding=koi8-r?>`:             "",
		`<?xml version="1.0" encoding="koi8-r?>`:            "",
		`<?xml version="1.0" encoding>`:                     "",
		`<?xml version="1.0" encoding=>`:                    "",
		`<?xml version="1.0" encoding= >`:                   "",
		`<?xml version="1.0" x="encoding" encoding="k"?>`:   "",
		`<?xml version=">" encoding="koi8-r"?>`:             "",
		`<?xml version="1.0" ENCODING="koi8-r"?>`:           "",
		`<?XML encoding="koi8-r"?>`:                         "",
		` <?xml encoding="koi8-r"?>`:                        "",
		`<?xm`:                                              "",
		``:                                                  "",
	} {
		if got := xmlDeclared([]byte(body)); got != want {
			t.Errorf("%q: %q, want %q", body, got, want)
		}
	}
}

func TestCSSCharsetIsChromes(t *testing.T) {
	for body, want := range map[string]string{
		`@charset "koi8-r"; a{}`: "koi8-r",
		`@charset "";`:           "",
		`@charset "koi8-r" ;`:    "",
		`@charset 'koi8-r';`:     "",
		`@CHARSET "koi8-r";`:     "",
		`@charset  "koi8-r";`:    "",
		` @charset "koi8-r";`:    "",
		`@charset "koi8-r"`:      "",
		`@charset "koi8-r`:       "",
		`a{}`:                    "",
	} {
		if got := cssCharset([]byte(body)); got != want {
			t.Errorf("%q: %q, want %q", body, got, want)
		}
	}
}

func TestUTF16Declared(t *testing.T) {
	for body, want := range map[string]string{
		"<\x00?\x00x\x00m\x00": "utf-16le", "\x00<\x00?\x00x\x00m": "utf-16be", "<\x00?\x00x": "",
		"\x00<\x00?\x00": "", "<?xml": "", "": "",
	} {
		if got := utf16Declared([]byte(body)); got != want {
			t.Errorf("%q: %q, want %q", body, got, want)
		}
	}
}

func TestMetaCharsetBeyondWhatWasMeasured(t *testing.T) {
	comment := "<!--" + strings.Repeat("x", 1100) + "-->"
	for _, tc := range []struct{ name, body, want string }{
		{"no <meta>", "<p>Цена</p>", ""},
		{"nothing", "", ""},
		{"a <meta> with no attributes, then one naming koi8-r", "<meta><meta charset=koi8-r>", "koi8-r"},
		{"a <meta> naming nothing, then one naming koi8-r", "<meta name=x><meta charset=koi8-r>", "koi8-r"},
		{"a <meta> left open at the end", `<meta charset="koi8-r"`, ""},
		{"a <meta> after </html>, past byte 1024", "<html></html>" + comment + "<meta charset=koi8-r>", ""},
		{"a <meta> after </head>, past byte 1024", "<head></head>" + comment + "<meta charset=koi8-r>", ""},
		{"a <meta> after </title> and </script>, past byte 1024",
			"<head><title>t</title><script></script>" + comment + "<meta charset=koi8-r>", "koi8-r"},
		{"a <meta> after a second <html> and <head>, past byte 1024",
			"<html><head><html><head>" + comment + "<meta charset=koi8-r>", "koi8-r"},
		{"a <meta> after a self-closing <noscript/>, past byte 1024",
			"<head><noscript/>" + comment + "<meta charset=koi8-r>", "koi8-r"},
		{"a <meta> after an unknown tag, early", "<head><x-y></x-y><meta charset=koi8-r>", "koi8-r"},
		{"a <meta> in <plaintext>", "<plaintext><meta charset=koi8-r>", ""},
		{"a <meta> naming x-user-defined", "<meta charset=x-user-defined>", "windows-1252"},
		{"a <meta> naming UTF-16BE in its content", `<meta http-equiv=content-type content="charset=utf-16be">`,
			"utf-8"},
		{"a <meta> naming replacement", "<meta charset=replacement>", "replacement"},
		{"a page in its head to the end", "<head>" + strings.Repeat("<title>t</title>", 200), ""},
	} {
		if got := metaCharset([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDecodedAs(t *testing.T) {
	for _, tc := range []struct{ label, body, want string }{
		{"utf-8", "Цена", "Цена"},
		{"utf-8", "x\xe2\x82y\xf0\x9f\x98z\xc0\xafw", "x�y�z��w"},
		{"windows-1251", "\xd6\xe5\xed\xe0", "Цена"},
		{"windows-1252", "caf\xe9 \x80", "café €"},
		{"x-user-defined", "a\x80\xff", "a"},
		{"replacement", "anything", "�"},
		{"replacement", "", ""},
		{"utf-16le", "&\x04A", "Ц�"},
	} {
		if got := string(decodedAs(tc.label, []byte(tc.body))); got != tc.want {
			t.Errorf("%s %q: %q, want %q", tc.label, tc.body, got, tc.want)
		}
	}
	// UTF-8 that is UTF-8 throughout is the body itself: nothing is copied.
	body := []byte(strings.Repeat("Цена ", 1000))
	if allocs := testing.AllocsPerRun(20, func() { decodedAs("utf-8", body) }); allocs != 0 {
		t.Errorf("valid UTF-8 cost %v allocations", allocs)
	}
}

func TestDecodedToErrorStopsWhereChromeDoes(t *testing.T) {
	for _, tc := range []struct{ label, body, want string }{
		{"utf-8", "Цена", "Цена"},
		{"utf-8", "Ц\xffена", "Ц"},
		{"utf-8", "Ц\xef\xbf\xbdена", "Ц�ена"},
		{"utf-8", "Цен\xd0", "Цен"},
		{"utf-8", "\xff", ""},
		{"utf-8", "", ""},
		{"windows-1253", "a\xaab", "a"},
		{"windows-1253", "a\xe1b", "aαb"},
		{"gbk", "a\xffb", "a"},
		{"koi8-r", "\xe3\xc5\xce\xc1", "Цена"},
		// UTF-16 is read to the end, an unpaired surrogate a U+FFFD.
		{"utf-16le", "a\x00\x00\xdcb\x00", "a�b"},
		{"utf-16be", "\x00a\xdc\x00\x00b", "a�b"},
	} {
		if got := string(decodedToError(tc.label, []byte(tc.body))); got != tc.want {
			t.Errorf("%s %q: %q, want %q", tc.label, tc.body, got, tc.want)
		}
	}
}

func TestBrowserTextOfStopsOnlyInXML(t *testing.T) {
	for contentType, want := range map[string]string{
		"application/xml":  "<r>a",
		"image/svg+xml":    "<r>a",
		"text/html":        "<r>aÿb</r>",
		"application/json": "<r>a�b</r>",
		"text/plain":       "<r>aÿb</r>",
	} {
		res := &tlsforge.Response{Header: map[string][]string{"Content-Type": {contentType}}, Body: []byte("<r>a\xffb</r>")}
		if got := string(browserTextOf(res)); got != want {
			t.Errorf("%s: %q, want %q", contentType, got, want)
		}
	}
}

func TestAttributesOfKeepsEveryOne(t *testing.T) {
	for tag, want := range map[string][]attribute{
		`<meta charset="a" charset="b">`:             {{"charset", "a"}, {"charset", "b"}},
		`<meta CHARSET='A' Content=b>`:               {{"charset", "A"}, {"content", "b"}},
		`<meta charset = "a"  content =b >`:          {{"charset", "a"}, {"content", "b"}},
		"<meta\tcharset=a\ncontent=b\fx\r>":          {{"charset", "a"}, {"content", "b"}, {"x", ""}},
		`<meta charset="a"charset='b'>`:              {{"charset", "a"}, {"charset", "b"}},
		`<meta/charset=a/>`:                          {{"charset", "a/"}},
		`<meta charset=a />`:                         {{"charset", "a"}},
		`<meta charset>`:                             {{"charset", ""}},
		`<meta charset= >`:                           {{"charset", ""}},
		`<meta =x charset=a>`:                        {{"=x", ""}, {"charset", "a"}},
		`<meta ==a>`:                                 {{"=", "a"}},
		`<meta a"b='c'>`:                             {{`a"b`, "c"}},
		`<meta charset=&#x77;indows&#45;1251>`:       {{"charset", "windows-1251"}},
		`<meta content="a&amp;b" http-equiv=x&y>`:    {{"content", "a&b"}, {"http-equiv", "x&y"}},
		`<meta charset="a>b">`:                       {{"charset", "a>b"}},
		`<meta charset="never closed`:                {{"charset", "never closed"}},
		`<meta charset=`:                             {{"charset", ""}},
		`<meta>`:                                     nil,
		`<meta/>`:                                    nil,
		`<meta`:                                      nil,
		`<META   >`:                                  nil,
		`<meta charset="Цена" data-x='İ'>`:           {{"charset", "Цена"}, {"data-x", "İ"}},
		"<meta charset=\"a\x00b\">":                  {{"charset", "a\x00b"}},
		`<meta http-equiv="Content-Type" content=x>`: {{"http-equiv", "Content-Type"}, {"content", "x"}},
	} {
		if got := attributesOf([]byte(tag)); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", tag, got, want)
		}
	}
}
