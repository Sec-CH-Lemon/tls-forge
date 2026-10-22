package main

import (
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v5"
)

// cp1251 is «Цена» in windows-1251, which as UTF-8 is not those letters at all.
const cp1251 = "\xd6\xe5\xed\xe0"

func TestTextOfReadsTheBodyAsABrowserDoes(t *testing.T) {
	// What a page holds past its first 1024 bytes, which are all ASCII: the
	// guess made from those alone is windows-1252.
	ascii := strings.Repeat("a", 1100)
	for _, tc := range []struct {
		name   string
		header map[string][]string
		body   string
		want   string
	}{
		{"UTF-8 named by nothing", nil, "<p>Цена</p>", "<p>Цена</p>"},
		{"UTF-8 past an ASCII first kilobyte, named by nothing", nil,
			"<!--" + ascii + "--><p>Цена</p>", "<!--" + ascii + "--><p>Цена</p>"},
		{"JSON sent without a charset, Cyrillic far into it", map[string][]string{"content-type": {"application/json"}},
			`{"a":"` + ascii + `","b":"Цена"}`, `{"a":"` + ascii + `","b":"Цена"}`},
		{"windows-1251 named by a <meta>", nil,
			`<meta charset="windows-1251"><p>` + cp1251 + `</p>`, `<meta charset="windows-1251"><p>Цена</p>`},
		{"windows-1251 named by Content-Type", map[string][]string{"content-type": {"text/html; charset=windows-1251"}},
			cp1251, "Цена"},
		{"Content-Type over a <meta>", map[string][]string{"content-type": {"text/html; charset=windows-1251"}},
			`<meta charset="koi8-r">` + cp1251, `<meta charset="koi8-r">Цена`},
		{"Content-Type over a body that is UTF-8", map[string][]string{"content-type": {"text/html; charset=windows-1251"}},
			"Ж", "Р–"},
		{"a charset nobody has heard of, and UTF-8", map[string][]string{"content-type": {"text/html; charset=nonsense"}},
			"Цена", "Цена"},
		{"the last of two Content-Type fields", map[string][]string{"content-type": {"text/html; charset=utf-8", "text/html; charset=windows-1251"}},
			cp1251, "Цена"},
		{"the last of two types in one field", map[string][]string{"content-type": {"text/plain, text/html; charset=windows-1251"}},
			cp1251, "Цена"},
		{"the same type again, naming no charset", map[string][]string{"content-type": {"text/html; charset=windows-1251, text/html"}},
			cp1251, "Цена"},
		{"another type, which names none", map[string][]string{"content-type": {"text/html; charset=windows-1251, text/plain"}},
			"Ж", "Ж"},
		{"*/* names no type", map[string][]string{"content-type": {"text/html; charset=windows-1251, */*"}},
			cp1251, "Цена"},
		{"a UTF-8 byte order mark, over Content-Type", map[string][]string{"content-type": {"text/html; charset=windows-1251"}},
			"\xef\xbb\xbfЦена", "Цена"},
		{"a UTF-16LE byte order mark", nil, "\xff\xfe&\x045\x04=\x040\x04", "Цена"},
		{"a UTF-16BE byte order mark", nil, "\xfe\xff\x04&\x045\x04=\x040", "Цена"},
		// Neither UTF-8 nor named: windows-1252, as a browser falls back to.
		{"Latin-1 named by nothing", nil, "caf\xe9", "café"},
		{"nothing at all", nil, "", ""},
	} {
		res := &tlsforge.Response{Status: 200, Header: tc.header, Body: []byte(tc.body)}
		if got := string(textOf(res)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCharsetOf(t *testing.T) {
	// Fields whose names differ in case are read in the order of their names.
	header := map[string][]string{
		"content-type": {"text/html; charset=koi8-r"},
		"Content-Type": {"text/html; charset=windows-1251"},
	}
	if got := charsetOf(header); got != "koi8-r" {
		t.Errorf("charsetOf = %q", got)
	}
	// The charset of the first of a run of one type, past one that names its
	// own, as the Fetch standard has it.
	header = map[string][]string{"content-type": {"text/html; charset=a, text/html; charset=b, text/html"}}
	if got := charsetOf(header); got != "a" {
		t.Errorf("charsetOf = %q", got)
	}
	if got := charsetOf(nil); got != "" {
		t.Errorf("charsetOf(nil) = %q", got)
	}
}

func TestCharsetParam(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"text/html", ""},
		{"text/html; charset=utf-8", "utf-8"},
		{"text/html;charset=utf-8", "utf-8"},
		{"text/html; CharSet=utf-8", "utf-8"},
		{"text/html;  charset=utf-8 \t", "utf-8"},
		{`text/html; charset="utf-8"`, "utf-8"},
		{`text/html; charset="utf\-8"`, "utf-8"},
		{`text/html; charset="utf-8"; level=1`, "utf-8"},
		{`text/html; charset="utf-8" junk`, "utf-8"},
		{`text/html; charset="utf-8`, "utf-8"},
		{`text/html; charset="utf-8\`, `utf-8\`},
		{`text/html; charset="\"`, `"`},
		// The first that has a value.
		{"text/html; charset=a; charset=b", "a"},
		{"text/html; charset=; charset=koi8-r", "koi8-r"},
		{`text/html; charset=""; charset=koi8-r`, "koi8-r"},
		// What only looks like one.
		{"text/html; charset", ""},
		{"text/html; charset =utf-8", ""},
		{"text/html; xcharset=utf-8", ""},
		{`text/html; title="a;charset=b"`, ""},
		{`text/html; title="a;charset=b"; charset=c`, "c"},
	} {
		if got := charsetParam(tc.value); got != tc.want {
			t.Errorf("charsetParam(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
}
