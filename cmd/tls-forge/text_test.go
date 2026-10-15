package main

import (
	"errors"
	"strings"
	"testing"
)

func TestTextCheckLooksForTheTextInTheBody(t *testing.T) {
	for _, tc := range []struct {
		given, body string
		lacks       bool
	}{
		// Text, as it is: in the markup, case and all.
		{"In stock", shop, false},
		{"In stock", challenge, true},
		{"in stock", shop, true},
		{`class="stock"`, shop, false},
		{"In  stock", shop, true},
		{"Цена", "<p>Цена: 9</p>", false},
		{"Tom & Jerry", "<p>Tom &amp; Jerry</p>", true},
		{"Tom &amp; Jerry", "<p>Tom &amp; Jerry</p>", false},
		{`"status":"ok"`, `{"status":"ok"}`, false},
		{"line one\nline two", "line one\nline two", false},
		{" ", "a b", false},
		{"x", "", true},
		// What only looks like a regular expression is text.
		{"/catalog/item.html", `<a href="/catalog/item.html">`, false},
		{"/catalog", `<a href="/catalog/item.html">`, false},
		{"/путь/файл", `<a href="/путь/файл">`, false},
		{"/a/ ", "/a/ ", false},
		{"/a/1", "/a/1", false},
		{"/", "a/b", false},
		// A regular expression, and its flags.
		{`/In stock: \d+/`, shop, false},
		{`/In stock: \d+ left/`, shop, true},
		{"/in stock/", shop, true},
		{"/in stock/i", shop, false},
		{"/цена/i", "<p>ЦЕНА</p>", false},
		{"/^In stock/", shop, true},
		{"/^b$/", "a\nb\nc", true},
		{"/^b$/m", "a\nb\nc", false},
		{"/a.b/", "a\nb", true},
		{"/a.b/s", "a\nb", false},
		{"/a.+?b/U", "a-b", false},
		{"/A|z/i", "a", false},
		{"/a/b/", "x a/b x", false},
		{"/a/b/", "x a b x", true},
		{"///", "x/y", false},
		{`/\/catalog\/item/`, `<a href="/catalog/item">`, false},
	} {
		check, err := newTextCheck(tc.given)
		if err != nil {
			t.Fatalf("%q: %v", tc.given, err)
		}
		if got := check.lacksIn([]byte(tc.body)); got != tc.lacks {
			t.Errorf("%q in %.40q: lacks = %v, want %v", tc.given, tc.body, got, tc.lacks)
		}
	}
}

func TestTextCheckOfNothingOrOfWhatCannotBeLookedFor(t *testing.T) {
	if check, err := newTextCheck(""); err != nil || check != nil {
		t.Errorf("no text: %v, %v", check, err)
	}
	for _, tc := range []struct{ given, says string }{
		{"/in stock/g", `--wait-for "/in stock/g": g is not a flag a regular expression takes; they are i, m, s and U`},
		{"/in stock/iI", "I is not a flag"},
		{"/path/to/file", "f is not a flag"},
		{"//", `--wait-for "//" is an empty regular expression, which every body matches`},
		{"//i", "is an empty regular expression"},
		{"/a\nb/", `--wait-for "/a\nb/" has a control character in it; a regular expression writes one as \n, \t or \x{…}`},
		{"/a\tb/", "has a control character in it"},
		{"/\x1b[31m/", "has a control character in it"},
		{"/a(/", `--wait-for "/a(/" is not a regular expression: error parsing regexp: missing closing ): ` + "`a(`"},
		{"/a(/i", "missing closing ): `a(`"},
		{"/*/", "missing argument to repetition operator"},
		{"/\xff/", "invalid UTF-8"},
		{"caf\xe9", `--wait-for "caf\xe9" is not UTF-8, which the body is read as`},
	} {
		_, err := newTextCheck(tc.given)
		if !errors.Is(err, errUsage) || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%q: %v\nwant it to say %q", tc.given, err, tc.says)
		}
	}
}

func TestRegexLiteral(t *testing.T) {
	for _, tc := range []struct {
		given, pattern, flags string
		ok                    bool
	}{
		{"/a/", "a", "", true},
		{"/a/i", "a", "i", true},
		{"/a/imsU", "a", "imsU", true},
		{"/a/gi", "a", "gi", true},
		{"/a/b/", "a/b", "", true},
		{"/a/b/c", "a/b", "c", true},
		{"//", "", "", true},
		{"///", "/", "", true},
		{"/", "", "", false},
		{"a/b/", "", "", false},
		{" /a/", "", "", false},
		{"/a", "", "", false},
		{"/a/1", "", "", false},
		{"/a/ ", "", "", false},
		{"/a/i.", "", "", false},
		{"/путь/файл", "", "", false},
		{"", "", "", false},
	} {
		pattern, flags, ok := regexLiteral(tc.given)
		if pattern != tc.pattern || flags != tc.flags || ok != tc.ok {
			t.Errorf("regexLiteral(%q) = %q, %q, %v; want %q, %q, %v", tc.given, pattern, flags, ok, tc.pattern, tc.flags, tc.ok)
		}
	}
}

func TestShownText(t *testing.T) {
	for _, tc := range []struct{ given, want string }{
		{"In stock", `"In stock"`},
		{"Цена", `"Цена"`},
		{`say "hi"`, `"say \"hi\""`},
		{"line one\nline two", `"line one\nline two"`},
		{"\u00a0", `"\u00a0"`},
		{"/catalog/item.html", `"/catalog/item.html"`},
		{`/\d+ in stock/i`, `/\d+ in stock/i`},
		{"/a b/", "/a b/"},
	} {
		if got := shownText(tc.given); got != tc.want {
			t.Errorf("shownText(%q) = %s, want %s", tc.given, got, tc.want)
		}
	}
}
