package main

import (
	"errors"
	"maps"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

func TestPageCheckIsWhatTheTwoFlagsSay(t *testing.T) {
	// Neither is no check, and asks nothing of any answer.
	none, err := newPageCheck("", "")
	if err != nil || none != nil || none.look(&tlsforge.Response{Status: 200}) != (finding{}) {
		t.Errorf("no check: %v, %v", none, err)
	}
	if selector, text := none.wants(); selector != "" || text != "" {
		t.Errorf("no check wants %q and %q", selector, text)
	}
	// Either that cannot be used is said before anything is fetched.
	for _, bad := range [][2]string{{"div[", ""}, {"", "//"}, {"#price", "/a(/"}, {"div[", "In stock"}} {
		if _, err := newPageCheck(bad[0], bad[1]); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, tc := range []struct{ selector, text string }{{"#price", ""}, {"", "In stock"}, {"#price", `/in stock/i`}} {
		check, err := newPageCheck(tc.selector, tc.text)
		if err != nil {
			t.Fatalf("%q: %v", tc, err)
		}
		if selector, text := check.wants(); selector != tc.selector || text != tc.text {
			t.Errorf("%q wants %q and %q", tc, selector, text)
		}
	}
}

func TestPageCheckSaysWhatABodyHas(t *testing.T) {
	both, err := newPageCheck("#price", "In stock")
	if err != nil {
		t.Fatalf("newPageCheck: %v", err)
	}
	element, err := newPageCheck("#price", "")
	if err != nil {
		t.Fatalf("newPageCheck: %v", err)
	}
	for _, tc := range []struct {
		name  string
		check *pageCheck
		res   *tlsforge.Response
		want  finding
	}{
		{"the page", both, &tlsforge.Response{Status: 200, Body: []byte(shop)}, finding{looked: true}},
		{"the page with no content", both, &tlsforge.Response{Status: 204, Body: []byte(shop)}, finding{looked: true}},
		{"the element and not the text", both, &tlsforge.Response{Status: 200, Body: []byte(sold)},
			finding{MissingText: "In stock", looked: true}},
		{"neither", both, &tlsforge.Response{Status: 200, Body: []byte(challenge)},
			finding{MissingElement: "#price", MissingText: "In stock", looked: true}},
		{"an empty 2xx", both, &tlsforge.Response{Status: 200},
			finding{MissingElement: "#price", MissingText: "In stock", looked: true}},
		// Whatever its status: a 403 with both is the page, and a 503 without
		// them is not.
		{"a 403 with both", both, &tlsforge.Response{Status: 403, Body: []byte(shop)}, finding{looked: true}},
		{"a 503 without either", both, &tlsforge.Response{Status: 503, Body: []byte(challenge)},
			finding{MissingElement: "#price", MissingText: "In stock", looked: true}},
		{"a redirect with no body", both, &tlsforge.Response{Status: 302},
			finding{MissingElement: "#price", MissingText: "In stock", looked: true}},
		{"a 503, the element only asked for", element, &tlsforge.Response{Status: 503, Body: []byte(challenge)},
			finding{MissingElement: "#price", looked: true}},
		{"a 200, the element only asked for", element, &tlsforge.Response{Status: 200, Body: []byte(sold)},
			finding{looked: true}},
		{"nothing", both, nil, finding{}},
	} {
		if got := tc.check.look(tc.res); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestPageCheckReadsThePageOnceInItsEncoding(t *testing.T) {
	// The attribute and the text, in windows-1251, which only the page says.
	check, err := newPageCheck(`[data-name="Цена"]`, "/цена: 9/i")
	if err != nil {
		t.Fatalf("newPageCheck: %v", err)
	}
	page := `<html><head><meta charset="windows-1251"></head><body><span data-name="` + cp1251 + `">` + cp1251 + `: 9</span></body></html>`
	for _, status := range []int{200, 403} {
		if got := check.look(&tlsforge.Response{Status: status, Body: []byte(page)}); got.misses() || !got.looked {
			t.Errorf("the %d in windows-1251 is without %+v", status, got)
		}
	}
}

func TestFindingSaysWhatItWasWithout(t *testing.T) {
	for _, tc := range []struct {
		found       finding
		misses      bool
		brief, said string
		args        traceArgs
	}{
		{finding{}, false, "", "", traceArgs{}},
		{finding{looked: true}, false, "", "", traceArgs{}},
		{finding{MissingElement: "#price", looked: true}, true, "no #price", "no element matching #price",
			traceArgs{"missing_element": "#price"}},
		{finding{MissingText: "In stock", looked: true}, true, `no "In stock"`, `no text matching "In stock"`,
			traceArgs{"missing_text": "In stock"}},
		{finding{MissingText: `/\d+ left/i`, looked: true}, true, `no /\d+ left/i`, `no text matching /\d+ left/i`,
			traceArgs{"missing_text": `/\d+ left/i`}},
		{finding{MissingElement: "#price", MissingText: "In stock", looked: true}, true,
			`no #price and no "In stock"`, `no element matching #price and no text matching "In stock"`,
			traceArgs{"missing_element": "#price", "missing_text": "In stock"}},
	} {
		args := traceArgs{}
		tc.found.missingInto(args)
		if tc.found.misses() != tc.misses || tc.found.brief() != tc.brief || tc.found.said() != tc.said ||
			!maps.Equal(args, tc.args) {
			t.Errorf("%+v: misses %v, %q, %q, %v", tc.found, tc.found.misses(), tc.found.brief(), tc.found.said(), args)
		}
	}
}
