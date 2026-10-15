package main

import (
	"errors"
	"maps"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

func TestPageCheckIsWhatTheFlagSays(t *testing.T) {
	// Nothing is no check, and asks nothing of any answer.
	none, err := newPageCheck("")
	if err != nil || none != nil || none.look(&tlsforge.Response{Status: 200}) != (finding{}) || none.wants() != "" {
		t.Errorf("no check: %v, %v", none, err)
	}
	// A selector that cannot be used is said before anything is fetched.
	if _, err := newPageCheck("div["); !errors.Is(err, errUsage) {
		t.Errorf("div[: %v", err)
	}
	check, err := newPageCheck("#price")
	if err != nil || check.wants() != "#price" {
		t.Errorf("#price: %v, %v", check, err)
	}
}

func TestPageCheckSaysWhatABodyHas(t *testing.T) {
	check, err := newPageCheck("#price")
	if err != nil {
		t.Fatalf("newPageCheck: %v", err)
	}
	for _, tc := range []struct {
		name string
		res  *tlsforge.Response
		want finding
	}{
		{"the page", &tlsforge.Response{Status: 200, Body: []byte(shop)}, finding{looked: true}},
		{"the page with no content", &tlsforge.Response{Status: 204, Body: []byte(shop)}, finding{looked: true}},
		{"a challenge", &tlsforge.Response{Status: 200, Body: []byte(challenge)},
			finding{MissingElement: "#price", looked: true}},
		{"an empty 2xx", &tlsforge.Response{Status: 200}, finding{MissingElement: "#price", looked: true}},
		// Whatever its status: a 403 with it is the page, and a 503 without it
		// is not.
		{"a 403 with it", &tlsforge.Response{Status: 403, Body: []byte(shop)}, finding{looked: true}},
		{"a 503 without it", &tlsforge.Response{Status: 503, Body: []byte(challenge)},
			finding{MissingElement: "#price", looked: true}},
		{"a redirect with no body", &tlsforge.Response{Status: 302}, finding{MissingElement: "#price", looked: true}},
		{"nothing", nil, finding{}},
	} {
		if got := check.look(tc.res); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestPageCheckReadsThePageInItsEncoding(t *testing.T) {
	// The attribute in windows-1251, which only the page says.
	check, err := newPageCheck(`[data-name="Цена"]`)
	if err != nil {
		t.Fatalf("newPageCheck: %v", err)
	}
	page := `<html><head><meta charset="windows-1251"></head><body><span data-name="` + cp1251 + `">9</span></body></html>`
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
	} {
		args := traceArgs{}
		tc.found.missingInto(args)
		if tc.found.misses() != tc.misses || tc.found.brief() != tc.brief || tc.found.said() != tc.said ||
			!maps.Equal(args, tc.args) {
			t.Errorf("%+v: misses %v, %q, %q, %v", tc.found, tc.found.misses(), tc.found.brief(), tc.found.said(), args)
		}
	}
}
