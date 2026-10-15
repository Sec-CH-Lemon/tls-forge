package main

import (
	"errors"
	"strings"
	"testing"
)

// shop is a page that has a price and says it is in stock, sold one that has
// the price and says it is sold out, and challenge one that is somebody's
// notice instead: each a 200.
const (
	shop      = `<!doctype html><title>shop</title><main><div class="card big" data-sku="7"><span id="price">9.99</span></div><p class="stock">In stock: 12</p><a href="/next">next</a></main>`
	sold      = `<!doctype html><title>shop</title><main><div class="card big" data-sku="7"><span id="price">9.99</span></div><p class="stock">Sold out</p></main>`
	challenge = `<!doctype html><title>Just a moment...</title><div class="challenge">checking your browser</div>`
	// denied is what a CDN that turns a client away at its edge answers with,
	// in the words Akamai uses, with a 403.
	denied = `<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>
You don't have permission to access "http&#58;&#47;&#47;shop&#46;example&#47;" on this server.<P>
Reference&#32;&#35;18&#46;d16bd117</BODY></HTML>`
)

func TestElementCheckLooksForTheSelectorInThePage(t *testing.T) {
	for _, tc := range []struct {
		selector, body string
		lacks          bool
	}{
		{"#price", shop, false},
		{"#price", challenge, true},
		{"span", shop, false},
		{".card", shop, false},
		{".card.big", shop, false},
		{".card.small", shop, true},
		{"[data-sku]", shop, false},
		{`[data-sku="7"]`, shop, false},
		{`[data-sku="8"]`, shop, true},
		{"div > #price", shop, false},
		{"main #price", shop, false},
		{"main > #price", shop, true},
		{`a[href^="/next"]`, shop, false},
		{"div:not(.card)", shop, true},
		// One of a group is enough.
		{"#basket, #price", shop, false},
		{"#basket, #cart", shop, true},
		// What is not HTML is still parsed as some, and has no such element.
		{"#price", `{"price": 9.99}`, true},
		{"#price", "", true},
	} {
		check, err := newElementCheck(tc.selector)
		if err != nil {
			t.Fatalf("%q: %v", tc.selector, err)
		}
		if got := check.lacksIn([]byte(tc.body)); got != tc.lacks {
			t.Errorf("%q in %.40q: lacks = %v, want %v", tc.selector, tc.body, got, tc.lacks)
		}
	}
}

func TestElementCheckOfNothingOrOfWhatIsNotASelector(t *testing.T) {
	// No selector is no check.
	if check, err := newElementCheck(""); err != nil || check != nil {
		t.Errorf("no selector: %v, %v", check, err)
	}
	// One that is not a selector is said to be one, before anything is fetched;
	// spaces too, which would otherwise turn the check off without a word.
	for _, bad := range []string{"div[", "#", "a >", ":nope", "  ", "\t\n"} {
		if _, err := newElementCheck(bad); !errors.Is(err, errUsage) || !strings.Contains(err.Error(), "is not a CSS selector") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
