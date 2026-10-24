package tlsforge

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"
)

// A request without a browser context goes, where its profile says so
// (headers.without_context), as a navigation typed into the address bar, which
// is what the profile's headers are: Chrome's own, worked out for where it goes
// as a typed navigation's are (testdata/chrome155-requests.json: nav-direct*,
// redir-nav-direct*, ch-*), its client hints, Accept-CH, Critical-CH and ALPS
// included. The fields it and its client are given each go in the slot Chrome
// writes that field in, in place of what Chrome would give it; one Chrome has
// no slot for goes where Chrome, driven over DevTools, writes the extra headers
// it is given (Network.setExtraHTTPHeaders, Playwright's extraHTTPHeaders):
// after User-Agent, after Origin in a form's, by their names' bytes
// (testdata/chrome155-given.json).

// ErrNeedsContext is a request without a browser context that a navigation
// typed into the address bar cannot be: one by another method than GET, or
// with a body. Chrome sends such a request only from a page, as a form,
// fetch() or an XHR: a browser context says which, and from which page.
var ErrNeedsContext = errors.New("needs a browser context")

// explicit reports a request in a browser context its caller gave it, which
// is answered as one: not one without, sent as a typed navigation, nor one a
// browser sent (sent.go), which are answered as a request without a context
// always was, without the cache and with the framing of a decoded answer.
func (r *browserRequest) explicit() bool {
	return r != nil && !r.implicit && !r.sent
}

// hostOf is the Host hop h goes with, to host: the one the request was given,
// to the origin of its URL.
func (r *browserRequest) hostOf(h hop, host string) string {
	if r.host != "" && h.to == r.hostFor {
		return r.host
	}
	return host
}

// spelt are the fields of hop h that go over HTTP/1.1 spelt as they were
// given: those it was given that Chrome has no slot for, as DevTools' extra
// headers go; and whether it was given a Priority, which goes over HTTP/1.1
// too, as Chrome sends one it is given.
func (r *browserRequest) spelt(h hop) Header {
	var out Header
	block := r.givenBlock(h, r.slots(h))
	for _, f := range h.given {
		if slices.ContainsFunc(block, func(name string) bool { return strings.EqualFold(name, f.Name) }) ||
			strings.EqualFold(f.Name, "priority") {
			out = append(out, f)
		}
	}
	return out
}

// typedWithoutContext reports a client whose requests without a browser
// context go as navigations typed into the address bar: its profile says so,
// and has the headers to send them with.
func (c *Client) typedWithoutContext() bool {
	return c.behavior().Text("headers.without_context") == "typed-navigation" && c.headers.Has("user-agent")
}

// typedNavigation is req, a request without a browser context, to target, as
// the navigation typed into the address bar it goes as, with the fields it and
// its client were given; or why it cannot be one.
func (c *Client) typedNavigation(req *Request, method string, target *url.URL) (*browserRequest, error) {
	if normalizedMethod(method) != fhttp.MethodGet || req.Body != nil {
		what := method + " " + target.Redacted()
		if normalizedMethod(method) == fhttp.MethodGet {
			what += " with a body"
		}
		return nil, fmt.Errorf("tlsforge: %s %w: without one it goes as a navigation typed into the "+
			"address bar, a GET with no body; say the form, fetch() or XHR that sends it, and from which page",
			what, ErrNeedsContext)
	}
	r, err := (&BrowserContext{Kind: KindNavigation}).resolve(method, target, nil, nil, c.behavior())
	if err != nil {
		return nil, err
	}
	r.implicit = true
	// The client's own fields, but those the request gives itself.
	given := append(c.given.without(req.Header.Names()...), req.Header...)
	// A Host it was given names the origin its requests to the URL's go to.
	if hosts := given.Values("host"); len(hosts) > 0 {
		r.host, r.hostFor = hosts[len(hosts)-1], originOf(target)
		given = given.without("host")
	}
	r.given = given
	return r, nil
}
