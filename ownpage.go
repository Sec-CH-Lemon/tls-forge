package tlsforge

import (
	"cmp"
	"fmt"

	fhttp "github.com/igor-lemon/fhttp"
)

// OwnPage is the page a request to rawURL is sent from when no other is
// named: the root of the URL's own origin, its port said where it is not the
// scheme's own ("https://www.example.com/", "https://[::1]:8443/"); or why
// rawURL does not read.
func OwnPage(rawURL string) (string, error) {
	target, err := parseURL(rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("tlsforge: %q %w", rawURL, err)
	}
	return originOf(target.url()).String() + "/", nil
}

// FromItsOwnPage is req sent as the script of a page of its URL's own origin,
// the origin's root (OwnPage), sends it by XMLHttpRequest, when req says
// nothing of what sends it (no browser context) and is no navigation typed
// into the address bar, which a GET is: a POST, PUT, PATCH, DELETE or HEAD as
// an ordinary XHR of the site. A request in a browser context, a GET (one with
// a body too) and one whose URL does not read come back as they are, for Do to
// send or refuse as ever.
func (req Request) FromItsOwnPage() Request {
	if req.Browser != nil || normalizedMethod(cmp.Or(req.Method, fhttp.MethodGet)) == fhttp.MethodGet {
		return req
	}
	page, err := OwnPage(req.URL)
	if err != nil {
		return req
	}
	req.Browser = &BrowserContext{Kind: KindXHR, Initiator: page}
	return req
}
