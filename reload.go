package tlsforge

import (
	"cmp"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"
)

// Reloaded is the request Chrome sends when the page req opened, res its
// answer, is reloaded (Ctrl+R): req again with Reload, to the URL res is at,
// where a redirect may have taken it, and by the method res answers. A form
// posted that a redirect made a GET is reloaded as that GET, a navigation
// from the form's page without the form's body, as Chrome reloads the page
// it ended on; one posted to the end is posted again. res nil, no answer,
// reloads req's own URL. A script's request opens no page and comes back as
// it is, for the page's script to send it again.
func (req Request) Reloaded(res *Response) Request {
	if req.Browser != nil && (req.Browser.Kind == KindFetch || req.Browser.Kind == KindXHR) {
		return req
	}
	req.Reload = true
	if res == nil {
		return req
	}
	// A redirect that took the page to another origin left the caller's
	// credentials behind on its way there, and the reload of that page keeps
	// them behind: they stay within the origin the caller gave them for.
	if crossedOrigin(req.URL, res.URL) {
		req.Header = req.Header.without(redirectCredentialHeaders...)
	}
	req.URL = res.URL
	if res.Method != "" && !strings.EqualFold(res.Method, cmp.Or(req.Method, fhttp.MethodGet)) {
		req.Method, req.Body = res.Method, nil
		// The form's encoding went with its body.
		req.Header = req.Header.without("content-type")
		if req.Browser != nil && req.Browser.Kind == KindForm {
			browser := *req.Browser
			browser.Kind = KindNavigation
			req.Browser = &browser
		}
	}
	return req
}

// crossedOrigin says whether to is of another origin than from, as a browser
// reads both. One that cannot be read is taken for another: the credentials a
// caller gave stay behind unless it is sure where they would go.
func crossedOrigin(from, to string) bool {
	a, err := parseURL(from, nil)
	if err != nil {
		return true
	}
	b, err := parseURL(to, nil)
	if err != nil {
		return true
	}
	return originOf(a.url()) != originOf(b.url())
}
