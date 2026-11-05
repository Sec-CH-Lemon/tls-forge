package tlsforge

import (
	"cmp"
	"net/url"
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
	// them behind: they stay within the origin the caller gave them for, the
	// one it asked for, which a reload of a reload remembers. The caller's
	// cookies stay with that URL's host (seedingURL), the client's fields
	// with its origin (typedNavigation).
	if req.asked == "" {
		req.asked = req.URL
	}
	if crossedOrigin(req.asked, res.URL) {
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

// seedingURL is the URL the caller's cookies, the request's and the client's
// warmed ones, are filed against: the request's own, parsed; or for a reload,
// the URL the caller asked for (Request.asked), whose host they were given
// for, wherever a redirect took the page. Nil when that URL does not read:
// they are then filed nowhere, rather than where the redirect sent the page.
func (c *Client) seedingURL(req *Request, parsed *url.URL) *url.URL {
	if req.asked == "" {
		return parsed
	}
	asked, err := requestURL(req.asked, nil, c.behavior())
	if err != nil {
		return nil
	}
	return asked
}
