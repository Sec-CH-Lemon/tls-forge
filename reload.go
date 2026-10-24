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
