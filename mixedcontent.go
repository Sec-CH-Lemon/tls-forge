package tlsforge

import (
	"errors"
	"fmt"
	"net/url"

	fhttp "github.com/igor-lemon/fhttp"
)

// ErrMixedContent is what an error wraps when a page over https would make a
// request Chrome does not send, to a URL that is not potentially trustworthy:
// plain http to a name that is not localhost or under .localhost, nor a
// loopback address. Chrome blocks fetch() and an XHR there, on the first
// request or a redirect's; a form it submits there, or posts there again
// after a 307 or a 308, only once the person using it says to go on past a
// warning. Nothing is sent to that URL. A navigation is never stopped, nor
// anything from a page that is not over https, http://localhost's too.
var ErrMixedContent = errors.New("mixed content")

func mixedContentError(format string, args ...any) error {
	return fmt.Errorf("tlsforge: %w: "+format, append([]any{ErrMixedContent}, args...)...)
}

// mixed is why Chrome does not send the request to u a page makes by method,
// its first or a redirect's hop, or nil when it sends it.
func (r *browserRequest) mixed(u *url.URL, method string, first bool) error {
	if r.initiator == nil || r.initiator.Scheme != "https" || trustworthy(originOf(u)) {
		return nil
	}
	const untrusted = "which is not potentially trustworthy"
	const warned = "until the person using Chrome says to go on"
	switch {
	case r.scripted() && first:
		return mixedContentError("%s from a page over https is not sent to %s, %s", r.kindName(), u.Redacted(), untrusted)
	case r.scripted():
		return mixedContentError("%s from a page over https follows no redirect to %s, %s", r.kindName(), u.Redacted(),
			untrusted)
	case r.kind == KindForm && first:
		return mixedContentError("a form of a page over https is not submitted to %s, %s, %s", u.Redacted(), untrusted,
			warned)
	case r.kind == KindForm && method == fhttp.MethodPost:
		return mixedContentError("a form of a page over https is not posted again to %s, %s, %s", u.Redacted(),
			untrusted, warned)
	}
	return nil
}
