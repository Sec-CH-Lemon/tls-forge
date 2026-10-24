package main

import (
	"errors"
	"fmt"
	"strings"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// requestKinds are what --request-kind takes.
var requestKinds = []tlsforge.RequestKind{tlsforge.KindNavigation, tlsforge.KindForm, tlsforge.KindFetch, tlsforge.KindXHR}

// browserContextOf is the browser context --request-kind, --initiator-url and
// --clicked give every request of a run, or nil when none is given.
func browserContextOf(kind, initiator string, initiatorGiven, clicked bool) (*tlsforge.BrowserContext, error) {
	if kind == "" {
		switch {
		case initiatorGiven:
			return nil, fmt.Errorf("%w: --initiator-url names the page a --request-kind request is sent from: "+
				"give --request-kind", errUsage)
		case clicked:
			return nil, fmt.Errorf("%w: --clicked says a click on the --initiator-url page sends the request: "+
				"give --request-kind navigation or form", errUsage)
		}
		return nil, nil
	}
	for _, known := range requestKinds {
		if tlsforge.RequestKind(kind) == known {
			return &tlsforge.BrowserContext{Kind: known, Initiator: initiator, Clicked: clicked}, nil
		}
	}
	return nil, badValue("--request-kind", kind, "navigation, form, fetch or xhr")
}

// checkBrowser refuses a run whose requests a browser would not send as the
// kind says, or this profile cannot send as one, or, without --request-kind,
// as the navigation typed into the address bar a request without one goes as;
// and, with --retry-as-browser (reload), one whose page the profile cannot
// reload as Chrome does: the request of every URL of the list is checked as
// the library would check it, before anything is sent. A GET with no body and
// no kind, not reloaded, has nothing to check that the list has not been
// checked for.
func checkBrowser(worn *profile.Profile, jobs []job, method string, header headerFlag, data []byte,
	browser *tlsforge.BrowserContext, reload bool,
) error {
	if browser == nil && strings.EqualFold(method, "GET") && data == nil && !reload {
		return nil
	}
	checker, err := newClient("", tlsforge.WithProfileValue(worn))
	if err != nil {
		return err
	}
	defer func() { _ = checker.Close() }()
	for _, j := range jobs {
		req := tlsforge.Request{Method: method, URL: j.URL, Header: tlsforge.Header(header), Body: data, Browser: browser}
		err := checker.Validate(&req)
		if again := req.Reloaded(nil); err == nil && reload {
			if err := checker.Validate(&again); err != nil {
				return fmt.Errorf("%w: --retry-as-browser: %s: %s", errUsage, safeURL(j.URL),
					strings.TrimPrefix(err.Error(), "tlsforge: "))
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, tlsforge.ErrNeedsContext):
			what := method + " " + safeURL(j.URL)
			if data != nil && strings.EqualFold(method, "GET") {
				what += " with a body"
			}
			return fmt.Errorf("%w: %s needs --request-kind: without it a request goes as a navigation typed into "+
				"the address bar, a GET with no body; give --request-kind form, fetch or xhr, and --initiator-url, "+
				"the page that sends it", errUsage, what)
		case browser == nil:
			return fmt.Errorf("%w: %s: %s", errUsage, safeURL(j.URL), strings.TrimPrefix(err.Error(), "tlsforge: "))
		default:
			return fmt.Errorf("%w: --request-kind %s: %s: %s", errUsage, browser.Kind, safeURL(j.URL),
				strings.TrimPrefix(err.Error(), "tlsforge: "))
		}
	}
	return nil
}

// warnAboutReferer says, of a run that gives its requests a Referer, that
// they go as navigations typed into the address bar, which say
// Sec-Fetch-Site: none: Chrome sends that with a Referer only when automation
// gives it one (Network.setExtraHTTPHeaders, as measured), and a request from
// a page says where the page is. With --request-kind a Referer given is
// refused before (checkBrowser).
func warnAboutReferer(errOut *printer, worn *profile.Profile, header headerFlag) {
	if !tlsforge.Header(header).Has("referer") ||
		worn.RuntimeBehavior().Text("headers.without_context") != "typed-navigation" {
		return
	}
	errOut.println("WARN: -H Referer without --request-kind goes as a navigation typed into the address bar,")
	errOut.println("      with Sec-Fetch-Site: none, which Chrome sends only when automation gives it a Referer.")
	errOut.println("      For a request from a page, give --request-kind navigation --initiator-url PAGE instead.")
}

// describeContext is what a run's requests are sent as, for its header: the
// kind and the page, or nothing when they go as they always have.
func describeContext(browser *tlsforge.BrowserContext) string {
	if browser == nil {
		return ""
	}
	if browser.Initiator == "" {
		return "a navigation typed into the address bar"
	}
	page := safeURL(browser.Initiator)
	clicked := ""
	if browser.Clicked {
		clicked = ", clicked"
	}
	switch browser.Kind {
	case tlsforge.KindNavigation:
		return "a navigation from " + page + clicked
	case tlsforge.KindForm:
		return "a form from " + page + clicked
	case tlsforge.KindFetch:
		return "fetch() from " + page
	}
	return "an XHR from " + page
}

// againAs says how a request is asked for again under --retry-as-browser, for
// the run's header: nothing without it.
func againAs(asBrowser bool, browser *tlsforge.BrowserContext) string {
	switch {
	case !asBrowser:
		return ""
	case browser != nil && (browser.Kind == tlsforge.KindFetch || browser.Kind == tlsforge.KindXHR):
		return "as the page's script sends it again, on the connection it went on"
	}
	return "as Chrome reloads the page (Ctrl+R): its URL, on the connection it came on"
}

// requestBody preserves -d "" as an explicit empty upload and an omitted -d as
// no body. Nonempty data in an in-memory fetch plan is provided by definition.
func requestBody(data string, provided bool) []byte {
	if provided || data != "" {
		return []byte(data)
	}
	return nil
}
