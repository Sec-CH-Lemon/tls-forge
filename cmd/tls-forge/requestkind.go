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

// browserContextOf is the browser context --request-kind, --initiator-url,
// --clicked and --form give every request of a run, or nil when none is
// given. --form is the form a person's click submits, on the page
// --initiator-url names or, with none, on the root of each URL's own origin,
// which checkBrowser and the run fill in for each URL.
func browserContextOf(kind, initiator string, initiatorGiven, clicked, form bool) (*tlsforge.BrowserContext, error) {
	switch {
	case form && kind != "":
		return nil, fmt.Errorf("%w: --form says the request is the form a click submits, and --request-kind says "+
			"what sends it: give one of them", errUsage)
	case form:
		return &tlsforge.BrowserContext{Kind: tlsforge.KindForm, Initiator: initiator, Clicked: true}, nil
	case kind == "" && initiatorGiven:
		return nil, fmt.Errorf("%w: --initiator-url names the page a --request-kind or --form request is sent "+
			"from: give one of them", errUsage)
	case kind == "" && clicked:
		return nil, fmt.Errorf("%w: --clicked says a click on the --initiator-url page sends the request: "+
			"give --request-kind navigation or form, or --form", errUsage)
	case kind == "":
		return nil, nil
	}
	for _, known := range requestKinds {
		if tlsforge.RequestKind(kind) == known {
			return &tlsforge.BrowserContext{Kind: known, Initiator: initiator, Clicked: clicked}, nil
		}
	}
	return nil, badValue("--request-kind", kind, "navigation, form, fetch or xhr")
}

// onOwnPage is req, to its URL, as it goes from the root of the URL's own
// origin as own says: the form a person's click there submits (--form with no
// --initiator-url), or an XHR of that page (tlsforge.Request.FromItsOwnPage,
// a request without --request-kind that no typed navigation is: owner
// decision, 2026-10-24); req as it is for neither.
func onOwnPage(req tlsforge.Request, own tlsforge.RequestKind) (tlsforge.Request, error) {
	switch own {
	case tlsforge.KindForm:
		page, err := tlsforge.OwnPage(req.URL)
		if err != nil {
			return req, err
		}
		req.Browser = &tlsforge.BrowserContext{Kind: tlsforge.KindForm, Initiator: page, Clicked: true}
	case tlsforge.KindXHR:
		req = req.FromItsOwnPage()
	}
	return req, nil
}

// checkBrowser refuses a run whose requests a browser would not send as the
// kind says, or this profile cannot send as one, or, without --request-kind,
// as the navigation typed into the address bar a GET without one goes as, or
// as the XHR of its URL's own page anything else without one goes as; and,
// with --retry-as-browser (reload), one whose page the profile cannot reload
// as Chrome does: the request of every URL of the list is checked as the
// library would check it, before anything is sent. It says what the requests
// go as from their URL's own page (onOwnPage): a form with --form and no
// --initiator-url, an XHR without --request-kind, else nothing. A GET with no
// body and no kind, not reloaded, has nothing to check that the list has not
// been checked for.
func checkBrowser(worn *profile.Profile, jobs []job, method string, header headerFlag, data []byte,
	browser *tlsforge.BrowserContext, form, reload bool,
) (own tlsforge.RequestKind, err error) {
	if browser == nil && strings.EqualFold(method, "GET") && data == nil && !reload {
		return "", nil
	}
	checker, err := newClient("", tlsforge.WithProfileValue(worn))
	if err != nil {
		return "", err
	}
	defer func() { _ = checker.Close() }()
	said := "--form"
	switch {
	case !form && browser != nil:
		said = "--request-kind " + string(browser.Kind)
	case form && browser.Initiator == "":
		own = tlsforge.KindForm
	}
	for _, j := range jobs {
		req, err := onOwnPage(tlsforge.Request{Method: method, URL: j.URL, Header: tlsforge.Header(header), Body: data,
			Browser: browser}, own)
		if err == nil {
			err = checker.Validate(&req)
		}
		if page := req.FromItsOwnPage(); errors.Is(err, tlsforge.ErrNeedsContext) && page.Browser != nil {
			// No navigation typed into the address bar: as the script of its
			// URL's own page sends it.
			req, own = page, tlsforge.KindXHR
			if err := checker.Validate(&req); err != nil {
				return "", fmt.Errorf("%w: %s: sent as %s, without --request-kind: %s", errUsage, safeURL(j.URL),
					describeContext(req.Browser), strings.TrimPrefix(err.Error(), "tlsforge: "))
			}
			err = nil
		}
		if again := req.Reloaded(nil); err == nil && reload {
			if err := checker.Validate(&again); err != nil {
				return "", fmt.Errorf("%w: --retry-as-browser: %s: %s", errUsage, safeURL(j.URL),
					strings.TrimPrefix(err.Error(), "tlsforge: "))
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, tlsforge.ErrNeedsContext):
			return "", fmt.Errorf("%w: GET %s with a body: no page sends one; give its fields in the URL, or "+
				"send it with -X POST", errUsage, safeURL(j.URL))
		case browser == nil:
			return "", fmt.Errorf("%w: %s: %s", errUsage, safeURL(j.URL), strings.TrimPrefix(err.Error(), "tlsforge: "))
		default:
			return "", fmt.Errorf("%w: %s: %s: %s", errUsage, said, safeURL(j.URL),
				strings.TrimPrefix(err.Error(), "tlsforge: "))
		}
	}
	return own, nil
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

// describeRequests is what a run's requests are sent as, for its header: as
// --request-kind or --form says, or, from their URL's own page (own,
// checkBrowser), as onOwnPage sends the one URL a run of one asks for, or
// each URL of a list; or nothing when they go as they always have.
func describeRequests(browser *tlsforge.BrowserContext, own tlsforge.RequestKind, method string, header headerFlag,
	data []byte, jobs []job,
) string {
	without := map[tlsforge.RequestKind]string{tlsforge.KindXHR: ", without --request-kind"}[own]
	switch {
	case own == "":
		return describeContext(browser)
	case len(jobs) != 1 && own == tlsforge.KindForm:
		return "the form a click submits on the root of each URL's own origin"
	case len(jobs) != 1:
		return "an XHR of the root of each URL's own origin" + without
	}
	req, _ := onOwnPage(tlsforge.Request{Method: method, URL: jobs[0].URL, Header: tlsforge.Header(header), Body: data,
		Browser: browser}, own)
	return describeContext(req.Browser) + without
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
// the run's header, by the kind of what sends it (kindOf): nothing without it.
func againAs(asBrowser bool, kind tlsforge.RequestKind) string {
	switch {
	case !asBrowser:
		return ""
	case kind == tlsforge.KindFetch || kind == tlsforge.KindXHR:
		return "as the page's script sends it again, on the connection it went on"
	}
	return "as Chrome reloads the page (Ctrl+R): its URL, on the connection it came on"
}

// kindOf is the kind of what sends a run's requests: the kind --request-kind
// or --form says, else the kind they go as from their URL's own page, else
// none (a navigation typed into the address bar).
func kindOf(browser *tlsforge.BrowserContext, own tlsforge.RequestKind) tlsforge.RequestKind {
	if browser != nil {
		return browser.Kind
	}
	return own
}

// requestBody preserves -d "" as an explicit empty upload and an omitted -d as
// no body. Nonempty data in an in-memory fetch plan is provided by definition.
func requestBody(data string, provided bool) []byte {
	if provided || data != "" {
		return []byte(data)
	}
	return nil
}
