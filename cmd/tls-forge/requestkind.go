package main

import (
	"fmt"
	"strings"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v2"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// requestKinds are what --request-kind takes.
var requestKinds = []tlsforge.RequestKind{tlsforge.KindNavigation, tlsforge.KindForm, tlsforge.KindFetch, tlsforge.KindXHR}

// browserContextOf is the browser context --request-kind and --initiator-url
// give every request of a run, or nil when neither is given.
func browserContextOf(kind, initiator string, initiatorGiven bool) (*tlsforge.BrowserContext, error) {
	if kind == "" {
		if initiatorGiven {
			return nil, fmt.Errorf("%w: --initiator-url names the page a --request-kind request is sent from: "+
				"give --request-kind", errUsage)
		}
		return nil, nil
	}
	for _, known := range requestKinds {
		if tlsforge.RequestKind(kind) == known {
			return &tlsforge.BrowserContext{Kind: known, Initiator: initiator}, nil
		}
	}
	return nil, badValue("--request-kind", kind, "navigation, form, fetch or xhr")
}

// checkBrowser refuses a run whose requests a browser would not send as the
// kind says, or this profile cannot send as one: the request of every URL of
// the list is checked as the library would check it, before anything is sent.
func checkBrowser(worn *profile.Profile, jobs []job, method string, header headerFlag, data string,
	browser *tlsforge.BrowserContext,
) error {
	if browser == nil {
		return nil
	}
	checker, err := newClient("", tlsforge.WithProfileValue(worn))
	if err != nil {
		return err
	}
	defer func() { _ = checker.Close() }()
	for _, j := range jobs {
		err := checker.Validate(&tlsforge.Request{Method: method, URL: j.URL, Header: tlsforge.Header(header),
			Body: []byte(data), Browser: browser})
		if err != nil {
			return fmt.Errorf("%w: --request-kind %s: %s: %s", errUsage, browser.Kind, safeURL(j.URL),
				strings.TrimPrefix(err.Error(), "tlsforge: "))
		}
	}
	return nil
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
	switch browser.Kind {
	case tlsforge.KindNavigation:
		return "a navigation from " + page
	case tlsforge.KindForm:
		return "a form from " + page
	case tlsforge.KindFetch:
		return "fetch() from " + page
	}
	return "an XHR from " + page
}
