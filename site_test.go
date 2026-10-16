package tlsforge

import (
	"strings"
	"testing"
)

func TestAnOriginIsSerializedAsChromeSendsIt(t *testing.T) {
	for raw, want := range map[string]string{
		"https://www.example.com/x":                    "https://www.example.com",
		"https://WWW.Example.COM:443/x?y#z":            "https://www.example.com",
		"HTTPS://www.example.com/":                     "https://www.example.com",
		"http://www.example.com:80/":                   "http://www.example.com",
		"http://www.example.com:443/":                  "http://www.example.com:443",
		"https://www.example.com:80/":                  "https://www.example.com:80",
		"https://www.example.com:8443/":                "https://www.example.com:8443",
		"https://user:pw@www.example.com/":             "https://www.example.com",
		"https://bücher.de/":                           "https://xn--bcher-kva.de",
		"https://[::1]:8443/":                          "https://[::1]:8443",
		"https://[::1]/":                               "https://[::1]",
		"http://127.0.0.1:8080/":                       "http://127.0.0.1:8080",
		"https://under_score.example.com/":             "https://under_score.example.com",
		"https://a.b.example.co.uk/":                   "https://a.b.example.co.uk",
		"https://xn--bcher-kva.de/":                    "https://xn--bcher-kva.de",
		"https://www.example.com./":                    "https://www.example.com.",
		"https://[2001:DB8::1]/":                       "https://[2001:db8::1]",
		"https://WWW..EXAMPLE.com/":                    "https://www..example.com",
		"https://" + strings.Repeat("a", 64) + ".com/": "https://" + strings.Repeat("a", 64) + ".com",
	} {
		if got := originOf(mustURL(t, raw)).String(); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
	}
}

func TestTheRelationIsSecFetchSites(t *testing.T) {
	for _, tc := range []struct{ from, to, want string }{
		{"https://www.example.com/a", "https://www.example.com/b", "same-origin"},
		{"https://www.example.com/a", "https://www.example.com:443/b", "same-origin"},
		{"https://www.example.com/a", "https://WWW.EXAMPLE.COM/b", "same-origin"},
		{"https://www.example.com/a", "https://www.example.com:8443/b", "same-site"},
		{"https://www.example.com/a", "https://api.example.com/b", "same-site"},
		{"https://www.example.com/a", "https://example.com/b", "same-site"},
		{"https://a.b.example.co.uk/", "https://c.example.co.uk/", "same-site"},
		{"https://www.example.com/a", "https://www.example.net/b", "cross-site"},
		// Schemeful: the same host over http is another site.
		{"https://www.example.com/a", "http://www.example.com/b", "cross-site"},
		{"https://example.co.uk/", "https://other.co.uk/", "cross-site"},
		// A private suffix is a public one to a browser.
		{"https://a.github.io/", "https://b.github.io/", "cross-site"},
		// An address is its own site, whatever the port.
		{"http://127.0.0.1:8080/", "http://127.0.0.1:9090/", "same-site"},
		{"http://127.0.0.1/", "http://127.0.0.2/", "cross-site"},
		{"https://localhost/", "https://localhost:8443/", "same-site"},
		{"https://a.localhost/", "https://b.localhost/", "cross-site"},
		{"https://bücher.de/", "https://xn--bcher-kva.de/x", "same-origin"},
	} {
		if got := relation(originOf(mustURL(t, tc.from)), originOf(mustURL(t, tc.to))); got != tc.want {
			t.Errorf("%s to %s: %s, want %s", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestTrustworthyIsWhatChromeTrusts(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://www.example.com/": true, "https://192.0.2.1/": true,
		"http://localhost/": true, "http://LOCALHOST:8080/": true, "http://a.localhost/": true,
		"http://127.0.0.1/": true, "http://127.5.5.5:81/": true, "http://[::1]/": true,
		"http://localhost./": true, "http://a.localhost./": true,
		"http://www.example.com/": false, "http://10.0.0.1/": false, "http://localhost.example/": false,
		"http://[2001:db8::1]/": false, "http://notlocalhost/": false,
		// Chrome reads an IPv6 address as loopback when it is ::1, and no
		// other: an IPv4 one mapped into IPv6 is not.
		"http://[::ffff:127.0.0.1]/": false, "http://[0:0:0:0:0:0:0:1]/": true,
		"http://localhost../": false, "http://.localhost/": true,
	} {
		if got := trustworthy(originOf(mustURL(t, raw))); got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
}

func TestTheReferrerIsWhatThePolicySays(t *testing.T) {
	const page = "https://www.example.com/run/x?q=1#frag"
	sameOrigin := "https://www.example.com/p/next"
	sameSite := "https://api.example.com/p/next"
	crossSite := "https://www.example.net/p/next"
	downgrade := "http://www.example.com/p/next"
	const full, originOnly = "https://www.example.com/run/x?q=1", "https://www.example.com/"
	for _, tc := range []struct {
		policy, target, want string
	}{
		// What Chrome 155 was measured to send, testdata/chrome155-requests.json.
		{"", sameOrigin, full},
		{"", sameSite, originOnly},
		{"", crossSite, originOnly},
		{"", downgrade, ""},
		{policyNoReferrer, sameOrigin, ""},
		{policyOrigin, sameOrigin, originOnly},
		{policyUnsafeURL, crossSite, full},
		{policySameOrigin, crossSite, ""},
		{policyStrictOrigin, sameOrigin, originOnly},
		// And the rest of the standard's table.
		{policyStrictOriginWhenCrossOrigin, sameOrigin, full},
		{policyStrictOriginWhenCrossOrigin, crossSite, originOnly},
		{policyStrictOriginWhenCrossOrigin, downgrade, ""},
		{policyNoReferrer, crossSite, ""},
		{policyNoReferrer, downgrade, ""},
		{policyOrigin, crossSite, originOnly},
		{policyOrigin, downgrade, originOnly},
		{policyUnsafeURL, sameOrigin, full},
		{policyUnsafeURL, downgrade, full},
		{policySameOrigin, sameOrigin, full},
		{policySameOrigin, sameSite, ""},
		{policySameOrigin, downgrade, ""},
		{policyStrictOrigin, crossSite, originOnly},
		{policyStrictOrigin, downgrade, ""},
		{policyOriginWhenCrossOrigin, sameOrigin, full},
		{policyOriginWhenCrossOrigin, crossSite, originOnly},
		{policyOriginWhenCrossOrigin, downgrade, originOnly},
		{policyNoReferrerWhenDowngrade, sameOrigin, full},
		{policyNoReferrerWhenDowngrade, crossSite, full},
		{policyNoReferrerWhenDowngrade, downgrade, ""},
		// From https to the machine itself is a downgrade too, by name or by
		// address, as Chrome was measured to have it.
		{"", "http://localhost/p", ""},
		{"", "http://127.0.0.1:8080/p", ""},
		{policyNoReferrerWhenDowngrade, "http://localhost/p", ""},
	} {
		if got := referrerFor(mustURL(t, page), originOf(mustURL(t, tc.target)), tc.policy); got != tc.want {
			t.Errorf("%q to %s: %q, want %q", tc.policy, tc.target, got, tc.want)
		}
	}
}

func TestFromHTTPToHTTPIsNoDowngrade(t *testing.T) {
	// Not even from the machine itself, which is potentially trustworthy: as
	// Chrome was measured to have it, only https can be downgraded from.
	for _, page := range []string{"http://www.example.com", "http://localhost:8080", "http://127.0.0.1",
		"http://[::1]"} {
		for policy, want := range map[string]string{
			"":                            page + "/",
			policyStrictOrigin:            page + "/",
			policyNoReferrerWhenDowngrade: page + "/a?b",
		} {
			got := referrerFor(mustURL(t, page+"/a?b"), originOf(mustURL(t, "http://www.example.net/x")), policy)
			if got != want {
				t.Errorf("%s, %q: %q, want %q", page, policy, got, want)
			}
		}
	}
}

func TestAReferrerIsStrippedAsChromeStripsIt(t *testing.T) {
	target := originOf(mustURL(t, "https://www.example.com/"))
	long := "https://www.example.com/" + strings.Repeat("a", maxReferrerLength)
	for page, want := range map[string]string{
		"https://user:pw@www.example.com/a#frag":     "https://www.example.com/a",
		"https://WWW.Example.com:443/a/b?c=d&e":      "https://www.example.com/a/b?c=d&e",
		"https://www.example.com":                    "https://www.example.com/",
		"https://www.example.com/x?":                 "https://www.example.com/x?",
		"https://www.example.com/a%20b/%C3%A9?x=%20": "https://www.example.com/a%20b/%C3%A9?x=%20",
		long: "https://www.example.com/",
		"https://www.example.com/" + strings.Repeat("a", maxReferrerLength-len("https://www.example.com/")):   "https://www.example.com/" + strings.Repeat("a", maxReferrerLength-len("https://www.example.com/")),
		"https://www.example.com/" + strings.Repeat("a", maxReferrerLength-len("https://www.example.com/")+1): "https://www.example.com/",
	} {
		if got := referrerFor(mustURL(t, page), target, policyUnsafeURL); got != want {
			t.Errorf("%.60s: %.60q, want %.60q", page, got, want)
		}
	}
}
