package main

import (
	"errors"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// xhrAsked and formAsked are the fields Chrome gives an XHR of a page of the
// URL's own origin, and the form a person's click there submits.
func xhrAsked(page, origin string) map[string]string {
	return map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Sec-Fetch-User": "",
		"Sec-Fetch-Site": "same-origin", "Accept": "*/*", "Referer": page, "Origin": origin, "Cache-Control": "",
		"Upgrade-Insecure-Requests": "", "Priority": "u=1, i"}
}

func formAsked(page, origin string) map[string]string {
	return map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
		"Sec-Fetch-Site": "same-origin", "Referer": page, "Origin": origin, "Cache-Control": "max-age=0",
		"Upgrade-Insecure-Requests": "1", "Priority": "u=0, i"}
}

func with(base map[string]string, more ...string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i < len(more); i += 2 {
		out[more[i]] = more[i+1]
	}
	return out
}

func TestFetchSendsARequestWithoutAKindAsAnXHROfItsOwnPageOrAsAFormWithTheFlag(t *testing.T) {
	// Without --request-kind a GET is a navigation typed into the address
	// bar, and anything else an XHR of the root of its URL's own origin; with
	// --form, the form a click on that page, or on --initiator-url's, submits
	// (owner decision, 2026-10-24).
	site, seen := refusingOnce(t, true)
	page := site.URL + "/"
	xhr, form := xhrAsked(page, site.URL), formAsked(page, site.URL)
	for i, tc := range []struct {
		name   string
		args   []string
		method string
		want   map[string]string
		said   string
	}{
		{"a POST of a form's fields is an XHR", []string{"-X", "POST", "-d", "a=1"}, "POST", xhr,
			"sent as     an XHR from " + page + ", without --request-kind"},
		{"JSON", []string{"-X", "POST", "-H", "Content-Type: application/json", "-d", "{}"}, "POST",
			with(xhr, "Content-Type", "application/json"), "an XHR from " + page},
		{"a field of its own", []string{"-X", "POST", "-H", "X-Token: 1", "-d", "a=1"}, "POST",
			with(xhr, "X-Token", "1"), "an XHR from " + page},
		{"PUT", []string{"-X", "PUT", "-d", "a=1"}, "PUT", xhr, "an XHR from " + page},
		{"DELETE", []string{"-X", "DELETE"}, "DELETE", xhr, "an XHR from " + page},
		{"HEAD", []string{"-X", "HEAD"}, "HEAD", with(xhr, "Origin", ""), "an XHR from " + page},
		{"--form posts the form a click submits", []string{"--form", "-X", "POST", "-d", "a=1"}, "POST",
			with(form, "Content-Type", "application/x-www-form-urlencoded"),
			"sent as     a form from " + page + ", clicked\n"},
		{"in text", []string{"--form", "-X", "POST", "-H", "Content-Type: text/plain", "-d", "a=1"}, "POST",
			with(form, "Content-Type", "text/plain"), "a form from " + page + ", clicked"},
		{"by GET", []string{"--form"}, "GET", with(form, "Origin", "", "Cache-Control", ""),
			"a form from " + page + ", clicked"},
		{"on a page of its own", []string{"--form", "--initiator-url", site.URL + "/login", "-X", "POST", "-d", "a=1"},
			"POST", with(form, "Referer", site.URL+"/login", "Content-Type", "application/x-www-form-urlencoded"),
			"a form from " + site.URL + "/login, clicked"},
		{"--form with --clicked too", []string{"--form", "--clicked", "-X", "POST", "-d", "a=1"}, "POST", form,
			"a form from " + page + ", clicked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/own/" + strings.Repeat("x", i+1)
			code, _, stderr := exec(t, append(append([]string{"fetch", "--insecure"}, tc.args...), site.URL+path)...)
			if code != 0 || !strings.Contains(stderr, tc.said) {
				t.Fatalf("exit code %d, want the run to say %q:\n%s", code, tc.said, stderr)
			}
			var got *seenRequest
			for _, r := range seen() {
				if r.path == path {
					got = &r
				}
			}
			if got == nil || got.method != tc.method {
				t.Fatalf("asked %+v, want a %s", got, tc.method)
			}
			for name, want := range tc.want {
				if v := got.header.Get(name); v != want {
					t.Errorf("%s is %q, want %q", name, v, want)
				}
			}
		})
	}
}

func TestFetchSaysWhatAListGoesAsFromThePagesOfItsURLs(t *testing.T) {
	site, seen := refusingOnce(t, true)
	other, more := refusingOnce(t, true)
	for _, tc := range []struct {
		args       []string
		said, mode string
	}{
		{[]string{"-X", "PUT", "-d", "x"}, "an XHR of the root of each URL's own origin, without --request-kind", "cors"},
		{[]string{"--form", "-X", "POST", "-d", "a=1"}, "the form a click submits on the root of each URL's own origin",
			"navigate"},
	} {
		before := len(seen())
		code, _, stderr := exec(t, append(append([]string{"fetch", "--insecure"}, tc.args...), "--urls",
			site.URL+"/a,"+other.URL+"/b")...)
		if code != 0 || !strings.Contains(stderr, "sent as     "+tc.said) {
			t.Fatalf("%v: exit code %d:\n%s", tc.args, code, stderr)
		}
		mine, theirs := seen()[before:], more()[before:]
		if len(mine) != 1 || len(theirs) != 1 || mine[0].header.Get("Sec-Fetch-Mode") != tc.mode ||
			mine[0].header.Get("Referer") != site.URL+"/" {
			t.Errorf("%v: asked %+v and %+v", tc.args, mine, theirs)
		}
		if tc.mode == "cors" && strings.HasPrefix(tc.said, "an XHR") && theirs[0].header.Get("Referer") != other.URL+"/" {
			t.Errorf("%v: the other URL's from %q", tc.args, theirs[0].header.Get("Referer"))
		}
	}
	// A list a kind is given goes as the kind says, and a list of GETs as
	// typed navigations, which the run says nothing of.
	code, _, stderr := exec(t, "fetch", "--insecure", "--request-kind", "fetch", "--initiator-url", site.URL+"/",
		"-X", "PUT", "--urls", site.URL+"/c,"+site.URL+"/d")
	if code != 0 || !strings.Contains(stderr, "sent as     fetch() from "+site.URL+"/\n") {
		t.Errorf("a list with a kind: exit code %d:\n%s", code, stderr)
	}
	code, _, stderr = exec(t, "fetch", "--insecure", "--urls", site.URL+"/e,"+other.URL+"/f")
	if code != 0 || strings.Contains(stderr, "sent as") {
		t.Errorf("a list of GETs: exit code %d:\n%s", code, stderr)
	}
}

func TestFetchSendsAPostAsGivenWhereTheProfileSendsRequestsWithoutAContextSo(t *testing.T) {
	// A profile of the transport's catalogue sends a request without a
	// context as it is given, whatever its method: no page sends it.
	site, seen := refusingOnce(t, true)
	code, _, stderr := exec(t, "fetch", "--insecure", "-p", "firefox_148", "-X", "POST", "-d", "a=1", site.URL+"/x")
	if code != 0 || strings.Contains(stderr, "sent as") {
		t.Fatalf("exit code %d:\n%s", code, stderr)
	}
	got := seen()
	if len(got) != 1 || got[0].body != "a=1" || got[0].header.Get("Sec-Fetch-Mode") != "" ||
		got[0].header.Get("Origin") != "" {
		t.Errorf("asked %+v", got)
	}
}

func TestFetchAsksAgainAsAPersonWouldForWhatItSendsFromItsOwnPage(t *testing.T) {
	// The form --form posts is posted again as Chrome reloads its page; the
	// XHR a request without a kind goes as is sent again as the page's
	// script sends it: as it was, on the connection it went on.
	site, seen := refusingOnce(t, true)
	code, _, stderr := execWorkflow(t, "fetch", "--insecure", "--retry", "1", "--retry-as-browser", "--form", "-X", "POST",
		"-d", "a=b", site.URL+"/deny/form")
	if code != 0 {
		t.Fatalf("exit code %d:\n%s", code, stderr)
	}
	code, _, stderr = execWorkflow(t, "fetch", "--insecure", "--retry", "1", "--retry-as-browser", "-X", "POST",
		"-d", "a=b", site.URL+"/deny/xhr")
	if code != 0 || !strings.Contains(stderr, "tried again as the page's script sends it again") {
		t.Fatalf("exit code %d:\n%s", code, stderr)
	}
	got := seen()
	if len(got) != 4 || got[1].remote != got[0].remote || got[3].remote != got[2].remote {
		t.Fatalf("asked %+v", got)
	}
	for i, r := range got {
		if r.method != "POST" || r.body != "a=b" || r.header.Get("Referer") != site.URL+"/" {
			t.Errorf("request %d: %s %q with %v", i, r.method, r.body, r.header)
		}
	}
	if got[1].header.Get("Sec-Fetch-User") != "?1" || got[1].header.Get("Cache-Control") != "max-age=0" ||
		got[1].header.Get("Cookie") != "d=1" {
		t.Errorf("the form posted again: %v", got[1].header)
	}
	if got[3].header.Get("Sec-Fetch-Mode") != "cors" || got[3].header.Get("Cache-Control") != "" ||
		got[3].header.Get("Cookie") != "d=1" {
		t.Errorf("the XHR sent again: %v", got[3].header)
	}
}

func TestAURLTheListWouldNotHaveHasNoOwnPage(t *testing.T) {
	// validate refuses such a URL first; a request to one goes from no page,
	// and checkBrowser says so of --form.
	for _, own := range []tlsforge.RequestKind{"", tlsforge.KindXHR} {
		req := tlsforge.Request{Method: "POST", URL: "ftp://www.example.com/"}
		if got, err := onOwnPage(req, own); err != nil || got.Browser != nil {
			t.Errorf("%q: %+v, %v", own, got.Browser, err)
		}
	}
	if _, err := onOwnPage(tlsforge.Request{Method: "POST", URL: "ftp://www.example.com/"}, tlsforge.KindForm); err == nil ||
		!strings.Contains(err.Error(), `"ftp://www.example.com/" is not an http`) {
		t.Errorf("--form: %v", err)
	}
	worn, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkBrowser(worn, []job{{URL: "ftp://www.example.com/"}}, "POST", nil, []byte("a=1"),
		&tlsforge.BrowserContext{Kind: tlsforge.KindForm, Clicked: true}, true, false)
	if !errors.Is(err, errUsage) || !strings.Contains(err.Error(), "--form: ftp://www.example.com/: ") {
		t.Errorf("checkBrowser: %v", err)
	}
}
