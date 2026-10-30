package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// seenRequest is a request a site was asked: what, with which fields and
// body, on which connection.
type seenRequest struct {
	method, path string
	header       http.Header
	body         string
	remote       string
}

// refusingOnce is a site over TLS, HTTP/2 offered or HTTP/1.1 alone, that
// refuses the first request for each path under /deny/ (403), setting a
// cookie and asking for a client hint; redirects /r to its to (302); and
// answers everything else with a page. It keeps every request it is asked.
func refusingOnce(t *testing.T, h2 bool) (*httptest.Server, func() []seenRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []seenRequest
	refused := map[string]bool{}
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, seenRequest{method: r.Method, path: r.URL.RequestURI(), header: r.Header.Clone(),
			body: string(body), remote: r.RemoteAddr})
		first := strings.HasPrefix(r.URL.Path, "/deny/") && !refused[r.URL.Path]
		refused[r.URL.Path] = true
		mu.Unlock()
		switch {
		case r.URL.Path == "/r":
			http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
		case first:
			w.Header().Add("Set-Cookie", "d=1; Path=/")
			w.Header().Set("Accept-CH", "Sec-CH-UA-Arch")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "refused")
		default:
			_, _ = io.WriteString(w, "page")
		}
	}))
	site.EnableHTTP2 = h2
	site.StartTLS()
	t.Cleanup(site.Close)
	return site, func() []seenRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenRequest(nil), seen...)
	}
}

// hintOf is the value of a client hint the profile a run wears without
// --profile sends when it is asked for: the machine's own, Sec-CH-UA-Arch
// "arm" on a Mac and "x86" elsewhere.
func hintOf(t *testing.T, name string) string {
	t.Helper()
	worn, err := profile.Get(defaultProfileName())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range worn.ClientHints {
		if strings.EqualFold(f.Name, name) {
			return f.Value
		}
	}
	t.Fatalf("%s has no %s", worn.Name, name)
	return ""
}

func TestFetchRetriesAsAPersonReloadsThePageInChrome(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		t.Run(map[bool]string{true: "h2", false: "h1"}[h2], func(t *testing.T) {
			site, seen := refusingOnce(t, h2)
			code, stdout, stderr := exec(t, "fetch", "--insecure", "--retry", "1", "--retry-as-browser", "-v",
				site.URL+"/deny/page")
			if code != 0 || stdout != "page" {
				t.Fatalf("exit code = %d, stdout %q\n%s", code, stdout, stderr)
			}
			got := seen()
			if len(got) != 2 {
				t.Fatalf("%d requests: %+v", len(got), got)
			}
			first, again := got[0], got[1]
			if again.path != "/deny/page" || again.remote != first.remote {
				t.Errorf("the reload asked for %s on %s, the page came from %s", again.path, again.remote, first.remote)
			}
			for name, want := range map[string]string{"Cache-Control": "max-age=0", "Sec-Fetch-User": "?1",
				"Sec-Fetch-Site": "none", "Cookie": "d=1", "Sec-Ch-Ua-Arch": hintOf(t, "sec-ch-ua-arch")} {
				if v := again.header.Get(name); v != want {
					t.Errorf("the reload's %s is %q, want %q", name, v, want)
				}
			}
			if v := first.header.Get("Cache-Control"); v != "" {
				t.Errorf("the first request asked with Cache-Control %q", v)
			}
			for _, want := range []string{"try 1 of 2: HTTP 403, reloading in",
				"tried again as Chrome reloads the page (Ctrl+R): its URL, on the connection it came on"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr has no %q:\n%s", want, stderr)
				}
			}
		})
	}
}

func TestFetchRetriesOnAConnectionOfItsOwnUnlessAsABrowser(t *testing.T) {
	site, seen := refusingOnce(t, true)
	code, _, stderr := exec(t, "fetch", "--fresh-connection", "--insecure", "--retry", "1", site.URL+"/deny/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	got := seen()
	if len(got) != 2 || got[1].remote == got[0].remote {
		t.Fatalf("tried again on the same connection: %+v", got)
	}
	if v := got[1].header.Get("Cache-Control"); v != "" {
		t.Errorf("a try made again asked with Cache-Control %q", v)
	}
	if strings.Contains(stderr, "tried again") {
		t.Errorf("the run says it tries again as a browser:\n%s", stderr)
	}
}

func TestFetchReloadsThePageARedirectLedTo(t *testing.T) {
	site, seen := refusingOnce(t, true)
	code, _, stderr := exec(t, "fetch", "--insecure", "--retry", "1", "--retry-as-browser",
		site.URL+"/r?to=/deny/end")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	var paths []string
	for _, r := range seen() {
		paths = append(paths, r.path)
	}
	if want := []string{"/r?to=/deny/end", "/deny/end", "/deny/end"}; strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Errorf("asked for %v, want %v: the page the redirect led to, reloaded", paths, want)
	}
}

func TestFetchPostsAFormAgainAsAPersonReloadsItInChrome(t *testing.T) {
	site, seen := refusingOnce(t, true)
	code, _, stderr := exec(t, "fetch", "--insecure", "--retry", "1", "--retry-as-browser", "--request-kind", "form",
		"--initiator-url", site.URL+"/form", "--clicked", "-X", "POST", "-d", "a=b", site.URL+"/deny/post")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	got := seen()
	if len(got) != 2 {
		t.Fatalf("%d requests: %+v", len(got), got)
	}
	for i, r := range got {
		if r.method != "POST" || r.body != "a=b" || r.header.Get("Sec-Fetch-User") != "?1" ||
			r.header.Get("Cache-Control") != "max-age=0" || r.header.Get("Origin") != site.URL {
			t.Errorf("request %d: %s %q with %v", i, r.method, r.body, r.header)
		}
	}
	if got[1].remote != got[0].remote || got[1].header.Get("Cookie") != "d=1" {
		t.Errorf("posted again on %s with %q, the form went on %s", got[1].remote, got[1].header.Get("Cookie"), got[0].remote)
	}
	if !strings.Contains(stderr, "a form from "+site.URL+"/form, clicked") {
		t.Errorf("the run does not say the form is clicked:\n%s", stderr)
	}
}

func TestFetchSendsAScriptsRequestAgainAsItsPageWould(t *testing.T) {
	site, seen := refusingOnce(t, true)
	code, _, stderr := exec(t, "fetch", "--insecure", "--retry", "1", "--retry-as-browser", "-v",
		"--request-kind", "fetch", "--initiator-url", site.URL+"/page", site.URL+"/deny/api")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	got := seen()
	if len(got) != 2 || got[1].remote != got[0].remote {
		t.Fatalf("not sent again on its connection: %+v", got)
	}
	for _, name := range []string{"Cache-Control", "Sec-Fetch-User"} {
		if v := got[1].header.Get(name); v != "" {
			t.Errorf("fetch() sent again with %s %q", name, v)
		}
	}
	for _, want := range []string{"trying again in",
		"tried again as the page's script sends it again, on the connection it went on"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
}

func TestFetchLogsATryMadeAgainAsAReload(t *testing.T) {
	site, _ := refusingOnce(t, true)
	log := filepath.Join(t.TempDir(), "run.jsonl")
	code, _, stderr := exec(t, "fetch", "--insecure", "--retry", "1", "--retry-as-browser", "--log", log,
		site.URL+"/deny/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		switch record["msg"] {
		case "retry":
			found = record["as"] == "reload"
		case "run":
			if record["retry_as_browser"] != true {
				t.Errorf("the run record says nothing of --retry-as-browser: %v", record)
			}
		}
	}
	if !found {
		t.Errorf("no retry record says it was a reload:\n%s", raw)
	}
}

func TestRetryAsABrowserAndAClickAreRefusedWhereTheyMeanNothing(t *testing.T) {
	site, seen := refusingOnce(t, true)
	page := site.URL + "/page"
	for _, tc := range []struct {
		args []string
		says string
	}{
		{[]string{"--retry-as-browser", page},
			"--retry-as-browser says how a request is asked for again: give --retry"},
		{[]string{"--clicked", page},
			"--clicked says a click on the --initiator-url page sends the request: give --request-kind navigation or " +
				"form, or --form"},
		{[]string{"--clicked", "--request-kind", "fetch", "--initiator-url", page, page},
			"--request-kind fetch: " + page + ": browser context: fetch() is no navigation: a click says nothing of it"},
		{[]string{"--clicked", "--request-kind", "navigation", page},
			"a navigation typed into the address bar is the person's already"},
		{[]string{"--retry", "1", "--retry-as-browser", "-p", "firefox_148", page},
			`--retry-as-browser: ` + page + `: profile "firefox_148" sends a request without a browser context as it is ` +
				`given, which opens no page to reload`},
	} {
		code, _, stderr := exec(t, append([]string{"fetch", "--insecure"}, tc.args...)...)
		if code != 2 || !strings.Contains(stderr, tc.says) {
			t.Errorf("%v: exit code %d\n%s\nwant %q", tc.args, code, stderr, tc.says)
		}
	}
	if n := len(seen()); n != 0 {
		t.Errorf("%d requests sent by commands that were refused", n)
	}
}

func TestTheRunSaysHowARequestIsAskedForAgain(t *testing.T) {
	page := "https://www.example.com/page"
	reload := "as Chrome reloads the page (Ctrl+R): its URL, on the connection it came on"
	script := "as the page's script sends it again, on the connection it went on"
	for _, tc := range []struct {
		asBrowser bool
		browser   *tlsforge.BrowserContext
		own       tlsforge.RequestKind
		want      string
	}{
		{false, nil, "", ""},
		{false, &tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Initiator: page}, "", ""},
		{true, nil, "", reload},
		{true, &tlsforge.BrowserContext{Kind: tlsforge.KindNavigation, Initiator: page}, "", reload},
		{true, &tlsforge.BrowserContext{Kind: tlsforge.KindForm, Initiator: page}, "", reload},
		{true, &tlsforge.BrowserContext{Kind: tlsforge.KindForm, Clicked: true}, tlsforge.KindForm, reload},
		{true, &tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Initiator: page}, "", script},
		{true, &tlsforge.BrowserContext{Kind: tlsforge.KindXHR, Initiator: page}, "", script},
		{true, nil, tlsforge.KindXHR, script},
	} {
		if got := againAs(tc.asBrowser, kindOf(tc.browser, tc.own)); got != tc.want {
			t.Errorf("%v %+v %q: %q, want %q", tc.asBrowser, tc.browser, tc.own, got, tc.want)
		}
	}
}
