package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/cookie"
)

// cookieEcho reports the Cookie header it was sent, and sets two of its own,
// so both directions can be checked without a network.
func cookieEcho(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "visitor", Value: "42", Path: "/",
				Secure: true, HttpOnly: true})
			http.SetCookie(w, &http.Cookie{Name: "tier", Value: "gold", Path: "/"})
		}
		names := make([]string, 0, 4)
		for _, c := range r.Cookies() {
			names = append(names, c.Name+"="+c.Value)
		}
		sort.Strings(names)
		_, _ = fmt.Fprint(w, strings.Join(names, " "))
	}))
	t.Cleanup(server.Close)
	return server
}

// hostnameOf is the host without its port, which is what a cookie's domain is:
// a cookie never carries one. hostOf, in the proxy tests, keeps the port because
// a CONNECT target needs it.
func hostnameOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing %s: %v", rawURL, err)
	}
	return u.Hostname()
}

func writeCookieFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cookies.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	return path
}

func TestFetchSendsCookiesGivenOnTheCommandLine(t *testing.T) {
	// A bare name and value names no host, so there is nothing to file it under
	// until a request says which one.
	server := cookieEcho(t)
	code, stdout, stderr := exec(t, "fetch", "-k", "-b", "session=abc", "-b", "region=eu",
		server.URL+"/")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "region=eu") || !strings.Contains(stdout, "session=abc") {
		t.Errorf("the server was sent %q", stdout)
	}
}

func TestFetchRejectsACookieThatIsNotAPair(t *testing.T) {
	code, _, stderr := exec(t, "fetch", "-b", "nonsense", "https://example.com/")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "name=value") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestFetchTakesASetFromAFileByID(t *testing.T) {
	server := cookieEcho(t)
	host := hostnameOf(t, server.URL)
	path := writeCookieFile(t, `{"sets":[
	  {"id":"eu","cookies":[{"name":"session","value":"eu-1","domain":"`+host+`","path":"/"}]},
	  {"id":"us","cookies":[{"name":"session","value":"us-2","domain":"`+host+`","path":"/"}]}
	]}`)

	for id, want := range map[string]string{"eu": "session=eu-1", "us": "session=us-2"} {
		_, stdout, stderr := exec(t, "fetch", "-k", "--cookies", path, "--cookie-set", id, server.URL+"/")
		if !strings.Contains(stdout, want) {
			t.Errorf("set %s sent %q\n%s", id, stdout, stderr)
		}
	}
	// And says where the session came from, since the run did not choose it by
	// hand.
	_, _, stderr := exec(t, "fetch", "-k", "--cookies", path, "--cookie-set", "eu", server.URL+"/")
	if !strings.Contains(stderr, "warmed from") || !strings.Contains(stderr, "set eu") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestFetchTakesASetAtRandom(t *testing.T) {
	// A file of warmed sessions exists to be spread over, so with no id named
	// the choice is a draw rather than the first one every time.
	original := pickCookieSet
	t.Cleanup(func() { pickCookieSet = original })
	pickCookieSet = rand.New(rand.NewSource(7))

	server := cookieEcho(t)
	host := hostnameOf(t, server.URL)
	path := writeCookieFile(t, `{"sets":[
	  {"id":"a","cookies":[{"name":"s","value":"1","domain":"`+host+`","path":"/"}]},
	  {"id":"b","cookies":[{"name":"s","value":"2","domain":"`+host+`","path":"/"}]},
	  {"id":"c","cookies":[{"name":"s","value":"3","domain":"`+host+`","path":"/"}]}
	]}`)

	seen := map[string]bool{}
	for range 60 {
		_, stdout, _ := exec(t, "fetch", "-k", "--cookies", path, server.URL+"/")
		seen[stdout] = true
	}
	if len(seen) != 3 {
		t.Errorf("only %v were ever sent", seen)
	}
}

func TestFetchCookieFileErrors(t *testing.T) {
	for _, tc := range []struct{ name, path, set, want string }{
		{"a file that is not there", filepath.Join(t.TempDir(), "gone.json"), "", "gone.json"},
		{"a set that is not in it", writeCookieFile(t, `{"sets":[{"id":"a","cookies":[]}]}`),
			"nope", "nope"},
		{"a file that will not parse", writeCookieFile(t, `<html>`), "", "cookie"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"fetch", "--cookies", tc.path}
			if tc.set != "" {
				args = append(args, "--cookie-set", tc.set)
			}
			code, _, stderr := exec(t, append(args, "https://example.com/")...)
			if code == 0 {
				t.Fatal("exit code = 0")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestFetchSkipsExpiredCookies(t *testing.T) {
	// A cookie past its date is one the server would ignore; sending it says
	// this session is stale when the rest of it may not be.
	fakeClock(t)
	server := cookieEcho(t)
	host := hostnameOf(t, server.URL)
	path := writeCookieFile(t, `{"sets":[{"id":"a","cookies":[
	  {"name":"live","value":"1","domain":"`+host+`","path":"/","expires":"2030-01-01T00:00:00Z"},
	  {"name":"stale","value":"2","domain":"`+host+`","path":"/","expires":"2020-01-01T00:00:00Z"}
	]}]}`)

	_, stdout, stderr := exec(t, "fetch", "-k", "--cookies", path, server.URL+"/")
	if strings.Contains(stdout, "stale") {
		t.Errorf("an expired cookie was sent: %q", stdout)
	}
	if !strings.Contains(stdout, "live=1") {
		t.Errorf("the live one was not sent: %q", stdout)
	}
	if !strings.Contains(stderr, "1 expired") {
		t.Errorf("stderr does not say one was dropped: %q", stderr)
	}
}

func TestFetchSavesTheSessionItEndsWith(t *testing.T) {
	fakeClock(t)
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "warm.json")

	code, _, stderr := exec(t, "fetch", "-k", "--save-cookies", path, server.URL+"/set")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "saved 2 cookies") {
		t.Errorf("stderr = %q", stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	file, err := cookie.Load(data)
	if err != nil {
		t.Fatalf("loading what was written: %v", err)
	}
	if len(file.Sets) != 1 || len(file.Sets[0].Cookies) != 2 {
		t.Fatalf("sets: %+v", file.Sets)
	}
	// The flags survive the trip, or the session does not.
	var secure bool
	for _, c := range file.Sets[0].Cookies {
		if c.Name == "visitor" {
			secure = c.Secure && c.HTTPOnly
		}
	}
	if !secure {
		t.Errorf("the flags were lost: %+v", file.Sets[0].Cookies)
	}
	// A warmed session is a credential.
	info, err := os.Stat(path)
	// Skipped on Windows, which reports 0666 whatever was asked for: the mode is
	// a Unix idea, and a warmed session is still written 0600 where it means
	// something.
	if err != nil || (info.Mode().Perm() != 0o600 && runtime.GOOS != "windows") {
		t.Errorf("mode = %v", info.Mode().Perm())
	}

	// A second run adds to the file rather than replacing it.
	if code, _, _ := exec(t, "fetch", "-k", "--save-cookies", path, server.URL+"/set"); code != 0 {
		t.Fatalf("the second run failed")
	}
	data, _ = os.ReadFile(path)
	again, _ := cookie.Load(data)
	if len(again.Sets) != 2 {
		t.Errorf("%d sets after two runs", len(again.Sets))
	}
	if again.Sets[0].ID == again.Sets[1].ID {
		t.Errorf("two sets answer to %q", again.Sets[0].ID)
	}
}

func TestFetchSavesNothingWhenThereIsNothingToSave(t *testing.T) {
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "warm.json")
	// This path sets no cookies, so there is no session to write down.
	if code, _, _ := exec(t, "fetch", "-k", "--save-cookies", path, server.URL+"/"); code != 0 {
		t.Fatal("exit code")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a file was written for a run that warmed nothing")
	}
}

func TestFetchReportsASessionItCannotWrite(t *testing.T) {
	server := cookieEcho(t)
	_, _, stderr := exec(t, "fetch", "-k", "--save-cookies",
		filepath.Join(t.TempDir(), "no-such-directory", "warm.json"), server.URL+"/set")
	if !strings.Contains(stderr, "tlsforge:") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestBatchWarmsEveryRequest(t *testing.T) {
	// The flags are shared, so batch gets them too, and one warmed session is
	// one client's, which is the identity it was warmed for.
	server := cookieEcho(t)
	_, stdout, stderr := exec(t, "batch", "-k", "-b", "session=abc", "--progress", "never",
		server.URL+"/a", server.URL+"/b")
	if !strings.Contains(stdout, "session=abc") {
		t.Errorf("stdout = %q\n%s", stdout, stderr)
	}
	var sent int
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var r result
		if err := json.Unmarshal([]byte(line), &r); err == nil && strings.Contains(r.Body, "session=abc") {
			sent++
		}
	}
	if sent != 2 {
		t.Errorf("%d of the 2 requests carried the cookie", sent)
	}
}

func TestBatchSavesOneSessionPerProxy(t *testing.T) {
	// A jar is an identity, so two exits' sessions never share a set. The same
	// URL twice is one host, asked once.
	fakeClock(t)
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "warm.json")

	list := writeList(t, "mixed.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/set,\n%[1]s/set,\n%[1]s/set,http://127.0.0.1:9001\n", server.URL))

	code, _, stderr := exec(t, "batch", "-k", "--input", list, "--save-cookies", path,
		"--progress", "never", "--repeat", "0", "--timeout", "5s", "-o", os.DevNull)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (one URL went through a dead proxy)\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "saved 2 cookies") {
		t.Errorf("stderr = %q", stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	file, err := cookie.Load(data)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	// The dead proxy carried nothing, so it has no session to write down.
	if len(file.Sets) != 1 {
		t.Fatalf("%d sets: %+v", len(file.Sets), file.Sets)
	}
	if file.Sets[0].Note != "direct" {
		t.Errorf("the set does not say which exit warmed it: %q", file.Sets[0].Note)
	}
}

func TestBatchReportsASessionItCannotWrite(t *testing.T) {
	server := cookieEcho(t)
	_, _, stderr := exec(t, "batch", "-k", "--save-cookies",
		filepath.Join(t.TempDir(), "no-such-directory", "w.json"),
		"--progress", "never", "-o", os.DevNull, server.URL+"/set")
	if !strings.Contains(stderr, "tlsforge:") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestSaveSessionSkipsAURLItCannotRead(t *testing.T) {
	// A record whose URL will not parse has no jar to read; the rest of the run
	// is still written down.
	fakeClock(t)
	server := cookieEcho(t)
	fs := newFlagSet("batch", newPrinter(io.Discard))
	flags := addClientFlags(fs)
	path := filepath.Join(t.TempDir(), "warm.json")
	if err := parse(fs, []string{"--insecure", "--save-cookies", path}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	client, err := flags.client()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Get(server.URL + "/set"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	saved, err := flags.saveSession(client, []string{"://not a url", server.URL + "/"}, "")
	if err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	// The two the readable URL's host had; the unreadable one contributed
	// nothing rather than ending the save.
	if saved != 2 {
		t.Errorf("saved %d cookies, want the two the readable URL had", saved)
	}
}

func TestBatchSavesNothingForAProxyItCouldNotBuild(t *testing.T) {
	// A typo in the proxy column means no client was ever made for it, so there
	// is no jar to write down and the rest of the run is still saved.
	fakeClock(t)
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "warm.json")
	list := writeList(t, "typo.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/set,::not a proxy::\n%[1]s/set,\n", server.URL))

	code, _, stderr := exec(t, "batch", "-k", "--input", list, "--save-cookies", path,
		"--progress", "never", "--repeat", "0", "-o", os.DevNull)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	file, _ := cookie.Load(data)
	if len(file.Sets) != 1 {
		t.Errorf("%d sets, want the one the working client warmed", len(file.Sets))
	}
}

func TestCookiesTxtRoundTrip(t *testing.T) {
	// The Netscape cookie file is the one format everything agrees on: curl
	// writes it with -c and reads it with -b, and so do wget, yt-dlp and every
	// browser extension that offers an export. A session handed over as one of
	// these has to survive the trip out and back.
	fakeClock(t)
	server := cookieEcho(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "jar.txt")

	// Out: a run warms a session and writes it down.
	if code, _, stderr := exec(t, "fetch", "-k", "--save-cookies", path,
		server.URL+"/set"); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	// Seven tab-separated fields, and the HttpOnly one marked the way curl
	// marks it: a prefix that reads like a comment and is not one.
	var rows int
	for _, line := range strings.Split(strings.TrimSpace(string(written)), "\n") {
		if strings.HasPrefix(line, "# ") || line == "" {
			continue
		}
		rows++
		if got := len(strings.Split(line, "\t")); got != 7 {
			t.Errorf("%d fields in %q", got, line)
		}
	}
	if rows != 2 {
		t.Errorf("%d cookies written:\n%s", rows, written)
	}
	if !strings.Contains(string(written), "#HttpOnly_") {
		t.Errorf("the HttpOnly cookie was not marked:\n%s", written)
	}

	// Back in: the same run reads its own file and sends what it warmed.
	_, stdout, stderr := exec(t, "fetch", "-k", "--cookies", path, server.URL+"/")
	if !strings.Contains(stdout, "visitor=42") || !strings.Contains(stdout, "tier=gold") {
		t.Errorf("sent %q\n%s", stdout, stderr)
	}
}

func TestCookiesTxtIsReplacedRatherThanAddedTo(t *testing.T) {
	// A cookies.txt is a jar written down: one session, replaced. The JSON
	// format holds sets and is added to. Each behaves the way its own format
	// means, and the file's name is what says which.
	fakeClock(t)
	server := cookieEcho(t)
	dir := t.TempDir()

	txt, jsonPath := filepath.Join(dir, "jar.txt"), filepath.Join(dir, "jar.json")
	for range 2 {
		exec(t, "fetch", "-k", "--save-cookies", txt, server.URL+"/set")
		exec(t, "fetch", "-k", "--save-cookies", jsonPath, server.URL+"/set")
	}

	data, _ := os.ReadFile(txt)
	file, err := cookie.Load(data)
	if err != nil {
		t.Fatalf("loading the cookies.txt: %v", err)
	}
	if len(file.Sets) != 1 || len(file.Sets[0].Cookies) != 2 {
		t.Errorf("the cookies.txt grew: %+v", file.Sets)
	}

	data, _ = os.ReadFile(jsonPath)
	asJSON, err := cookie.Load(data)
	if err != nil {
		t.Fatalf("loading the json: %v", err)
	}
	if len(asJSON.Sets) != 2 {
		t.Errorf("%d sets in the json after two runs", len(asJSON.Sets))
	}
}

func TestCookiesTxtIsNotSentToAnotherSite(t *testing.T) {
	// A session warmed for one site is not handed to another, whatever else is
	// in the file.
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "mixed.txt")
	body := "# Netscape HTTP Cookie File\n" +
		".other-site.example\tTRUE\t/\tFALSE\t0\tleak\tshould-not-be-sent\n" +
		hostnameOf(t, server.URL) + "\tFALSE\t/\tFALSE\t0\tmine\tok\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	_, stdout, _ := exec(t, "fetch", "-k", "--cookies", path, server.URL+"/")
	if strings.Contains(stdout, "leak") {
		t.Errorf("another site's cookie was sent: %q", stdout)
	}
	if !strings.Contains(stdout, "mine=ok") {
		t.Errorf("this site's cookie was not sent: %q", stdout)
	}
}
