package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/cookie"
)

// cookieEcho reports the Cookie header it was sent, and sets two of its own,
// so both directions can be checked without a network.
func cookieEcho(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hop" {
			// To the same server under another name, which is another host to a
			// jar: what it sets there is not the asked-for host's.
			_, port, _ := net.SplitHostPort(r.Host)
			http.Redirect(w, r, "https://localhost:"+port+"/set", http.StatusFound)
			return
		}
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

func TestCookieSetRequiresACookieFile(t *testing.T) {
	code, _, stderr := exec(t, "fetch", "--cookie-set", "warm-eu", "https://example.com/")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "--cookie-set requires --cookies") {
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

func TestFetchReportsTheSameRandomSetItUses(t *testing.T) {
	original := pickCookieSet
	t.Cleanup(func() { pickCookieSet = original })

	// Find a seed whose first two draws differ. Before the selection was shared
	// between the client and its diagnostic, fetch drew twice and therefore said
	// it used the other set for exactly such a seed.
	var seed int64
	for {
		probe := rand.New(rand.NewSource(seed))
		if probe.Intn(2) != probe.Intn(2) {
			break
		}
		seed++
	}
	pickCookieSet = rand.New(rand.NewSource(seed))

	server := cookieEcho(t)
	host := hostnameOf(t, server.URL)
	path := writeCookieFile(t, `{"sets":[
	  {"id":"a","cookies":[{"name":"s","value":"a","domain":"`+host+`","path":"/"}]},
	  {"id":"b","cookies":[{"name":"s","value":"b","domain":"`+host+`","path":"/"}]}
	]}`)

	code, stdout, stderr := exec(t, "fetch", "-k", "--cookies", path, server.URL+"/")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	reported := ""
	for _, id := range []string{"a", "b"} {
		if strings.Contains(stderr, "set "+id) {
			reported = id
		}
	}
	if reported == "" {
		t.Fatalf("stderr does not name a set: %q", stderr)
	}
	if !strings.Contains(stdout, "s="+reported) {
		t.Errorf("reported set %s but sent %q", reported, stdout)
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

func TestClientFlagsReportCookieFileErrors(t *testing.T) {
	fs := newFlagSet("daemon", newPrinter(io.Discard))
	flags := addDaemonFlags(fs)
	missing := filepath.Join(t.TempDir(), "missing.json")
	if err := parse(fs, []string{"--cookies", missing}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := flags.client(); err == nil || !strings.Contains(err.Error(), "missing.json") {
		t.Fatalf("client error = %v, want missing file", err)
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
	if err := os.WriteFile(path, []byte(`{"sets":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 && runtime.GOOS != "windows" {
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
	code, _, stderr := exec(t, "fetch", "-k", "--save-cookies",
		filepath.Join(t.TempDir(), "no-such-directory", "warm.json"), server.URL+"/set")
	if code == 0 {
		t.Error("an unsaved session reported success")
	}
	if !strings.Contains(stderr, "tlsforge:") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestFetchDoesNotOverwriteACorruptSessionFile(t *testing.T) {
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "warm.json")
	original := []byte(`{"sets":[`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := exec(t, "fetch", "-k", "--save-cookies", path, server.URL+"/set")
	if code == 0 {
		t.Fatal("a corrupt existing session file reported success")
	}
	if !strings.Contains(stderr, "reading existing sessions") {
		t.Errorf("stderr = %q", stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Errorf("corrupt file was overwritten with %q", data)
	}
}

func TestSessionFileReportsAReadErrorOtherThanNotExist(t *testing.T) {
	_, err := sessionFile(t.TempDir(), cookie.Set{ID: "new"})
	if err == nil || !strings.Contains(err.Error(), "reading existing sessions") {
		t.Fatalf("error = %v", err)
	}
}

func TestListWarmsEveryRequest(t *testing.T) {
	// A list is given the session too, and one warmed session is
	// one client's, which is the identity it was warmed for.
	server := cookieEcho(t)
	_, stdout, stderr := exec(t, "fetch", "-k", "-b", "session=abc", "--progress", "never",
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

func TestListSavesOneSessionPerProxy(t *testing.T) {
	// A jar is an identity, so two exits' sessions never share a set. The same
	// URL twice is one host, asked once.
	fakeClock(t)
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "warm.json")

	list := writeList(t, "mixed.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/set,\n%[1]s/set,\n%[1]s/set,http://127.0.0.1:9001\n", server.URL))

	code, _, stderr := exec(t, "fetch", "-k", "--input", list, "--save-cookies", path,
		"--progress", "never", "--retry", "0", "--timeout", "5s")
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

func TestListReportsASessionItCannotWrite(t *testing.T) {
	server := cookieEcho(t)
	code, _, stderr := exec(t, "fetch", "-k", "--save-cookies",
		filepath.Join(t.TempDir(), "no-such-directory", "w.json"),
		"--progress", "never", server.URL+"/set")
	if code == 0 {
		t.Error("a run whose session could not be saved reported success")
	}
	if !strings.Contains(stderr, "tlsforge:") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestSaveSessionWritesTheWholeJar(t *testing.T) {
	// Every cookie the jar holds, whoever set it: the host a redirect led to as
	// well as the one asked for, which is often where a login lives. Each with
	// its scope, and a session cookie without an expiry, as the server set it.
	fakeClock(t)
	server := cookieEcho(t)
	fs := newFlagSet("fetch", newPrinter(io.Discard))
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
	if _, err := client.Get(server.URL + "/hop"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	saved, err := flags.saveSession(client, "")
	if err != nil || saved != 2 {
		t.Fatalf("saveSession = %d, %v; want the two cookies the redirect's host set", saved, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	file, err := cookie.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, c := range file.Sets[0].Cookies {
		if c.Domain != "localhost" || !c.HostOnly || !c.Expires.IsZero() {
			t.Errorf("cookie %s: domain %q, host only %v, expires %v; want localhost's alone, for the session",
				c.Name, c.Domain, c.HostOnly, c.Expires)
		}
	}
}

func TestListSavesNothingForAProxyItCouldNotBuild(t *testing.T) {
	// A typo in the proxy column means no client was ever made for it, so there
	// is no jar to write down and the rest of the run is still saved.
	fakeClock(t)
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "warm.json")
	list := writeList(t, "typo.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/set,::not a proxy::\n%[1]s/set,\n", server.URL))

	code, _, stderr := exec(t, "fetch", "-k", "--input", list, "--save-cookies", path,
		"--progress", "never", "--retry", "0")
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

func TestAnOlderCookieFileSaysWhatItDidNotKeep(t *testing.T) {
	// A version 1 file did not keep which cookies were their host's alone, so
	// each is sent to its domain's subdomains too, as it was then: the run says
	// so rather than widen a cookie's reach without a word.
	server := cookieEcho(t)
	file := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"sets":[{"id":"a","cookies":[`+
		`{"name":"s","value":"1","domain":"`+hostnameOf(t, server.URL)+`"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := exec(t, "fetch", "-k", "--cookies", file, server.URL+"/")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "written before tls-forge kept which cookies are their host's alone") {
		t.Errorf("the run did not say the file kept no scope:\n%s", stderr)
	}

	current := filepath.Join(t.TempDir(), "current.json")
	if err := os.WriteFile(current, []byte(`{"version":2,"sets":[{"id":"a","cookies":[`+
		`{"name":"s","value":"1","domain":"`+hostnameOf(t, server.URL)+`","host_only":true}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, stderr = exec(t, "fetch", "-k", "--cookies", current, server.URL+"/")
	if strings.Contains(stderr, "written before") {
		t.Errorf("a current file was said to keep no scope:\n%s", stderr)
	}
}

func TestANetscapeFileIsRefusedForARunWithMoreThanOneSession(t *testing.T) {
	// One session per proxy, and a cookies.txt holds one: each would replace
	// the last, and the count would say all were kept. Refused before anything
	// is asked of anybody, and the file is left as it was.
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	kept := filepath.Join(dir, "session.txt")
	if err := os.WriteFile(kept, []byte("# a session somebody kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		list string
		save string
	}{
		{"two proxies", "url,proxy\n%[1]s/,http://127.0.0.1:1\n%[1]s/,http://127.0.0.2:1\n", kept},
		{"a proxy and none", "url,proxy\n%[1]s/,http://127.0.0.1:1\n%[1]s/,\n", kept},
		{"a name in capitals", "url,proxy\n%[1]s/,http://127.0.0.1:1\n%[1]s/,\n", filepath.Join(dir, "OTHER.TXT")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := writeList(t, "list.csv", fmt.Sprintf(tc.list, server.URL))
			code, _, stderr := exec(t, "fetch", "-k", "--input", list, "--save-cookies", tc.save)
			if code != 2 || !strings.Contains(stderr, "is a Netscape cookie file, which holds one session") ||
				!strings.Contains(stderr, ".json") {
				t.Errorf("exit code %d, stderr %q; want a usage error that names .json", code, stderr)
			}
		})
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("the server was asked %d times; nothing should have been fetched", got)
	}
	if data, _ := os.ReadFile(kept); string(data) != "# a session somebody kept\n" {
		t.Errorf("the file was changed: %q", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "OTHER.TXT")); err == nil {
		t.Error("a file was written for a run that was refused")
	}

	// One session, whichever way: a cookies.txt is what it is for.
	list := writeList(t, "one.csv", fmt.Sprintf("url,proxy\n%[1]s/,\n%[1]s/,\n", server.URL))
	if code, _, stderr := exec(t, "fetch", "-k", "--input", list, "--save-cookies", kept); code != 0 {
		t.Errorf("a run of one session: exit code %d\n%s", code, stderr)
	}
}

func TestNetscapeFile(t *testing.T) {
	for path, want := range map[string]bool{
		"cookies.txt": true, "COOKIES.TXT": true, "dir.txt/cookies.json": false,
		"cookies.json": false, "cookies": false, "": false, "txt": false,
	} {
		if got := netscapeFile(path); got != want {
			t.Errorf("netscapeFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestASessionThatCannotBeWrittenLeavesTheFileAsItWas(t *testing.T) {
	// The encoder used to write an empty document for a date it could not hold,
	// and the file of sessions it was added to was replaced with a newline.
	path := filepath.Join(t.TempDir(), "warm.json")
	good := `{"version":2,"sets":[{"id":"kept","cookies":[{"name":"s","value":"1"}]}]}` + "\n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	set := cookie.Set{ID: "new", Cookies: []cookie.Cookie{
		{Name: "far", Value: "1", Expires: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}}
	data, err := sessionFile(path, set)
	if err == nil || data != nil || !strings.Contains(err.Error(), "writing the session to "+path) {
		t.Fatalf("sessionFile = %q, %v; want an error and nothing to write", data, err)
	}
	if got, _ := os.ReadFile(path); string(got) != good {
		t.Errorf("the file of sessions was changed: %q", got)
	}
}
