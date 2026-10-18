package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// cloudflareSite answers as a site behind Cloudflare does: every response with
// cf-ray, and /cdn-cgi/trace with the address the connection came from. That
// address is made up, one for each connection the site is asked over, so that
// an answer can be told to have come over the same one or not.
func cloudflareSite(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	numbers := map[string]int{}
	var busy atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Ray", "8f1c0d9e2b4a7f8e-AMS")
		// Turned away the first time, for a request to be tried again.
		if r.URL.Query().Has("busy-once") && busy.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
			return
		}
		if r.URL.Path == "/cdn-cgi/trace" {
			mu.Lock()
			n := numbers[r.RemoteAddr]
			mu.Unlock()
			_, _ = fmt.Fprintf(w, "fl=1\nh=example.test\nip=198.51.100.%d\nts=1\nloc=NL\n", n)
			return
		}
		if r.URL.Query().Has("close") {
			w.Header().Set("Connection", "close")
		}
		_, _ = w.Write([]byte("page"))
	}))
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			numbers[conn.RemoteAddr().String()] = len(numbers) + 1
			mu.Unlock()
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestASiteSaysWhereARequestCameFromOverTheSameConnection(t *testing.T) {
	// A proxy that says nothing, in front of a site behind Cloudflare, which
	// says where a visitor comes from: asked over the connection the request
	// went out on, that is where the request came out.
	site := cloudflareSite(t)
	via := startProxy(t)
	tmp := t.TempDir()
	report, trace := filepath.Join(tmp, "run.json"), filepath.Join(tmp, "run.trace.json")
	runLog := filepath.Join(tmp, "run.jsonl")

	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--trace", trace,
		"--report="+report, "--report-format", "json", "--log", runLog, site.URL+"/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// The question is logged with the request it was asked for.
	if asked := recordsOf(logRecords(t, runLog), "request", "probe", "/cdn-cgi/trace", "req", "1"); len(asked) != 1 {
		t.Errorf("the probe was logged as %v", asked)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	want := documentExit{IP: "198.51.100.1", Country: "NL", By: "Cloudflare /cdn-cgi/trace, on the same connection"}
	if got := doc.Requests[0].Exit; got == nil || *got != want {
		t.Errorf("the request came out of %+v, want %+v", got, want)
	}
	if probed := named(traceFile(t, trace), phaseInstant, "exit-probe"); len(probed) != 1 || probed[0].Args["same_connection"] != true {
		t.Errorf("the probe was traced as %+v", probed)
	}

	// The site closed the connection, so the probe went over another, which
	// came out somewhere else for all anybody knows: it is not believed.
	code, _, stderr = exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--report="+report,
		"--report-format", "json", site.URL+"/page?close")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc = decoded(t, []byte(reportOf(t, report)))
	if got := doc.Requests[0]; got.Exit != nil || got.ExitError != "the proxy did not say" {
		t.Errorf("an answer over another connection was believed: %+v, %q", got.Exit, got.ExitError)
	}
}

func TestASiteARedirectWentToIsNotBelievedOverAnotherSitesConnections(t *testing.T) {
	// A redirect from 127.0.0.1 to localhost, another site: the hop goes out
	// on the connections of the first hop's site, and the site is asked over
	// those of its own, as a request with no browser context is, through
	// another tunnel. What it says is not believed.
	site := cloudflareSite(t)
	via := startProxy(t)
	report := filepath.Join(t.TempDir(), "run.json")
	other := strings.Replace(site.URL, "127.0.0.1", "localhost", 1)
	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--report="+report,
		"--report-format", "json", site.URL+"/hop?to="+other+"/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	if got := doc.Requests[0]; got.Exit != nil || got.ExitError != "the proxy did not say" {
		t.Errorf("an answer over another site's connections was believed: %+v, %q", got.Exit, got.ExitError)
	}
}

func TestASiteIsAskedOverTheConnectionOfTheLastTry(t *testing.T) {
	// The first try is turned away and the second is not, each through a
	// tunnel of its own: the site is asked over the second's, the second
	// connection it was asked over, which is where the request came out.
	site := cloudflareSite(t)
	via := startProxy(t)
	report := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--retry", "1",
		"--report="+report, "--report-format", "json", site.URL+"/page?busy-once")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	want := documentExit{IP: "198.51.100.2", Country: "NL", By: "Cloudflare /cdn-cgi/trace, on the same connection"}
	if got := doc.Requests[0]; got.Exit == nil || *got.Exit != want || len(got.Tries) != 2 {
		t.Errorf("the request came out of %+v after %d tries, want %+v after 2", got.Exit, len(got.Tries), want)
	}
}

func TestAProxysNameForAnExitIsResolved(t *testing.T) {
	// A proxy that names every tunnel's exit by a hash, and goes out through the
	// exit of a hash when the user name asks it to: its own service, asked that
	// way, says the address. Once for each name.
	var users []string
	var mu sync.Mutex
	via := startProxyHearing(t, func(int, []string) string { return "x-brd-ip: r693f1c0d9e2b4a7f8e09ed8c00000001\r\n" })
	via.heard = func(asked []string) {
		for _, line := range asked {
			if encoded, ok := strings.CutPrefix(line, "Proxy-Authorization: Basic "); ok {
				decoded, _ := base64.StdEncoding.DecodeString(encoded)
				user, _, _ := strings.Cut(string(decoded), ":")
				mu.Lock()
				users = append(users, user)
				mu.Unlock()
			}
		}
	}
	var answered atomic.Int32
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		answered.Add(1)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.77","country":"US","asn":{"asnum":7922}}`))
	}))
	t.Cleanup(service.Close)
	site := tlsPathServer(t)

	tmp := t.TempDir()
	file := filepath.Join(tmp, "exit-headers.json")
	if err := os.WriteFile(file, []byte(`{"fields": [{"header": "x-brd-ip", "resolve": {
		"user": "{user}-ip-{value}", "url": "`+service.URL+`/myip.json", "format": "json", "ip": "ip", "country": "country"}}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	report := filepath.Join(tmp, "run.json")
	code, _, stderr := exec(t, "fetch", "--repeat", "2", "--proxy", "http://user:pw@"+via.addr, "--insecure",
		"--exit-headers", file, "--report="+report, "--report-format", "json", site.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	want := documentExit{IP: "203.0.113.77", Hash: "r693f1c0d9e2b4a7f8e09ed8c00000001", Country: "US",
		By: strings.TrimPrefix(service.URL, "https://") + ", through the exit the proxy named"}
	for _, r := range doc.Requests {
		if r.Exit == nil || *r.Exit != want {
			t.Errorf("a request came out of %+v, want %+v", r.Exit, want)
		}
	}
	if got := answered.Load(); got != 1 {
		t.Errorf("the service was asked %d times, want once for the one name", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(users, "user-ip-r693f1c0d9e2b4a7f8e09ed8c00000001") {
		t.Errorf("the proxy was never asked for the exit by its name: %q", users)
	}
}

func TestExitReading(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reading exitReading
		body    string
		want    egress
	}{
		{"an object", exitReading{Format: "json", IP: "ip", Country: "country"},
			`{"ip":"203.0.113.77","country":"US"}`, egress{IP: "203.0.113.77", Country: "US"}},
		{"an object whose address is not text", exitReading{Format: "json", IP: "ip"}, `{"ip":7}`, egress{}},
		{"not an object", exitReading{Format: "json", IP: "ip"}, `<html>`, egress{}},
		{"lines", exitReading{Format: "lines", IP: "ip", Country: "loc"},
			"fl=1\nip=2001:DB8::1\nloc=NL\n", egress{IP: "2001:db8::1", Country: "NL"}},
		// Somebody else's text: an address or nothing.
		{"lines without one", exitReading{Format: "lines", IP: "ip"}, "ip=\x1b[2J\n", egress{}},
	} {
		if got := tc.reading.read([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestPinnedProxy(t *testing.T) {
	for _, tc := range []struct {
		proxy, value, want string
		ok                 bool
	}{
		{"http://user:pw@proxy.test:22225", "r1", "http://user-ip-r1:pw@proxy.test:22225", true},
		{"http://user@proxy.test", "r1", "http://user-ip-r1@proxy.test", true},
		// A user name and a password escaped as a URL holds them.
		{"http://us%40er:p%3Aw@proxy.test", "r1", "http://us%40er-ip-r1:p%3Aw@proxy.test", true},
		// Nothing to put a name in, and a name no user name can hold.
		{"://not a proxy", "r1", "", false},
		{"http://user:pw@proxy.test", "6f1c0d9e-2b4a:7f8e09ed", "", false},
	} {
		if got, ok := pinnedProxy(tc.proxy, "{user}-ip-{value}", tc.value); got != tc.want || ok != tc.ok {
			t.Errorf("pinnedProxy(%q, %q) = %q, %v, want %q, %v", tc.proxy, tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseExitTableWithProbesAndResolving(t *testing.T) {
	good := `{"fields": [{"header": "x-brd-ip", "resolve": {"user": "{user}-ip-{value}", "url": "https://brdtest.com/myip.json",
		"format": "json", "ip": "ip"}}], "probes": [{"when": "cf-ray", "path": "/cdn-cgi/trace", "format": "lines", "ip": "ip"}]}`
	if table, err := parseExitTable([]byte(good), "mine.json"); err != nil || len(table.Probes) != 1 ||
		table.Fields[0].Resolve == nil || table.Fields[0].Resolve.URL != "https://brdtest.com/myip.json" {
		t.Errorf("parsed %+v, %v", table, err)
	}
	for _, tc := range []struct{ name, file, want string }{
		{"a resolve that names nothing", `{"fields": [{"header": "x", "resolve": {"user": "{user}", "url": "https://a/",
			"format": "json", "ip": "ip"}}]}`, "field 1 resolves with a user that has {value} in it"},
		{"a resolve in a format nobody knows", `{"fields": [{"header": "x", "resolve": {"user": "{value}", "url": "https://a/",
			"format": "xml", "ip": "ip"}}]}`, "field 1 resolves with"},
		{"a probe of no path", `{"fields": [], "probes": [{"when": "cf-ray", "path": "cdn-cgi/trace", "format": "lines",
			"ip": "ip"}]}`, "probe 1 needs a field to come when, a path"},
	} {
		if _, err := parseExitTable([]byte(tc.file), "mine.json"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestAskingThatGoesNowhere(t *testing.T) {
	flags := insecureFlags(t)
	how := exitResolve{User: "{user}-ip-{value}", URL: "https://127.0.0.1:1/myip.json",
		exitReading: exitReading{Format: "json", IP: "ip"}}
	named := egress{Hash: "r1"}
	// A proxy that is not one, a proxy nobody answers at, and a service that
	// will not say: the name stays a name.
	for _, proxy := range []string{"://not a proxy", "http://" + deadAddr(t)} {
		if got := (&resolver{}).resolve(context.Background(), flags, proxy, named, how, nil); got != named {
			t.Errorf("through %q: %+v", proxy, got)
		}
	}
	// A name no user name can hold asks nobody: through the proxy as it is, the
	// answer would be another exit's.
	var asked atomic.Int32
	listening := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked.Add(1) }))
	t.Cleanup(listening.Close)
	colon := egress{Hash: "6f1c0d9e-2b4a:7f8e09ed"}
	through := "http://user:pw@" + listening.Listener.Addr().String()
	if got := (&resolver{}).resolve(context.Background(), flags, through, colon, how, nil); got != colon || asked.Load() != 0 {
		t.Errorf("a name with a colon: %+v, and the proxy was asked %d times", got, asked.Load())
	}
	refusing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(refusing.Close)
	if _, err := askThrough(context.Background(), flags, "", refusing.URL); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Errorf("a service that would not say: %v", err)
	}
	// Flags no client can be made with ask nobody, and say why.
	unmade, never := flags, time.Duration(0)
	unmade.timeout = &never
	if _, err := askThrough(context.Background(), unmade, "", refusing.URL); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("flags no client can be made with: %v", err)
	}

	// A probe of a site whose address will not parse, or that cannot be reached.
	client, err := flags.clientVia("")
	if err != nil {
		t.Fatalf("clientVia: %v", err)
	}
	defer func() { _ = client.Close() }()
	b := runner{exits: exitTable{Probes: []exitProbe{{When: "cf-ray", Path: "/cdn-cgi/trace",
		exitReading: exitReading{Format: "lines", IP: "ip"}}}}}
	cloudflare := map[string][]string{"cf-ray": {"1"}}
	for _, at := range []string{"::not a URL::", "https://" + deadAddr(t) + "/"} {
		if got := b.probe(context.Background(), client, &tlsforge.Response{URL: at, Header: cloudflare}, 7, nil, nil); got.Known() {
			t.Errorf("a probe of %q answered %+v", at, got)
		}
	}
}
