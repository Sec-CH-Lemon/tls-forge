package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testURLCases are URL cases a urlBrowser goes through as Chrome went
// through the measured ones.
var testURLCases = map[string]urlCase{
	"plain":   {note: "a URL", input: "https://www.example.com:{P}/p/plain?q"},
	"default": {note: "on 443, said", input: "https://www.example.com:443/p/default"},
	"bad":     {note: "one the page cannot read", input: "https://www.example.com:{P}/p/%zz"},
	"none":    {note: "one nothing is sent for", input: "ftp://www.example.com/"},
	"located": {note: "a Location", input: "/p/located", redirect: true},
}

// urlBrowser is a browser that does what a URL case's run page says: it goes
// to the case's URL, or to the 302 that says it, and on; it tells /urlthrown/
// of a URL it cannot read, as the page's script does when Chrome throws. Told
// the bench's ports, it takes www.example.com on 443, 80 and plainPorts to
// them, as defaultPorts has Chrome do.
type urlBrowser struct {
	tls, plain int
	fail       bool
	// h2only goes no further than a run page that came over HTTP/1.1.
	h2only bool
}

func (b urlBrowser) defaultPorts(tls, plain int) Browser {
	b.tls, b.plain = tls, plain
	return b
}

func (b urlBrowser) Open(_ context.Context, page, _ string) (func(), error) {
	if b.fail {
		return nil, errors.New("the fake would not open " + page)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c := b.client()
		script, proto := readAll(c, page)
		if b.h2only && proto != 2 {
			return
		}
		origin, id := page[:strings.Index(page, "/urlrun/")], page[strings.LastIndex(page, "/")+1:]
		if at := strings.Index(script, "encodeURIComponent("); at >= 0 {
			_, _ = readAll(c, origin+"/r/302/"+id+"?to="+url.QueryEscape(jsonString(script[at+len("encodeURIComponent("):])))
			return
		}
		input := jsonString(script[strings.Index(script, "location.href=")+len("location.href="):])
		if _, err := url.Parse(input); err != nil {
			_, _ = readAll(c, origin+"/urlthrown/"+id)
			return
		}
		_, _ = readAll(c, input)
	}()
	return func() { <-done }, nil
}

func (b urlBrowser) DumpDOM(context.Context, string) ([]byte, error) { return nil, nil }

// client is how b asks: the loopback address for every name, www.example.com
// on the ports the bench was told of taken to its own.
func (b urlBrowser) client() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			switch n, _ := strconv.Atoi(port); {
			case b.tls != 0 && n == 443:
				port = strconv.Itoa(b.tls)
			case b.plain != 0 && (n == 80 || slices.Contains(plainPorts, n)):
				port = strconv.Itoa(b.plain)
			}
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the bench's own certificate
		ForceAttemptHTTP2: true,
	}}
}

// readAll is the body of the answer for page and the major version of the
// protocol it came in, or nothing.
func readAll(c *http.Client, page string) (string, int) {
	res, err := c.Get(page)
	if err != nil {
		return "", 0
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return string(body), res.ProtoMajor
}

// jsonString is the JSON string text begins with.
func jsonString(text string) string {
	var s string
	_ = json.NewDecoder(strings.NewReader(text)).Decode(&s)
	return s
}

// quickURLs has a URL case settle as long as a test can wait.
func quickURLs(t *testing.T) {
	t.Helper()
	old := urlSettle
	urlSettle = 300 * time.Millisecond
	t.Cleanup(func() { urlSettle = old })
}

func TestURLCasesAreMeasuredOverEachProtocol(t *testing.T) {
	quickURLs(t)
	var progress bytes.Buffer
	got, err := measureURLs(context.Background(), urlBrowser{}, testURLCases, nil, quick, &progress)
	if err != nil {
		t.Fatalf("measureURLs: %v", err)
	}
	sent := func(target string) SentURL {
		return SentURL{SNI: "www.example.com", Scheme: "https", Authority: "www.example.com", Target: target}
	}
	for id, want := range map[string]SentURL{
		"plain":   sent("/p/plain?q"),
		"default": {SNI: "www.example.com", Scheme: "https", Authority: "www.example.com:443", Target: "/p/default"},
		"bad":     {Refused: refusedThrown},
		"none":    {Refused: refusedBlocked},
		"located": sent("/p/located"),
	} {
		c := got[id]
		if c.H2 != want || c.H1 != want || c.Note != testURLCases[id].note || c.Input != testURLCases[id].input ||
			c.Redirect != testURLCases[id].redirect {
			t.Errorf("%s: measured %+v, want %v", id, c, want)
		}
	}
	if len(got) != len(testURLCases) || !strings.Contains(progress.String(), "h2 plain: https www.example.com/p/plain?q") ||
		!strings.Contains(progress.String(), "h1 bad: thrown\n") {
		t.Errorf("measured %d, said %q", len(got), progress.String())
	}
	// Each protocol's run is its own.
	if got, err := measureURLs(context.Background(), urlBrowser{h2only: true}, testURLCases, []string{"plain"}, quick, nil); err != nil ||
		got["plain"].H2 != sent("/p/plain?q") || got["plain"].H1 != (SentURL{Refused: refusedBlocked}) {
		t.Errorf("HTTP/2 alone: %+v, %v", got, err)
	}
	// A browser that cannot be told the bench's ports goes where the URL
	// says, which a case on the bench's own port is.
	if got, err := measureURLs(context.Background(), noPorts{}, testURLCases, []string{"plain"}, quick, nil); err != nil ||
		len(got) != 1 || got["plain"].H2 != sent("/p/plain?q") {
		t.Errorf("without its ports: %+v, %v", got, err)
	}
}

// noPorts is a urlBrowser that cannot be told the bench's ports.
type noPorts struct{ b urlBrowser }

func (n noPorts) Open(ctx context.Context, page, dir string) (func(), error) {
	return n.b.Open(ctx, page, dir)
}

func (n noPorts) DumpDOM(ctx context.Context, page string) ([]byte, error) {
	return n.b.DumpDOM(ctx, page)
}

func TestAURLMeasurementSaysWhyItIsNone(t *testing.T) {
	quickURLs(t)
	if _, err := MeasureURLs(context.Background(), urlBrowser{}, []string{"none"}, nil); err == nil ||
		!strings.Contains(err.Error(), "there is no scenario none") {
		t.Errorf("an unknown case: %v", err)
	}
	if _, err := measureURLs(context.Background(), urlBrowser{fail: true}, testURLCases, []string{"plain"}, quick, nil); err == nil ||
		!strings.HasPrefix(err.Error(), "harness: plain over h2: the fake would not open https://www.example.com:") {
		t.Errorf("a browser that does not open: %v", err)
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := measureURLs(context.Background(), urlBrowser{}, testURLCases, nil, quick, nil); !errors.Is(err, failing) {
		t.Errorf("measured with no server: %v", err)
	}
}

func TestARunPageGoesToItsURLOrToThe302ThatSaysIt(t *testing.T) {
	s := started(t, urlScenarios(testURLCases), withURLs(testURLCases))
	o := origins(s.H2, s.Plain)
	for id, want := range map[string]string{
		"plain":   `try{location.href="https://www.example.com:` + strconv.Itoa(s.H2) + `/p/plain?q"}catch(e){fetch('/urlthrown/plain')}`,
		"located": `location.href='/r/302/located?to='+encodeURIComponent("/p/located")`,
	} {
		res, body := get(t, http.MethodGet, o["A"]+"/urlrun/"+id, nil)
		if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/html; charset=utf-8" ||
			body != "<!doctype html><title>url</title><script>"+want+"</script>" {
			t.Errorf("%s: %d %q", id, res.StatusCode, body)
		}
	}
	if res, _ := get(t, http.MethodGet, o["A"]+"/urlrun/nothing", nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("a case there is none of: %d", res.StatusCode)
	}
	if res, _ := get(t, http.MethodGet, o["A"]+"/urlthrown/plain", nil); res.StatusCode != http.StatusNoContent {
		t.Errorf("a script that threw: %d", res.StatusCode)
	}
	if scenarios := urlScenarios(testURLCases); scenarios["plain"] != (scenario{note: "a URL", start: "{A}/urlrun/{ID}",
		wait: "/never", settle: urlSettle}) {
		t.Errorf("the scenario of a URL case is %+v", scenarios["plain"])
	}
}

func TestWhatWentOutForAURLCaseIsWhatCameAfterItsRunPage(t *testing.T) {
	s := &Server{H2: 8443, H1: 8444, Plain: 8080}
	entry := func(target, sni string) Entry { return Entry{Target: target, SNI: sni} }
	run := entry("https://www.example.com:8443/urlrun/x", "www.example.com")
	page := entry("https://www.example.com:8443/p/x?q", "www.example.com")
	for _, tc := range []struct {
		name     string
		entries  []Entry
		redirect bool
		want     SentURL
	}{
		{"no run page", []Entry{page}, false, SentURL{Refused: refusedBlocked}},
		{"nothing after it", []Entry{run}, false, SentURL{Refused: refusedBlocked}},
		{"a favicon alone", []Entry{run, entry("https://www.example.com:8443/favicon.ico", "")}, false,
			SentURL{Refused: refusedBlocked}},
		{"a script that threw", []Entry{run, entry("https://www.example.com:8443/urlthrown/x", "")}, false,
			SentURL{Refused: refusedThrown}},
		{"the page", []Entry{entry("https://www.example.com:8443/p/before", ""), run, page}, false,
			SentURL{SNI: "www.example.com", Scheme: "https", Authority: "www.example.com", Target: "/p/x?q"}},
		{"after its 302", []Entry{run, entry("https://www.example.com:8443/r/302/x?to=y", ""), page}, true,
			SentURL{SNI: "www.example.com", Scheme: "https", Authority: "www.example.com", Target: "/p/x?q"}},
		{"its 302, when it is no Location's", []Entry{run, entry("https://www.example.com:8443/r/302/x", ""), page}, false,
			SentURL{Scheme: "https", Authority: "www.example.com", Target: "/r/302/x"}},
		{"a host alone", []Entry{run, entry("http://127.0.0.1:8080", "")}, false,
			SentURL{Scheme: "http", Authority: "127.0.0.1"}},
		{"another port", []Entry{run, entry("http://www.example.com:6679/p/x", "")}, false,
			SentURL{Scheme: "http", Authority: "www.example.com:6679", Target: "/p/x"}},
	} {
		if got := s.sent(tc.entries, "x", tc.redirect); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := (SentURL{SNI: "a.example", Scheme: "https", Authority: "a.example", Target: "/b"}).String(); got != `https a.example/b (sni "a.example")` {
		t.Errorf("String() = %q", got)
	}
	if got := (SentURL{Refused: refusedThrown}).String(); got != "thrown" {
		t.Errorf("String() = %q", got)
	}
}

func TestWhatURLCasesDifferInIsSaid(t *testing.T) {
	sent := SentURL{Scheme: "https", Authority: "a.example", Target: "/"}
	want := map[string]URLCase{"same": {H2: sent, H1: sent}, "other": {H2: sent, H1: sent}, "gone": {H2: sent, H1: sent}}
	got := map[string]URLCase{"same": {H2: sent, H1: sent}, "other": {H2: sent, H1: SentURL{Refused: refusedBlocked}},
		"new": {H2: sent, H1: sent}}
	diff := CompareURLs(want, got)
	if !slices.Equal(diff, []string{
		"gone was not measured",
		"other over h1: blocked, want https a.example/ (sni \"\")",
		"new was measured, and the fixture has no such case",
	}) {
		t.Errorf("CompareURLs = %q", diff)
	}
	if diff := CompareURLs(want, want); diff != nil {
		t.Errorf("the same: %q", diff)
	}
}

func TestAFixtureOfURLsIsWrittenAsItIsKept(t *testing.T) {
	// The committed fixture reads, and writes back byte for byte.
	kept, err := os.ReadFile("../../testdata/chrome155-urls.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fixture, err := LoadURLs("../../testdata/chrome155-urls.json")
	if err != nil {
		t.Fatalf("LoadURLs: %v", err)
	}
	path := filepath.Join(t.TempDir(), "urls.json")
	if err := fixture.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if wrote, _ := os.ReadFile(path); !bytes.Equal(wrote, kept) {
		t.Errorf("wrote it otherwise:\n%s", wrote)
	}
	// Every case of the catalogue is measured, and nothing else.
	for id := range urlCatalogue {
		if _, ok := fixture.Cases[id]; !ok {
			t.Errorf("the fixture has no case %s", id)
		}
	}
	for id, c := range fixture.Cases {
		if want, ok := urlCatalogue[id]; !ok || c.Note != want.note || c.Input != want.input || c.Redirect != want.redirect {
			t.Errorf("the fixture's %s is %+v, the catalogue's %+v", id, c, want)
		}
	}
}

func TestAURLServerIsSentToAsChromeWas(t *testing.T) {
	quickURLs(t)
	u, err := StartURLServer()
	if err != nil {
		t.Fatalf("StartURLServer: %v", err)
	}
	t.Cleanup(func() { _ = u.Close() })
	tlsPort := map[string]string{"h2": strconv.Itoa(u.s.H2), "h1": strconv.Itoa(u.s.H1)}
	plain := strconv.Itoa(u.s.Plain)
	for _, proto := range []string{"h2", "h1"} {
		if got, err := u.URL("url-host-upper", proto); err != nil || got != "https://WWW.EXAMPLE.COM:"+tlsPort[proto]+"/p/url-host-upper" {
			t.Errorf("URL(url-host-upper, %s) = %q, %v", proto, got, err)
		}
		if got, err := u.URL("url-redirect-space", proto); err != nil ||
			got != "https://www.example.com:"+tlsPort[proto]+"/r/302/url-redirect-space?to=%2Fp%2Furl+redirect+space" {
			t.Errorf("URL(url-redirect-space, %s) = %q, %v", proto, got, err)
		}
		for addr, want := range map[string]string{
			"www.example.com:443":                       "127.0.0.1:" + tlsPort[proto],
			"www.example.com:80":                        "127.0.0.1:" + plain,
			"www.example.com:6679":                      "127.0.0.1:" + plain,
			"[::1]:" + plain:                            "127.0.0.1:" + plain,
			"xn--e1afmkfd.example.com:" + tlsPort["h2"]: "127.0.0.1:" + tlsPort["h2"],
		} {
			if got := u.Addr(addr, proto); got != want {
				t.Errorf("Addr(%s, %s) = %s, want %s", addr, proto, got, want)
			}
		}
	}
	if _, err := u.URL("nothing", "h2"); err == nil || err.Error() != `harness: no URL case "nothing"` {
		t.Errorf("a case there is none of: %v", err)
	}
	// What a client asked for is what went out for the case; reset, nothing
	// did.
	target, _ := u.URL("url-redirect-relative", "h1")
	if _, err := (urlBrowser{tls: u.s.H1, plain: u.s.Plain}).client().Get(target); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, err := u.Sent("url-redirect-relative"); err != nil ||
		got != (SentURL{SNI: "www.example.com", Scheme: "https", Authority: "www.example.com", Target: "/r/p/url-redirect-relative/y"}) {
		t.Errorf("Sent = %v, %v", got, err)
	}
	u.Reset()
	if got, err := u.Sent("url-redirect-relative"); err != nil || got.Refused != refusedBlocked {
		t.Errorf("Sent after Reset = %v, %v", got, err)
	}
	u.s.troubled(errors.New("unreadable"))
	if _, err := u.Sent("url-host-upper"); err == nil || err.Error() != "unreadable" {
		t.Errorf("Sent of what could not be read: %v", err)
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := StartURLServer(); !errors.Is(err, failing) {
		t.Errorf("a server with no port: %v", err)
	}
}

func TestChromeIsToldTheBenchsPortsForWhatAURLCaseNames(t *testing.T) {
	// www.example.com on 443, on 80 and on every other port a case names for
	// plain http, to the bench; the browser it was told by is as it was.
	chrome := Chrome{Path: "chrome"}
	told, ok := chrome.defaultPorts(1, 2).(Chrome)
	want := "MAP www.example.com:443 127.0.0.1:1, MAP www.example.com:80 127.0.0.1:2, " +
		"MAP www.example.com:4190 127.0.0.1:2, MAP www.example.com:6000 127.0.0.1:2, " +
		"MAP www.example.com:6679 127.0.0.1:2, MAP www.example.com:8080 127.0.0.1:2, "
	if !ok || told.rules != want || told.Path != "chrome" || chrome.rules != "" {
		t.Errorf("told %+v, was %+v", told, chrome)
	}
	if args := flags("d", "", told.rules); !slices.Contains(args, "--host-resolver-rules="+want+hostRules) {
		t.Errorf("flags %q", args)
	}
	for _, port := range plainPorts {
		if !strings.Contains(want, ":"+strconv.Itoa(port)+" ") {
			t.Errorf("port %d is not taken to the bench", port)
		}
	}
}
