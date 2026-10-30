package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// countingService stands in for the address services a run asks where it
// comes out, and counts how often it was asked.
func countingService(t *testing.T) *atomic.Int32 {
	t.Helper()
	var asked atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","country":"PL"}`))
	}))
	t.Cleanup(service.Close)
	original := ipServices
	ipServices = []addressService{{URL: service.URL, read: readJSON}}
	t.Cleanup(func() { ipServices = original })
	return &asked
}

// countingSite is a page that counts what was asked of it, path by path.
func countingSite(t *testing.T, header http.Header) (*httptest.Server, func(path string) int32) {
	t.Helper()
	var page, trace atomic.Int32
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, values := range header {
			w.Header()[name] = values
		}
		if r.URL.Path == "/cdn-cgi/trace" {
			trace.Add(1)
			_, _ = w.Write([]byte("ip=198.51.100.1\nloc=NL\n"))
			return
		}
		page.Add(1)
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(site.Close)
	return site, func(path string) int32 {
		if path == "/cdn-cgi/trace" {
			return trace.Load()
		}
		return page.Load()
	}
}

func TestNoExitLookupAsksNoAddressService(t *testing.T) {
	// A run that goes one way asks an address service where it comes out,
	// once, before its first request: unless told not to.
	asked := countingService(t)
	site, seen := countingSite(t, nil)
	report := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--no-exit-lookup", "--insecure", "--report="+report,
		"--report-format", "json", site.URL+"/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if asked.Load() != 0 || seen("/page") != 1 {
		t.Errorf("the service was asked %d times, the page %d", asked.Load(), seen("/page"))
	}
	if !strings.Contains(stderr, "exit-ip     not looked up · not requested (enable with --exit-lookup)") {
		t.Errorf("stderr:\n%s", stderr)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	if r := doc.Requests[0]; r.Exit != nil || r.ExitError != errNotAsked.Error() {
		t.Errorf("the request came out of %+v, %q", r.Exit, r.ExitError)
	}

	// With the opt-in, it is asked.
	if code, _, stderr := exec(t, "fetch", "--exit-lookup", "--insecure", site.URL+"/page"); code != 0 || asked.Load() != 1 {
		t.Errorf("without the flag: exit %d, asked %d\n%s", code, asked.Load(), stderr)
	}
}

func TestNoExitLookupProbesNoSite(t *testing.T) {
	// Through a proxy that says nothing, a site behind Cloudflare is asked
	// where the request came from: unless told not to, and then nothing is
	// asked, of the site or of an address service through the proxy.
	asked := countingService(t)
	site, seen := countingSite(t, http.Header{"Cf-Ray": {"8f1c0d9e2b4a7f8e-AMS"}})
	via := startProxy(t)
	tmp := t.TempDir()
	report, trace := filepath.Join(tmp, "run.json"), filepath.Join(tmp, "run.trace.json")

	code, _, stderr := exec(t, "fetch", "--no-exit-lookup", "--proxy", "http://"+via.addr, "--insecure",
		"--trace", trace, "--report="+report, "--report-format", "json", site.URL+"/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if seen("/cdn-cgi/trace") != 0 || asked.Load() != 0 || seen("/page") != 1 {
		t.Errorf("the site was probed %d times, the service asked %d, the page %d", seen("/cdn-cgi/trace"),
			asked.Load(), seen("/page"))
	}
	if probed := named(traceFile(t, trace), phaseInstant, "exit-probe"); len(probed) != 0 {
		t.Errorf("a probe was traced: %+v", probed)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	if r := doc.Requests[0]; r.Exit != nil || r.ExitError != "the proxy did not say" {
		t.Errorf("the request came out of %+v, %q", r.Exit, r.ExitError)
	}

	// With the opt-in, the site is probed for a run that says
	// where its requests came out.
	if code, _, stderr := exec(t, "fetch", "--exit-lookup", "--proxy", "http://"+via.addr, "--insecure", "--report="+report,
		"--report-format", "json", site.URL+"/page"); code != 0 || seen("/cdn-cgi/trace") != 1 {
		t.Errorf("without the flag: exit %d, probed %d\n%s", code, seen("/cdn-cgi/trace"), stderr)
	}
}

func TestNoExitLookupResolvesNoName(t *testing.T) {
	// A proxy that names its exit by a hash, and a file that says how to ask
	// its service for the address behind the name: not asked, and the name is
	// what is known.
	via := startProxySaying(t, func(int) string { return "x-brd-ip: r693f1c0d9e2b4a7f8e09ed8c00000001\r\n" })
	var answered atomic.Int32
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		answered.Add(1)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.77"}`))
	}))
	t.Cleanup(service.Close)
	site := tlsPathServer(t)
	tmp := t.TempDir()
	file := filepath.Join(tmp, "exit-headers.json")
	if err := os.WriteFile(file, []byte(`{"fields": [{"header": "x-brd-ip", "resolve": {
		"user": "{user}-ip-{value}", "url": "`+service.URL+`/myip.json", "format": "json", "ip": "ip"}}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	report := filepath.Join(tmp, "run.json")
	code, _, stderr := exec(t, "fetch", "--no-exit-lookup", "--proxy", "http://user:pw@"+via.addr, "--insecure",
		"--exit-headers", file, "--report="+report, "--report-format", "json", site.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	if r := doc.Requests[0]; r.Exit == nil || r.Exit.IP != "" || r.Exit.Hash != "r693f1c0d9e2b4a7f8e09ed8c00000001" {
		t.Errorf("the request came out of %+v", r.Exit)
	}
	if answered.Load() != 0 {
		t.Errorf("the proxy's service was asked %d times", answered.Load())
	}
}

func TestNoExitLookupStillReadsWhatTheProxySays(t *testing.T) {
	// What the proxy says when it opens the tunnel is not asked for: it is
	// read, with or without the flag, and is where the request came out.
	via := startProxySaying(t, func(int) string { return "X-Exit-IP: 203.0.113.9\r\n" })
	asked := countingService(t)
	site := tlsPathServer(t)
	report := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--no-exit-lookup", "--proxy", "http://"+via.addr, "--insecure",
		"--report="+report, "--report-format", "json", site.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	if r := doc.Requests[0]; r.Exit == nil || r.Exit.IP != "203.0.113.9" || asked.Load() != 0 {
		t.Errorf("the request came out of %+v; the service asked %d times", r.Exit, asked.Load())
	}
}

func TestNoExitLookupOnAListThatGoesSeveralWays(t *testing.T) {
	// Several proxies: no address service is asked before the run, flag or not,
	// and with it no site is probed either.
	asked := countingService(t)
	site, seen := countingSite(t, http.Header{"Cf-Ray": {"8f1c0d9e2b4a7f8e-AMS"}})
	first, second := startProxy(t), startProxy(t)
	list := filepath.Join(t.TempDir(), "urls.json")
	if err := os.WriteFile(list, []byte(`[{"url": "`+site.URL+`/a", "proxy": "http://`+first.addr+`"},
		{"url": "`+site.URL+`/b", "proxy": "http://`+second.addr+`"}]`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	report := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--no-exit-lookup", "--insecure", "--input", list, "--report="+report,
		"--report-format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if seen("/cdn-cgi/trace") != 0 || asked.Load() != 0 || seen("/page") != 2 {
		t.Errorf("probed %d, asked %d, pages %d", seen("/cdn-cgi/trace"), asked.Load(), seen("/page"))
	}
}
