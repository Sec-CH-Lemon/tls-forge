package echo

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// browserFor is one simulated browser: its own connection, its own ClientHello.
//
// The TLS settings differ per browser so their JA4s differ, which is the whole
// point — a test where both look the same could not tell whose fingerprint came
// back.
func browserFor(t *testing.T, server *Server, maxVersion uint16) *http.Client {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         maxVersion,
		},
		// A connection of its own, never shared with the other browser.
		DisableKeepAlives: false,
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

// visit does what the capture page does: load it, then report the browser's own
// JS data back. It returns the capture the server answered /collect with.
func visit(t *testing.T, client *http.Client, base, userAgent string) map[string]any {
	t.Helper()
	collect := loadCapturePage(t, client, base)

	report := `{"user_agent":"` + userAgent + `","languages":["en-US"],"platform":"Test"}`
	return postReport(t, client, base+collect, report)
}

func loadCapturePage(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	res, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	page, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("reading /: %v", err)
	}
	const marker = "fetch('"
	start := strings.Index(string(page), marker)
	if start < 0 {
		t.Fatalf("capture page has no fetch endpoint: %s", page)
	}
	start += len(marker)
	end := strings.IndexByte(string(page[start:]), '\'')
	if end < 0 {
		t.Fatalf("capture page has an unterminated fetch endpoint: %s", page)
	}
	return string(page[start : start+end])
}

func postReport(t *testing.T, client *http.Client, endpoint, report string) map[string]any {
	t.Helper()
	res, err := client.Post(endpoint, "application/json", strings.NewReader(report))
	if err != nil {
		t.Fatalf("POST /collect: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading /collect: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding /collect: %v (%s)", err, body)
	}
	return out
}

func ja4Of(t *testing.T, capture map[string]any) string {
	t.Helper()
	tlsPart, ok := capture["tls"].(map[string]any)
	if !ok {
		t.Fatalf("capture has no tls section: %v", capture)
	}
	ja4, _ := tlsPart["ja4"].(string)
	if ja4 == "" {
		t.Fatalf("capture has no JA4: %v", tlsPart)
	}
	return ja4
}

// TestASecondBrowserGetsItsOwnFingerprint is the bug this file exists for.
//
// The server used to pin the first connection that fetched "/" and file every
// later report against it, so the second browser to open the page was handed
// the FIRST browser's ClientHello, JA4 and header order, labelled with its own
// user agent — while the first browser's session had its navigator overwritten
// with the second's. Both halves were wrong and neither was visible.
func TestASecondBrowserGetsItsOwnFingerprint(t *testing.T) {
	server, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Close() }()
	base := "https://" + server.Addr()

	first := visit(t, browserFor(t, server, tls.VersionTLS13), base, "browser-A")
	second := visit(t, browserFor(t, server, tls.VersionTLS12), base, "browser-B")

	firstJA4, secondJA4 := ja4Of(t, first), ja4Of(t, second)
	if firstJA4 == secondJA4 {
		t.Fatalf("both browsers reported the same JA4 (%s), so this test cannot "+
			"tell whose fingerprint came back", firstJA4)
	}

	// A TLS 1.2 client must not be told it negotiated TLS 1.3.
	if !strings.HasPrefix(secondJA4, "t12") {
		t.Errorf("the second browser was handed a JA4 that is not its own: %s "+
			"(the first browser's was %s)", secondJA4, firstJA4)
	}

	// And each capture carries the user agent of the browser it describes.
	for name, capture := range map[string]map[string]any{"first": first, "second": second} {
		nav, ok := capture["navigator"].(map[string]any)
		if !ok {
			t.Errorf("%s capture has no navigator", name)
			continue
		}
		want := map[string]string{"first": "browser-A", "second": "browser-B"}[name]
		if got, _ := nav["user_agent"].(string); got != want {
			t.Errorf("%s capture reports user_agent %q, want %q", name, got, want)
		}
	}
}

// TestOverlappingBrowsersAreMatchedByThePageToken covers the ordering the old
// "newest unreported navigation" heuristic could not distinguish: browser A
// loads, browser B loads, then A reports. A used to receive B's fingerprint.
func TestOverlappingBrowsersAreMatchedByThePageToken(t *testing.T) {
	server, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Close() }()
	base := "https://" + server.Addr()

	browserA := browserFor(t, server, tls.VersionTLS13)
	browserB := browserFor(t, server, tls.VersionTLS12)
	collectA := loadCapturePage(t, browserA, base)
	collectB := loadCapturePage(t, browserB, base)
	if collectA == collectB {
		t.Fatalf("both pages received the same collection endpoint %q", collectA)
	}

	gotA := postReport(t, browserFor(t, server, tls.VersionTLS12), base+collectA,
		`{"user_agent":"browser-A"}`)
	gotB := postReport(t, browserFor(t, server, tls.VersionTLS13), base+collectB,
		`{"user_agent":"browser-B"}`)

	if ja4 := ja4Of(t, gotA); !strings.HasPrefix(ja4, "t13") {
		t.Errorf("browser A received another navigation's JA4: %s", ja4)
	}
	if ja4 := ja4Of(t, gotB); !strings.HasPrefix(ja4, "t12") {
		t.Errorf("browser B received another navigation's JA4: %s", ja4)
	}
}

// TestAReloadIsNotASecondNavigation keeps the behaviour the old pinning got
// right: loading the page twice on one connection is one navigation, because
// the second load resumes a connection rather than making a cold handshake.
func TestAReloadIsNotASecondNavigation(t *testing.T) {
	server, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Close() }()

	client := browserFor(t, server, tls.VersionTLS13)
	base := "https://" + server.Addr()

	for range 3 {
		res, err := client.Get(base + "/")
		if err != nil {
			t.Fatalf("GET /: %v", err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}

	server.mu.Lock()
	navigations := len(server.navigations)
	server.mu.Unlock()
	if navigations != 1 {
		t.Errorf("%d navigations after three loads on one connection, want 1", navigations)
	}
}

// TestAReportOnAnotherConnectionFindsItsOwnNavigation covers the case the
// pinning was written for and got half right: the browser sends the XHR over a
// connection other than the one it loaded the page on.
//
// The report still belongs to the page load — a POST's header order is an
// XHR's, not a navigation's — but to THIS browser's page load, which is what
// claiming an unreported navigation gets right and pinning the first one did
// not.
func TestAReportOnAnotherConnectionFindsItsOwnNavigation(t *testing.T) {
	server, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Close() }()
	base := "https://" + server.Addr()

	// A new connection for every request, so /collect never lands on the
	// connection that fetched the page.
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	got := visit(t, client, base, "browser-C")

	// The capture describes the navigation's handshake, not the XHR's, and the
	// navigation was this browser's.
	if ja4 := ja4Of(t, got); !strings.HasPrefix(ja4, "t12") {
		t.Errorf("JA4 %s is not this browser's", ja4)
	}
	nav, ok := got["navigator"].(map[string]any)
	if !ok {
		t.Fatalf("capture has no navigator: %v", got)
	}
	if agent, _ := nav["user_agent"].(string); agent != "browser-C" {
		t.Errorf("user_agent = %q, want browser-C", agent)
	}

	server.mu.Lock()
	navigations := len(server.navigations)
	server.mu.Unlock()
	// The page load is the navigation; the XHR's connection is not adopted as a
	// second one.
	if navigations != 1 {
		t.Errorf("%d navigations, want 1", navigations)
	}
}
