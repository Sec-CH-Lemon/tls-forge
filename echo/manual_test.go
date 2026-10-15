package echo

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

const visitorAgent = "Mozilla/5.0 (Test) Visitor/1.0"

// openPage opens the capture page as a person does, typing the address into a new
// tab: with the fields a browser sends then, changed or taken out by extra (an
// empty value takes one out).
func openPage(t *testing.T, client *http.Client, url string, extra ...[2]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	for _, field := range [][2]string{
		{"User-Agent", visitorAgent}, {"Sec-Fetch-Site", "none"}, {"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Dest", "document"}, {"Sec-Fetch-User", "?1"},
	} {
		req.Header.Set(field[0], field[1])
	}
	for _, field := range extra {
		if field[1] == "" {
			req.Header.Del(field[0])
			continue
		}
		req.Header.Set(field[0], field[1])
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	return res, string(body)
}

// measured opens the page as a person does, and reports what JavaScript
// would, which completes the capture.
func collect(t *testing.T, client *http.Client, server *Server, page string) *capture.Capture {
	t.Helper()
	const marker = "/collect?navigation="
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatalf("the page does not report back:\n%s", page)
	}
	end := strings.IndexByte(page[start:], '\'')
	res, err := client.Post(server.URL()+page[start:start+end], "application/json",
		strings.NewReader(`{"user_agent":"`+visitorAgent+`"}`))
	if err != nil {
		t.Fatalf("POST /collect: %v", err)
	}
	res.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := server.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	return session.Capture(capture.SourceBrowser)
}

func TestManualFirstVisitOnlyShowsWhatToDoNext(t *testing.T) {
	server := startServer(t, WithManual(true))
	client := http2Client()

	_, page := openPage(t, client, server.URL()+"/")
	if !strings.Contains(page, "accepted the certificate") || !strings.Contains(page, server.URL()+"/") ||
		strings.Contains(page, "/collect") {
		t.Fatalf("the first visit was shown:\n%s", page)
	}
	// The next visit, typed into a new tab, comes on a connection of its own,
	// and is the one measured: over HTTP/2 alone, with no trip to the HTTP/1.1
	// listener.
	_, page = openPage(t, client, server.URL()+"/")
	if strings.Contains(page, server.CaptureURL()) {
		t.Error("a visiting browser was sent to the HTTP/1.1 listener")
	}
	measured := collect(t, client, server, page)
	if len(server.Sessions()) < 2 {
		t.Errorf("the measured visit came on the connection the first one did: %d sessions", len(server.Sessions()))
	}
	if measured.HTTP2 == nil || measured.HTTP1 != nil || measured.UserAgent() != visitorAgent {
		t.Fatalf("measured %+v", measured)
	}
	for _, field := range measured.HTTP2.Headers {
		if field.Name == "sec-fetch-site" && field.Value != "none" {
			t.Errorf("the measured visit is not the typed one: %+v", measured.HTTP2.Headers)
		}
	}
}

func TestManualVisitThatIsNotOpenedFromTheAddressBar(t *testing.T) {
	server := startServer(t, WithManual(true))
	client := http2Client()
	openPage(t, client, server.URL()+"/")

	for _, tc := range []struct {
		name  string
		extra [][2]string
		says  string
	}{
		{"a reload", [][2]string{{"Cache-Control", "max-age=0"}}, "it was a reload"},
		{"a hard reload", [][2]string{{"Pragma", "no-cache"}}, "it was a reload"},
		{"a link", [][2]string{{"Sec-Fetch-Site", "same-origin"}}, "it came from a link"},
		{"a link from an older browser", [][2]string{{"Sec-Fetch-Site", ""}, {"Referer", "https://example.test/"}},
			"it came from a link"},
		{"a fetch", [][2]string{{"Sec-Fetch-Mode", "cors"}}, "it was not a page being opened"},
		{"an image", [][2]string{{"Sec-Fetch-Dest", "image"}}, "it was not a page being opened"},
	} {
		_, page := openPage(t, client, server.URL()+"/", tc.extra...)
		if !strings.Contains(page, "That visit was not measured: "+tc.says) {
			t.Errorf("%s was shown:\n%s", tc.name, page)
		}
	}

	// A browser that sends no Sec-Fetch-* is not held to them.
	_, page := openPage(t, client, server.URL()+"/",
		[2]string{"Sec-Fetch-Site", ""}, [2]string{"Sec-Fetch-Mode", ""}, [2]string{"Sec-Fetch-Dest", ""},
		[2]string{"Sec-Fetch-User", ""})
	if !strings.Contains(page, "/collect?navigation=") {
		t.Fatalf("a visit without Sec-Fetch-* was shown:\n%s", page)
	}
	// And the page it is measured with keeps its connection, which a second
	// visit on it then cannot be measured on.
	_, page = openPage(t, client, server.URL()+"/")
	if !strings.Contains(page, "it came on a connection that had already carried another") {
		t.Errorf("a second visit on one connection was shown:\n%s", page)
	}

	// None of them completed a capture.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := server.Await(ctx); err == nil {
		t.Error("a visit that was turned away completed a capture")
	}
}

func TestManualVisitorsAreToldApart(t *testing.T) {
	// Another browser on the same machine has a certificate warning of its own
	// to get past, and so a first visit of its own.
	server := startServer(t, WithManual(true))
	client := http2Client()
	openPage(t, client, server.URL()+"/")
	_, page := openPage(t, client, server.URL()+"/", [2]string{"User-Agent", "Mozilla/5.0 (Test) Other/2.0"})
	if !strings.Contains(page, "accepted the certificate") {
		t.Errorf("another browser's first visit was shown:\n%s", page)
	}
	if got := visitorOf(&Session{remote: "pipe"}, &request{headers: map[string]string{"user-agent": "x"}}); got != "pipe\nx" {
		t.Errorf("visitorOf an address with no port = %q", got)
	}
}

func TestManualVisitOverHTTP1(t *testing.T) {
	// A browser that keeps to HTTP/1.1 has its connection closed by saying so.
	server := startServer(t, WithManual(true))
	client := http1Client()
	res, page := openPage(t, client, server.URL()+"/")
	if !res.Close || !strings.Contains(page, "accepted the certificate") {
		t.Errorf("the first visit over HTTP/1.1 kept its connection:\n%s", page)
	}
	res, page = openPage(t, client, server.URL()+"/")
	if res.Close || !strings.Contains(page, "/collect?navigation=") {
		t.Errorf("the measured visit over HTTP/1.1 closed its connection:\n%s", page)
	}
	res, _ = openPage(t, client, server.URL()+"/favicon.ico")
	if res.StatusCode != http.StatusNotFound || !res.Close {
		t.Errorf("an answer outside a measurement: %d, closing %v", res.StatusCode, res.Close)
	}
}

func TestManualConnectionTakesNoStreamAfterItsLast(t *testing.T) {
	// Once the first visit is answered, the connection takes no new stream: one
	// is refused, which a client makes again on a connection of its own.
	server := startServer(t, WithManual(true))
	c := dialH2(t, server)
	if err := c.framer.WriteSettings(); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	page := func(stream uint32) {
		c.headers(t, stream, true,
			[2]string{":method", "GET"}, [2]string{":authority", "localhost"},
			[2]string{":scheme", "https"}, [2]string{":path", "/"}, [2]string{"user-agent", visitorAgent})
	}
	page(1)
	goAway := c.readUntil(t, func(f http2.Frame) bool { _, ok := f.(*http2.GoAwayFrame); return ok }).(*http2.GoAwayFrame)
	if goAway.LastStreamID != 1 || goAway.ErrCode != http2.ErrCodeNo {
		t.Errorf("GOAWAY = %+v", goAway)
	}
	page(3)
	refused := c.readUntil(t, func(f http2.Frame) bool { _, ok := f.(*http2.RSTStreamFrame); return ok }).(*http2.RSTStreamFrame)
	if refused.StreamID != 3 || refused.ErrCode != http2.ErrCodeRefusedStream {
		t.Errorf("RST_STREAM = %+v", refused)
	}
}

func TestNotFresh(t *testing.T) {
	typed := map[string]string{
		"sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-user": "?1",
	}
	with := func(name, value string) map[string]string {
		out := map[string]string{}
		for k, v := range typed {
			out[k] = v
		}
		out[name] = value
		return out
	}
	for _, tc := range []struct {
		headers map[string]string
		want    string
	}{
		{typed, ""},
		{map[string]string{}, ""},
		{with("cache-control", "max-age=0"), "it was a reload"},
		{with("pragma", "no-cache"), "it was a reload"},
		{with("referer", "https://example.test/"), "it came from a link, not from the address bar"},
		{with("sec-fetch-site", "cross-site"), "it came from a link, not from the address bar"},
		{with("sec-fetch-site", ""), "it came from a link, not from the address bar"},
		{with("sec-fetch-mode", "no-cors"), "it was not a page being opened"},
		{with("sec-fetch-dest", "iframe"), "it was not a page being opened"},
		// Sec-Fetch-User is not asked for: not every browser sends it.
		{with("sec-fetch-user", "?0"), ""},
	} {
		if got := notFresh(tc.headers); got != tc.want {
			t.Errorf("notFresh(%v) = %q, want %q", tc.headers, got, tc.want)
		}
	}
}

// answerWatcher is a connection that notes whether a capture had already been
// handed over when a response was written to it.
type answerWatcher struct {
	net.Conn
	server *Server
	early  atomic.Bool
}

func (w *answerWatcher) Write(p []byte) (int, error) {
	w.server.mu.Lock()
	if len(w.server.completed) > 0 {
		w.early.Store(true)
	}
	w.server.mu.Unlock()
	return w.Conn.Write(p)
}

func TestCollectIsAnsweredBeforeTheCaptureIsHandedOver(t *testing.T) {
	// Whoever waits may close the server the moment it hears; the page that
	// reported back is to hear first, over either protocol.
	for _, protocol := range []string{"HTTP/2", "HTTP/1.1"} {
		server := startServer(t)
		sess := &Session{remote: "test"}
		token, err := server.setNavigation(sess, "")
		if err != nil {
			t.Fatalf("setNavigation: %v", err)
		}
		ours, theirs := net.Pipe()
		watcher := &answerWatcher{Conn: ours, server: server}
		go func() { _, _ = io.Copy(io.Discard, theirs) }()
		path := "/collect?navigation=" + token
		if protocol == "HTTP/2" {
			req := &request{method: "POST", path: path, stream: 1, body: []byte(`{}`), headers: map[string]string{}}
			if err := server.respond(newH2Conn(watcher), sess, req); err != nil {
				t.Fatalf("respond: %v", err)
			}
		} else {
			go func() {
				_, _ = io.WriteString(theirs, "POST "+path+" HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
			}()
			go func() { _ = server.serveHTTP1(watcher, sess) }()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := server.Await(ctx); err != nil {
			t.Fatalf("%s: Await: %v", protocol, err)
		}
		cancel()
		if watcher.early.Load() {
			t.Errorf("%s: the capture was handed over before the page was answered", protocol)
		}
		_ = ours.Close()
		_ = theirs.Close()
	}
}
