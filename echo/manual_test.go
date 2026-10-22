package echo

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/Sec-CH-Lemon/tls-forge/v3/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v3/fingerprint"
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
	// Finished without the HTTP/1.1 visit, which a capture waits for.
	token := page[start+len(marker) : start+end]
	if status, _ := get(t, client, server.URL()+"/skip?navigation="+token); status != 200 {
		t.Fatalf("finishing: %d", status)
	}
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
	if !strings.Contains(page, "const http1Navigation = '';") ||
		!strings.Contains(page, "const http1Address = '"+server.CaptureURL()+"/';") {
		t.Error("a visiting browser was sent to the HTTP/1.1 listener, or not given its address to open")
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
	if got := visitorOf(&Session{remote: "pipe"}, map[string]string{"user-agent": "x"}); got != "pipe\nx" {
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
			h := newH2Conn(watcher)
			h.answered = server.completeAfter
			st := answering(h, 1, 65535)
			st.req.method, st.req.path, st.req.body = "POST", path, []byte(`{}`)
			if err := server.arrived(h, sess, st); err != nil {
				t.Fatalf("arrived: %v", err)
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

// pageSays is what the page says after marker, up to the end of a word.
func pageSays(t *testing.T, page, marker string) string {
	t.Helper()
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatalf("the page says no %q:\n%s", marker, page)
	}
	start += len(marker)
	end := strings.IndexAny(page[start:], "';")
	return page[start : start+end]
}

func TestManualPageSaysItsHelloOnConnectionsOfItsOwn(t *testing.T) {
	// After the visit measured, the page opens as many connections as it says,
	// the server ending each after its answer, then one given a ticket and one
	// that resumes it: their hellos are the navigation's, the resumed one
	// apart, and none of a connection that carried another request.
	server := startServer(t, WithManual(true))
	transport := http2Transport(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: tls.NewLRUClientSessionCache(8)})
	client := &http.Client{Transport: transport}
	openPage(t, client, server.URL()+"/")
	_, page := openPage(t, client, server.URL()+"/")
	hellos, err := strconv.Atoi(pageSays(t, page, "const hellos = "))
	if err != nil || hellos != manualHellos {
		t.Fatalf("the page asks for %d hellos, %v", hellos, err)
	}
	address := server.URL() + pageSays(t, page, "const hello = '")
	// Each on a connection of its own, as a browser opens one once the server
	// says it is going away: Go's transport may pick the old one up first.
	say := func(what string) int {
		status, _ := get(t, client, address+what)
		transport.CloseIdleConnections()
		return status
	}
	// On the measured visit's connection, which carried it: no hello filed.
	if status := say("&i=x"); status != 200 {
		t.Fatalf("a hello on the visit's connection: %d", status)
	}
	for i := range hellos {
		say("&i=" + strconv.Itoa(i))
	}
	say("&step=tickets")
	say("&i=" + strconv.Itoa(hellos))
	say("&step=resumed")
	if server.ticketsUntil.Load() != 0 {
		t.Error("tickets are still given after the page resumed one")
	}
	measured := collect(t, client, server, page)
	if len(measured.Connections) != hellos+2 || measured.ResumedClientHello == nil {
		t.Fatalf("%d hellos, resumed %d bytes", len(measured.Connections), len(measured.ResumedClientHello))
	}
	for i, raw := range append(measured.Connections, measured.ResumedClientHello) {
		hello, err := fingerprint.ParseClientHello(raw)
		if err != nil {
			t.Fatalf("hello %d: %v", i, err)
		}
		if _, resumed := hello.Extension(fingerprint.ExtPreSharedKey); resumed != (i == hellos+2) {
			t.Errorf("hello %d resumed: %v", i, resumed)
		}
	}
}

func TestManualHellosAreKeptWithinBounds(t *testing.T) {
	server := startServer(t, WithManual(true))
	transport := http2Transport(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: tls.NewLRUClientSessionCache(8)})
	client := &http.Client{Transport: transport}
	openPage(t, client, server.URL()+"/")
	_, page := openPage(t, client, server.URL()+"/")
	address := server.URL() + pageSays(t, page, "const hello = '")
	say := func(what string) {
		get(t, client, address+what)
		transport.CloseIdleConnections()
	}
	// No more than maxHellos, and a resumed hello the page does not say
	// resumes is none of them.
	for i := 0; i < maxHellos+3; i++ {
		say("&i=" + strconv.Itoa(i))
	}
	say("&step=tickets")
	say("&i=ticket")
	say("&i=resumes")
	t.Cleanup(func() { t.Logf("panics: %q", server.Panics()) })
	measured := collect(t, client, server, page)
	if len(measured.Connections) != maxHellos || measured.ResumedClientHello != nil {
		t.Fatalf("%d hellos, resumed %d bytes", len(measured.Connections), len(measured.ResumedClientHello))
	}
	// The report closed the tickets the page opened.
	if server.ticketsUntil.Load() != 0 {
		t.Error("tickets are still given after the report")
	}
	// A hello for no navigation, or one the server does not know, is refused;
	// a server that is no manual one has no such page.
	for _, path := range []string{"/hello", "/hello?navigation=nope"} {
		if status, _ := get(t, client, server.URL()+path); status != 400 {
			t.Errorf("%s: %d", path, status)
		}
	}
	if status, _ := get(t, http2Client(), startServer(t).URL()+"/hello?navigation=1"); status != 404 {
		t.Errorf("a launched browser's server: %d", status)
	}
	if page := string(launchedPage(t)); !strings.Contains(page, "const hellos = 0;") {
		t.Errorf("a launched browser is asked for hellos:\n%s", page)
	}
}

// launchedPage is the capture page a server for a launched browser serves.
func launchedPage(t *testing.T) []byte {
	t.Helper()
	server := startServer(t)
	_, page := get(t, http2Client(), server.URL()+"/?http1=done")
	return page
}

func TestManualTicketsAreGivenWhileTheyAreOpen(t *testing.T) {
	server := startServer(t, WithManual(true))
	given := func() bool {
		config, err := server.tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{})
		return err == nil && config == server.ticketed
	}
	if given() {
		t.Error("tickets given before a page asked")
	}
	server.ticketsUntil.Store(time.Now().Add(time.Minute).UnixNano())
	if !given() || server.ticketed.SessionTicketsDisabled {
		t.Error("tickets not given while open")
	}
	server.ticketsUntil.Store(time.Now().Add(-time.Second).UnixNano())
	if given() {
		t.Error("tickets given once their time passed")
	}
	// A key it cannot draw is a server it cannot start.
	old := readRandom
	readRandom = func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
	defer func() { readRandom = old }()
	if _, err := Start(WithManual(true)); err == nil || !strings.Contains(err.Error(), "a session ticket key") {
		t.Errorf("Start: %v", err)
	}
}

// report posts what the page's script would, and the capture waits for the
// HTTP/1.1 visit or a finish without it; the token the page was served with.
func report(t *testing.T, client *http.Client, server *Server, page string) string {
	t.Helper()
	const marker = "/collect?navigation="
	start := strings.Index(page, marker)
	end := strings.IndexByte(page[start:], '\'')
	// From the browser's page, whose user agent it is.
	req, err := http.NewRequest("POST", server.URL()+page[start:start+end],
		strings.NewReader(`{"user_agent":"`+visitorAgent+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", visitorAgent)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /collect: %v", err)
	}
	res.Body.Close()
	return page[start+len(marker) : start+end]
}

// waiting says the server holds no capture for a while.
func waiting(t *testing.T, server *Server) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := server.Await(ctx)
	return err != nil
}

func TestManualHTTP1VisitJoinsTheNavigationAndCompletesIt(t *testing.T) {
	server := startServer(t, WithManual(true))
	client, h1 := http2Client(), http1Client()
	// Before the browser's HTTP/2 visit, there is nothing to join: its first
	// visit here only gets it past the certificate, and the next is told.
	if _, page := openPage(t, h1, server.CaptureURL()+"/"); !strings.Contains(page, "accepted the certificate") ||
		!strings.Contains(page, server.CaptureURL()+"/") {
		t.Fatalf("the first HTTP/1.1 visit:\n%s", page)
	}
	if _, page := openPage(t, h1, server.CaptureURL()+"/"); !strings.Contains(page, "not been measured over HTTP/2 yet") {
		t.Fatalf("an HTTP/1.1 visit before the HTTP/2 one:\n%s", page)
	}
	openPage(t, client, server.URL()+"/")
	_, page := openPage(t, client, server.URL()+"/")
	report(t, client, server, page)
	if !waiting(t, server) {
		t.Fatal("the capture did not wait for the HTTP/1.1 visit")
	}
	// A reload is not the visit measured; the next typed one is, and completes.
	if _, page := openPage(t, h1, server.CaptureURL()+"/", [2]string{"Cache-Control", "max-age=0"}); !strings.Contains(page, "it was a reload") {
		t.Fatalf("a reload over HTTP/1.1:\n%s", page)
	}
	if _, page := openPage(t, h1, server.CaptureURL()+"/"); !strings.Contains(page, "measured, over HTTP/1.1 too") {
		t.Fatalf("the HTTP/1.1 visit:\n%s", page)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := server.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	measured := session.Capture(capture.SourceBrowser)
	if measured.HTTP2 == nil || measured.HTTP1 == nil || measured.HTTP1.Proto != "HTTP/1.1" {
		t.Fatalf("measured %+v", measured)
	}
	// Joined once: another visit there has nothing to join.
	if _, page := openPage(t, h1, server.CaptureURL()+"/"); !strings.Contains(page, "not been measured over HTTP/2 yet") {
		t.Errorf("a second HTTP/1.1 visit:\n%s", page)
	}
	// A browser trusted at the main listener has a first visit of its own at
	// this one: a browser may keep a certificate it took for one port alone.
	other := [2]string{"User-Agent", "Mozilla/5.0 (Test) Other/2.0"}
	openPage(t, client, server.URL()+"/", other)
	if _, page := openPage(t, h1, server.CaptureURL()+"/", other); !strings.Contains(page, "accepted the certificate") {
		t.Errorf("another browser's first HTTP/1.1 visit:\n%s", page)
	}
	// The library's own measurement of itself is answered there as before.
	if status, body := get(t, h1, server.CaptureURL()+"/api/all"); status != 200 || !strings.Contains(string(body), `"http1"`) {
		t.Errorf("/api/all over HTTP/1.1: %d %s", status, body)
	}
}

func TestManualCaptureFinishesWithoutHTTP1(t *testing.T) {
	server := startServer(t, WithManual(true))
	client, h1 := http2Client(), http1Client()
	openPage(t, client, server.URL()+"/")
	_, page := openPage(t, client, server.URL()+"/")
	if !strings.Contains(page, `href="/skip?navigation=`) {
		t.Fatalf("the page has no way to finish:\n%s", page)
	}
	token := report(t, client, server, page)
	if status, body := get(t, client, server.URL()+"/skip?navigation="+token); status != 200 ||
		!strings.Contains(string(body), "measured, over HTTP/2 alone") {
		t.Fatalf("finishing: %d %s", status, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := server.Await(ctx)
	if err != nil || session.Capture(capture.SourceBrowser).HTTP1 != nil {
		t.Fatalf("Await: %v", err)
	}
	// Nothing waits any more for an HTTP/1.1 visit to join.
	openPage(t, h1, server.CaptureURL()+"/")
	if _, page := openPage(t, h1, server.CaptureURL()+"/"); !strings.Contains(page, "not been measured over HTTP/2 yet") {
		t.Errorf("an HTTP/1.1 visit after finishing:\n%s", page)
	}
	// A finish for no navigation, or one the server does not know, is refused,
	// and a launched browser's server has no such page.
	for _, path := range []string{"/skip", "/skip?navigation=nope"} {
		if status, _ := get(t, client, server.URL()+path); status != 400 {
			t.Errorf("%s: %d", path, status)
		}
	}
	if status, _ := get(t, http2Client(), startServer(t).URL()+"/skip?navigation=1"); status != 404 {
		t.Errorf("a launched browser's server: %d", status)
	}
}

func TestManualCapturesWaitingAreKeptWithinBounds(t *testing.T) {
	limited(t, func(l *limits) { l.kept = 2 })
	server := startServer(t, WithManual(true))
	for _, visitor := range []string{"a", "b", "a", "c"} {
		server.awaitHTTP1(visitor, &Session{})
	}
	if len(server.awaiting) != 2 || server.awaiting["a"] == nil || server.awaiting["c"] == nil ||
		!slices.Equal(server.awaitingOrder, []string{"a", "c"}) {
		t.Errorf("waiting %v, in order %v", server.awaiting, server.awaitingOrder)
	}
}
