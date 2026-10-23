package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v7"
	"github.com/Sec-CH-Lemon/tls-forge/v7/echo"
)

// rotatingProxy hands every tunnel an address of its own, and says which.
func rotatingProxy(t *testing.T) *recordingProxy {
	t.Helper()
	return startProxySaying(t, func(n int) string { return fmt.Sprintf("X-Exit-IP: 203.0.113.%d\r\n", n) })
}

func TestEveryRequestThroughAProxyGoesOutOnATunnelOfItsOwn(t *testing.T) {
	// In front of a site that speaks HTTP/2, which would carry every request
	// over one connection, in turn or at once, were it let to.
	via := rotatingProxy(t)
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("page"))
	}))
	site.EnableHTTP2 = true
	site.StartTLS()
	t.Cleanup(site.Close)

	for _, workers := range []string{"1", "3"} {
		t.Run(workers+" at a time", func(t *testing.T) {
			before := len(via.seen())
			path := filepath.Join(t.TempDir(), "run.json")
			code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--repeat", "3",
				"-c", workers, "--report="+path, "--report-format", "json", site.URL+"/page")
			if code != 0 {
				t.Fatalf("exit code = %d\n%s", code, stderr)
			}
			doc := decoded(t, []byte(reportOf(t, path)))
			exits := map[string]bool{}
			for _, r := range doc.Requests {
				if len(r.Tries) != 1 || r.Tries[0].Connection == nil || r.Exit == nil {
					t.Fatalf("a request was kept as %+v", r)
				}
				if conn := r.Tries[0].Connection; conn.Reused || conn.ALPN != "h2" || conn.Exit == nil || conn.Exit.IP != r.Exit.IP {
					t.Errorf("a request went out on %+v and came out of %+v", conn, r.Exit)
				}
				exits[r.Exit.IP] = true
			}
			if len(exits) != 3 {
				t.Errorf("three requests came out of %v", exits)
			}
			// The question before the run, and a tunnel for each request.
			if opened := len(via.seen()) - before; opened != 4 {
				t.Errorf("the proxy opened %d tunnels, want 4", opened)
			}
		})
	}
}

func TestEveryTryThroughAProxyGoesOutOnATunnelOfItsOwn(t *testing.T) {
	// Turned away once, from wherever the first try came: the second comes from
	// somewhere else, as a try again through a rotating proxy is made to.
	via := rotatingProxy(t)
	var asked atomic.Int32
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if asked.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(site.Close)
	path := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--retry", "1",
		"--report="+path, "--report-format", "json", site.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	r := decoded(t, []byte(reportOf(t, path))).Requests[0]
	if len(r.Tries) != 2 || r.Tries[0].Connection == nil || r.Tries[1].Connection == nil {
		t.Fatalf("the request was kept as %+v", r)
	}
	first, second := r.Tries[0].Connection, r.Tries[1].Connection
	if first.Reused || second.Reused || first.Exit == nil || second.Exit == nil || first.Exit.IP == second.Exit.IP {
		t.Errorf("the tries went out on %+v and %+v", first, second)
	}
	// Where the request came out is where its last try did.
	if r.Exit == nil || second.Exit == nil || r.Exit.IP != second.Exit.IP {
		t.Errorf("the request came out of %+v, its last try of %+v", r.Exit, second.Exit)
	}
}

func TestEveryRequestWithoutAProxyGoesOutOnAConnectionOfItsOwn(t *testing.T) {
	// Every repeat and every URL, from the machine's own address as well.
	site := tlsPathServer(t)
	list := writeList(t, "two.txt", site.URL+"/a\n"+site.URL+"/b\n")
	path := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--insecure", "--input", list, "--repeat", "2", "-c", "1",
		"--report="+path, "--report-format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	for _, r := range decoded(t, []byte(reportOf(t, path))).Requests {
		if len(r.Tries) != 1 || r.Tries[0].Connection == nil || r.Tries[0].Connection.Reused {
			t.Errorf("%s went out on %+v", r.URL, r.Tries)
		}
	}
}

func TestReuseConnectionKeepsAURLsConnection(t *testing.T) {
	// Each URL keeps the tunnel its first request opened, for its repeats and
	// its tries, and the other URL has one of its own.
	via := rotatingProxy(t)
	var asked atomic.Int32
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The first request to /b is turned away, so it is tried again.
		if r.URL.Path == "/b" && asked.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(site.Close)
	list := writeList(t, "two.txt", site.URL+"/a\n"+site.URL+"/b\n")
	path := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--input", list,
		"--repeat", "2", "--retry", "1", "--reuse-connection", "-c", "1", "--report="+path, "--report-format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	exits := map[string][]string{}
	var reused []bool
	for _, r := range decoded(t, []byte(reportOf(t, path))).Requests {
		for _, try := range r.Tries {
			if try.Connection == nil || try.Connection.Exit == nil {
				t.Fatalf("%s was tried on %+v", r.URL, try.Connection)
			}
			exits[r.URL] = append(exits[r.URL], try.Connection.Exit.IP)
			reused = append(reused, try.Connection.Reused)
		}
	}
	a, b := exits[site.URL+"/a"], exits[site.URL+"/b"]
	// /a twice, and /b three times, its first turned away: one tunnel each.
	if len(a) != 2 || len(b) != 3 || a[0] != a[1] || b[0] != b[1] || b[1] != b[2] || a[0] == b[0] {
		t.Errorf("/a came out of %v and /b of %v", a, b)
	}
	if want := []bool{false, false, true, true, true}; !slices.Equal(reused, want) {
		t.Errorf("the tries reused their connection: %v, want %v", reused, want)
	}
	// The question before the run, and a tunnel for each URL.
	if opened := len(via.seen()); opened != 3 {
		t.Errorf("the proxy opened %d tunnels, want 3", opened)
	}
}

func TestReuseConnectionAsksTheSiteOverTheURLsConnection(t *testing.T) {
	// A proxy that says nothing, in front of a site behind Cloudflare: every
	// repeat is asked about over the connection the URL kept, which the site
	// numbers as its first.
	site := cloudflareSite(t)
	via := startProxy(t)
	path := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--repeat", "2",
		"--reuse-connection", "--report="+path, "--report-format", "json", site.URL+"/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	for _, r := range decoded(t, []byte(reportOf(t, path))).Requests {
		if r.Exit == nil || r.Exit.IP != "198.51.100.1" {
			t.Errorf("a repeat came out of %+v (%q)", r.Exit, r.ExitError)
		}
	}
}

func TestHeldClients(t *testing.T) {
	site := tlsPathServer(t)
	session, err := tlsforge.New(tlsforge.WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	works := func(client *tlsforge.Client) bool {
		_, err := client.Get(site.URL)
		return err == nil
	}

	// A URL's client is the same for every repeat, and another URL's another.
	held := newHeldClients(2)
	first, err := held.of(0, session)
	if err != nil {
		t.Fatalf("of: %v", err)
	}
	if again, _ := held.of(0, session); again != first {
		t.Error("a URL was handed a second client")
	}
	if other, _ := held.of(1, session); other == first {
		t.Error("two URLs were handed one client")
	}
	// Open until the last of its repeats is over, and closed after.
	held.done(0)
	if !works(first) {
		t.Error("a URL's client was closed before its last repeat")
	}
	held.done(0)
	if works(first) {
		t.Error("a URL's client was left open after its last repeat")
	}
	// Once more is nothing to let go of, and neither is a URL never asked for.
	held.done(0)
	held.done(7)

	// What a run that ended early left held is closed with it.
	left, _ := held.of(1, session)
	held.closeAll()
	if works(left) {
		t.Error("closeAll left a client open")
	}
	(*heldClients)(nil).closeAll()

	// A session that is closed makes no client.
	closed, err := tlsforge.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = closed.Close()
	if _, err := newHeldClients(1).of(0, closed); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a client of a closed session: %v", err)
	}
}

func TestRequestsResumeTheSessionTheirSiteHandedOut(t *testing.T) {
	// A site that hands out session tickets, as most do: every repeat is a
	// connection of its own, and every one after the first resumes the session
	// the one before was handed, as a browser's new connection does.
	server, err := echo.Start(echo.WithSessionTickets(true))
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	path := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--insecure", "--repeat", "3", "-c", "1",
		"--report="+path, "--report-format", "json", server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	var reused, resumed []bool
	for _, r := range decoded(t, []byte(reportOf(t, path))).Requests {
		if len(r.Tries) != 1 || r.Tries[0].Connection == nil {
			t.Fatalf("a request was kept as %+v", r)
		}
		reused = append(reused, r.Tries[0].Connection.Reused)
		resumed = append(resumed, r.Tries[0].Connection.Resumed)
	}
	if !slices.Equal(reused, []bool{false, false, false}) || !slices.Equal(resumed, []bool{false, true, true}) {
		t.Errorf("the three went out reused %v and resumed %v", reused, resumed)
	}
}

func TestRequestsAndTheirTriesThroughAProxyResume(t *testing.T) {
	// Through a proxy, as without one: every try is a tunnel of its own, and
	// every one after the first resumes the session the one before was handed,
	// the try made again after a 503 among them.
	via := startProxy(t)
	var asked atomic.Int32
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if asked.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(site.Close)
	path := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--repeat", "2", "--retry", "1",
		"-c", "1", "--report="+path, "--report-format", "json", site.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	var reused, resumed []bool
	for _, r := range decoded(t, []byte(reportOf(t, path))).Requests {
		for _, try := range r.Tries {
			if try.Connection == nil {
				t.Fatalf("a try of %s went out on nothing", r.URL)
			}
			reused = append(reused, try.Connection.Reused)
			resumed = append(resumed, try.Connection.Resumed)
		}
	}
	// The first run's two tries, the 503 and the page, and the second run's one.
	if !slices.Equal(reused, []bool{false, false, false}) || !slices.Equal(resumed, []bool{false, true, true}) {
		t.Errorf("the tries went out reused %v and resumed %v", reused, resumed)
	}
	tunnels := 0
	for _, target := range via.seen() {
		if target == strings.TrimPrefix(site.URL, "https://") {
			tunnels++
		}
	}
	if tunnels != 3 {
		t.Errorf("the proxy opened %d tunnels to the site, want one for each of the 3 tries", tunnels)
	}
}

func TestWorkerClients(t *testing.T) {
	session, err := tlsforge.New(tlsforge.WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	// One client for each proxy, the same every time it is asked for.
	own := newWorkerClients()
	direct, err := own.of("", session)
	if err != nil {
		t.Fatalf("of: %v", err)
	}
	if again, _ := own.of("", session); again != direct {
		t.Error("a worker was handed a second client for one proxy")
	}
	if proxied, _ := own.of("http://127.0.0.1:1", session); proxied == direct {
		t.Error("two proxies were handed one client")
	}
	// Closed with the worker.
	own.close()
	if _, err := direct.Get("https://127.0.0.1:1/"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a worker's client after the worker was done: %v", err)
	}

	// A session that is closed makes no client.
	closed, err := tlsforge.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = closed.Close()
	if _, err := newWorkerClients().of("", closed); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a client of a closed session: %v", err)
	}
}

func TestConnectionsOfAClosedSession(t *testing.T) {
	// A session closed under a try: the try fails as a try does, saying why,
	// and there is no connection of it to ask anything over, whether the URL
	// keeps its connection or not.
	session, err := tlsforge.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = session.Close()
	for _, conns := range []*connections{{session: session, own: newWorkerClients()}, {session: session, held: newHeldClients(1)}} {
		if _, err := conns.do(&tlsforge.Request{URL: "https://127.0.0.1:1/"}); err == nil || !strings.Contains(err.Error(), "closed") {
			t.Errorf("a try through a closed session: %v", err)
		}
		if conns.current() != session {
			t.Error("a try that never went out left a client of its own behind")
		}
		conns.close()
	}
}
