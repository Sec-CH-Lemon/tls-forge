package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
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

func TestRequestsWithoutAProxyKeepTheirConnection(t *testing.T) {
	// From the machine's own address a new handshake for every request is what
	// a browser does not do, so the second goes where the first went.
	site := tlsPathServer(t)
	path := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--insecure", "--repeat", "2", "--report="+path, "--report-format", "json",
		site.URL+"/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, path)))
	var reused []bool
	for _, r := range doc.Requests {
		if len(r.Tries) != 1 || r.Tries[0].Connection == nil {
			t.Fatalf("a request was kept as %+v", r)
		}
		reused = append(reused, r.Tries[0].Connection.Reused)
	}
	if len(reused) != 2 || reused[0] || !reused[1] {
		t.Errorf("the two requests reused their connection: %v, want false and then true", reused)
	}
}

func TestConnectionsOfAClosedSession(t *testing.T) {
	// A session closed under a try: the try fails as a try does, saying why,
	// and there is no connection of it to ask anything over.
	session, err := tlsforge.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = session.Close()
	conns := &connections{session: session, fresh: true}
	if _, err := conns.do(&tlsforge.Request{URL: "https://127.0.0.1:1/"}); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a try through a closed session: %v", err)
	}
	if conns.current() != session {
		t.Error("a try that never went out left a client of its own behind")
	}
	conns.close()
}
