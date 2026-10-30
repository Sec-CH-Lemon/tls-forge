package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pit lets its first connection through to the server and holds every later
// one, taken and never answered: the handshake of a try after the first hangs.
type pit struct {
	net.Listener
	taken  atomic.Int32
	mu     sync.Mutex
	held   []net.Conn
	caught chan struct{}
}

func (p *pit) Accept() (net.Conn, error) {
	for {
		c, err := p.Listener.Accept()
		if err != nil || p.taken.Add(1) == 1 {
			return c, err
		}
		p.mu.Lock()
		p.held = append(p.held, c)
		p.mu.Unlock()
		p.caught <- struct{}{}
	}
}

// handshakePit serves HTTP/2 over TLS through a pit.
func handshakePit(t *testing.T) (*httptest.Server, *pit) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	p := &pit{Listener: server.Listener, caught: make(chan struct{}, 16)}
	server.Listener = p
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(func() {
		p.mu.Lock()
		for _, c := range p.held {
			_ = c.Close()
		}
		p.mu.Unlock()
		server.Close()
	})
	return server, p
}

func TestFetchEndsATryWhoseHandshakeHangsAtItsTimeout(t *testing.T) {
	// Every try goes out on a connection of its own: the second's handshake
	// the server never answers, and --timeout ends it.
	server, _ := handshakePit(t)
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	start := time.Now()
	go func() {
		done <- run(context.Background(), []string{"fetch", "--fresh-connection", "--insecure", "--concurrency", "1", "--progress", "never",
			"--timeout", "500ms", server.URL + "/a", server.URL + "/b"}, &stdout, &stderr)
	}()
	select {
	case code := <-done:
		said := `"error":"tlsforge: Get \"` + server.URL + `/b\": context deadline exceeded"`
		if code != 1 || !strings.Contains(stdout.String(), said) {
			t.Errorf("exit %d\n%s\n%s", code, stdout.String(), stderr.String())
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("the run took %v", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run had not ended 10s after a timeout of 500ms")
	}
}

func TestFetchStopsOnSIGTERMWhileAHandshakeHangs(t *testing.T) {
	// As at Ctrl-C: the try waiting for its connection is cancelled and said
	// to be, and the run ends with its report written.
	server, p := handshakePit(t)
	report := filepath.Join(t.TempDir(), "report.json")
	cmd := program(t, "fetch", "--fresh-connection", "--insecure", "--concurrency", "1", "--progress", "never", "--report="+report,
		server.URL+"/a", server.URL+"/b")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting: %v", err)
	}
	select {
	case <-p.caught:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the second try never dialed")
	}
	told(t, cmd)
	if status := ended(t, cmd, 10*time.Second); status.ExitStatus() != 1 {
		t.Errorf("exit status %v\n%s", status, stderr.String())
	}
	doc := decoded(t, []byte(reportOf(t, report)))
	if len(doc.Requests) != 2 || doc.Requests[0].Error != "" || !strings.Contains(doc.Requests[1].Error, "context canceled") {
		t.Errorf("the report: %+v", doc.Requests)
	}
}
