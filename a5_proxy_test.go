package tlsforge

import (
	"context"
	"crypto/x509"
	"errors"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestHTTP1HTTPSProxyForwardsConcurrently(t *testing.T) {
	entered := make(chan string, 4)
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	via := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || !r.URL.IsAbs() {
			t.Errorf("unexpected proxy request: %s %s", r.Proto, r.RequestURI)
		}
		entered <- r.URL.Path
		if r.URL.Path == "/hold" {
			<-release
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	}))
	via.StartTLS()
	t.Cleanup(via.Close)
	old := proxyRoots
	proxyRoots = x509.NewCertPool()
	proxyRoots.AddCert(via.Certificate())
	defer func() { proxyRoots = old }()
	c := newTestClient(t, WithProxy(via.URL), WithTimeout(3*time.Second))
	defer c.Close()
	done := make(chan error, 2)
	go func() { _, err := c.Get("http://origin.test/hold"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first proxy request never arrived")
	}
	go func() { _, err := c.Get("http://origin.test/next"); done <- err }()
	select {
	case path := <-entered:
		if path != "/next" {
			t.Errorf("unexpected %s", path)
		}
		t.Log("RESULT: second request arrived before first response")
	case <-time.After(500 * time.Millisecond):
		t.Error("RESULT: second request blocked by first proxy response")
	}
	finish()
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

type a5RoundTrip func(*fhttp.Request) (*fhttp.Response, error)

func (f a5RoundTrip) RoundTrip(req *fhttp.Request) (*fhttp.Response, error) { return f(req) }

func TestProxyDiscoveryEndsBeforeResponse(t *testing.T) {
	d := &connectDialer{proxyPool: newProxyH2Pool()}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	plain, other := net.Pipe()
	defer plain.Close()
	defer other.Close()
	fallback := a5RoundTrip(func(req *fhttp.Request) (*fhttp.Response, error) {
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: plain})
		}
		entered <- struct{}{}
		<-release
		return &fhttp.Response{StatusCode: 200, Body: fhttp.NoBody}, nil
	})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := fhttp.NewRequest("GET", "http://origin.test/", nil)
			if _, err := d.RoundTripProxyHTTP(req, fallback); err != nil {
				t.Error(err)
			}
		}()
	}
	<-entered
	select {
	case <-entered:
		t.Log("RESULT: both module requests active before either response")
	case <-time.After(500 * time.Millisecond):
		t.Error("module forwarding still serialized on response")
	}
	close(release)
	wg.Wait()
}

type discoveryWaitContext struct {
	context.Context
	selected chan struct{}
	once     sync.Once
}

func (c *discoveryWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.selected) })
	return c.Context.Done()
}

func TestQueuedDiscoveryObservesLearnedHTTP1(t *testing.T) {
	d := &connectDialer{proxyPool: newProxyH2Pool()}
	if err := d.lockProxyDial(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := &discoveryWaitContext{Context: context.Background(), selected: make(chan struct{})}
	result := make(chan func(), 1)
	go func() {
		release, err := d.lockProxyDiscovery(ctx)
		if err != nil {
			t.Error(err)
		}
		result <- release
	}()
	<-ctx.selected
	d.proxyProtocol(true)
	d.unlockProxyDial()
	release := <-result
	if len(d.proxyPool.dial) != 0 {
		t.Error("queued H1 discovery retained dial lock")
	}
	release()
	if err := d.lockProxyDial(context.Background()); err != nil {
		t.Fatal(err)
	}
	release, err := d.lockProxyDiscovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	d.unlockProxyDial()
}

func TestProxyDiscoveryFailureReleasesGateAndPreservesTrace(t *testing.T) {
	d := &connectDialer{proxyPool: newProxyH2Pool()}
	req, _ := fhttp.NewRequest("GET", "http://origin.test/", nil)
	failed := errors.New("owned handshake failed")
	if _, err := d.RoundTripProxyHTTP(req, a5RoundTrip(func(*fhttp.Request) (*fhttp.Response, error) { return nil, failed })); err != failed {
		t.Fatal(err)
	}
	if len(d.proxyPool.dial) != 0 {
		t.Fatal("failed handshake retained gate")
	}
	plain, other := net.Pipe()
	defer plain.Close()
	defer other.Close()
	calls := 0
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { calls++ }}))
	_, err := d.RoundTripProxyHTTP(req, a5RoundTrip(func(req *fhttp.Request) (*fhttp.Response, error) {
		httptrace.ContextClientTrace(req.Context()).GotConn(httptrace.GotConnInfo{Conn: plain})
		return &fhttp.Response{StatusCode: 200, Body: fhttp.NoBody}, nil
	}))
	if err != nil || calls != 1 || !d.proxyIsH1() || len(d.proxyPool.dial) != 0 {
		t.Fatalf("trace=%d, H1=%v, err=%v", calls, d.proxyIsH1(), err)
	}
}
